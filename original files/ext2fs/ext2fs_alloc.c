/*	$NetBSD: ext2fs_alloc.c,v 1.52 2017/05/28 16:38:55 hannken Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ffs_alloc.c	8.11 (Berkeley) 10/27/94
 *  Modified for ext2fs by Manuel Bouyer.
 */

/*
 * Copyright (c) 1997 Manuel Bouyer.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	@(#)ffs_alloc.c	8.11 (Berkeley) 10/27/94
 *  Modified for ext2fs by Manuel Bouyer.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: ext2fs_alloc.c,v 1.52 2017/05/28 16:38:55 hannken Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/kauth.h>

#include <lib/libkern/crc16.h>

#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufs_extern.h>
#include <ufs/ufs/ufsmount.h>

#include <ufs/ext2fs/ext2fs.h>
#include <ufs/ext2fs/ext2fs_extern.h>

u_long ext2gennumber;

static daddr_t	ext2fs_alloccg(struct inode *, int, daddr_t, int);
static u_long	ext2fs_dirpref(struct m_ext2fs *);
static void	ext2fs_fserr(struct m_ext2fs *, u_int, const char *);
static u_long	ext2fs_hashalloc(struct inode *, int, long, int,
		    daddr_t (*)(struct inode *, int, daddr_t, int));
static daddr_t	ext2fs_nodealloccg(struct inode *, int, daddr_t, int);
static daddr_t	ext2fs_mapsearch(struct m_ext2fs *, char *, daddr_t);
static __inline void	ext2fs_cg_update(struct m_ext2fs *, int, struct ext2_gd *, int, int, int, daddr_t);
static uint16_t 	ext2fs_cg_get_csum(struct m_ext2fs *, int, struct ext2_gd *);
static void		ext2fs_init_bb(struct m_ext2fs *, int, struct ext2_gd *, char *);

/*
 * Allocate a block in the file system.
 *
 * A preference may be optionally specified. If a preference is given
 * the following hierarchy is used to allocate a block:
 *   1) allocate the requested block.
 *   2) allocate a rotationally optimal block in the same cylinder.
 *   3) allocate a block in the same cylinder group.
 *   4) quadradically rehash into other cylinder groups, until an
 *	  available block is located.
 * If no block preference is given the following hierarchy is used
 * to allocate a block:
 *   1) allocate a block in the cylinder group that contains the
 *	  inode for the file.
 *   2) quadradically rehash into other cylinder groups, until an
 *	  available block is located.
 
 error = ext2fs_alloc(ip, bn,
     ext2fs_blkpref(ip, bn, bn, &ip->i_e2fs_blocks[0]),
     cred, &newb)
 */
int
ext2fs_alloc(struct inode *ip, daddr_t lbn, daddr_t bpref,
    kauth_cred_t cred, daddr_t *bnp)
{
	struct m_ext2fs *fs;
	daddr_t bno;
	int cg;

	*bnp = 0;
	fs = ip->i_e2fs;
#ifdef DIAGNOSTIC
	if (cred == NOCRED)
		panic("ext2fs_alloc: missing credential");
#endif /* DIAGNOSTIC */
	if (fs->e2fs.e2fs_fbcount == 0)
		goto nospace;
	if (kauth_authorize_system(cred, KAUTH_SYSTEM_FS_RESERVEDSPACE, 0, NULL,
	    NULL, NULL) != 0 &&
	    freespace(fs) <= 0)
		goto nospace;
	if (bpref >= fs->e2fs.e2fs_bcount)
		bpref = 0;
	if (bpref == 0)
        // convert inode number to cylinder group number
        // (ino - 1) / ino per group
		cg = ino_to_cg(fs, ip->i_number);
	else
        // dtog(fs, d) (((d) - (fs)->e2fs.e2fs_first_dblock) / (fs)->e2fs.e2fs_fpg)
        // (bpref - first datablock) / fragments per group
		cg = dtog(fs, bpref);
	bno = (daddr_t)ext2fs_hashalloc(ip, cg, bpref, fs->e2fs_bsize,
	    ext2fs_alloccg);
	if (bno > 0) {
        // btodb - convert bytes to disk blocks
		ext2fs_setnblock(ip, ext2fs_nblock(ip) + btodb(fs->e2fs_bsize));
		ip->i_flag |= IN_CHANGE | IN_UPDATE;
		*bnp = bno;
		return 0;
	}
nospace:
	ext2fs_fserr(fs, kauth_cred_geteuid(cred), "file system full");
	uprintf("\n%s: write failed, file system is full\n", fs->e2fs_fsmnt);
	return ENOSPC;
}

/*
 * Allocate an inode in the file system.
 *
 * If allocating a directory, use ext2fs_dirpref to select the inode.
 * If allocating in a directory, the following hierarchy is followed:
 *   1) allocate the preferred inode.
 *   2) allocate an inode in the same cylinder group.
 *   3) quadradically rehash into other cylinder groups, until an
 *	  available inode is located.
 * If no inode preference is given the following hierarchy is used
 * to allocate an inode:
 *   1) allocate an inode in cylinder group 0.
 *   2) quadradically rehash into other cylinder groups, until an
 *	  available inode is located.
 */
int
ext2fs_valloc(struct vnode *pvp, int mode, kauth_cred_t cred, ino_t *inop)
{
	struct inode *pip;
	struct m_ext2fs *fs;
	ino_t ino, ipref;
	int cg;

	pip = VTOI(pvp);
	fs = pip->i_e2fs;
	if (fs->e2fs.e2fs_ficount == 0)
		goto noinodes;

	if ((mode & IFMT) == IFDIR)
		cg = ext2fs_dirpref(fs);
	else
		cg = ino_to_cg(fs, pip->i_number);
	ipref = cg * fs->e2fs.e2fs_ipg + 1;
	ino = (ino_t)ext2fs_hashalloc(pip, cg, (long)ipref, mode, ext2fs_nodealloccg);
	if (ino == 0)
		goto noinodes;

	*inop = ino;
	return 0;

noinodes:
	ext2fs_fserr(fs, kauth_cred_geteuid(cred), "out of inodes");
	uprintf("\n%s: create/symlink failed, no inodes free\n", fs->e2fs_fsmnt);
	return ENOSPC;
}

/*
 * Find a cylinder to place a directory.
 *
 * The policy implemented by this algorithm is to select from
 * among those cylinder groups with above the average number of
 * free inodes, the one with the smallest number of directories.
 */
static u_long
ext2fs_dirpref(struct m_ext2fs *fs)
{
	int cg, maxspace, mincg, avgifree;

	avgifree = fs->e2fs.e2fs_ficount / fs->e2fs_ncg;
	maxspace = 0;
	mincg = -1;
	for (cg = 0; cg < fs->e2fs_ncg; cg++)
		if (fs2h16(fs->e2fs_gd[cg].ext2bgd_nifree) >= avgifree) {
			if (mincg == -1 || fs2h16(fs->e2fs_gd[cg].ext2bgd_nbfree) > maxspace) {
				mincg = cg;
				maxspace = fs2h16(fs->e2fs_gd[cg].ext2bgd_nbfree);
			}
		}
	return mincg;
}

/*
 * Select the desired position for the next block in a file.  The file is
 * logically divided into sections. The first section is composed of the
 * direct blocks. Each additional section contains fs_maxbpg blocks.
 *
 * If no blocks have been allocated in the first section, the policy is to
 * request a block in the same cylinder group as the inode that describes
 * the file. Otherwise, the policy is to try to allocate the blocks
 * contigously. The two fields of the ext2 inode extension (see
 * ufs/ufs/inode.h) help this.
 */
daddr_t
ext2fs_blkpref(struct inode *ip, daddr_t lbn, int indx,
		int32_t *bap /* XXX ondisk32 */)
{
	struct m_ext2fs *fs;
	int cg, i;

	fs = ip->i_e2fs;
	/*
	 * if we are doing contigous lbn allocation, try to alloc blocks
	 * contigously on disk
	 */

	if ( ip->i_e2fs_last_blk && lbn == ip->i_e2fs_last_lblk + 1) {
		return ip->i_e2fs_last_blk + 1;
	}

	/*
	 * bap, if provided, gives us a list of blocks to which we want to
	 * stay close
	 */

	if (bap) {
		for (i = indx; i >= 0 ; i--) {
			if (bap[i]) {
				return fs2h32(bap[i]) + 1;
			}
		}
	}

	/* fall back to the first block of the cylinder containing the inode */

	cg = ino_to_cg(fs, ip->i_number);
	return fs->e2fs.e2fs_bpg * cg + fs->e2fs.e2fs_first_dblock + 1;
}

/*
 * Implement the cylinder overflow algorithm.
 *
 * The policy implemented by this algorithm is:
 *   1) allocate the block in its requested cylinder group.
 *   2) quadradically rehash on the cylinder group number.
 *   3) brute force search for a free block.
 */
static u_long
ext2fs_hashalloc(struct inode *ip, int cg, long pref, int size,
		daddr_t (*allocator)(struct inode *, int, daddr_t, int))
{
	struct m_ext2fs *fs;
	long result;
	int i, icg = cg;

	fs = ip->i_e2fs;
	/*
	 * 1: preferred cylinder group
	 */
	result = (*allocator)(ip, cg, pref, size);
	if (result)
		return result;
	/*
	 * 2: quadratic rehash
	 */
	for (i = 1; i < fs->e2fs_ncg; i *= 2) {
		cg += i;
		if (cg >= fs->e2fs_ncg)
			cg -= fs->e2fs_ncg;
		result = (*allocator)(ip, cg, 0, size);
		if (result)
			return result;
	}
	/*
	 * 3: brute force search
	 * Note that we start at i == 2, since 0 was checked initially,
	 * and 1 is always checked in the quadratic rehash.
	 */
	cg = (icg + 2) % fs->e2fs_ncg;
	for (i = 2; i < fs->e2fs_ncg; i++) {
		result = (*allocator)(ip, cg, 0, size);
		if (result)
			return result;
		cg++;
		if (cg == fs->e2fs_ncg)
			cg = 0;
	}
	return 0;
}

/*
 * Determine whether a block can be allocated.
 *
 * Check to see if a block of the appropriate size is available,
 * and if it is, allocate it.
 */

static daddr_t
ext2fs_alloccg(struct inode *ip, int cg, daddr_t bpref, int size)
{
	struct m_ext2fs *fs;
	char *bbp;
	struct buf *bp;
	/* XXX ondisk32 */
	int error, bno, start, end, loc;

	fs = ip->i_e2fs;
	if (fs->e2fs_gd[cg].ext2bgd_nbfree == 0)
		return 0;
	error = bread(ip->i_devvp, EXT2_FSBTODB(fs,
		fs2h32(fs->e2fs_gd[cg].ext2bgd_b_bitmap)),
		(int)fs->e2fs_bsize, B_MODIFY, &bp);
	if (error) {
		return 0;
	}
	bbp = (char *)bp->b_data;

	if (dtog(fs, bpref) != cg)
		bpref = 0;

	/* initialize block bitmap now if uninit */
	if (__predict_false(E2FS_HAS_GD_CSUM(fs) &&
	    (fs->e2fs_gd[cg].ext2bgd_flags & h2fs16(E2FS_BG_BLOCK_UNINIT)))) {
		ext2fs_init_bb(fs, cg, &fs->e2fs_gd[cg], bbp);
		fs->e2fs_gd[cg].ext2bgd_flags &= h2fs16(~E2FS_BG_BLOCK_UNINIT);
	}

	if (bpref != 0) {
		bpref = dtogd(fs, bpref);
		/*
		 * if the requested block is available, use it
		 */
		if (isclr(bbp, bpref)) {
			bno = bpref;
			goto gotit;
		}
	}
	/*
	 * no blocks in the requested cylinder, so take next
	 * available one in this cylinder group.
	 * first try to get 8 contigous blocks, then fall back to a single
	 * block.
	 */
	if (bpref)
		start = dtogd(fs, bpref) / NBBY;
	else
		start = 0;
	end = howmany(fs->e2fs.e2fs_fpg, NBBY) - start;
	for (loc = start; loc < end; loc++) {
		if (bbp[loc] == 0) {
			bno = loc * NBBY;
			goto gotit;
		}
	}
	for (loc = 0; loc < start; loc++) {
		if (bbp[loc] == 0) {
			bno = loc * NBBY;
			goto gotit;
		}
	}

	bno = ext2fs_mapsearch(fs, bbp, bpref);
#if 0
	/*
	 * XXX jdolecek mapsearch actually never fails, it panics instead.
	 * If re-enabling, make sure to brele() before returning.
	 */
	if (bno < 0)
		return 0;
#endif
gotit:
#ifdef DIAGNOSTIC
	if (isset(bbp, (daddr_t)bno)) {
		printf("ext2fs_alloccgblk: cg=%d bno=%d fs=%s\n",
			cg, bno, fs->e2fs_fsmnt);
		panic("ext2fs_alloccg: dup alloc");
	}
#endif
	setbit(bbp, (daddr_t)bno);
	fs->e2fs.e2fs_fbcount--;
	ext2fs_cg_update(fs, cg, &fs->e2fs_gd[cg], -1, 0, 0, 0);
	fs->e2fs_fmod = 1;
	bdwrite(bp);
	return cg * fs->e2fs.e2fs_fpg + fs->e2fs.e2fs_first_dblock + bno;
}

/*
 * Determine whether an inode can be allocated.
 *
 * Check to see if an inode is available, and if it is,
 * allocate it using the following policy:
 *   1) allocate the requested inode.
 *   2) allocate the next available inode after the requested
 *	  inode in the specified cylinder group.
 */
static daddr_t
ext2fs_nodealloccg(struct inode *ip, int cg, daddr_t ipref, int mode)
{
	struct m_ext2fs *fs;
	char *ibp;
	struct buf *bp;
	int error, start, len, loc, map, i;

	ipref--; /* to avoid a lot of (ipref -1) */
	if (ipref == -1)
		ipref = 0;
	fs = ip->i_e2fs;
	if (fs->e2fs_gd[cg].ext2bgd_nifree == 0)
		return 0;
	error = bread(ip->i_devvp, EXT2_FSBTODB(fs,
		fs2h32(fs->e2fs_gd[cg].ext2bgd_i_bitmap)),
		(int)fs->e2fs_bsize, B_MODIFY, &bp);
	if (error) {
		return 0;
	}
	ibp = (char *)bp->b_data;

	KASSERT(!E2FS_HAS_GD_CSUM(fs) || (fs->e2fs_gd[cg].ext2bgd_flags & h2fs16(E2FS_BG_INODE_ZEROED)) != 0);

	/* initialize inode bitmap now if uninit */
	if (__predict_false(E2FS_HAS_GD_CSUM(fs) &&
	    (fs->e2fs_gd[cg].ext2bgd_flags & h2fs16(E2FS_BG_INODE_UNINIT)))) {
		KASSERT(fs2h16(fs->e2fs_gd[cg].ext2bgd_nifree) == fs->e2fs.e2fs_ipg);
		memset(ibp, 0, fs->e2fs_bsize);
		fs->e2fs_gd[cg].ext2bgd_flags &= h2fs16(~E2FS_BG_INODE_UNINIT);
	}

	if (ipref) {
		ipref %= fs->e2fs.e2fs_ipg;
		if (isclr(ibp, ipref))
			goto gotit;
	}
	start = ipref / NBBY;
	len = howmany(fs->e2fs.e2fs_ipg - ipref, NBBY);
	loc = skpc(0xff, len, &ibp[start]);
	if (loc == 0) {
		len = start + 1;
		start = 0;
		loc = skpc(0xff, len, &ibp[0]);
		if (loc == 0) {
			printf("cg = %d, ipref = %lld, fs = %s\n",
				cg, (long long)ipref, fs->e2fs_fsmnt);
			panic("ext2fs_nodealloccg: map corrupted");
			/* NOTREACHED */
		}
	}
	i = start + len - loc;
	map = ibp[i] ^ 0xff;
	if (map == 0) {
		printf("fs = %s\n", fs->e2fs_fsmnt);
		panic("ext2fs_nodealloccg: inode not in map");
	}
	ipref = i * NBBY + ffs(map) - 1;
gotit:
	setbit(ibp, ipref);
	fs->e2fs.e2fs_ficount--;
	ext2fs_cg_update(fs, cg, &fs->e2fs_gd[cg],
		0, -1, ((mode & IFMT) == IFDIR) ? 1 : 0, ipref);
	fs->e2fs_fmod = 1;
	bdwrite(bp);
	return cg * fs->e2fs.e2fs_ipg + ipref + 1;
}

/*
 * Free a block.
 *
 * The specified block is placed back in the
 * free map.
 */
void
ext2fs_blkfree(struct inode *ip, daddr_t bno)
{
	struct m_ext2fs *fs;
	char *bbp;
	struct buf *bp;
	int error, cg;

	fs = ip->i_e2fs;
	cg = dtog(fs, bno);

	KASSERT(!E2FS_HAS_GD_CSUM(fs) || (fs->e2fs_gd[cg].ext2bgd_flags & h2fs16(E2FS_BG_BLOCK_UNINIT)) == 0);

	if ((u_int)bno >= fs->e2fs.e2fs_bcount) {
		printf("bad block %lld, ino %llu\n", (long long)bno,
		    (unsigned long long)ip->i_number);
		ext2fs_fserr(fs, ip->i_uid, "bad block");
		return;
	}
	error = bread(ip->i_devvp,
		EXT2_FSBTODB(fs, fs2h32(fs->e2fs_gd[cg].ext2bgd_b_bitmap)),
		(int)fs->e2fs_bsize, B_MODIFY, &bp);
	if (error) {
		return;
	}
	bbp = (char *)bp->b_data;
	bno = dtogd(fs, bno);
	if (isclr(bbp, bno)) {
		printf("dev = 0x%llx, block = %lld, fs = %s\n",
		    (unsigned long long)ip->i_dev, (long long)bno,
		    fs->e2fs_fsmnt);
		panic("blkfree: freeing free block");
	}
	clrbit(bbp, bno);
	fs->e2fs.e2fs_fbcount++;
	ext2fs_cg_update(fs, cg, &fs->e2fs_gd[cg], 1, 0, 0, 0);
	fs->e2fs_fmod = 1;
	bdwrite(bp);
}

/*
 * Free an inode.
 *
 * The specified inode is placed back in the free map.
 */
int
ext2fs_vfree(struct vnode *pvp, ino_t ino, int mode)
{
	struct m_ext2fs *fs;
	char *ibp;
	struct inode *pip;
	struct buf *bp;
	int error, cg;

	pip = VTOI(pvp);
	fs = pip->i_e2fs;

	if ((u_int)ino > fs->e2fs.e2fs_icount || (u_int)ino < EXT2_FIRSTINO)
		panic("ifree: range: dev = 0x%llx, ino = %llu, fs = %s",
		    (unsigned long long)pip->i_dev, (unsigned long long)ino,
		    fs->e2fs_fsmnt);

	cg = ino_to_cg(fs, ino);

	KASSERT(!E2FS_HAS_GD_CSUM(fs) || (fs->e2fs_gd[cg].ext2bgd_flags & h2fs16(E2FS_BG_INODE_UNINIT)) == 0);

	error = bread(pip->i_devvp,
		EXT2_FSBTODB(fs, fs2h32(fs->e2fs_gd[cg].ext2bgd_i_bitmap)),
		(int)fs->e2fs_bsize, B_MODIFY, &bp);
	if (error) {
		return 0;
	}
	ibp = (char *)bp->b_data;
	ino = (ino - 1) % fs->e2fs.e2fs_ipg;
	if (isclr(ibp, ino)) {
		printf("dev = 0x%llx, ino = %llu, fs = %s\n",
		    (unsigned long long)pip->i_dev,
		    (unsigned long long)ino, fs->e2fs_fsmnt);
		if (fs->e2fs_ronly == 0)
			panic("ifree: freeing free inode");
	}
	clrbit(ibp, ino);
	fs->e2fs.e2fs_ficount++;
	ext2fs_cg_update(fs, cg, &fs->e2fs_gd[cg],
		0, 1, ((mode & IFMT) == IFDIR) ? -1 : 0, 0);
	fs->e2fs_fmod = 1;
	bdwrite(bp);
	return 0;
}

/*
 * Find a block in the specified cylinder group.
 *
 * It is a panic if a request is made to find a block if none are
 * available.
 */

static daddr_t
ext2fs_mapsearch(struct m_ext2fs *fs, char *bbp, daddr_t bpref)
{
	int start, len, loc, i, map;

	/*
	 * find the fragment by searching through the free block
	 * map for an appropriate bit pattern
	 */
	if (bpref)
		start = dtogd(fs, bpref) / NBBY;
	else
		start = 0;
	len = howmany(fs->e2fs.e2fs_fpg, NBBY) - start;
	loc = skpc(0xff, len, &bbp[start]);
	if (loc == 0) {
		len = start + 1;
		start = 0;
		loc = skpc(0xff, len, &bbp[start]);
		if (loc == 0) {
			printf("start = %d, len = %d, fs = %s\n",
				start, len, fs->e2fs_fsmnt);
			panic("ext2fs_alloccg: map corrupted");
			/* NOTREACHED */
		}
	}
	i = start + len - loc;
	map = bbp[i] ^ 0xff;
	if (map == 0) {
		printf("fs = %s\n", fs->e2fs_fsmnt);
		panic("ext2fs_mapsearch: block not in map");
	}
	return i * NBBY + ffs(map) - 1;
}

/*
 * Fserr prints the name of a file system with an error diagnostic.
 *
 * The form of the error message is:
 *	fs: error message
 */
static void
ext2fs_fserr(struct m_ext2fs *fs, u_int uid, const char *cp)
{

	log(LOG_ERR, "uid %d on %s: %s\n", uid, fs->e2fs_fsmnt, cp);
}

static __inline void
ext2fs_cg_update(struct m_ext2fs *fs, int cg, struct ext2_gd *gd, int nbfree, int nifree, int ndirs, daddr_t ioff)
{
	/* XXX disk32 */
	if (nifree) {
		gd->ext2bgd_nifree = h2fs16(fs2h16(gd->ext2bgd_nifree) + nifree);
		/*
		 * If we allocated inode on bigger offset than what was
		 * ever used before, bump the itable_unused count. This
		 * member only ever grows, and is used only for initialization
		 * !INODE_ZEROED groups with used inodes. Of course, by the
		 * time we get here the itables are already zeroed, but
		 * e2fstools fsck.ext4 still checks this.
		 */
		if (E2FS_HAS_GD_CSUM(fs) && nifree < 0 && (ioff+1) >= (fs->e2fs.e2fs_ipg - fs2h16(gd->ext2bgd_itable_unused_lo))) {
			gd->ext2bgd_itable_unused_lo = h2fs16(fs->e2fs.e2fs_ipg - (ioff + 1));
		}

		KASSERT(!E2FS_HAS_GD_CSUM(fs) || gd->ext2bgd_itable_unused_lo <= gd->ext2bgd_nifree);
	}


	if (nbfree)
		gd->ext2bgd_nbfree = h2fs16(fs2h16(gd->ext2bgd_nbfree) + nbfree);

	if (ndirs)
		gd->ext2bgd_ndirs = h2fs16(fs2h16(gd->ext2bgd_ndirs) + ndirs);

	if (E2FS_HAS_GD_CSUM(fs))
		gd->ext2bgd_checksum = ext2fs_cg_get_csum(fs, cg, gd);
}

/*
 * Compute group description csum. Structure data must be LE (not host).
 * Returned as LE (disk encoding).
 */
static uint16_t
ext2fs_cg_get_csum(struct m_ext2fs *fs, int cg, struct ext2_gd *gd)
{
	uint16_t crc;
	uint32_t cg_bswapped = h2fs32((uint32_t)cg);
	size_t off;

	if (!EXT2F_HAS_ROCOMPAT_FEATURE(fs, EXT2F_ROCOMPAT_GDT_CSUM))
		return 0;

	off = offsetof(struct ext2_gd, ext2bgd_checksum);

	crc = crc16(~0, (uint8_t *)fs->e2fs.e2fs_uuid, sizeof(fs->e2fs.e2fs_uuid));
	crc = crc16(crc, (uint8_t *)&cg_bswapped, sizeof(cg_bswapped));
	crc = crc16(crc, (uint8_t *)gd, off);
	/* XXX ondisk32 */

	return h2fs16(crc);
}

static void
ext2fs_init_bb(struct m_ext2fs *fs, int cg, struct ext2_gd *gd, char *bbp)
{
	int i;

	memset(bbp, 0, fs->e2fs_bsize);

	/*
	 * No block was ever allocated on this cg before, so the only used
	 * blocks are metadata blocks on start of the group. We could optimize
	 * this to set by bytes, but since this is done once per the group
	 * in lifetime of filesystem, it really is not worth it.
	 */
	for(i=0; i < fs->e2fs.e2fs_bpg - fs2h16(gd->ext2bgd_nbfree); i++)
		setbit(bbp, i);
}

/*
 * Verify csum and initialize itable if not done already
 */
int
ext2fs_cg_verify_and_initialize(struct vnode *devvp, struct m_ext2fs *fs, int ronly)
{
	/* XXX disk32 */
	struct ext2_gd *gd;
	ino_t ioff;
	size_t boff;
	struct buf *bp;
	int cg, i, error;

	if (!E2FS_HAS_GD_CSUM(fs))
		return 0;

	for(cg=0; cg < fs->e2fs_ncg; cg++) {
		gd = &fs->e2fs_gd[cg];

		/* Verify checksum */
		if (gd->ext2bgd_checksum != ext2fs_cg_get_csum(fs, cg, gd)) {
			printf("ext2fs_cg_verify_and_initialize: group %d invalid csum\n", cg);
			return EINVAL;
		}

		/* if mounting read-write, zero itable if not already done */
		if (ronly || (gd->ext2bgd_flags & h2fs16(E2FS_BG_INODE_ZEROED)) != 0)
			continue;

		/*
		 * We are skipping already used inodes, zero rest of itable
		 * blocks. First block to zero could be only partial wipe, all
		 * others are wiped completely. This might take a while,
		 * there could be many inode table blocks. We use
		 * delayed writes, so this shouldn't block for very
		 * long.
		 */
		ioff = fs->e2fs.e2fs_ipg - fs2h16(gd->ext2bgd_itable_unused_lo);
		boff = (ioff % fs->e2fs_ipb) * EXT2_DINODE_SIZE(fs);

		for(i = ioff / fs->e2fs_ipb; i < fs->e2fs_itpg; i++) {
			if (boff) {
				/* partial wipe, must read old data */
				error = bread(devvp,
					EXT2_FSBTODB(fs, fs2h32(gd->ext2bgd_i_tables) + i),
					(int)fs->e2fs_bsize, B_MODIFY, &bp);
				if (error) {
					printf("ext2fs_cg_verify_and_initialize: can't read itable block");
					return error;
				}
				memset((char *)bp->b_data + boff, 0, fs->e2fs_bsize - boff);
				boff = 0;
			} else {
				/*
				 * Complete wipe, don't need to read data. This
				 * assumes nothing else is changing the data.
				 */
				bp = getblk(devvp,
					EXT2_FSBTODB(fs, fs2h32(gd->ext2bgd_i_tables) + i),
					(int)fs->e2fs_bsize, 0, 0);
				clrbuf(bp);
			}
	
			bdwrite(bp);
		}

		gd->ext2bgd_flags |= h2fs16(E2FS_BG_INODE_ZEROED);
		gd->ext2bgd_checksum = ext2fs_cg_get_csum(fs, cg, gd);
		fs->e2fs_fmod = 1;
	}

	return 0;
}
