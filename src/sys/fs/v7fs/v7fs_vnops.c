/*	$NetBSD: v7fs_vnops.c,v 1.31 2020/06/27 17:29:18 christos Exp $	*/

/*-
 * Copyright (c) 2004, 2011 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by UCHIYAMA Yasushi.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: v7fs_vnops.c,v 1.31 2020/06/27 17:29:18 christos Exp $");
#if defined _KERNEL_OPT
#include "opt_v7fs.h"
#endif

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/resource.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/dirent.h>
#include <sys/kmem.h>
#include <sys/lockf.h>
#include <sys/unistd.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <sys/buf.h>
#include <sys/stat.h>	/*APPEND */
#include <miscfs/genfs/genfs.h>

#include <fs/v7fs/v7fs.h>
#include <fs/v7fs/v7fs_impl.h>
#include <fs/v7fs/v7fs_inode.h>
#include <fs/v7fs/v7fs_dirent.h>
#include <fs/v7fs/v7fs_file.h>
#include <fs/v7fs/v7fs_datablock.h>
#include <fs/v7fs/v7fs_extern.h>
#include <fs/v7fs/v7fs_endian.h>


#ifdef V7FS_VNOPS_DEBUG
#define	DPRINTF(fmt, args...)	printf("%s: " fmt, __func__, ##args)
#else
#define	DPRINTF(arg...)		((void)0)
#endif

static v7fs_mode_t vtype_to_v7fs_mode(enum vtype);
static uint8_t v7fs_mode_to_d_type(v7fs_mode_t);


static v7fs_mode_t
vtype_to_v7fs_mode(enum vtype type)
{
	/* Convert Vnode types to V7FS types (sys/vnode.h)*/
	v7fs_mode_t table[] = { 0, V7FS_IFREG, V7FS_IFDIR, V7FS_IFBLK,
				V7FS_IFCHR, V7FSBSD_IFLNK, V7FSBSD_IFSOCK,
				V7FSBSD_IFFIFO };
	return table[type];
}

static uint8_t
v7fs_mode_to_d_type(v7fs_mode_t mode)
{
	/* Convert V7FS types to dirent d_type (sys/dirent.h)*/

	return (mode & V7FS_IFMT) >> 12;
}

/* MOP functions introduced */

// MOP and helper function(s) related to create()

void v7fs_mop_get_dirbuf_size(size_t *dirbuf)
{
    *dirbuf = sizeof(struct v7fs_dirent);
}

void v7fs_mop_filename_truncate(char* filename, struct componentname *cnp)
{

    strncpy(filename, cnp->cn_nameptr, V7FS_NAME_MAX);
    filename[V7FS_NAME_MAX] = '\0';
    
}

ino_t v7fs_mop_get_inumber(struct vnode *vp)
{
    struct v7fs_node *new_node = vp->v_data;
    struct v7fs_inode inode = new_node->inode;
    return (ino_t) inode.inode_number;
  
}


void v7fs_mop_set_dirent(struct vnode *vp, struct componentname *cnp, char *dirbuf, size_t *newentrysize, const char* name, size_t namelen)
{
    struct v7fs_dirent newdir;
    ino_t ino_temp = MOP_GET_INUMBER(vp);
    KASSERT(ino_temp < 0xFFFF);
    v7fs_ino_t ino = (v7fs_ino_t) ino_temp;
  
    newdir.inode_number = ino;
    
    memcpy(newdir.name, name, V7FS_NAME_MAX);
    *newentrysize = sizeof(newdir);
    
    memcpy(dirbuf, &newdir, sizeof(struct v7fs_dirent));
    
    
}

int v7fs_mop_dirent_writeback(struct vnode *vp, char* buf, daddr_t blk)
{
    struct v7fs_node *v7node = vp->v_data;
    struct v7fs_mount *v7fsmount = v7node->v7fsmount;
    struct v7fs_self *fs = v7fsmount->core;
    
    if (!fs->io.write(fs->io.cookie, buf, blk)) {
        scratch_free(fs, buf);
        return EIO;
    }
    scratch_free(fs, buf);
    return 0;
}

void v7fs_mop_add_direntry(char *buf, char* dirbuf, size_t dirsize, int n)
{
    struct v7fs_dirent *dir = (struct v7fs_dirent *) buf;
    memcpy(dir + n, dirbuf, dirsize);
}

void v7fs_mop_get_bufsize(size_t *buf_size)
{
    *buf_size = V7FS_BSIZE;
}

int v7fs_mop_get_blk(struct vnode *dvp, struct vnode *vp, char **buf, int n, daddr_t *blk, int isdir)
{
    struct v7fs_node *v7node = vp->v_data;
    struct v7fs_inode inode = v7node->inode;
    struct v7fs_mount *v7fsmount = v7node->v7fsmount;
    struct v7fs_self *fs = v7fsmount->core;
    v7fs_ino_t ino = inode.inode_number;
    
    struct v7fs_node *parent_node = dvp->v_data;
    struct v7fs_inode *parent_dir = &parent_node->inode;
    v7fs_daddr_t v7blk;

    
    if (isdir) {
        v7blk = inode.addr[n];
        if (!(*buf = scratch_read(fs, v7blk))) {
            v7fs_inode_deallocate(fs, ino);
            return EIO;
        }
    } else {
        if (!(v7blk = v7fs_datablock_last(fs, parent_dir, v7fs_mop_get_filesize(dvp))))
            return EIO;
        
        if (!(*buf = scratch_read(fs, v7blk)))
            return EIO;
    }
    
    *blk = v7blk;
    
    return 0;
}

int v7fs_mop_lookup_by_name(struct vnode *dvp, struct vnode *vp, char* filename)
{
    struct v7fs_node *parent_node = dvp->v_data;
    struct v7fs_inode *parent_dir = &parent_node->inode;
    struct v7fs_mount *v7fsmount = parent_node->v7fsmount;
    struct v7fs_self *fs = v7fsmount->core;
    ino_t ino_temp = MOP_GET_INUMBER(vp);
    v7fs_ino_t ino = (v7fs_ino_t) ino_temp;
    
    if (v7fs_file_lookup_by_name(fs, parent_dir, filename, &ino) == 0) {
        DPRINTF("%s exists\n", filename);
        return EEXIST;
    }
    
    return 0;
}

void v7fs_mop_parentdir_update(struct vnode *dvp)
{
    struct v7fs_node *parent_node = dvp->v_data;
    struct v7fs_mount *v7fsmount = parent_node->v7fsmount;
    struct v7fs_self *fs = v7fsmount->core;
    struct v7fs_inode *inode = &parent_node->inode;

    inode->nlink++;
    v7fs_inode_writeback(fs, inode);
}

void v7fs_mop_get_max_namesize(size_t *max_namesize)
{
    *max_namesize = V7FS_NAME_MAX;
}

int v7fs_mop_isdir(struct vnode *vp)
{
    struct v7fs_node *new_node = vp->v_data;
    struct v7fs_inode inode = new_node->inode;
    return v7fs_inode_isdir(&inode);
}

void v7fs_mop_get_dirent_pos(struct vnode *dvp, int *idx, size_t dirsize)
{
    size_t sz = MOP_GET_FILESIZE(dvp);
    sz = V7FS_RESIDUE_BSIZE(sz);    /* last block payload. */
    *idx = sz / dirsize - 1;
}

int v7fs_mop_grow_parentdir(struct vnode *dvp, size_t *dirsize)
{
    struct v7fs_node *parent_node = dvp->v_data;
    struct v7fs_mount *v7fsmount = parent_node->v7fsmount;
    struct v7fs_self *fs = v7fsmount->core;
    struct v7fs_inode *parent_inode = &parent_node->inode;
    
    return v7fs_datablock_expand(fs, parent_inode, *dirsize);
    
}


int v7fs_mop_create(struct vnode* dvp, struct vnode** vpp, struct componentname* cnp, struct vattr* vap, char *dirbuf, size_t newentrysize, char *filename, char* buf)
{
    int error = 0;
    struct v7fs_node *parent_node = dvp->v_data;
    struct v7fs_mount *v7fsmount = parent_node->v7fsmount;
    struct v7fs_self *fs = v7fsmount->core;
    char filename[V7FS_NAME_MAX + 1];
    struct v7fs_inode *parent_dir = &parent_node->inode;
    struct v7fs_node *new_node = (*vpp)->v_data;
    struct v7fs_inode inode = new_node->inode;
    daddr_t blk;
    
    MOP_FILENAME_TRUNCATE(filename, cnp);

    size_t dirsize = -1;
    MOP_GET_DIRBUF_SIZE(&dirsize);
    

    //void *buf;

    
    if ((error = MOP_LOOKUP_BY_NAME(dvp, *vpp, filename))) {
        return error;
    }
    
    if (v7fs_inode_isdir(&inode)) {
        if ((error = MOP_GET_BLK(dvp, *vpp, &buf, 0, &blk, 1))) {
            return error;
        }
        MOP_SET_DIRENT(*vpp, dirbuf, &newentrysize, ".", strlen("."));
        MOP_ADD_DIRENTRY(buf, dirbuf, dirsize, 0);
        MOP_SET_DIRENT(dvp, dirbuf, &newentrysize, "..", strlen(".."));
        MOP_ADD_DIRENTRY(buf, dirbuf, dirsize, 1);
        
        MOP_PARENTDIR_UPDATE(dvp);

        
        if ((error = MOP_DIRENT_WRITEBACK((*vpp), buf, blk)) != 0) {
            return error;
        }
    }
    
    // Expand datablock.
    if ((error = v7fs_datablock_expand(fs, parent_dir, dirsize)))
        return error;

    
   // void *buf;
    
    
    size_t sz = MOP_GET_FILESIZE(dvp);
    sz = V7FS_RESIDUE_BSIZE(sz);    // last block payload.
    int n = sz / dirsize - 1;
    
    if ((error = MOP_GET_BLK(dvp, *vpp, &buf, n, &blk, 0))) {
        return error;
    }

    MOP_SET_DIRENT(*vpp, dirbuf, &newentrysize, filename, V7FS_NAME_MAX);
    MOP_ADD_DIRENTRY(buf, dirbuf, dirsize, n);
    if (!fs->io.write(fs->io.cookie, buf, blk))
        error = EIO;
    scratch_free(fs, buf);


    if (v7fs_inode_isdir(&inode)) {
        parent_dir->nlink++;
        v7fs_inode_writeback(fs, parent_dir);
    }

    DPRINTF("done. (dirent size=%dbyte)\n", parent_dir->filesize);
    
    // Sync dirent size change.
    uvm_vnp_setsize(dvp, v7fs_inode_filesize(&parent_node->inode));

    return error;
    
}

void v7fs_mop_postcreate_update(struct vnode** vpp)
{
 
    /* Scheduling update time. real update by v7fs_update */
    struct v7fs_node *newnode = (*vpp)->v_data;
    newnode->update_ctime = true;
    newnode->update_mtime = true;
    newnode->update_atime = true;
}

// MOP and helper function(s) related to open()

int
v7fs_mop_open_opt(struct vnode *vp, int mode)
{
    struct v7fs_node *v7node = vp->v_data;
    struct v7fs_inode *inode = &v7node->inode;

    DPRINTF("inode %d\n", inode->inode_number);
    if (inode->append_mode &&
        ((mode & (FWRITE | O_APPEND)) == FWRITE)) {
        DPRINTF("file is already opened by append mode.\n");
        return EPERM;
    }

    return 0;
}

// MOP and helper function(s) related to close()

void
v7fs_mop_close_update(struct vnode *vp)
{
#ifdef V7FS_VNOPS_DEBUG
    struct v7fs_node *v7node = vp->v_data;
    struct v7fs_inode *inode = &v7node->inode;
#endif
    DPRINTF("#%d (i)%dbyte (v)%zubyte\n", inode->inode_number,
        v7fs_inode_filesize(inode), vp->v_size);

    // Update timestamp
    v7fs_update(vp, 0, 0, UPDATE_WAIT);
}

// MOP and helper function(s) related to read()

vsize_t v7fs_mop_get_filesize(struct vnode* vp)
{
    struct v7fs_node *v7node = VNTOV7FSN(vp);
    struct v7fs_inode *inode = &v7node->inode;
    vsize_t filesize = v7fs_inode_filesize(inode);
    
    return filesize;
}

int v7fs_mop_check_maxsize(struct vnode* vp, struct uio* uio)
{
    int error = 0;
    
    if (uio->uio_offset > V7FS_MAX_FILESIZE) {
        return EFBIG;
    }
    
    return error;
}

int
v7fs_mop_postread_update(struct vnode *vp, int ioflag, int oerror)
{
    int error = oerror;
    struct v7fs_node *v7node = VNTOV7FSN(vp);
    
    v7node->update_atime = true;
    return (error);
}

// MOP and helper function(s) related to write()

int
v7fs_mop_write_checks(struct vnode* vp, struct uio* uio, kauth_cred_t cred, int ioflag)
{
    struct v7fs_node *v7node = vp->v_data;
    struct v7fs_inode *inode = &v7node->inode;
    vsize_t size = v7fs_inode_filesize(inode);
    int error = 0;
    
    if (ioflag & IO_APPEND) {
        uio->uio_offset = size;
    }
    return error;
}

int v7fs_mop_get_blkoff(struct vnode* vp, struct uio* uio)
{
    return (uio->uio_offset & (V7FS_BSIZE - 1));
}

vsize_t v7fs_mop_get_bytelen(struct vnode* vp, int blkoff, struct uio* uio)
{
    return MIN(V7FS_BSIZE - blkoff, uio->uio_resid);
}

int v7fs_mop_datablock_expand(struct vnode* vp, struct uio* uio, vsize_t bytelen, kauth_cred_t cred)
{
    struct v7fs_node *v7node = vp->v_data;
    struct v7fs_inode *inode = &v7node->inode;
    struct v7fs_self *fs = v7node->v7fsmount->core;
    int error = 0;
    vsize_t current_size = v7fs_inode_filesize(inode);
    vsize_t new_size = uio->uio_offset + bytelen;
    ssize_t expand = new_size - current_size;
    
    if (expand > 0) {
        if ((error = v7fs_datablock_expand(fs, inode, expand)))
            return error;
    }

    return error;
}

vsize_t v7fs_mop_round(struct vnode * vp, struct uio* uio)
{
    return V7FS_ROUND_BSIZE(uio->uio_offset);
}



void v7fs_mop_postwrite_update(struct vnode* vp, struct uio* uio, kauth_cred_t cred, int resid)
{
    struct v7fs_node *v7node = vp->v_data;
    v7node->update_mtime = true;
}

/* Original v7fs functions */

int
v7fs_create(void *v)
{
    struct vop_create_v3_args /* {
                  struct vnode *a_dvp;
                  struct vnode **a_vpp;
                  struct componentname *a_cnp;
                  struct vattr *a_vap;
                  } */ *a = v;
    struct v7fs_node *parent_node = a->a_dvp->v_data;
    struct v7fs_mount *v7fsmount = parent_node->v7fsmount;
    struct v7fs_self *fs = v7fsmount->core;
    struct mount *mp = v7fsmount->mountp;
    struct v7fs_fileattr attr;
    struct vattr *va = a->a_vap;
    kauth_cred_t cr = a->a_cnp->cn_cred;
    v7fs_ino_t ino;
    int error = 0;

    DPRINTF("%s parent#%d\n", a->a_cnp->cn_nameptr,
        parent_node->inode.inode_number);
    KDASSERT((va->va_type == VREG) || (va->va_type == VSOCK));

    memset(&attr, 0, sizeof(attr));
    attr.uid = kauth_cred_geteuid(cr);
    attr.gid = kauth_cred_getegid(cr);
    attr.mode = va->va_mode | vtype_to_v7fs_mode (va->va_type);
    attr.device = 0;

    /* Allocate disk entry. and register its entry to parent directory. */
    if ((error = v7fs_file_allocate(fs, &parent_node->inode,
            a->a_cnp->cn_nameptr, &attr, &ino))) {
        DPRINTF("v7fs_file_allocate failed.\n");
        return error;
    }
    /* Sync dirent size change. */
    uvm_vnp_setsize(a->a_dvp, v7fs_inode_filesize(&parent_node->inode));

    /* Get myself vnode. */
    *a->a_vpp = 0;
    error = v7fs_vget(mp, ino, LK_EXCLUSIVE, a->a_vpp);
    if (error != 0) {
        DPRINTF("v7fs_vget failed.\n");
        return error;
    }

    /* Scheduling update time. real update by v7fs_update */
    struct v7fs_node *newnode = (*a->a_vpp)->v_data;
    newnode->update_ctime = true;
    newnode->update_mtime = true;
    newnode->update_atime = true;
    DPRINTF("allocated %s->#%d\n", a->a_cnp->cn_nameptr, ino);

    if (error == 0)
        VOP_UNLOCK(*a->a_vpp);

    return error;
}

int
v7fs_lookup(void *v)
{
	struct vop_lookup_v2_args  /*{
				  struct vnode *a_dvp;
				  struct vnode **a_vpp;
				  struct componentname *a_cnp;
				  } */  *a = v;
	struct vnode *dvp = a->a_dvp;
	struct v7fs_node *parent_node = dvp->v_data;
	struct v7fs_inode *parent = &parent_node->inode;
	struct v7fs_self *fs = parent_node->v7fsmount->core; //my filesystem
	struct vnode *vpp;
	struct componentname *cnp = a->a_cnp;
	int nameiop = cnp->cn_nameiop;
	const char *name = cnp->cn_nameptr;
	int namelen = cnp->cn_namelen;
	int flags = cnp->cn_flags;
	bool isdotdot = flags & ISDOTDOT;
	bool islastcn = flags & ISLASTCN;
	v7fs_ino_t ino;
	int error;
#ifdef V7FS_VNOPS_DEBUG
	const char *opname[] = { "LOOKUP", "CREATE", "DELETE", "RENAME" };
#endif
	DPRINTF("'%s' op=%s flags=%d parent=%d %o %dbyte\n", name,
	    opname[nameiop], cnp->cn_flags, parent->inode_number, parent->mode,
	    parent->filesize);

	*a->a_vpp = 0;

	// Check directory permission for search
	if ((error = VOP_ACCESS(dvp, VEXEC, cnp->cn_cred))) {
		DPRINTF("***perm.\n");
		return error;
	}

	// Deny last component write operation on a read-only mount
	if (islastcn && (dvp->v_mount->mnt_flag & MNT_RDONLY) &&
	    (nameiop == DELETE || nameiop == RENAME)) {
		DPRINTF("***ROFS.\n");
		return EROFS;
	}

	// No lookup on removed directory
	if (v7fs_inode_nlink(parent) == 0)
		return ENOENT;

	// "."
	if (namelen == 1 && name[0] == '.') {
		if ((nameiop == RENAME) && islastcn) {
			return EISDIR; // t_vnops rename_dir(3)
		}
		vref(dvp); // usecount++
		*a->a_vpp = dvp;
		DPRINTF("done.(.)\n");
		return 0;
	}

	// ".." and reguler file.
	if ((error = v7fs_file_lookup_by_name(fs, parent, name, &ino))) {
		// Not found. Tell this entry be able to allocate.
		if (((nameiop == CREATE) || (nameiop == RENAME)) && islastcn) {
			// Check directory permission to allocate.
			if ((error = VOP_ACCESS(dvp, VWRITE, cnp->cn_cred))) {
				DPRINTF("access denied. (%s)\n", name);
				return error;
			}
			DPRINTF("EJUSTRETURN op=%d (%s)\n", nameiop, name);
			return EJUSTRETURN;
		}
		DPRINTF("lastcn=%d\n", flags & ISLASTCN);
		return error;
	}

	if ((nameiop == DELETE) && islastcn) {
		if ((error = VOP_ACCESS(dvp, VWRITE, cnp->cn_cred))) {
			DPRINTF("access denied. (%s)\n", name);
			return error;
		}
	}

	// Entry found. Allocate v-node
	// Check permissions?
	vpp = 0;
	if (isdotdot) {
		VOP_UNLOCK(dvp); // preserve reference count. (not vput)
	}
	DPRINTF("enter vget\n");
	error = v7fs_vget(dvp->v_mount, ino, LK_EXCLUSIVE, &vpp);
	if (error != 0) {
		DPRINTF("***can't get vnode.\n");
		return error;
	}
	DPRINTF("exit vget\n");
	if (isdotdot) {
		vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY);
	}
	if (vpp != dvp)
		VOP_UNLOCK(vpp);
	*a->a_vpp = vpp;
	DPRINTF("done.(%s)\n", name);

	return 0;
}

int
v7fs_mknod(void *v)
{
	struct vop_mknod_v3_args /* {
				 struct vnode		*a_dvp;
				 struct vnode		**a_vpp;
				 struct componentname	*a_cnp;
				 struct vattr		*a_vap;
				 } */  *a = v;
	struct componentname *cnp = a->a_cnp;
	kauth_cred_t cr = cnp->cn_cred;
	struct vnode *dvp = a->a_dvp;
	struct vattr *va = a->a_vap;
	struct v7fs_node *parent_node = dvp->v_data;
	struct v7fs_mount *v7fsmount = parent_node->v7fsmount;
	struct v7fs_self *fs = v7fsmount->core;
	struct mount *mp = v7fsmount->mountp;
	struct v7fs_fileattr attr;

	v7fs_ino_t ino;
	int error = 0;

	DPRINTF("%s %06o %lx %d\n", cnp->cn_nameptr, va->va_mode,
	    (long)va->va_rdev, va->va_type);
	memset(&attr, 0, sizeof(attr));
	attr.uid = kauth_cred_geteuid(cr);
	attr.gid = kauth_cred_getegid(cr);
	attr.mode = va->va_mode | vtype_to_v7fs_mode(va->va_type);
	attr.device = va->va_rdev;

	if ((error = v7fs_file_allocate(fs, &parent_node->inode,
	    cnp->cn_nameptr, &attr, &ino)))
		return error;
	// Sync dirent size change.
	uvm_vnp_setsize(dvp, v7fs_inode_filesize(&parent_node->inode));

	error = v7fs_vget(mp, ino, LK_EXCLUSIVE, a->a_vpp);
	if (error != 0) {
		DPRINTF("can't get vnode.\n");
		return error;
	}
	struct v7fs_node *newnode = (*a->a_vpp)->v_data;
	newnode->update_ctime = true;
	newnode->update_mtime = true;
	newnode->update_atime = true;

	if (error == 0)
		VOP_UNLOCK(*a->a_vpp);

	return error;
}

static int
v7fs_check_possible(struct vnode *vp, struct v7fs_node *v7node,
    mode_t mode)
{

	if (!(mode & VWRITE))
	  return 0;

	switch (vp->v_type) {
	default:
		/*  special file is always writable. */
		return 0;
	case VDIR:
	case VLNK:
	case VREG:
		break;
	}

	return vp->v_mount->mnt_flag & MNT_RDONLY ? EROFS : 0;
}

static int
v7fs_check_permitted(struct vnode *vp, struct v7fs_node *v7node,
    accmode_t accmode, kauth_cred_t cred)
{

	struct v7fs_inode *inode = &v7node->inode;

	return kauth_authorize_vnode(cred, KAUTH_ACCESS_ACTION(accmode,
	    vp->v_type, inode->mode), vp, NULL, genfs_can_access(vp, cred,
	    inode->uid, inode->gid, inode->mode, NULL, accmode));
}

int
v7fs_access(void *v)
{
	struct vop_access_args /* {
		struct vnode	*a_vp;
		accmode_t	a_accmode;
		kauth_cred_t	a_cred;
	} */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct v7fs_node *v7node = vp->v_data;
	int error;

	error = v7fs_check_possible(vp, v7node, ap->a_accmode);
	if (error)
		return error;

	error = v7fs_check_permitted(vp, v7node, ap->a_accmode, ap->a_cred);

	return error;
}

int
v7fs_getattr(void *v)
{
	struct vop_getattr_args /* {
				   struct vnode *a_vp;
				   struct vattr *a_vap;
				   kauth_cred_t a_cred;
				   } */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct v7fs_node *v7node = vp->v_data;
	struct v7fs_inode *inode = &v7node->inode;
	struct v7fs_mount *v7fsmount = v7node->v7fsmount;
	struct vattr *vap = ap->a_vap;

	DPRINTF("\n");
	vap->va_type = vp->v_type;
	vap->va_mode = inode->mode;
	vap->va_nlink = inode->nlink;
	vap->va_uid = inode->uid;
	vap->va_gid = inode->gid;
	vap->va_fsid = v7fsmount->devvp->v_rdev;
	vap->va_fileid = inode->inode_number;
	vap->va_size = vp->v_size;
	if (vp->v_type == VLNK) {
		/* Ajust for trailing NUL. */
		KASSERT(vap->va_size > 0);
		vap->va_size -= 1;
	}
	vap->va_atime.tv_sec = inode->atime;
	vap->va_mtime.tv_sec = inode->mtime;
	vap->va_ctime.tv_sec = inode->ctime;
	vap->va_birthtime.tv_sec = 0;
	vap->va_gen = 1;
	vap->va_flags = inode->append_mode ? SF_APPEND : 0;
	vap->va_rdev = inode->device;
	vap->va_bytes = vap->va_size; /* No sparse support. */
	vap->va_filerev = 0;
	vap->va_vaflags = 0;
	/* PAGE_SIZE is larger than sizeof(struct dirent). OK.
	   getcwd_scandir()@vfs_getcwd.c */
	vap->va_blocksize = PAGE_SIZE;

	return 0;
}

int
v7fs_setattr(void *v)
{
	struct vop_setattr_args /* {
				   struct vnode *a_vp;
				   struct vattr *a_vap;
				   kauth_cred_t a_cred;
				   struct proc *p;
				   } */ *ap = v;
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct v7fs_node *v7node = vp->v_data;
	struct v7fs_self *fs = v7node->v7fsmount->core;
	struct v7fs_inode *inode = &v7node->inode;
	kauth_cred_t cred = ap->a_cred;
	struct timespec *acc, *mod;
	int error = 0;
	acc = mod = NULL;

	DPRINTF("\n");

	if (vp->v_mount->mnt_flag & MNT_RDONLY) {
		switch (vp->v_type) {
		default:
			/*  special file is always writable. */
			break;
		case VDIR:
		case VLNK:
		case VREG:
			DPRINTF("read-only mount\n");
			return EROFS;
		}
	}

	if ((vap->va_type != VNON) || (vap->va_nlink != VNOVAL) ||
	    (vap->va_fsid != VNOVAL) || (vap->va_fileid != VNOVAL) ||
	    (vap->va_blocksize != VNOVAL) || (vap->va_rdev != VNOVAL) ||
	    ((int)vap->va_bytes != VNOVAL) || (vap->va_gen != VNOVAL)) {
		DPRINTF("invalid request\n");
		return EINVAL;
	}
	/* File pointer mode. */
	if (vap->va_flags != VNOVAL) {
		error = kauth_authorize_vnode(cred, KAUTH_VNODE_WRITE_FLAGS,
		    vp, NULL, genfs_can_chflags(vp, cred, inode->uid,
		    false));
		if (error)
			return error;
		inode->append_mode = vap->va_flags & SF_APPEND;
	}

	/* File size change. */
	if ((vap->va_size != VNOVAL) && (vp->v_type == VREG)) {
		error = v7fs_datablock_size_change(fs, vap->va_size, inode);
		if (error == 0) {
			uvm_vnp_setsize(vp, vap->va_size);
			v7node->update_mtime = true;
			v7node->update_ctime = true;
		}
	}
	uid_t uid = inode->uid;
	gid_t gid = inode->gid;

	if (vap->va_uid != (uid_t)VNOVAL) {
		uid = vap->va_uid;
		error = kauth_authorize_vnode(cred,
		    KAUTH_VNODE_CHANGE_OWNERSHIP, vp, NULL,
		    genfs_can_chown(vp, cred, inode->uid, inode->gid, uid,
		    gid));
		if (error)
			return error;
		inode->uid = uid;
	}
	if (vap->va_gid != (uid_t)VNOVAL) {
		gid = vap->va_gid;
		error = kauth_authorize_vnode(cred,
		    KAUTH_VNODE_CHANGE_OWNERSHIP, vp, NULL,
		    genfs_can_chown(vp, cred, inode->uid, inode->gid, uid,
		    gid));
		if (error)
			return error;
		inode->gid = gid;
	}
	if (vap->va_mode != (mode_t)VNOVAL) {
		mode_t mode = vap->va_mode;
		error = kauth_authorize_vnode(cred, KAUTH_VNODE_WRITE_SECURITY,
		    vp, NULL, genfs_can_chmod(vp, cred, inode->uid, inode->gid,
		    mode));
		if (error) {
			return error;
		}
		v7fs_inode_chmod(inode, mode);
	}
	if ((vap->va_atime.tv_sec != VNOVAL) ||
	    (vap->va_mtime.tv_sec != VNOVAL) ||
	    (vap->va_ctime.tv_sec != VNOVAL)) {
		error = kauth_authorize_vnode(cred, KAUTH_VNODE_WRITE_TIMES, vp,
		    NULL, genfs_can_chtimes(vp, cred, inode->uid,
		    vap->va_vaflags));
		if (error)
			return error;

		if (vap->va_atime.tv_sec != VNOVAL) {
			acc = &vap->va_atime;
		}
		if (vap->va_mtime.tv_sec != VNOVAL) {
			mod = &vap->va_mtime;
			v7node->update_mtime = true;
		}
		if (vap->va_ctime.tv_sec != VNOVAL) {
			v7node->update_ctime = true;
		}
	}

	v7node->update_atime = true;
	v7fs_update(vp, acc, mod, 0);

	return error;
}

int
v7fs_fsync(void *v)
{
	struct vop_fsync_args /* {
				 struct vnode *a_vp;
				 kauth_cred_t a_cred;
				 int a_flags;
				 off_t offlo;
				 off_t offhi;
				 } */ *a = v;
	struct vnode *vp = a->a_vp;
	int error, wait;

	DPRINTF("%p\n", a->a_vp);
	if (a->a_flags & FSYNC_CACHE) {
		return EOPNOTSUPP;
	}

	wait = (a->a_flags & FSYNC_WAIT);
	error = vflushbuf(vp, a->a_flags);

	if (error == 0 && (a->a_flags & FSYNC_DATAONLY) == 0)
		error = v7fs_update(vp, NULL, NULL, wait ? UPDATE_WAIT : 0);

	return error;
}

int
v7fs_remove(void *v)
{
	struct vop_remove_v2_args /* {
				  struct vnodeop_desc *a_desc;
				  struct vnode * a_dvp;
				  struct vnode * a_vp;
				  struct componentname * a_cnp;
				  } */ *a = v;
	struct v7fs_node *parent_node = a->a_dvp->v_data;
	struct v7fs_mount *v7fsmount = parent_node->v7fsmount;
	struct vnode *vp = a->a_vp;
	struct vnode *dvp = a->a_dvp;
	struct v7fs_inode *inode = &((struct v7fs_node *)vp->v_data)->inode;
	struct v7fs_self *fs = v7fsmount->core;
	int error = 0;

	DPRINTF("delete %s\n", a->a_cnp->cn_nameptr);

	if (vp->v_type == VDIR) {
		error = EPERM;
		goto out;
	}

	if ((error = v7fs_file_deallocate(fs, &parent_node->inode,
		    a->a_cnp->cn_nameptr))) {
		DPRINTF("v7fs_file_delete failed.\n");
		goto out;
	}
	error = v7fs_inode_load(fs, inode, inode->inode_number);
	if (error)
		goto out;
	/* Sync dirent size change. */
	uvm_vnp_setsize(dvp, v7fs_inode_filesize(&parent_node->inode));

out:
	if (dvp == vp)
		vrele(vp); /* usecount-- of unlocked vp */
	else
		vput(vp); /* unlock vp and then usecount-- */

	return error;
}

int
v7fs_link(void *v)
{
	struct vop_link_v2_args /* {
				struct vnode *a_dvp;
				struct vnode *a_vp;
				struct componentname *a_cnp;
				} */ *a = v;
	struct vnode *dvp = a->a_dvp;
	struct vnode *vp = a->a_vp;
	struct v7fs_node *parent_node = dvp->v_data;
	struct v7fs_node *node = vp->v_data;
	struct v7fs_inode *parent = &parent_node->inode;
	struct v7fs_inode *p = &node->inode;
	struct v7fs_self *fs = node->v7fsmount->core;
	struct componentname *cnp = a->a_cnp;
	int error = 0;

	DPRINTF("%p\n", vp);
	/* Lock soruce file */
	if ((error = vn_lock(vp, LK_EXCLUSIVE))) {
		DPRINTF("lock failed. %p\n", vp);
		VOP_ABORTOP(dvp, cnp);
		goto unlock;
	}
	error = v7fs_file_link(fs, parent, p, cnp->cn_nameptr);
	/* Sync dirent size change. */
	uvm_vnp_setsize(dvp, v7fs_inode_filesize(&parent_node->inode));

	VOP_UNLOCK(vp);
unlock:
	return error;
}

int
v7fs_rename(void *v)
{
	struct vop_rename_args /* {
				  struct vnode *a_fdvp;	from parent-directory
				  struct vnode *a_fvp;	from file
				  struct componentname *a_fcnp;
				  struct vnode *a_tdvp;	to parent-directory
				  struct vnode *a_tvp;	to file
				  struct componentname *a_tcnp;
				  } */ *a = v;
	struct vnode *fvp = a->a_fvp;
	struct vnode *tvp = a->a_tvp;
	struct vnode *fdvp = a->a_fdvp;
	struct vnode *tdvp = a->a_tdvp;
	struct v7fs_node *parent_from = fdvp->v_data;
	struct v7fs_node *parent_to = tdvp->v_data;
	struct v7fs_node *v7node = fvp->v_data;
	struct v7fs_self *fs = v7node->v7fsmount->core;
	const char *from_name = a->a_fcnp->cn_nameptr;
	const char *to_name = a->a_tcnp->cn_nameptr;
	int error;

	DPRINTF("%s->%s %p %p\n", from_name, to_name, fvp, tvp);

	if ((fvp->v_mount != tdvp->v_mount) ||
	    (tvp && (fvp->v_mount != tvp->v_mount))) {
		error = EXDEV;
		DPRINTF("cross-device link\n");
		goto out;
	}
	// XXXsource file lock?
	error = v7fs_file_rename(fs, &parent_from->inode, from_name,
	    &parent_to->inode, to_name);
	/* 'to file' inode may be changed. (hard-linked and it is cached.)
	   t_vnops rename_reg_nodir */
	if (error == 0 && tvp) {
		struct v7fs_inode *inode =
		    &((struct v7fs_node *)tvp->v_data)->inode;

		error = v7fs_inode_load(fs, inode, inode->inode_number);
		uvm_vnp_setsize(tvp, v7fs_inode_filesize(inode));
	}
	/* Sync dirent size change. */
	uvm_vnp_setsize(tdvp, v7fs_inode_filesize(&parent_to->inode));
	uvm_vnp_setsize(fdvp, v7fs_inode_filesize(&parent_from->inode));
out:
	if (tvp)
		vput(tvp);  /* locked on entry */
	if (tdvp == tvp)
		vrele(tdvp);
	else
		vput(tdvp);
	vrele(fdvp);
	vrele(fvp);

	return error;
}

int
v7fs_mkdir(void *v)
{
	struct vop_mkdir_v3_args /* {
				 struct vnode		*a_dvp;
				 struct vnode		**a_vpp;
				 struct componentname	*a_cnp;
				 struct vattr		*a_vap;
				 } */ *a = v;
	struct componentname *cnp = a->a_cnp;
	kauth_cred_t cr = cnp->cn_cred;
	struct vnode *dvp = a->a_dvp;
	struct vattr *va = a->a_vap;
	struct v7fs_node *parent_node = dvp->v_data;
	struct v7fs_mount *v7fsmount = parent_node->v7fsmount;
	struct v7fs_self *fs = v7fsmount->core;
	struct v7fs_fileattr attr;
	struct mount *mp = v7fsmount->mountp;
	v7fs_ino_t ino;
	int error = 0;

	DPRINTF("\n");
	memset(&attr, 0, sizeof(attr));
	attr.uid = kauth_cred_geteuid(cr);
	attr.gid = kauth_cred_getegid(cr);
	attr.mode = va->va_mode | vtype_to_v7fs_mode(va->va_type);

	if ((error = v7fs_file_allocate(fs, &parent_node->inode,
	    cnp->cn_nameptr, &attr, &ino)))
		return error;
	// Sync dirent size change.
	uvm_vnp_setsize(dvp, v7fs_inode_filesize(&parent_node->inode));

	error = v7fs_vget(mp, ino, LK_EXCLUSIVE, a->a_vpp);
	if (error != 0) {
		DPRINTF("can't get vnode.\n");
	}
	struct v7fs_node *newnode = (*a->a_vpp)->v_data;
	newnode->update_ctime = true;
	newnode->update_mtime = true;
	newnode->update_atime = true;

	if (error == 0)
		VOP_UNLOCK(*a->a_vpp);

	return error;
}

int
v7fs_rmdir(void *v)
{
	struct vop_rmdir_v2_args /* {
				 struct vnode		*a_dvp;
				 struct vnode		*a_vp;
				 struct componentname	*a_cnp;
				 } */ *a = v;
	struct vnode *vp = a->a_vp;
	struct vnode *dvp = a->a_dvp;
	struct v7fs_node *parent_node = dvp->v_data;
	struct v7fs_mount *v7fsmount = parent_node->v7fsmount;
	struct v7fs_inode *inode = &((struct v7fs_node *)vp->v_data)->inode;
	struct v7fs_self *fs = v7fsmount->core;
	int error = 0;

	DPRINTF("delete %s\n", a->a_cnp->cn_nameptr);

	KDASSERT(vp->v_type == VDIR);

	if ((error = v7fs_file_deallocate(fs, &parent_node->inode,
	    a->a_cnp->cn_nameptr))) {
		DPRINTF("v7fs_directory_deallocate failed.\n");
		goto out;
	}
	error = v7fs_inode_load(fs, inode, inode->inode_number);
	if (error)
		goto out;
	uvm_vnp_setsize(vp, v7fs_inode_filesize(inode));
	/* Sync dirent size change. */
	uvm_vnp_setsize(dvp, v7fs_inode_filesize(&parent_node->inode));
out:
	vput(vp);

	return error;
}

struct v7fs_readdir_arg {
	struct dirent *dp;
	struct uio *uio;
	int start;
	int end;
	int cnt;
};
static int readdir_subr(struct v7fs_self *, void *, v7fs_daddr_t, size_t);

int
readdir_subr(struct v7fs_self *fs, void *ctx, v7fs_daddr_t blk, size_t sz)
{
	struct v7fs_readdir_arg *p = (struct v7fs_readdir_arg *)ctx;
	struct v7fs_dirent *dir;
	struct dirent *dp = p->dp;
	struct v7fs_inode inode;
	char filename[V7FS_NAME_MAX + 1];
	int i, n;
	int error = 0;
	void *buf;

	if (!(buf = scratch_read(fs, blk)))
		return EIO;
	dir = (struct v7fs_dirent *)buf;

	n = sz / sizeof(*dir);

	for (i = 0; (i < n) && (p->cnt < p->end); i++, dir++, p->cnt++) {
		if (p->cnt < p->start)
			continue;

		if ((error = v7fs_inode_load(fs, &inode, (v7fs_ino_t) dir->inode_number)))
			break;

		v7fs_dirent_filename(filename, dir->name);

		DPRINTF("inode=%d name=%s %s\n", dir->inode_number, filename,
		    v7fs_inode_isdir(&inode) ? "DIR" : "FILE");
		memset(dp, 0, sizeof(*dp));
		dp->d_fileno = dir->inode_number;
		dp->d_type = v7fs_mode_to_d_type(inode.mode);
		dp->d_namlen = strlen(filename);
		strcpy(dp->d_name, filename);
		dp->d_reclen = sizeof(*dp);
		if ((error = uiomove(dp, dp->d_reclen, p->uio))) {
			DPRINTF("uiomove failed.\n");
			break;
		}
	}
	scratch_free(fs, buf);

	if (p->cnt == p->end)
		return V7FS_ITERATOR_BREAK;

	return error;
}

int
v7fs_readdir(void *v)
{
	struct vop_readdir_args /* {
				   struct vnode *a_vp;
				   struct uio *a_uio;
				   kauth_cred_t a_cred;
				   int *a_eofflag;
				   off_t **a_cookies;
				   int *a_ncookies;
				   } */ *a = v;
	struct uio *uio = a->a_uio;
	struct vnode *vp = a->a_vp;
	struct v7fs_node *v7node = vp->v_data;
	struct v7fs_inode *inode = &v7node->inode;
	struct v7fs_self *fs = v7node->v7fsmount->core;
	struct dirent *dp;
	int error;

	DPRINTF("offset=%zu residue=%zu\n", uio->uio_offset, uio->uio_resid);

	KDASSERT(vp->v_type == VDIR);
	KDASSERT(uio->uio_offset >= 0);
	KDASSERT(v7fs_inode_isdir(inode));

	struct v7fs_readdir_arg arg;
	arg.start = uio->uio_offset / sizeof(*dp);
	arg.end = arg.start +  uio->uio_resid / sizeof(*dp);
	if (arg.start == arg.end) {/* user buffer has not enuf space. */
		DPRINTF("uio buffer too small\n");
		return ENOMEM;
	}
	dp = kmem_zalloc(sizeof(*dp), KM_SLEEP);
	arg.cnt = 0;
	arg.dp = dp;
	arg.uio = uio;

	*a->a_eofflag = false;
	error = v7fs_datablock_foreach(fs, inode, readdir_subr, &arg);
	if (error == V7FS_ITERATOR_END) {
		*a->a_eofflag = true;
	}
	if (error < 0)
		error = 0;

	kmem_free(dp, sizeof(*dp));

	return error;
}

int
v7fs_inactive(void *v)
{
	struct vop_inactive_v2_args /* {
				    struct vnode *a_vp;
				    bool *a_recycle;
				    } */ *a = v;
	struct vnode *vp = a->a_vp;
	struct v7fs_node *v7node = vp->v_data;
	struct v7fs_inode *inode = &v7node->inode;

	DPRINTF("%p #%d\n", vp, inode->inode_number);
	if (v7fs_inode_nlink(inode) > 0) {
		v7fs_update(vp, 0, 0, UPDATE_WAIT);
		*a->a_recycle = false;
	} else {
		*a->a_recycle = true;
	}

	return 0;
}

int
v7fs_reclaim(void *v)
{
	/*This vnode is no longer referenced by kernel. */
	extern struct pool v7fs_node_pool;
	struct vop_reclaim_v2_args /* {
				   struct vnode *a_vp;
				   } */ *a = v;
	struct vnode *vp = a->a_vp;
	struct v7fs_node *v7node = vp->v_data;
	struct v7fs_self *fs = v7node->v7fsmount->core;
	struct v7fs_inode *inode = &v7node->inode;

	VOP_UNLOCK(vp);

	DPRINTF("%p #%d\n", vp, inode->inode_number);
	if (v7fs_inode_nlink(inode) == 0) {
		v7fs_datablock_size_change(fs, 0, inode);
		DPRINTF("remove datablock\n");
		v7fs_inode_deallocate(fs, inode->inode_number);
		DPRINTF("remove inode\n");
	}
	genfs_node_destroy(vp);
	pool_put(&v7fs_node_pool, v7node);
	mutex_enter(vp->v_interlock);
	vp->v_data = NULL;
	mutex_exit(vp->v_interlock);

	return 0;
}

int
v7fs_bmap(void *v)
{
	struct vop_bmap_args /* {
				struct vnode *a_vp;
				daddr_t  a_bn;
				struct vnode **a_vpp;
				daddr_t *a_bnp;
				int *a_runp;
				} */ *a = v;
	struct vnode *vp = a->a_vp;
	struct v7fs_node *v7node = vp->v_data;
	struct v7fs_mount *v7fsmount = v7node->v7fsmount;
	struct v7fs_self *fs = v7node->v7fsmount->core;
	struct v7fs_inode *inode = &v7node->inode;
	int error = 0;

	DPRINTF("inode=%d offset=%zu %p\n", inode->inode_number, a->a_bn, vp);
	DPRINTF("filesize: %d\n", inode->filesize);
	if (!a->a_bnp)
		return 0;

	v7fs_daddr_t blk;
	if (!(blk = v7fs_datablock_last(fs, inode,
	    (a->a_bn + 1) << V7FS_BSHIFT))) {
		/* +1 converts block # to file offset. */
		return ENOSPC;
	}

	*a->a_bnp = blk;

	if (a->a_vpp)
		*a->a_vpp = v7fsmount->devvp;
	if (a->a_runp)
		*a->a_runp = 0; /*XXX TODO */

	DPRINTF("%d  %zu->%zu status=%d\n", inode->inode_number, a->a_bn,
	    *a->a_bnp, error);

	return error;
}

int
v7fs_strategy(void *v)
{
	struct vop_strategy_args /* {
				    struct vnode *a_vp;
				    struct buf *a_bp;
				    } */ *a = v;
	struct buf *b = a->a_bp;
	struct vnode *vp = a->a_vp;
	struct v7fs_node *v7node = vp->v_data;
	struct v7fs_mount *v7fsmount = v7node->v7fsmount;
	int error;

	DPRINTF("%p\n", vp);
	KDASSERT(vp->v_type == VREG);
	if (b->b_blkno == b->b_lblkno) {
		error = VOP_BMAP(vp, b->b_lblkno, NULL, &b->b_blkno, NULL);
		if (error) {
			b->b_error = error;
			biodone(b);
			return error;
		}
		if ((long)b->b_blkno == -1)
			clrbuf(b);
	}
	if ((long)b->b_blkno == -1) {
		biodone(b);
		return 0;
	}

	return VOP_STRATEGY(v7fsmount->devvp, b);
}

int
v7fs_print(void *v)
{
	struct vop_print_args /* {
				 struct vnode *a_vp;
				 } */ *a = v;
	struct v7fs_node *v7node = a->a_vp->v_data;

	v7fs_inode_dump(&v7node->inode);

	return 0;
}

int
v7fs_advlock(void *v)
{
	struct vop_advlock_args /* {
				   struct vnode *a_vp;
				   void *a_id;
				   int a_op;
				   struct flock *a_fl;
				   int a_flags;
				   } */ *a = v;
	struct v7fs_node *v7node = a->a_vp->v_data;

	DPRINTF("op=%d\n", a->a_op);

	return lf_advlock(a, &v7node->lockf,
	    v7fs_inode_filesize(&v7node->inode));
}

int
v7fs_pathconf(void *v)
{
	struct vop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		register_t *a_retval;
	} */ *ap = v;
	DPRINTF("%p\n", ap->a_vp);

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = V7FS_LINK_MAX;
		return 0;
	case _PC_NAME_MAX:
		*ap->a_retval = V7FS_NAME_MAX;
		return 0;
	case _PC_PATH_MAX:
		*ap->a_retval = V7FS_PATH_MAX;
		return 0;
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		return 0;
	case _PC_NO_TRUNC:
		*ap->a_retval = 0;
		return 0;
	case _PC_SYNC_IO:
		*ap->a_retval = 1;
		return 0;
	case _PC_FILESIZEBITS:
		*ap->a_retval = 30; /* ~1G */
		return 0;
	case _PC_SYMLINK_MAX:
		*ap->a_retval = V7FSBSD_MAXSYMLINKLEN;
		return 0;
	case _PC_2_SYMLINKS:
		*ap->a_retval = 1;
		return 0;
	default:
		return genfs_pathconf(ap);
	}
}

int
v7fs_update(struct vnode *vp, const struct timespec *acc,
    const struct timespec *mod, int flags)
{
	struct v7fs_node *v7node = vp->v_data;
	struct v7fs_inode *inode = &v7node->inode;
	struct v7fs_self *fs = v7node->v7fsmount->core;
	bool update = false;

	DPRINTF("%p %zu %d\n", vp, vp->v_size, v7fs_inode_filesize(inode));
	KDASSERT(vp->v_size == v7fs_inode_filesize(inode));

	if (v7node->update_atime) {
		inode->atime = acc ? acc->tv_sec : time_second;
		v7node->update_atime = false;
		update = true;
	}
	if (v7node->update_ctime) {
		inode->ctime = time_second;
		v7node->update_ctime = false;
		update = true;
	}
	if (v7node->update_mtime) {
		inode->mtime = mod ? mod->tv_sec : time_second;
		v7node->update_mtime = false;
		update = true;
	}

	if (update)
		v7fs_inode_writeback(fs, inode);

	return 0;
}

int
v7fs_symlink(void *v)
{
	struct vop_symlink_v3_args /* {
				   struct vnode		*a_dvp;
				   struct vnode		**a_vpp;
				   struct componentname	*a_cnp;
				   struct vattr		*a_vap;
				   char			*a_target;
				   } */ *a = v;
	struct v7fs_node *parent_node = a->a_dvp->v_data;
	struct v7fs_mount *v7fsmount = parent_node->v7fsmount;
	struct v7fs_self *fs = v7fsmount->core;
	struct vattr *va = a->a_vap;
	kauth_cred_t cr = a->a_cnp->cn_cred;
	struct componentname *cnp = a->a_cnp;
	struct v7fs_fileattr attr;
	v7fs_ino_t ino;
	const char *from = a->a_target;
	const char *to = cnp->cn_nameptr;
	size_t len = strlen(from) + 1;
	int error = 0;

	if (len > V7FS_BSIZE) { /* limited to 512byte pathname */
		DPRINTF("too long pathname.");
		return ENAMETOOLONG;
	}

	memset(&attr, 0, sizeof(attr));
	attr.uid = kauth_cred_geteuid(cr);
	attr.gid = kauth_cred_getegid(cr);
	attr.mode = va->va_mode | vtype_to_v7fs_mode(va->va_type);

	if ((error = v7fs_file_allocate
		(fs, &parent_node->inode, to, &attr, &ino))) {
		return error;
	}
	/* Sync dirent size change. */
	uvm_vnp_setsize(a->a_dvp, v7fs_inode_filesize(&parent_node->inode));

	/* Get myself vnode. */
	error = v7fs_vget(v7fsmount->mountp, ino, LK_EXCLUSIVE, a->a_vpp);
	if (error != 0) {
		DPRINTF("can't get vnode.\n");
	}

	struct v7fs_node *newnode = (*a->a_vpp)->v_data;
	struct v7fs_inode *p = &newnode->inode;
	v7fs_file_symlink(fs, p, from);
	uvm_vnp_setsize(*a->a_vpp, v7fs_inode_filesize(p));

	newnode->update_ctime = true;
	newnode->update_mtime = true;
	newnode->update_atime = true;

	if (error == 0)
		VOP_UNLOCK(*a->a_vpp);

	return error;
}

int
v7fs_readlink(void *v)
{
	struct vop_readlink_args /* {
				    struct vnode	*a_vp;
				    struct uio		*a_uio;
				    kauth_cred_t	a_cred;
				    } */ *a = v;
	struct uio *uio = a->a_uio;
	struct vnode *vp = a->a_vp;
	struct v7fs_node *v7node = vp->v_data;
	struct v7fs_inode *inode = &v7node->inode;
	struct v7fs_self *fs = v7node->v7fsmount->core;
	int error = 0;

	KDASSERT(vp->v_type == VLNK);
	KDASSERT(uio->uio_offset >= 0);
	KDASSERT(v7fs_inode_islnk(inode));

	v7fs_daddr_t blk = inode->addr[0];
	void *buf;
	if (!(buf = scratch_read(fs, blk))) {
		error = EIO;
		goto error_exit;
	}

	if ((error = uiomove(buf, strlen(buf), uio))) {
		DPRINTF("uiomove failed.\n");
	}
	scratch_free(fs, buf);

error_exit:
	return error;
}
