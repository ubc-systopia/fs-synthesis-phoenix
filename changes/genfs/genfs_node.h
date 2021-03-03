/* $NetBSD: genfs_node.h,v 1.24 2020/03/14 21:47:41 ad Exp $ */

/*
 * Copyright (c) 2001 Chuck Silvers.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Chuck Silvers.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 */

#ifndef	_MISCFS_GENFS_GENFS_NODE_H_
#define	_MISCFS_GENFS_GENFS_NODE_H_

#include <sys/rwlock.h>
#include <sys/types.h>

struct vm_page;
struct kauth_cred;
struct uio;
struct vnode;
struct componentname;
struct vattr;


struct genfs_ops {
	void	(*gop_size)(struct vnode *, off_t, off_t *, int);
	int	(*gop_alloc)(struct vnode *, off_t, off_t, int,
	    struct kauth_cred *);
	int	(*gop_write)(struct vnode *, struct vm_page **, int, int);
	void	(*gop_markupdate)(struct vnode *, int);
	void	(*gop_putrange)(struct vnode *, off_t, off_t *, off_t *);
};

struct genfs_mops {
    int (*mop_create_rootsize) (struct vnode *);
    int (*mop_get_newvnode) (struct vnode *, struct vnode **, struct vattr *, struct componentname *);
    int (*mop_create) (struct vnode *, struct vnode **, struct componentname *, struct vattr *);
    void (*mop_postcreate_update) (struct vnode **);
    int (*mop_postcreate_unlock) (void);
    
    int (*mop_open_opt) (struct vnode *, int);
    void (*mop_close_update) (struct vnode *);

    int (*mop_check_maxsize) (struct vnode *, struct uio *);
    unsigned long (*mop_get_filesize) (struct vnode *);
    int (*mop_dirread) (struct vnode *, struct uio *, int, unsigned long);
    int (*mop_fileread) (struct vnode *, struct uio *, int, unsigned long);
    int (*mop_postread_update) (struct vnode *, int, int);
    
    int (*mop_write_checks) (struct vnode *, struct uio *, kauth_cred_t, int);
    int (*mop_fill_holes) (struct vnode *, struct uio *, kauth_cred_t);
    int (*mop_get_blkoff) (struct vnode *, struct uio *);
    unsigned long (*mop_get_bytelen) (struct vnode *, int, struct uio *);
    unsigned long (*mop_round) (struct vnode *, struct uio *);
    int (*mop_balloc) (struct vnode *, struct uio *, unsigned long, kauth_cred_t);
    void (*mop_postwrite_update) (struct vnode *, struct uio *, kauth_cred_t, int);
    int (*mop_postwrite_truncate) (struct vnode *, struct uio *, int, kauth_cred_t, off_t, int, int);
};

#define GOP_SIZE(vp, size, eobp, flags) \
	(*VTOG(vp)->g_op->gop_size)((vp), (size), (eobp), (flags))
#define GOP_ALLOC(vp, off, len, flags, cred) \
	(*VTOG(vp)->g_op->gop_alloc)((vp), (off), (len), (flags), (cred))
#define GOP_WRITE(vp, pgs, npages, flags) \
	(*VTOG(vp)->g_op->gop_write)((vp), (pgs), (npages), (flags))
#define GOP_PUTRANGE(vp, off, lop, hip) \
	(*VTOG(vp)->g_op->gop_putrange)((vp), (off), (lop), (hip))

#define MOP_FILEREAD(vp, uio, ioflag, filesize) \
    (*VTOG(vp)->g_mop->mop_fileread)((vp), (uio), (ioflag), (filesize))
#define MOP_DIRREAD(vp, uio, ioflag, filesize) \
    (*VTOG(vp)->g_mop->mop_dirread)((vp), (uio), (ioflag), (filesize))
#define MOP_CHECK_MAXSIZE(vp, uio) \
    (*VTOG(vp)->g_mop->mop_check_maxsize)((vp), (uio))
#define MOP_GET_FILESIZE(vp) \
    (*VTOG(vp)->g_mop->mop_get_filesize)((vp))
#define MOP_POSTREAD_UPDATE(vp, ioflag, oerror) \
    (*VTOG(vp)->g_mop->mop_postread_update)((vp), (ioflag), (oerror))

#define MOP_WRITE_CHECKS(vp, uio, cred, ioflag) \
    (*VTOG(vp)->g_mop->mop_write_checks)((vp), (uio), (cred), (ioflag))
#define MOP_FILL_HOLES(vp, uio, cred) \
    (*VTOG(vp)->g_mop->mop_fill_holes)((vp), (uio), (cred))
#define MOP_WRITE(vp, uio, cred, ioflag) \
    (*VTOG(vp)->g_mop->mop_write)((vp), (uio), (cred), (ioflag))
#define MOP_GET_BLKOFF(vp, uio) \
    (*VTOG(vp)->g_mop->mop_get_blkoff)((vp), (uio))
#define MOP_GET_BYTELEN(vp, blkoffset, uio) \
    (*VTOG(vp)->g_mop->mop_get_bytelen)((vp), (blkoffset), (uio))
#define MOP_POSTWRITE_UPDATE(vp, uio, cred, resid) \
    (*VTOG(vp)->g_mop->mop_postwrite_update)((vp), (uio), (cred), (resid))
#define MOP_POSTWRITE_TRUNCATE(vp, uio, ioflag, cred, osize, resid, error) \
    (*VTOG(vp)->g_mop->mop_postwrite_truncate)((vp), (uio), (ioflag), (cred), (osize), (resid), (error))
#define MOP_BALLOC(vp, uio, bytelen, cred) \
    (*VTOG(vp)->g_mop->mop_balloc)((vp), (uio), (bytelen), (cred))
#define MOP_ROUND(vp, uio) \
    (*VTOG(vp)->g_mop->mop_round)((vp), (uio))

#define MOP_OPEN_OPT(vp, mode) \
    (*VTOG(vp)->g_mop->mop_open_opt)((vp), (mode))
#define MOP_CLOSE_UPDATE(vp) \
    (*VTOG(vp)->g_mop->mop_close_update)((vp))

#define MOP_CREATE(dvp, vpp, cnp, vap) \
    (*VTOG(dvp)->g_mop->mop_create)((dvp), (vpp), (cnp), (vap))
#define MOP_CREATE_ROOTSIZE(dvp) \
    (*VTOG(dvp)->g_mop->mop_create_rootsize)((dvp))
#define MOP_GET_NEWVNODE(dvp, vpp, vap, cnp) \
    (*VTOG(dvp)->g_mop->mop_get_newvnode)((dvp), (vpp), (vap), (cnp))
#define MOP_POSTCREATE_UPDATE(vpp) \
    (*VTOG(*vpp)->g_mop->mop_postcreate_update)((vpp))

#define MOP_POSTCREATE_UNLOCK() \
    (*VTOG(*vpp)->g_mop->mop_postcreate_unlock)()




/*
 * GOP_MARKUPDATE: mark vnode's timestamps for update.
 *
 * => called with vmobjlock (and possibly other locks) held.
 * => used for accesses via mmap.
 */

#define GOP_MARKUPDATE(vp, flags) \
	(VTOG(vp)->g_op->gop_markupdate) ? \
	(*VTOG(vp)->g_op->gop_markupdate)((vp), (flags)) : \
	(void)0;

/* Flags to GOP_SIZE */
#define	GOP_SIZE_MEM	0x4	/* in-memory size */

/* Flags to GOP_MARKUPDATE */
#define	GOP_UPDATE_ACCESSED	1
#define	GOP_UPDATE_MODIFIED	2

struct genfs_node {
	const struct genfs_ops	*g_op;		/* ops vector */
	krwlock_t		g_glock;	/* getpages lock */
    const struct genfs_mops *g_mop;  /* µ-ops vector */
};

#define VTOG(vp) ((struct genfs_node *)(vp)->v_data)

void	genfs_size(struct vnode *, off_t, off_t *, int);
void	genfs_node_init(struct vnode *, const struct genfs_ops *, const struct genfs_mops *);
void	genfs_node_destroy(struct vnode *);
void	genfs_gop_putrange(struct vnode *, off_t, off_t *, off_t *);
int	genfs_gop_write(struct vnode *, struct vm_page **, int, int);
int	genfs_gop_write_rwmap(struct vnode *, struct vm_page **, int, int);
int	genfs_compat_gop_write(struct vnode *, struct vm_page **, int, int);
void	genfs_directio(struct vnode *, struct uio *, int);

void	genfs_node_wrlock(struct vnode *);
void	genfs_node_rdlock(struct vnode *);
int	genfs_node_rdtrylock(struct vnode *);
void	genfs_node_unlock(struct vnode *);
int	genfs_node_wrlocked(struct vnode *);

#endif	/* _MISCFS_GENFS_GENFS_NODE_H_ */
