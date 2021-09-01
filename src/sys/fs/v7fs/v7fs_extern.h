/*	$NetBSD: v7fs_extern.h,v 1.2 2014/12/29 15:29:38 hannken Exp $	*/

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

#ifndef _FS_V7FS_EXTERN_H_
#define	_FS_V7FS_EXTERN_H_

//#include <fs/v7fs/v7fs_args.h>

#include <miscfs/genfs/genfs.h>
#include <miscfs/genfs/genfs_node.h>
#include <miscfs/specfs/specdev.h>

#include "v7fs.h"
#include "v7fs_impl.h"
#include "v7fs_inode.h"
#include "v7fs_args.h"

struct v7fs_mount {
	struct mount *mountp;
	struct vnode *devvp;		/* block device mounted vnode */
	struct v7fs_self *core;		/* filesystem dependent implementation*/
};

struct v7fs_node {
	struct genfs_node gnode;
	struct v7fs_inode inode; /* filesystem dependent implementation */
	struct vnode *vnode;		/* back-link */
	struct v7fs_mount *v7fsmount;	/* our filesystem */
	struct lockf *lockf;		/* advlock */

	int update_ctime;
	int update_atime;
	int update_mtime;
};

#define	VFSTOV7FS(mp)	((struct v7fs_mount *)((mp)->mnt_data))
#define VNTOV7FSN(vp)   ((struct v7fs_node *) ((vp)->v_data))

__BEGIN_DECLS
/* v-node ops. */
int v7fs_lookup(void *);
int v7fs_create(void *);
int v7fs_access(void *);
int v7fs_getattr(void *);
int v7fs_setattr(void *);
int v7fs_fsync(void *);
int v7fs_remove(void *);
int v7fs_rename(void *);
int v7fs_readdir(void *);
int v7fs_inactive(void *);
int v7fs_reclaim(void *);
int v7fs_bmap(void *);
int v7fs_strategy(void *);
int v7fs_print(void *);
int v7fs_advlock(void *);
int v7fs_pathconf(void *);

int v7fs_link(void *);
int v7fs_symlink(void *);
int v7fs_readlink(void *);

int v7fs_mkdir(void *);
int v7fs_rmdir(void *);

int v7fs_mknod(void *);

/* vfs ops. */
VFS_PROTOS(v7fs);

int v7fs_mountroot(void);
extern int (**v7fs_vnodeop_p)(void *);
extern int (**v7fs_specop_p)(void *);
extern int (**v7fs_fifoop_p)(void *);

/* genfs ops */
int v7fs_gop_alloc(struct vnode *, off_t, off_t, int, kauth_cred_t);
extern const struct genfs_ops v7fs_genfsops;

/* MOP and helper function(s) */
// Create
int v7fs_mop_create(struct vnode* dvp, struct vnode** vpp, struct componentname* cnp, struct vattr* vap, char *dirbuf, size_t newentrysize, char *filename);
void v7fs_mop_postcreate_update(struct vnode** vpp);
void v7fs_mop_get_dirbuf_size(size_t *);
void v7fs_mop_filename_truncate(char* filename, struct componentname *cnp);
ino_t v7fs_mop_get_inumber(struct vnode *vp);
void v7fs_mop_set_dirent(struct vnode *vp, char *dirbuf, size_t *newentrysize, const char* name, size_t namelen);
int v7fs_mop_get_blk(struct vnode *dvp, struct vnode *vp, char **bpp, int n, daddr_t *blk, int isdir);
void v7fs_mop_add_direntry(void *buf, char* dirbuf, size_t dirsize, int n);
int v7fs_mop_lookup_by_name(struct vnode *dvp, struct vnode *vp, char* filename);
int v7fs_mop_dirent_writeback(struct vnode *vp, void* buf, daddr_t blk);
void v7fs_mop_get_max_namesize(size_t *);
void v7fs_mop_parentdir_update(struct vnode *dvp);
void v7fs_mop_get_dirent_pos(struct vnode *dvp, int *idx, size_t dirsize);
int v7fs_mop_isdir(struct vnode *vp);
void v7fs_mop_get_bufsize(size_t *);
int v7fs_mop_grow_parentdir(struct vnode *, size_t *);

// Open/close
int v7fs_mop_open_opt(struct vnode *, int);
void v7fs_mop_close_update(struct vnode *);

// Read
int v7fs_mop_read(struct vnode *, struct uio *, int);
vsize_t v7fs_mop_get_filesize(struct vnode *);
int v7fs_mop_postread_update(struct vnode *, int, int);
int v7fs_mop_check_maxsize(struct vnode *, struct uio *);

// Write
int v7fs_mop_write_checks(struct vnode *, struct uio *, kauth_cred_t, int);
int v7fs_mop_get_blkoff(struct vnode *, struct uio *);
vsize_t v7fs_mop_get_bytelen(struct vnode *, int, struct uio *);
vsize_t v7fs_mop_round(struct vnode *, struct uio*);
int v7fs_mop_datablock_expand(struct vnode *, struct uio *, vsize_t, kauth_cred_t);
void v7fs_mop_postwrite_update(struct vnode *, struct uio *, kauth_cred_t, int);
extern const struct genfs_mops v7fs_genfsmops;


/* internal service */
int v7fs_update(struct vnode *, const struct timespec *,
    const struct timespec *, int);

// Helper functions
int v7fs_read_flagssubr(struct vnode *vp, int ioflag, int oerror);
__END_DECLS
#endif /* _FS_V7FS_EXTERN_H_ */
