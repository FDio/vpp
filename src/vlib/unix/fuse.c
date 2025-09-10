/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <fcntl.h>
#include <sys/uio.h>
#include <sys/mount.h>
#include <dirent.h>
#include <linux/fuse.h>

#include <vlib/unix/fuse.h>

VLIB_REGISTER_LOG_CLASS (fuse_log, static) = {
  .class_name = "fuse",
};

#define log_debug(f, ...)                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, fuse_log.class, "%s: " f,                   \
	    clib_string_skip_prefix (__func__, "vlib_fuse_"), ##__VA_ARGS__)
#define log_notice(f, ...)                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, fuse_log.class, f, ##__VA_ARGS__)
#define log_warn(f, ...)                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, fuse_log.class, f, ##__VA_ARGS__)
#define log_err(f, ...)                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, fuse_log.class, f, ##__VA_ARGS__)

static u32 fuse_process_node_index;

#define VLIB_FUSE_MAX_WRITE (4 * 4096)

typedef struct vlib_fuse_node_t
{
  vlib_fuse_nodeid_t nodeid;
  struct vlib_fuse_node_t *parent_node;
  struct vlib_fuse_node_t **child_nodes;
  u32 mode;
  u32 size;
  u32 nlink;
  u32 type;
  u64 private_data;
  vlib_fuse_file_op_fn_t *op_fn;
  u16 namelen;
  u8 name[];
} vlib_fuse_node_t;

struct vlib_fuse_handle_t
{
  vlib_fuse_node_t **nodes; /* pool of pointers to nodes */
  u32 uid;
  u32 gid;
  u32 blksize;
  int fd;
  u64 private_data;
  u8 *mountpoint;
  u32 clib_file_index;
  vlib_fuse_node_t root_node;
};

always_inline vlib_fuse_node_t *
vlib_fuse_get_node (vlib_fuse_handle_t h, vlib_fuse_nodeid_t nodeid)
{
  if (nodeid == FUSE_ROOT_ID)
    return &h->root_node;

  return *pool_elt_at_index (h->nodes, nodeid - FUSE_ROOT_ID - 1);
}

always_inline vlib_fuse_node_t *
vlib_fuse_node_alloc (vlib_fuse_handle_t h, u8 *name)
{
  vlib_fuse_node_t *n, **p;
  u32 namelen = vec_len (name);

  n = clib_mem_alloc (sizeof (vlib_fuse_node_t) + namelen);
  pool_get (h->nodes, p);
  *p = n;
  *n = (vlib_fuse_node_t){
    .nodeid = p - h->nodes + FUSE_ROOT_ID + 1,
    .namelen = namelen,
  };
  clib_memcpy (n->name, name, namelen);
  return n;
}

always_inline vlib_fuse_node_t *
vlib_fuse_find_child_by_name (vlib_fuse_node_t *p, const char *name, u32 len)
{
  vec_foreach_pointer (cn, p->child_nodes)
    if (cn->namelen == len && memcmp (name, cn->name, len) == 0)
      return cn;
  return 0;
}

__clib_export vlib_fuse_nodeid_t
vlib_fuse_add_file (vlib_fuse_handle_t h, vlib_fuse_nodeid_t parent_nodeid,
		    vlib_fuse_add_file_args_t *a, char *fmt, ...)
{
  vlib_fuse_node_t *n;
  vlib_fuse_node_t *p = vlib_fuse_get_node (h, parent_nodeid);
  vlib_fuse_add_file_args_t default_args = {};
  va_list va;
  u8 *name = 0;

  if (p->type != DT_DIR)
    return VLIB_FUSE_INVALID_NODEID;

  if (!a)
    a = &default_args;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  n = vlib_fuse_node_alloc (h, name);
  vec_free (name);

  n->nlink = 1;
  n->mode = S_IFREG | (a->mode ? a->mode : 0444);
  n->size = 4096;
  n->parent_node = vlib_fuse_get_node (h, parent_nodeid);
  n->type = DT_REG;
  n->op_fn = a->file_op;
  n->private_data = a->private_data;

  vec_add1 (p->child_nodes, n);

  return n->nodeid;
}

static vlib_fuse_nodeid_t
vlib_fuse_find_by_name_internal (vlib_fuse_handle_t h,
				 vlib_fuse_nodeid_t parent_nodeid, u8 *name)
{
  vlib_fuse_node_t *n;
  vlib_fuse_node_t *p = vlib_fuse_get_node (h, parent_nodeid);

  if (p->type != DT_DIR)
    return VLIB_FUSE_INVALID_NODEID;

  n = vlib_fuse_find_child_by_name (p, (const char *) name, vec_len (name));

  return n ? n->nodeid : VLIB_FUSE_INVALID_NODEID;
}

__clib_export vlib_fuse_nodeid_t
vlib_fuse_find_by_name (vlib_fuse_handle_t h, vlib_fuse_nodeid_t parent_nodeid,
			char *fmt, ...)
{
  vlib_fuse_nodeid_t rv;
  va_list va;
  u8 *name;
  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  rv = vlib_fuse_find_by_name_internal (h, parent_nodeid, name);
  va_end (va);
  vec_free (name);
  return rv;
}

static vlib_fuse_nodeid_t
vlib_fuse_add_dir_internal (vlib_fuse_handle_t h,
			    vlib_fuse_nodeid_t parent_nodeid,
			    vlib_fuse_add_dir_args_t *a, u8 *name)
{
  vlib_fuse_node_t *n;
  vlib_fuse_node_t *p = vlib_fuse_get_node (h, parent_nodeid);
  vlib_fuse_add_dir_args_t default_args = {};

  if (p->type != DT_DIR)
    return VLIB_FUSE_INVALID_NODEID;

  if (!a)
    a = &default_args;

  n = vlib_fuse_node_alloc (h, name);

  n->nlink = 2, n->mode = S_IFDIR | (a->mode ? a->mode : 0555),
  n->type = DT_DIR, n->parent_node = vlib_fuse_get_node (h, parent_nodeid),
  n->private_data = a->private_data,

  vec_add1 (p->child_nodes, n);
  p->nlink++;

  return n->nodeid;
}

__clib_export vlib_fuse_nodeid_t
vlib_fuse_add_dir (vlib_fuse_handle_t h, vlib_fuse_nodeid_t parent_nodeid,
		   vlib_fuse_add_dir_args_t *a, char *fmt, ...)
{
  vlib_fuse_nodeid_t rv;
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  rv = vlib_fuse_add_dir_internal (h, parent_nodeid, a, name);
  va_end (va);
  if (rv == VLIB_FUSE_INVALID_NODEID)
    vec_free (name);
  return rv;
}

__clib_export vlib_fuse_nodeid_t
vlib_fuse_find_or_add_dir (vlib_fuse_handle_t h,
			   vlib_fuse_nodeid_t parent_nodeid,
			   vlib_fuse_add_dir_args_t *a, char *fmt, ...)
{
  vlib_fuse_nodeid_t rv;
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  rv = vlib_fuse_find_by_name_internal (h, parent_nodeid, name);
  if (rv != VLIB_FUSE_INVALID_NODEID)
    {
      vec_free (name);
      return rv;
    }

  rv = vlib_fuse_add_dir_internal (h, parent_nodeid, a, name);
  if (rv == VLIB_FUSE_INVALID_NODEID)
    vec_free (name);

  return rv;
}

static void
vlib_fuse_reply (vlib_fuse_handle_t h, const struct fuse_in_header *in,
		 const void *payload, size_t len)
{
  int rv;
  struct fuse_out_header out = {
    .len = sizeof (out) + len,
    .error = 0,
    .unique = in->unique,
  };

  if (payload)
    {
      struct iovec iov[2] = {
	{
	  .iov_base = &out,
	  .iov_len = sizeof (out),
	},
	{
	  .iov_base = (void *) payload,
	  .iov_len = len,
	},
      };

      rv = writev (h->fd, iov, 2);
    }
  else
    rv = write (h->fd, &out, sizeof (out));

  if (rv < 0)
    log_err ("failed to send reply [opcode %d, errno %d]", in->opcode, errno);
}

static void
vlib_fuse_reply_errno (vlib_fuse_handle_t h, const struct fuse_in_header *in,
		       int err)
{
  ssize_t rv;
  struct fuse_out_header out = {
    .len = sizeof (out),
    .error = -abs (err),
    .unique = in->unique,
  };
  rv = write (h->fd, &out, sizeof (out));
  if (rv != sizeof (out))
    log_err ("failed to send error reply [errno %d]", errno);
}

static void
vlib_fuse_fill_attr (vlib_fuse_handle_t h, vlib_fuse_nodeid_t ino,
		     struct fuse_attr *a)
{
  vlib_fuse_node_t *n = vlib_fuse_get_node (h, ino);
  struct timespec ts;
  u64 t;

  clock_gettime (CLOCK_REALTIME, &ts);
  t = ((u64) ts.tv_sec * 1000000000ull + ts.tv_nsec) / 1000000000ull;

  *a = (struct fuse_attr){
    .ino = ino,
    .uid = h->uid,
    .gid = h->gid,
    .blksize = h->blksize,
    .blocks = (n->size + 511) / 512,
    .atime = t,
    .mtime = t,
    .ctime = t,
    .mode = n->mode,
    .size = n->size,
    .nlink = n->nlink,
  };
}

static void
vlib_fuse_reply_lookup (vlib_fuse_handle_t h, const struct fuse_in_header *in,
			const char *name)
{
  vlib_fuse_node_t *p = vlib_fuse_get_node (h, in->nodeid);
  vlib_fuse_node_t *n = 0;
  log_debug ("FUSE_LOOKUP[%u]: nodeid %u name '%s'", in->unique, in->nodeid,
	     name);

  n = vlib_fuse_find_child_by_name (p, name, strlen (name));

  if (n == 0)
    {
      vlib_fuse_reply_errno (h, in, ENOENT);
      return;
    }

  struct fuse_entry_out e = {
    .nodeid = n->nodeid,
    .generation = 1,
    .entry_valid = 10,
    .attr_valid = 10,
  };

  vlib_fuse_fill_attr (h, n->nodeid, &e.attr);
  vlib_fuse_reply (h, in, &e, sizeof (e));
}

static void
vlib_fuse_reply_setattr (vlib_fuse_handle_t h, const struct fuse_in_header *in,
			 struct fuse_setattr_in *si)
{
  u32 supported_fattr = FATTR_LOCKOWNER | FATTR_SIZE;

  log_debug ("FUSE_SETATTR[%u]: nodeid %u valid 0x%x", in->unique, in->nodeid,
	     si->valid);

  if (si->valid & ~supported_fattr)
    vlib_fuse_reply_errno (h, in, ENOSYS);

  if (si->valid & FATTR_SIZE && si->size != 0)
    vlib_fuse_reply_errno (h, in, ENOSYS);

  struct fuse_attr_out o = { .attr_valid = 5 };
  vlib_fuse_fill_attr (h, in->nodeid, &o.attr);
  vlib_fuse_reply (h, in, &o, sizeof (o));
}

static void
vlib_fuse_reply_getattr (vlib_fuse_handle_t h, const struct fuse_in_header *in)
{
  log_debug ("FUSE_GETATTR[%u]: nodeid %u", in->unique, in->nodeid);

  struct fuse_attr_out o = { .attr_valid = 5 };
  vlib_fuse_fill_attr (h, in->nodeid, &o.attr);
  vlib_fuse_reply (h, in, &o, sizeof (o));
}

static void
vlib_fuse_reply_init (vlib_fuse_handle_t h, const struct fuse_in_header *in,
		      struct fuse_init_in *init_in)
{
  u32 minor = clib_min (init_in->minor, FUSE_KERNEL_MINOR_VERSION);
  u32 payload_len;

  struct fuse_init_out o = {
    .major = FUSE_KERNEL_VERSION,
    .minor = minor,
    .max_readahead = clib_min (init_in->max_readahead, 4 * 1024),
    .flags = FUSE_ASYNC_READ,
    .max_background = 16,
    .congestion_threshold = 12,
    .max_write = VLIB_FUSE_MAX_WRITE,
    .time_gran = 1,
  };

  log_debug ("FUSE_INIT[%u]: version %u.%u max_readahead %lu flags 0x%x",
	     in->unique, init_in->major, init_in->minor,
	     init_in->max_readahead, init_in->flags);

  if (minor < 12)
    payload_len = offsetof (struct fuse_init_out, flags);
  if (minor < 17)
    payload_len = offsetof (struct fuse_init_out, max_background);
  if (minor < 23)
    payload_len = offsetof (struct fuse_init_out, max_write);
  if (minor < 36)
    payload_len = offsetof (struct fuse_init_out, time_gran) +
		  sizeof (((struct fuse_init_out *) 0)->time_gran);
  else
    payload_len = sizeof (struct fuse_init_out);

  vlib_fuse_reply (h, in, &o, payload_len);
}

static void
vlib_fuse_reply_opendir (vlib_fuse_handle_t h, const struct fuse_in_header *in)
{
  struct fuse_open_out o = {
    .fh = 1,
    .open_flags = 0,
  };
  log_debug ("FUSE_OPENDIR[%u]: nodeid %u", in->unique, in->nodeid);
  vlib_fuse_reply (h, in, &o, sizeof (o));
}

static void
vlib_fuse_reply_readdir (vlib_fuse_handle_t h, const struct fuse_in_header *in,
			 struct fuse_read_in *ri)
{
  vlib_fuse_node_t *n = vlib_fuse_get_node (h, in->nodeid);

  log_debug ("FUSE_READDIR[%u]: nodeid %u offset %u size %u", in->unique,
	     in->nodeid, ri->offset, ri->size);

  u8 *buf = 0, *p;
  u32 sz;
  struct fuse_dirent *e = (struct fuse_dirent *) buf;
  u32 off = ri->offset;

  if (off == 0)
    {
      sz = round_pow2 (sizeof (struct fuse_dirent) + 1, 8);
      if (vec_len (buf) + sz > ri->size)
	goto done;
      vec_add2 (buf, p, sz);
      e = (struct fuse_dirent *) p;
      *e = (struct fuse_dirent){
	.ino = in->nodeid,
	.off = 1,
	.namelen = 1,
	.type = DT_DIR,
      };
      e->name[0] = '.';
      off++;
    }

  if (off == 1)
    {
      sz = round_pow2 (sizeof (struct fuse_dirent) + 1, 8);
      if (vec_len (buf) + sz > ri->size)
	goto done;
      vec_add2 (buf, p, sz);
      e = (struct fuse_dirent *) p;
      *e = (struct fuse_dirent){
	.ino = vlib_fuse_get_parent_nodeid (h, in->nodeid),
	.off = 2,
	.namelen = 2,
	.type = DT_DIR,
      };
      e->name[0] = '.';
      e->name[1] = '.';
      off++;
    }

  while (1)
    {
      u32 n_ent = vec_len (n->child_nodes);
      vlib_fuse_node_t *c;
      if (off - 2 >= n_ent)
	goto done;
      c = n->child_nodes[off - 2];
      sz = round_pow2 (sizeof (struct fuse_dirent) + c->namelen, 8);
      if (vec_len (buf) + sz > ri->size)
	goto done;
      vec_add2 (buf, p, sz);
      e = (struct fuse_dirent *) p;
      *e = (struct fuse_dirent){
	.ino = c->nodeid,
	.off = off + 1,
	.namelen = c->namelen,
	.type = c->type,
      };
      clib_memcpy (e->name, c->name, c->namelen);
      off++;
    }

done:
  vlib_fuse_reply (h, in, buf, vec_len (buf));
  vec_free (buf);
}

static void
vlib_fuse_reply_releasedir (vlib_fuse_handle_t h,
			    const struct fuse_in_header *in)
{
  log_debug ("FUSE_RELEASEDIR[%u]:", in->unique);
  vlib_fuse_reply (h, in, 0, 0);
}

static void
vlib_fuse_reply_open (vlib_main_t *vm, vlib_fuse_handle_t h,
		      const struct fuse_in_header *in)
{
  struct fuse_open_out o = {};
  vlib_fuse_node_t *n = vlib_fuse_get_node (h, in->nodeid);
  int rv;

  log_debug ("FUSE_OPEN[%u]: nodeid %u", in->unique, in->nodeid);

  if (n->type == DT_DIR)
    {
      vlib_fuse_reply_errno (h, in, EISDIR);
      return;
    }

  if (!n->op_fn)
    {
      vlib_fuse_reply_errno (h, in, ENOTSUP);
      return;
    }

  vlib_fuse_file_op_data_t od = {
    .h = h,
    .type = VLIB_FUSE_FILE_OP_OPEN,
    .nodeid = in->nodeid,
  };

  rv = n->op_fn (vm, &od);

  if (rv < 0)
    {
      vlib_fuse_reply_errno (h, in, rv);
      return;
    }

  o.fh = od.file_handle;
  o.open_flags |= od.open.noflush ? FOPEN_NOFLUSH : 0;
  o.open_flags |= od.open.direct_io ? FOPEN_DIRECT_IO : 0;
  o.open_flags |= od.open.nonseekable ? FOPEN_NONSEEKABLE : 0;

  vlib_fuse_reply (h, in, &o, sizeof (o));
}

static void
vlib_fuse_reply_read (vlib_main_t *vm, vlib_fuse_handle_t h,
		      const struct fuse_in_header *in, struct fuse_read_in *ri)
{
  vlib_fuse_node_t *n = vlib_fuse_get_node (h, in->nodeid);
  u64 off = ri->offset;
  u32 size = ri->size;
  int rv;

  log_debug ("FUSE_READ[%u]: nodeid %u offset %u size %u", in->unique,
	     in->nodeid, off, size);

  if (!n->op_fn)
    return vlib_fuse_reply_errno (h, in, ENOTSUP);

  vlib_fuse_file_op_data_t od = {
    .h = h,
    .type = VLIB_FUSE_FILE_OP_READ,
    .nodeid = in->nodeid,
    .file_handle = ri->fh,
    .read = {
       .req_offset = off,
       .req_bytes = size,
    },
  };

  rv = n->op_fn (vm, &od);

  if (rv < 0)
    return vlib_fuse_reply_errno (h, in, rv);

  log_debug ("FUSE_READ[%u]: %u bytes read", in->unique, od.read.bytes_read);
  vlib_fuse_reply (h, in, od.read.bytes_read ? od.read.start : 0,
		   od.read.bytes_read);
}

static void
vlib_fuse_reply_write (vlib_main_t *vm, vlib_fuse_handle_t h,
		       const struct fuse_in_header *in,
		       struct fuse_write_in *wi)
{
  vlib_fuse_node_t *n = vlib_fuse_get_node (h, in->nodeid);
  u64 off = wi->offset;
  u32 size = wi->size;
  int rv;

  log_debug ("FUSE_WRITE[%u]: nodeid %u offset %u size %u", in->unique,
	     in->nodeid, off, size);

  if (!n->op_fn)
    return vlib_fuse_reply_errno (h, in, ENOTSUP);

  vlib_fuse_file_op_data_t od = {
    .h = h,
    .type = VLIB_FUSE_FILE_OP_WRITE,
    .nodeid = in->nodeid,
    .file_handle = wi->fh,
    .write = {
       .req_offset = off,
       .req_size = size,
       .start = (u8 *)(wi + 1),
    },
  };

  rv = n->op_fn (vm, &od);

  if (rv < 0)
    return vlib_fuse_reply_errno (h, in, rv);

  log_debug ("FUSE_WRITE[%u]: %u bytes written", in->unique,
	     od.write.bytes_written);

  vlib_fuse_reply (h, in,
		   &(struct fuse_write_out){ .size = od.write.bytes_written },
		   sizeof (struct fuse_write_out));
}

static void
vlib_fuse_reply_flush (vlib_main_t *vm, vlib_fuse_handle_t h,
		       const struct fuse_in_header *in,
		       struct fuse_flush_in *fi)
{
  vlib_fuse_node_t *n = vlib_fuse_get_node (h, in->nodeid);
  int rv;
  log_debug ("FUSE_FLUSH[%u]: nodeid %u", in->unique, in->nodeid);
  if (!n->op_fn)
    return vlib_fuse_reply_errno (h, in, ENOTSUP);

  rv = n->op_fn (vm, &(vlib_fuse_file_op_data_t){
		       .h = h,
		       .type = VLIB_FUSE_FILE_OP_FLUSH,
		       .nodeid = in->nodeid,
		       .file_handle = fi->fh,
		     });

  if (rv < 0)
    return vlib_fuse_reply_errno (h, in, rv);

  vlib_fuse_reply (h, in, 0, 0);
}

static void
vlib_fuse_reply_release (vlib_main_t *vm, vlib_fuse_handle_t h,
			 const struct fuse_in_header *in,
			 struct fuse_release_in *ri)
{
  vlib_fuse_node_t *n = vlib_fuse_get_node (h, in->nodeid);
  int rv;

  log_debug ("FUSE_RELEASE[%u]: nodeid %u", in->unique, in->nodeid);

  if (!n->op_fn)
    return vlib_fuse_reply_errno (h, in, ENOTSUP);

  rv = n->op_fn (vm, &(vlib_fuse_file_op_data_t){
		       .h = h,
		       .type = VLIB_FUSE_FILE_OP_RELEASE,
		       .nodeid = in->nodeid,
		       .file_handle = ri->fh,
		     });

  if (rv < 0)
    return vlib_fuse_reply_errno (h, in, rv);

  vlib_fuse_reply (h, in, 0, 0);
}

static clib_error_t *
vlib_fuse_fd_read (struct clib_file *f)
{
  vlib_fuse_handle_t h = (vlib_fuse_handle_t) f->private_data;
  vlib_process_signal_event (vlib_get_main (), fuse_process_node_index, 0,
			     (uword) h);
  return 0;
}

static void
vlib_fuse_read (vlib_main_t *vm, vlib_fuse_handle_t h)
{
  static u8 __clib_aligned (4096)
  buf[VLIB_FUSE_MAX_WRITE + 4096]; /* 3 pages */
  struct fuse_in_header *in = (struct fuse_in_header *) buf;
  void *payload = buf + sizeof (*in);
  ssize_t n = read (h->fd, buf, sizeof (buf));

  if (n <= 0)
    {
      if (n < 0)
	log_err ("failed to read from '/dev/fuse' fd [errno: %d]", errno);
      return;
    }

  switch (in->opcode)
    {
    case FUSE_LOOKUP:
      vlib_fuse_reply_lookup (h, in, payload);
      break;
    case FUSE_SETATTR:
      vlib_fuse_reply_setattr (h, in, payload);
      break;
    case FUSE_GETATTR:
      vlib_fuse_reply_getattr (h, in);
      break;
    case FUSE_INIT:
      vlib_fuse_reply_init (h, in, payload);
      break;
    case FUSE_OPENDIR:
      vlib_fuse_reply_opendir (h, in);
      break;
    case FUSE_READDIR:
      vlib_fuse_reply_readdir (h, in, payload);
      break;
    case FUSE_RELEASEDIR:
      vlib_fuse_reply_releasedir (h, in);
      break;
    case FUSE_OPEN:
      vlib_fuse_reply_open (vm, h, in);
      break;
    case FUSE_READ:
      vlib_fuse_reply_read (vm, h, in, payload);
      break;
    case FUSE_WRITE:
      vlib_fuse_reply_write (vm, h, in, payload);
      break;
    case FUSE_FLUSH:
      vlib_fuse_reply_flush (vm, h, in, payload);
      break;
    case FUSE_RELEASE:
      vlib_fuse_reply_release (vm, h, in, payload);
      break;
    default:
      log_warn ("unsupported fuse opcode %u received", in->opcode);
      vlib_fuse_reply_errno (h, in, ENOSYS);
      break;
    }
}

static clib_error_t *
vlib_fuse_fd_error (struct clib_file *f)
{
  log_err ("fd err", 0);
  return 0;
}

static uword
vlib_fuse_process (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *f)
{
  uword *event_data = NULL, *u;

  while (1)
    {
      vlib_process_wait_for_event (vm);
      vlib_process_get_events (vm, &event_data);
      vec_foreach (u, event_data)
	{
	  vlib_fuse_handle_t h = (void *) *u;
	  vlib_fuse_read (vm, h);
	}
      vec_reset_length (event_data);
    }
  return 0;
}

__clib_export void
vlib_fuse_destroy (vlib_fuse_handle_t h)
{
  clib_file_del_by_index (&file_main, h->clib_file_index);
  vec_add1 (h->mountpoint, 0);
  if (umount2 ((char *) h->mountpoint, MNT_DETACH))
    log_err ("umount2('%s') failed", h->mountpoint);
  vec_free (h->mountpoint);

  pool_foreach_pointer (n, h->nodes)
    {
      vec_free (n->name);
      vec_free (n->child_nodes);
      clib_mem_free (n);
    }
  pool_free (h->nodes);
  clib_mem_free (h);
}

__clib_export clib_error_t *
vlib_fuse_create (vlib_fuse_handle_t *hp, vlib_fuse_create_args_t *args,
		  char *fmt, ...)
{
  unformat_input_t input;
  u8 *mp = 0, *opts = 0;
  va_list va;
  clib_error_t *err = 0;
  u32 len;
  int fd;

  fd = open ("/dev/fuse", O_RDWR | O_CLOEXEC);
  if (fd < 0)
    {
      err = clib_error_return_unix (0, "cannot open '/dev/fuse'");
      goto done;
    }

  va_start (va, fmt);
  mp = va_format (0, fmt, &va);
  va_end (va);
  len = vec_len (mp);

  if (unformat_init_file (&input, "/proc/mounts"))
    {
      while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
	{
	  u8 *t = 0, *p = 0;
	  if (unformat (&input, "%s %v", &t, &p))
	    {
	      if (vec_is_equal (mp, p))
		{
		  vec_add1 (p, 0);
		  if (args->umount_stale && strcmp ((char *) t, "fuse") == 0)
		    {
		      log_notice ("unmounting stale fuse filesystem at '%s'",
				  p);
		      if (umount2 ((char *) p, MNT_DETACH) < 0)
			err = clib_error_return_unix (
			  0, "umount2('%s') failed", p);
		    }
		  else
		    err = clib_error_return (
		      0, "filesystem already mounted at '%s'", p);
		}
	      vec_free (p);
	      vec_free (t);
	      if (err)
		goto done;
	    }
	  unformat_skip_line (&input);
	}
      unformat_free (&input);
    }

  opts = format (
    0, "fd=%d,rootmode=%o,user_id=%u,group_id=%u,subtype=fusefs,allow_other%c",
    fd, S_IFDIR, getuid (), getgid (), 0);

  if (mount ("fuse", (char *) mp, "fuse", MS_NOSUID | MS_NODEV,
	     (char *) opts) < 0)
    {
      err =
	clib_error_return_unix (0, "cannot mount fusefs to '%s'", (char *) mp);
      goto done;
    }

  vec_set_len (mp, len);

  vlib_fuse_handle_t h = clib_mem_alloc (sizeof (*h));
  *h = (struct vlib_fuse_handle_t){
    .blksize = args->blksize ? args->blksize : 4096,
    .fd = fd,
    .uid = getuid (),
    .gid = getgid (),
  };

  log_debug ("fusefd is %u", h->fd);

  *vlib_fuse_get_node (h, VLIB_FUSE_ROOT_NODEID) = (vlib_fuse_node_t){
    .nodeid = VLIB_FUSE_ROOT_NODEID,
    .nlink = 2,
    .mode = S_IFDIR | 0555,
    .type = DT_DIR,
  };

  if (fuse_process_node_index == 0)
    {
      vlib_main_t *vm = vlib_get_main ();
      vlib_node_t *n;
      vlib_node_registration_t r = {
	.function = vlib_fuse_process,
	.type = VLIB_NODE_TYPE_PROCESS,
	.process_log2_n_stack_bytes = 16,
      };
      vlib_register_node (vm, &r, "fuse");
      n = vlib_get_node (vm, r.index);
      vlib_start_process (vm, n->runtime_index);
      fuse_process_node_index = r.index;

      log_debug ("process node '%U' (%u) created", format_vlib_node_name, vm,
		 r.index, r.index);
    }

  h->clib_file_index =
    clib_file_add (&file_main, &(clib_file_t){
				 .file_descriptor = h->fd,
				 .read_function = vlib_fuse_fd_read,
				 .error_function = vlib_fuse_fd_error,
				 .description = format (0, "fuse"),
				 .private_data = pointer_to_uword (h),
			       });

  h->mountpoint = mp;
  mp = 0;
  *hp = h;
done:
  vec_free (mp);
  vec_free (opts);
  return err;
}

__clib_export vlib_fuse_nodeid_t
vlib_fuse_get_parent_nodeid (vlib_fuse_handle_t h, vlib_fuse_nodeid_t ino)
{
  vlib_fuse_node_t *n = vlib_fuse_get_node (h, ino);
  if (ino > VLIB_FUSE_ROOT_NODEID)
    return n->parent_node->nodeid;
  if (ino == VLIB_FUSE_ROOT_NODEID)
    return VLIB_FUSE_ROOT_NODEID;
  return VLIB_FUSE_INVALID_NODEID;
}

__clib_export u64
vlib_fuse_get_private_data (vlib_fuse_handle_t h)
{
  return h->private_data;
}

__clib_export void
vlib_fuse_set_private_data (vlib_fuse_handle_t h, u64 private_data)
{
  h->private_data = private_data;
}

__clib_export u64
vlib_fuse_get_node_private_data (vlib_fuse_handle_t h, vlib_fuse_nodeid_t ino)
{
  return vlib_fuse_get_node (h, ino)->private_data;
}

__clib_export void
vlib_fuse_set_node_private_data (vlib_fuse_handle_t h, vlib_fuse_nodeid_t ino,
				 u64 private_data)
{
  vlib_fuse_get_node (h, ino)->private_data = private_data;
}
