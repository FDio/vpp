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

#include <vppinfra/fuse.h>

#define log_debug(h, fmt, ...)                                                \
  if (h->log_fn)                                                              \
  h->log_fn (h->log_level_debug, fmt, __VA_ARGS__)
#define log_warn(h, fmt, ...)                                                 \
  if (h->log_fn)                                                              \
  h->log_fn (h->log_level_warn, fmt, __VA_ARGS__)
#define log_err(h, fmt, ...)                                                  \
  if (h->log_fn)                                                              \
  h->log_fn (h->log_level_err, fmt, __VA_ARGS__)

typedef struct clib_fuse_node_t
{
  clib_fuse_nodeid_t nodeid;
  struct clib_fuse_node_t *parent_node;
  struct clib_fuse_node_t **child_nodes;
  u32 mode;
  u32 size;
  u32 nlink;
  u32 type;
  u64 private_data;
  clib_fuse_file_op_fn_t *op_fn;
  u16 namelen;
  u8 name[];
} clib_fuse_node_t;

struct clib_fuse_handle_t
{
  clib_fuse_node_t **nodes; /* pool of pointers to nodes */
  u32 uid;
  u32 gid;
  u32 blksize;
  int fd;
  u8 log_level_warn;
  u8 log_level_debug;
  u8 log_level_err;
  clib_fuse_log_fn_t *log_fn;
  u8 *mountpoint;
  u32 clib_file_index;
  clib_file_main_t *file_main;
  clib_fuse_node_t root_node;
};

always_inline clib_fuse_node_t *
clib_fuse_get_node (clib_fuse_handle_t h, clib_fuse_nodeid_t nodeid)
{
  if (nodeid == FUSE_ROOT_ID)
    return &h->root_node;

  return *pool_elt_at_index (h->nodes, nodeid - FUSE_ROOT_ID - 1);
}

always_inline clib_fuse_node_t *
clib_fuse_node_alloc (clib_fuse_handle_t h, u8 *name)
{
  clib_fuse_node_t *n, **p;
  u32 namelen = vec_len (name);

  n = clib_mem_alloc (sizeof (clib_fuse_node_t) + namelen);
  pool_get (h->nodes, p);
  *p = n;
  *n = (clib_fuse_node_t){
    .nodeid = p - h->nodes + FUSE_ROOT_ID + 1,
    .namelen = namelen,
  };
  clib_memcpy (n->name, name, namelen);
  return n;
}

always_inline clib_fuse_node_t *
fuse_find_child_by_name (clib_fuse_handle_t h, clib_fuse_node_t *p,
			 const char *name, u32 len)
{
  vec_foreach_pointer (cn, p->child_nodes)
    if (cn->namelen == len && memcmp (name, cn->name, len) == 0)
      return cn;
  return 0;
}

__clib_export clib_fuse_nodeid_t
clib_fuse_add_file (clib_fuse_handle_t h, clib_fuse_nodeid_t parent_nodeid,
		    clib_fuse_add_file_args_t *a, char *fmt, ...)
{
  clib_fuse_node_t *n;
  clib_fuse_node_t *p = clib_fuse_get_node (h, parent_nodeid);
  clib_fuse_add_file_args_t default_args = {};
  va_list va;
  u8 *name = 0;

  if (p->type != DT_DIR)
    return CLIB_FUSE_INVALID_NODEID;

  if (!a)
    a = &default_args;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  n = clib_fuse_node_alloc (h, name);
  vec_free (name);

  n->nlink = 1;
  n->mode = S_IFREG | (a->mode ? a->mode : 0444);
  n->size = 4096;
  n->parent_node = clib_fuse_get_node (h, parent_nodeid);
  n->type = DT_REG;
  n->op_fn = a->file_op;
  n->private_data = a->private_data;

  vec_add1 (p->child_nodes, n);

  return n->nodeid;
}

static clib_fuse_nodeid_t
clib_fuse_find_by_name_internal (clib_fuse_handle_t h,
				 clib_fuse_nodeid_t parent_nodeid, u8 *name)
{
  clib_fuse_node_t *n;
  clib_fuse_node_t *p = clib_fuse_get_node (h, parent_nodeid);

  if (p->type != DT_DIR)
    return CLIB_FUSE_INVALID_NODEID;

  n = fuse_find_child_by_name (h, p, (const char *) name, vec_len (name));

  return n ? n->nodeid : CLIB_FUSE_INVALID_NODEID;
}

__clib_export clib_fuse_nodeid_t
clib_fuse_find_by_name (clib_fuse_handle_t h, clib_fuse_nodeid_t parent_nodeid,
			char *fmt, ...)
{
  clib_fuse_nodeid_t rv;
  va_list va;
  u8 *name;
  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  rv = clib_fuse_find_by_name_internal (h, parent_nodeid, name);
  va_end (va);
  vec_free (name);
  return rv;
}

static clib_fuse_nodeid_t
clib_fuse_add_dir_internal (clib_fuse_handle_t h,
			    clib_fuse_nodeid_t parent_nodeid,
			    clib_fuse_add_dir_args_t *a, u8 *name)
{
  clib_fuse_node_t *n;
  clib_fuse_node_t *p = clib_fuse_get_node (h, parent_nodeid);
  clib_fuse_add_dir_args_t default_args = {};

  if (p->type != DT_DIR)
    return CLIB_FUSE_INVALID_NODEID;

  if (!a)
    a = &default_args;

  n = clib_fuse_node_alloc (h, name);

  n->nlink = 2, n->mode = S_IFDIR | (a->mode ? a->mode : 0555),
  n->type = DT_DIR, n->parent_node = clib_fuse_get_node (h, parent_nodeid),
  n->private_data = a->private_data,

  vec_add1 (p->child_nodes, n);
  p->nlink++;

  return n->nodeid;
}

__clib_export clib_fuse_nodeid_t
clib_fuse_add_dir (clib_fuse_handle_t h, clib_fuse_nodeid_t parent_nodeid,
		   clib_fuse_add_dir_args_t *a, char *fmt, ...)
{
  clib_fuse_nodeid_t rv;
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  rv = clib_fuse_add_dir_internal (h, parent_nodeid, a, name);
  va_end (va);
  if (rv == CLIB_FUSE_INVALID_NODEID)
    vec_free (name);
  return rv;
}

__clib_export clib_fuse_nodeid_t
clib_fuse_find_or_add_dir (clib_fuse_handle_t h,
			   clib_fuse_nodeid_t parent_nodeid,
			   clib_fuse_add_dir_args_t *a, char *fmt, ...)
{
  clib_fuse_nodeid_t rv;
  va_list va;
  u8 *name;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);

  rv = clib_fuse_find_by_name_internal (h, parent_nodeid, name);
  if (rv != CLIB_FUSE_INVALID_NODEID)
    {
      vec_free (name);
      return rv;
    }

  rv = clib_fuse_add_dir_internal (h, parent_nodeid, a, name);
  if (rv == CLIB_FUSE_INVALID_NODEID)
    vec_free (name);

  return rv;
}

static void
fuse_reply (clib_fuse_handle_t h, const struct fuse_in_header *in,
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
    log_err (h, "failed to send reply [opcode %d, errno %d]", in->opcode,
	     errno);
}

static void
fuse_reply_errno (clib_fuse_handle_t h, const struct fuse_in_header *in,
		  int err)
{
  struct fuse_out_header out = {
    .len = sizeof (out),
    .error = -abs (err),
    .unique = in->unique,
  };
  write (h->fd, &out, sizeof (out));
}

static void
fill_attr (clib_fuse_handle_t h, clib_fuse_nodeid_t ino, struct fuse_attr *a)
{
  clib_fuse_node_t *n = clib_fuse_get_node (h, ino);
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
fuse_reply_lookup (clib_fuse_handle_t h, const struct fuse_in_header *in,
		   const char *name)
{
  clib_fuse_node_t *p = clib_fuse_get_node (h, in->nodeid);
  clib_fuse_node_t *n = 0;
  log_debug (h, "FUSE_LOOKUP[%u]: nodeid %u name '%s'", in->unique, in->nodeid,
	     name);

  n = fuse_find_child_by_name (h, p, name, strlen (name));

  if (n == 0)
    {
      fuse_reply_errno (h, in, ENOENT);
      return;
    }

  struct fuse_entry_out e = {
    .nodeid = n->nodeid,
    .generation = 1,
    .entry_valid = 10,
    .attr_valid = 10,
  };

  fill_attr (h, n->nodeid, &e.attr);
  fuse_reply (h, in, &e, sizeof (e));
}

static void
fuse_reply_setattr (clib_fuse_handle_t h, const struct fuse_in_header *in,
		    struct fuse_setattr_in *si)
{
  u32 supported_fattr = FATTR_LOCKOWNER | FATTR_SIZE;

  log_debug (h, "FUSE_SETATTR[%u]: nodeid %u valid 0x%x", in->unique,
	     in->nodeid, si->valid);

  if (si->valid & ~supported_fattr)
    fuse_reply_errno (h, in, ENOSYS);

  if (si->valid & FATTR_SIZE && si->size != 0)
    fuse_reply_errno (h, in, ENOSYS);

  struct fuse_attr_out o = { .attr_valid = 5 };
  fill_attr (h, in->nodeid, &o.attr);
  fuse_reply (h, in, &o, sizeof (o));
}

static void
fuse_reply_getattr (clib_fuse_handle_t h, const struct fuse_in_header *in)
{
  log_debug (h, "FUSE_GETATTR[%u]: nodeid %u", in->unique, in->nodeid);

  struct fuse_attr_out o = { .attr_valid = 5 };
  fill_attr (h, in->nodeid, &o.attr);
  fuse_reply (h, in, &o, sizeof (o));
}

static void
fuse_reply_init (clib_fuse_handle_t h, const struct fuse_in_header *in,
		 struct fuse_init_in *init_in)
{
  u32 minor = clib_min (init_in->minor, FUSE_KERNEL_MINOR_VERSION);
  u32 payload_len;

  struct fuse_init_out o = {
    .major = FUSE_KERNEL_VERSION,
    .minor = minor,
    .max_readahead = clib_min (init_in->max_readahead, 64 * 1024),
    .flags = FUSE_ASYNC_READ | FUSE_EXPORT_SUPPORT,
    .max_background = 16,
    .congestion_threshold = 12,
    .max_write = 64 * 1024,
    .time_gran = 1,
  };

  log_debug (
    h, "FUSE_INIT[%u]: version %u.%u max_readahead %lu flags 0x%x flags3 0x%x",
    in->unique, init_in->major, init_in->minor, init_in->max_readahead,
    init_in->flags, init_in->flags2);

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

  fuse_reply (h, in, &o, payload_len);
}

static void
fuse_reply_opendir (clib_fuse_handle_t h, const struct fuse_in_header *in)
{
  struct fuse_open_out o = {
    .fh = 1,
    .open_flags = 0,
  };
  log_debug (h, "FUSE_OPENDIR[%u]: nodeid %u", in->unique, in->nodeid);
  fuse_reply (h, in, &o, sizeof (o));
}

static void
fuse_reply_readdir (clib_fuse_handle_t h, const struct fuse_in_header *in,
		    struct fuse_read_in *ri)
{
  clib_fuse_node_t *n = clib_fuse_get_node (h, in->nodeid);

  log_debug (h, "FUSE_READDIR[%u]: nodeid %u offset %u size %u", in->unique,
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
	.ino = clib_fuse_get_node (h, in->nodeid)->parent_node->nodeid,
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
      clib_fuse_node_t *c;
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
  fuse_reply (h, in, buf, vec_len (buf));
  vec_free (buf);
}

static void
fuse_reply_releasedir (clib_fuse_handle_t h, const struct fuse_in_header *in)
{
  log_debug (h, "FUSE_RELEASEDIR[%u]:", in->unique);
  fuse_reply (h, in, 0, 0);
}

static void
fuse_reply_open (clib_fuse_handle_t h, const struct fuse_in_header *in)
{
  struct fuse_open_out o = {};
  clib_fuse_node_t *n = clib_fuse_get_node (h, in->nodeid);
  int rv;

  log_debug (h, "FUSE_OPEN[%u]: nodeid %u", in->unique, in->nodeid);

  if (n->type == DT_DIR)
    {
      fuse_reply_errno (h, in, EISDIR);
      return;
    }

  if (!n->op_fn)
    {
      fuse_reply_errno (h, in, ENOTSUP);
      return;
    }

  clib_fuse_file_op_data_t od = {
    .h = h,
    .type = CLIB_FUSE_FILE_OP_OPEN,
    .nodeid = in->nodeid,
  };

  rv = n->op_fn (&od);

  if (rv < 0)
    {
      fuse_reply_errno (h, in, rv);
      return;
    }

  o.fh = od.file_handle;
  o.open_flags |= od.open.noflush ? FOPEN_NOFLUSH : 0;
  o.open_flags |= od.open.direct_io ? FOPEN_DIRECT_IO : 0;
  o.open_flags |= od.open.nonseekable ? FOPEN_NONSEEKABLE : 0;

  fuse_reply (h, in, &o, sizeof (o));
}

static void
fuse_reply_read (clib_fuse_handle_t h, const struct fuse_in_header *in,
		 struct fuse_read_in *ri)
{
  clib_fuse_node_t *n = clib_fuse_get_node (h, in->nodeid);
  u64 off = ri->offset;
  u32 size = ri->size;
  int rv;

  log_debug (h, "FUSE_READ[%u]: nodeid %u offset %u size %u", in->unique,
	     in->nodeid, off, size);

  if (!n->op_fn)
    return fuse_reply_errno (h, in, ENOTSUP);

  clib_fuse_file_op_data_t od = {
    .h = h,
    .type = CLIB_FUSE_FILE_OP_READ,
    .nodeid = in->nodeid,
    .file_handle = ri->fh,
    .read = {
       .req_offset = off,
       .req_bytes = size,
    },
  };

  rv = n->op_fn (&od);

  if (rv < 0)
    return fuse_reply_errno (h, in, rv);

  fuse_reply (h, in, od.read.bytes_read ? od.read.start : 0,
	      od.read.bytes_read);
}

static void
fuse_reply_write (clib_fuse_handle_t h, const struct fuse_in_header *in,
		  struct fuse_write_in *wi)
{
  clib_fuse_node_t *n = clib_fuse_get_node (h, in->nodeid);
  u64 off = wi->offset;
  u32 size = wi->size;
  int rv;

  log_debug (h, "FUSE_READ[%u]: nodeid %u offset %u size %u", in->unique,
	     in->nodeid, off, size);

  if (!n->op_fn)
    return fuse_reply_errno (h, in, ENOTSUP);

  clib_fuse_file_op_data_t od = {
    .h = h,
    .type = CLIB_FUSE_FILE_OP_WRITE,
    .nodeid = in->nodeid,
    .file_handle = wi->fh,
    .write = {
       .req_offset = off,
       .req_size = size,
       .start = (u8 *)(wi + 1),
    },
  };

  rv = n->op_fn (&od);

  if (rv < 0)
    return fuse_reply_errno (h, in, rv);

  fuse_reply (h, in,
	      &(struct fuse_write_out){ .size = od.write.bytes_written },
	      sizeof (struct fuse_write_out));
}

static void
fuse_reply_flush (clib_fuse_handle_t h, const struct fuse_in_header *in,
		  struct fuse_flush_in *fi)
{
  clib_fuse_node_t *n = clib_fuse_get_node (h, in->nodeid);
  int rv;
  log_debug (h, "FUSE_FLUSH[%u]: nodeid %u", in->unique, in->nodeid);
  fuse_reply (h, in, 0, 0);
  if (!n->op_fn)
    return fuse_reply_errno (h, in, ENOTSUP);

  rv = n->op_fn (&(clib_fuse_file_op_data_t){
    .h = h,
    .type = CLIB_FUSE_FILE_OP_FLUSH,
    .nodeid = in->nodeid,
    .file_handle = fi->fh,
  });

  if (rv < 0)
    return fuse_reply_errno (h, in, rv);

  fuse_reply (h, in, 0, 0);
}

static void
fuse_reply_release (clib_fuse_handle_t h, const struct fuse_in_header *in,
		    struct fuse_release_in *ri)
{
  clib_fuse_node_t *n = clib_fuse_get_node (h, in->nodeid);
  int rv;

  log_debug (h, "FUSE_RELEASE[%u]: nodeid %u", in->unique, in->nodeid);

  if (!n->op_fn)
    return fuse_reply_errno (h, in, ENOTSUP);

  rv = n->op_fn (&(clib_fuse_file_op_data_t){
    .h = h,
    .type = CLIB_FUSE_FILE_OP_RELEASE,
    .nodeid = in->nodeid,
    .file_handle = ri->fh,
  });

  if (rv < 0)
    return fuse_reply_errno (h, in, rv);

  fuse_reply (h, in, 0, 0);
}

static clib_error_t *
fuse_fd_read (struct clib_file *f)
{
  int fd = f->file_descriptor;
  clib_fuse_handle_t h = (clib_fuse_handle_t) f->private_data;
  char ibuf[1024 * 1024];
  struct fuse_in_header *in = (struct fuse_in_header *) ibuf;
  void *payload = ibuf + sizeof (*in);
  int n = read (fd, ibuf, sizeof (ibuf));
  if (n < 0)
    {
      fformat (stderr, "errno %d\n", errno);
      exit (1);
    }

  if (n > 0)
    {
      switch (in->opcode)
	{
	case FUSE_LOOKUP:
	  fuse_reply_lookup (h, in, payload);
	  break;
	case FUSE_SETATTR:
	  fuse_reply_setattr (h, in, payload);
	  break;
	case FUSE_GETATTR:
	  fuse_reply_getattr (h, in);
	  break;
	case FUSE_INIT:
	  fuse_reply_init (h, in, payload);
	  break;
	case FUSE_OPENDIR:
	  fuse_reply_opendir (h, in);
	  break;
	case FUSE_READDIR:
	  fuse_reply_readdir (h, in, payload);
	  break;
	case FUSE_RELEASEDIR:
	  fuse_reply_releasedir (h, in);
	  break;
	case FUSE_OPEN:
	  fuse_reply_open (h, in);
	  break;
	case FUSE_READ:
	  fuse_reply_read (h, in, payload);
	  break;
	case FUSE_WRITE:
	  fuse_reply_write (h, in, payload);
	  break;
	case FUSE_FLUSH:
	  fuse_reply_flush (h, in, payload);
	  break;
	case FUSE_RELEASE:
	  fuse_reply_release (h, in, payload);
	  break;
	case FUSE_GETXATTR:
	case FUSE_LISTXATTR:
	case FUSE_REMOVEXATTR:
	case FUSE_SETXATTR:
	case FUSE_ACCESS:
	  fuse_reply_errno (h, in, ENOSYS);
	  break;
	default:
	  log_warn (h, "unsupported fuse opcode %u received", in->opcode);
	  fuse_reply_errno (h, in, ENOTSUP);
	  break;
	}
    }
  return 0;
}

static clib_error_t *
fuse_fd_error (struct clib_file *f)
{
  clib_fuse_handle_t h = (clib_fuse_handle_t) f->private_data;
  log_err (h, "fd err", 0);
  return 0;
}

__clib_export clib_error_t *
clib_fuse_create (clib_fuse_handle_t *hp, clib_fuse_create_args_t *args)
{
  clib_error_t *err = 0;

  clib_fuse_handle_t h = clib_mem_alloc (sizeof (*h));
  *h = (struct clib_fuse_handle_t){
    .blksize = 4096,
    .uid = getuid (),
    .gid = getgid (),
    .log_fn = args->log_fn,
    .log_level_err = args->log_level_err,
    .log_level_warn = args->log_level_warn,
    .log_level_debug = args->log_level_debug,
  };

  h->fd = open ("/dev/fuse", O_RDWR | O_CLOEXEC);
  if (h->fd < 0)
    {
      err = clib_error_return_unix (0, "cannot open '/dev/fuse'");
      goto done;
    }

  log_debug (h, "fusefd is %u", h->fd);

  *clib_fuse_get_node (h, CLIB_FUSE_ROOT_NODEID) = (clib_fuse_node_t){
    .nlink = 2,
    .mode = S_IFDIR | 0555,
    .parent_node = 0,
    .type = DT_DIR,
  };

  *hp = h;

done:
  if (err)
    {
      if (h->fd >= 0)
	close (h->fd);
      clib_mem_free (h);
    }
  return err;
}

__clib_export void
clib_fuse_destroy (clib_fuse_handle_t h)
{
  pool_foreach_pointer (n, h->nodes)
    {
      vec_free (n->name);
      vec_free (n->child_nodes);
      clib_mem_free (n);
    }
  clib_fuse_umount (h);
  pool_free (h->nodes);
  clib_mem_free (h);
}

__clib_export clib_error_t *
clib_fuse_mount (clib_fuse_handle_t h, char *fmt, ...)
{
  struct stat st, pst;
  u8 *mp = 0, *opts = 0;
  va_list va;
  clib_error_t *err = 0;
  u32 len;

  if (h->mountpoint)
    return clib_error_return (0, "already mounted");

  va_start (va, fmt);
  mp = va_format (0, fmt, &va);
  va_end (va);
  len = vec_len (mp);

  mp = format (mp, "/..%c", 0);
  if (stat ((char *) mp, &pst) != 0)
    {
      err = clib_error_return_unix (0, "stat '%s' failed", mp);
      goto done;
    }

  vec_set_len (mp, len);
  vec_add1 (mp, 0);
  if (stat ((char *) mp, &st) != 0)
    {
      err = clib_error_return_unix (0, "stat '%s' failed", mp);
      goto done;
    }

  if (st.st_dev != pst.st_dev)
    {
      err = clib_error_return_unix (0, "mountpoint '%s' already mounted", mp);
      goto done;
    }

  opts = format (
    0, "fd=%d,rootmode=%o,user_id=%u,group_id=%u,subtype=fusefs,allow_other%c",
    h->fd, S_IFDIR, getuid (), getgid (), 0);

  if (mount ("fuse", (char *) mp, "fuse", MS_NOSUID | MS_NODEV,
	     (char *) opts) < 0)
    {
      err =
	clib_error_return_unix (0, "cannot mount fusefs to '%s'", (char *) mp);
      goto done;
    }

  vec_set_len (mp, len);
  h->mountpoint = mp;
  mp = 0;

  h->clib_file_index =
    clib_file_add (h->file_main, &(clib_file_t){
				   .file_descriptor = h->fd,
				   .read_function = fuse_fd_read,
				   .error_function = fuse_fd_error,
				   .description = format (0, "fuse"),
				   .private_data = pointer_to_uword (h),
				 });

done:
  vec_free (mp);
  vec_free (opts);
  return err;
}

__clib_export clib_error_t *
clib_fuse_umount (clib_fuse_handle_t h)
{
  clib_error_t *err = 0;
  if (h->mountpoint)
    {
      clib_file_del_by_index (h->file_main, h->clib_file_index);
      vec_add1 (h->mountpoint, 0);
      if (umount2 ((char *) h->mountpoint, MNT_DETACH))
	err =
	  clib_error_return_unix (0, "umount2('%s') failed", h->mountpoint);
      vec_free (h->mountpoint);
    }
  return err;
}

__clib_export clib_fuse_nodeid_t
clib_fuse_get_parent_nodeid (clib_fuse_handle_t h, clib_fuse_nodeid_t ino)
{
  clib_fuse_node_t *n = clib_fuse_get_node (h, ino);
  return n->parent_node ? n->parent_node->nodeid : CLIB_FUSE_INVALID_NODEID;
}

__clib_export u64
clib_fuse_get_node_private_data (clib_fuse_handle_t h, clib_fuse_nodeid_t ino)
{
  return clib_fuse_get_node (h, ino)->private_data;
}

__clib_export void
clib_fuse_set_node_private_data (clib_fuse_handle_t h, clib_fuse_nodeid_t ino,
				 u64 private_data)
{
  clib_fuse_get_node (h, ino)->private_data = private_data;
}
