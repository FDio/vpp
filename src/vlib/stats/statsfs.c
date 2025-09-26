/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/stats/stats.h>

VLIB_REGISTER_LOG_CLASS (statsfs_log, static) = {
  .class_name = "stats",
  .subclass_name = "fs",
};

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (statsfs_log.class, fmt, __VA_ARGS__)
#define log_warn(fmt, ...) vlib_log_warn (statsfs_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)  vlib_log_err (statsfs_log.class, fmt, __VA_ARGS__)

typedef struct
{
  u8 *data;
  u32 offset;
} statfs_file_handle_t;

typedef struct
{
  u64 inode;
} statfs_entry_data_t;

typedef struct
{
  statfs_file_handle_t *file_handles;
  statfs_entry_data_t *entry_data;
} statfs_main_t;
static statfs_main_t statfs_main;

static u8 *
format_statsfs_value (u8 *s, va_list *args)
{
  u32 idx = va_arg (*args, u32);
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  vlib_stats_entry_t *se = vec_elt_at_index (sm->directory_vector, idx);

  s = format (s, "%lu", se->value);
  vec_add1 (s, '\n');
  return s;
}

static int
statsfs_file_op_fn (vlib_main_t *vm, vlib_fuse_file_op_data_t *op)
{
  statfs_main_t *sfm = &statfs_main;
  statfs_file_handle_t *fh;
  int rv = 0;

  log_debug ("file_op: nodeid %u type %d", op->nodeid, op->type);

  if (op->type == VLIB_FUSE_FILE_OP_OPEN)
    {
      pool_get_zero (sfm->file_handles, fh);
      op->file_handle = fh - sfm->file_handles;
      op->open.noflush = 1;
      op->open.direct_io = 1;
      return 0;
    }

  if (op->type == VLIB_FUSE_FILE_OP_WRITE ||
      op->type == VLIB_FUSE_FILE_OP_TRUNCATE)
    return -EACCES;

  fh = pool_elt_at_index (sfm->file_handles, op->file_handle);

  if (op->type == VLIB_FUSE_FILE_OP_READ)
    {
      u32 off = op->read.req_offset;
      u32 idx = vlib_fuse_get_node_private_data (op->h, op->nodeid);

      if (off != fh->offset)
	return -EINVAL;

      if (off > 0)
	{
	  u32 size = vec_len (fh->data);
	  if (off < size)
	    {
	      op->read.start = fh->data + off;
	      op->read.bytes_read = clib_min (op->read.req_bytes, size - off);
	      fh->offset += op->read.bytes_read;
	    }
	  else
	    op->read.bytes_read = 0;
	  return 0;
	}

      vec_reset_length (fh->data);
      fh->data = format (fh->data, "%U", format_statsfs_value, idx);
      op->read.start = fh->data;
      op->read.bytes_read = clib_min (op->read.req_bytes, vec_len (fh->data));
      fh->offset = op->read.bytes_read;

      return 0;
    }

  if (op->type == VLIB_FUSE_FILE_OP_FLUSH)
    return rv;

  if (op->type == VLIB_FUSE_FILE_OP_RELEASE)
    {
      vec_free (fh->data);
      pool_put (sfm->file_handles, fh);
    }

  return 0;
}

vlib_fuse_nodeid_t
vlib_statsfs_add_node (vlib_stats_segment_t *sm, u32 idx)
{
  char name[VLIB_STATS_MAX_NAME_SZ], *next, *dirname = name;
  vlib_fuse_nodeid_t ni = VLIB_FUSE_ROOT_NODEID;
  vlib_stats_entry_t *e = vec_elt_at_index (sm->directory_vector, idx);
  vlib_fuse_handle_t h = sm->fuse_handle;
  statfs_main_t *sfm = &statfs_main;
  statfs_entry_data_t *sed;

  clib_memcpy (name, e->name, sizeof (name));

  while (dirname[0] == '/')
    dirname++;

  while ((next = strchr (dirname, '/')))
    {
      next[0] = 0;
      ni = vlib_fuse_find_or_add_dir (h, ni, 0, "%s", dirname);
      dirname = next + 1;
    }

  ni = vlib_fuse_add_file (h, ni,
			   &(vlib_fuse_add_file_args_t){
			     .private_data = idx,
			     .file_op = statsfs_file_op_fn,
			   },
			   "%s", dirname);

  if (ni != VLIB_FUSE_INVALID_NODEID)
    {
      vec_validate (sfm->entry_data, idx);
      sed = vec_elt_at_index (sfm->entry_data, idx);
      sed->inode = ni;
    }

  return ni;
}

static clib_error_t *
statfs_init (vlib_main_t *vm)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  clib_error_t *err;
  vlib_fuse_create_args_t fa = {
    .umount_stale = 1,
    .mkdir = 1,
    .allow_other = 1,
    .default_permissions = 1,
  };

  if (!sm->fs_mountpoint)
    return 0;

  err = vlib_fuse_create (&sm->fuse_handle, &fa, "%v", sm->fs_mountpoint);
  vec_free (sm->fs_mountpoint);

  if (err)
    return err;

  for (u32 i = 0; i < vec_len (sm->directory_vector); i++)
    {
      vlib_stats_entry_t *e = vec_elt_at_index (sm->directory_vector, i);
      if (e->type != STAT_DIR_TYPE_GAUGE)
	continue;

      if (vlib_statsfs_add_node (sm, i) == VLIB_FUSE_INVALID_NODEID)
	return clib_error_return (0, "failed to create statfs node '%v'",
				  sm->fs_mountpoint);
    }

  return err;
}

VLIB_INIT_FUNCTION (statfs_init) = {
  .runs_after = VLIB_INITS ("statseg_init"),
};
