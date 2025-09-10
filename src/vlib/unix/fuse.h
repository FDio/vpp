/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/file.h>

typedef u32 vlib_fuse_nodeid_t;
typedef struct vlib_fuse_handle_t *vlib_fuse_handle_t;
typedef void (vlib_fuse_log_fn_t) (u8 level, char *fmt, ...);

#define VLIB_FUSE_ROOT_NODEID	 1
#define VLIB_FUSE_INVALID_NODEID 0

typedef enum
{
  VLIB_FUSE_FILE_OP_OPEN,
  VLIB_FUSE_FILE_OP_READ,
  VLIB_FUSE_FILE_OP_WRITE,
  VLIB_FUSE_FILE_OP_TRUNCATE,
  VLIB_FUSE_FILE_OP_FLUSH,
  VLIB_FUSE_FILE_OP_RELEASE,
} __clib_packed vlib_fuse_file_op_type_t;

typedef struct
{
  vlib_fuse_handle_t h;
  vlib_fuse_file_op_type_t type;
  vlib_fuse_nodeid_t nodeid;
  u64 file_handle;
  union
  {
    struct
    {
      /* return */
      u8 direct_io : 1;
      u8 nonseekable : 1;
      u8 noflush : 1;
    } open;
    struct
    {
      u64 req_offset;
      u32 req_bytes;

      /* return */
      u8 *start;
      u32 bytes_read;
    } read;
    struct
    {
      u64 req_offset;
      u32 req_size;
      u8 *start;

      /* return */
      u32 bytes_written;
    } write;
    struct
    {
      u32 size;
    } truncate;
  };
} vlib_fuse_file_op_data_t;

typedef int (vlib_fuse_file_op_fn_t) (vlib_fuse_file_op_data_t *);

typedef struct
{
  vlib_fuse_log_fn_t *log_fn;
  u8 log_level_err;
  u8 log_level_warn;
  u8 log_level_debug;
} vlib_fuse_create_args_t;

clib_error_t *vlib_fuse_create (vlib_fuse_handle_t *h,
				vlib_fuse_create_args_t *args);
void vlib_fuse_destroy (vlib_fuse_handle_t h);
clib_error_t *vlib_fuse_mount (vlib_fuse_handle_t h, char *fmt, ...);
clib_error_t *vlib_fuse_umount (vlib_fuse_handle_t h);
vlib_fuse_nodeid_t vlib_fuse_find_by_name (vlib_fuse_handle_t h,
					   vlib_fuse_nodeid_t parent_nodeid,
					   char *fmt, ...);

typedef struct
{
  u32 mode;
  u64 private_data;
  vlib_fuse_file_op_fn_t *file_op;
} vlib_fuse_add_file_args_t;

vlib_fuse_nodeid_t vlib_fuse_add_file (vlib_fuse_handle_t h,
				       vlib_fuse_nodeid_t parent_nodeid,
				       vlib_fuse_add_file_args_t *a, char *fmt,
				       ...);
typedef struct
{
  u32 mode;
  u64 private_data;
} vlib_fuse_add_dir_args_t;

vlib_fuse_nodeid_t vlib_fuse_add_dir (vlib_fuse_handle_t h,
				      vlib_fuse_nodeid_t parent_nodeid,
				      vlib_fuse_add_dir_args_t *a, char *fmt,
				      ...);
vlib_fuse_nodeid_t vlib_fuse_find_or_add_dir (vlib_fuse_handle_t h,
					      vlib_fuse_nodeid_t parent_nodeid,
					      vlib_fuse_add_dir_args_t *a,
					      char *fmt, ...);
vlib_fuse_nodeid_t vlib_fuse_get_parent_nodeid (vlib_fuse_handle_t h,
						vlib_fuse_nodeid_t ino);
void vlib_fuse_set_node_private_data (vlib_fuse_handle_t h,
				      vlib_fuse_nodeid_t ino,
				      u64 private_data);
u64 vlib_fuse_get_node_private_data (vlib_fuse_handle_t h,
				     vlib_fuse_nodeid_t ino);
