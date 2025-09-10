/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/file.h>

typedef u32 clib_fuse_nodeid_t;
typedef struct clib_fuse_handle_t *clib_fuse_handle_t;
typedef void (clib_fuse_log_fn_t) (u8 level, char *fmt, ...);

#define CLIB_FUSE_ROOT_NODEID	 1
#define CLIB_FUSE_INVALID_NODEID 0

typedef enum
{
  CLIB_FUSE_FILE_OP_OPEN,
  CLIB_FUSE_FILE_OP_READ,
  CLIB_FUSE_FILE_OP_WRITE,
  CLIB_FUSE_FILE_OP_TRUNCATE,
  CLIB_FUSE_FILE_OP_FLUSH,
  CLIB_FUSE_FILE_OP_RELEASE,
} __clib_packed clib_fuse_file_op_type_t;

typedef struct
{
  clib_fuse_handle_t h;
  clib_fuse_file_op_type_t type;
  clib_fuse_nodeid_t nodeid;
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
} clib_fuse_file_op_data_t;

typedef int (clib_fuse_file_op_fn_t) (clib_fuse_file_op_data_t *);

typedef struct
{
  clib_fuse_log_fn_t *log_fn;
  u8 log_level_err;
  u8 log_level_warn;
  u8 log_level_debug;
  clib_file_main_t *file_main;
} clib_fuse_create_args_t;

clib_error_t *clib_fuse_create (clib_fuse_handle_t *h,
				clib_fuse_create_args_t *args);
void clib_fuse_destroy (clib_fuse_handle_t h);
clib_error_t *clib_fuse_mount (clib_fuse_handle_t h, char *fmt, ...);
clib_error_t *clib_fuse_umount (clib_fuse_handle_t h);
clib_fuse_nodeid_t clib_fuse_find_by_name (clib_fuse_handle_t h,
					   clib_fuse_nodeid_t parent_nodeid,
					   char *fmt, ...);

typedef struct
{
  u32 mode;
  u64 private_data;
  clib_fuse_file_op_fn_t *file_op;
} clib_fuse_add_file_args_t;

clib_fuse_nodeid_t clib_fuse_add_file (clib_fuse_handle_t h,
				       clib_fuse_nodeid_t parent_nodeid,
				       clib_fuse_add_file_args_t *a, char *fmt,
				       ...);
typedef struct
{
  u32 mode;
  u64 private_data;
} clib_fuse_add_dir_args_t;

clib_fuse_nodeid_t clib_fuse_add_dir (clib_fuse_handle_t h,
				      clib_fuse_nodeid_t parent_nodeid,
				      clib_fuse_add_dir_args_t *a, char *fmt,
				      ...);
clib_fuse_nodeid_t clib_fuse_find_or_add_dir (clib_fuse_handle_t h,
					      clib_fuse_nodeid_t parent_nodeid,
					      clib_fuse_add_dir_args_t *a,
					      char *fmt, ...);
clib_fuse_nodeid_t clib_fuse_get_parent_nodeid (clib_fuse_handle_t h,
						clib_fuse_nodeid_t ino);
void clib_fuse_set_node_private_data (clib_fuse_handle_t h,
				      clib_fuse_nodeid_t ino,
				      u64 private_data);
u64 clib_fuse_get_node_private_data (clib_fuse_handle_t h,
				     clib_fuse_nodeid_t ino);
