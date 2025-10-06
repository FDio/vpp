/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#ifndef __snort_export_h__
#define __snort_export_h__

#include <vppinfra/error.h>
#include <vppinfra/socket.h>
#include <vppinfra/file.h>
#include <vlib/vlib.h>

typedef struct
{
  u8 log2_queue_sz;
  u8 log2_empty_buf_queue_sz;
  u8 drop_on_disconnect;
  u8 qpairs_per_thread;
  u8 drop_bitmap; /* bits indexed by verdict, 0 = pass, 1 = drop */
} snort_instance_create_args_t;

typedef u16 snort_instance_index_t;

typedef int (snort_instance_create_fn_t) (vlib_main_t *vm,
					  snort_instance_create_args_t *args,
					  char *fmt, ...);
typedef int (snort_instance_delete_fn_t) (
  vlib_main_t *vm, snort_instance_index_t instance_index);

typedef int (snort_instance_get_index_by_name_fn_t) (
  vlib_main_t *vm, const char *name, snort_instance_index_t *instance_index);

snort_instance_create_fn_t snort_instance_create;
snort_instance_delete_fn_t snort_instance_delete;
snort_instance_get_index_by_name_fn_t snort_instance_get_index_by_name;

#endif /* __snort_export_h__ */
