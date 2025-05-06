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
  u8 drop_on_disconnect;
} snort_instance_create_args_t;

typedef int (snort_instance_create_fn_t) (vlib_main_t *vm,
					  snort_instance_create_args_t *args,
					  char *fmt, ...);
typedef int (snort_instance_delete_fn_t) (vlib_main_t *vm, u32 instance_index);

snort_instance_create_fn_t snort_instance_create;
snort_instance_delete_fn_t snort_instance_delete;

#endif /* __snort_export_h__ */
