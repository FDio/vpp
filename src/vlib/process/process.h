/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef __PROCESS_H__
#define __PROCESS_H__

#include <vlib/process/capabilities.h>

format_function_t format_vlib_process_effective_capabilities;
format_function_t format_vlib_process_permitted_capabilities;
format_function_t format_vlib_process_inheritable_capabilities;
unformat_function_t unformat_vlib_process_capabilities;

extern clib_error_t *vlib_process_get_capabilities (vlib_main_t *vm,
						    cap_user_data_t *data);
extern clib_error_t *vlib_process_set_capabilities (vlib_main_t *vm,
						    u64 capabilities);
extern void vlib_process_get_privileges (vlib_main_t *vm, u32 *gid, u32 *uid);
extern clib_error_t *vlib_process_drop_privileges (vlib_main_t *vm, u32 gid,
						   u32 uid);
#endif
