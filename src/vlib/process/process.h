/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */
#ifndef __PROCESS_H__
#define __PROCESS_H__

#include <vlib/process/capabilities.h>
#include <vppinfra/format.h>
#include <vlib/vlib.h>
#define foreach_process_error					        \
  _(MKDIR, -1, "mkdir command failed")					\
  _(CHOWN, -2, "chown command failed")					\
  _(CHDIR, -3,"chdir command failed")					\
  _(CHROOT, -4,"chroot command failed")					\
  _(SETGID, -5, "setgid command failed")			        \
  _(SETUID, -6, "setuid command failed")				\
  _(PRIVILEGES_REGAINED, -7, "root privilege regained after drop")      \
  _(GET_CAPABILITIES, -8, "error getting process capabilities")         \
  _(UNSUPPORTED_CAPABILITIES, -9, "error non supported capabilities")   \
  _(MODIFY_CAPABILITIES, -10, "error modifying process capabilities")   \


typedef enum
{
#define _(a,b,c) VLIB_PROCESS_API_ERROR_##a = (b),
  foreach_process_error
#undef _
    VLIB_PROCESS_API_N_ERROR,
} process_privilege_reply_error_t;

format_function_t format_vlib_process_effective_capabilities;
format_function_t format_vlib_process_permitted_capabilities;
format_function_t format_vlib_process_inheritable_capabilities;
unformat_function_t unformat_vlib_process_capabilities;
extern int vlib_process_get_capabilities (vlib_main_t *vm,
						    cap_user_data_t *data);
extern  int vlib_process_set_capabilities (vlib_main_t *vm,
						    u64 capabilities);
extern void vlib_process_get_privileges (vlib_main_t *vm, u32 *gid, u32 *uid);
extern int vlib_process_drop_privileges (u32 gid, u32 uid, char *chroot_dir);
#endif