/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */
#ifndef __PROCESS_H__
#define __PROCESS_H__

#include <plugins/process/capabilities.h>
#include <vppinfra/format.h>
#include <vlib/vlib.h>
#define foreach_process_error                                                 \
  _ (MKDIR, -1, "mkdir command failed")                                       \
  _ (CHOWN, -2, "chown command failed")                                       \
  _ (CHDIR, -3, "chdir command failed")                                       \
  _ (CHROOT, -4, "chroot command failed")                                     \
  _ (SETGID, -5, "setgid command failed")                                     \
  _ (SETUID, -6, "setuid command failed")                                     \
  _ (PRIVILEGES_REGAINED, -7, "root privilege regained after drop")           \
  _ (GET_CAPABILITIES, -8, "error getting process capabilities")              \
  _ (UNSUPPORTED_CAPABILITIES, -9, "error non supported capabilities")        \
  _ (MODIFY_CAPABILITIES, -10, "error modifying process capabilities")

typedef enum
{
#define _(a, b, c) PROCESS_API_ERROR_##a = (b),
  foreach_process_error
#undef _
    VLIB_PROCESS_API_N_ERROR,
} process_privilege_reply_error_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  /* logging class */
  vlib_log_class_t log_class;
} process_main_t;

extern process_main_t process_main;

format_function_t format_process_effective_capabilities;
format_function_t format_process_permitted_capabilities;
format_function_t format_process_inheritable_capabilities;
unformat_function_t unformat_process_capabilities;
extern int process_get_capabilities (vlib_main_t *vm, cap_user_data_t *data);
extern int process_set_capabilities (vlib_main_t *vm, u64 capabilities,
				     u8 change_permitted);
extern void process_get_privileges (vlib_main_t *vm, u32 *gid, u32 *uid);
extern int process_drop_privileges (u32 gid, u32 uid, char *chroot_dir);

#define process_log_debug(f, ...)                                             \
  do                                                                          \
    {                                                                         \
      vlib_log (VLIB_LOG_LEVEL_DEBUG, process_main.log_class, f,              \
		##__VA_ARGS__);                                               \
    }                                                                         \
  while (0)

#define process_log_warning(f, ...)                                           \
  do                                                                          \
    {                                                                         \
      vlib_log (VLIB_LOG_LEVEL_WARNING, process_main.log_class, f,            \
		##__VA_ARGS__);                                               \
    }                                                                         \
  while (0)

#define process_log_err(f, ...)                                               \
  do                                                                          \
    {                                                                         \
      vlib_log (VLIB_LOG_LEVEL_ERR, process_main.log_class, f,                \
		##__VA_ARGS__);                                               \
    }                                                                         \
  while (0)

#endif
