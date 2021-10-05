/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/format.h>
#include <plugins/process/process.h>

u8 *
format_process_effective_capabilities (u8 *s, va_list *args)
{
  cap_user_data_t *data = va_arg (*args, cap_user_data_t *);

#define _(name, bit, ss)                                                      \
  if (data->effective & CAP_BIT_SET (name))                                   \
    s = format (s, "%s ", ss);
  foreach_process_capabilities
#undef _

    return s;
}

u8 *
format_process_permitted_capabilities (u8 *s, va_list *args)
{
  cap_user_data_t *data = va_arg (*args, cap_user_data_t *);

#define _(name, bit, ss)                                                      \
  if (data->permitted & CAP_BIT_SET (name))                                   \
    s = format (s, "%s ", ss);
  foreach_process_capabilities
#undef _

    return s;
}

u8 *
format_process_inheritable_capabilities (u8 *s, va_list *args)
{
  cap_user_data_t *data = va_arg (*args, cap_user_data_t *);

#define _(name, bit, ss)                                                      \
  if (data->inheritable & CAP_BIT_SET (name))                                 \
    s = format (s, "%s ", ss);
  foreach_process_capabilities
#undef _
    return s;
}

uword
unformat_process_capabilities (unformat_input_t *input, va_list *args)
{
  u64 *cap_p = va_arg (*args, u64 *);
  int rv = 0;
  u64 cap = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0)
	;
#define _(name, bit, str)                                                     \
  else if (unformat (input, str))                                             \
  {                                                                           \
    cap |= CAP_BIT_SET (name);                                                \
    rv = 1;                                                                   \
  }
      foreach_process_capabilities
#undef _
	else break;
    }
  if (rv)
    *cap_p = cap; //(cap[0] | (u64) cap[1] << 32);
  return rv;
}

int
process_get_capabilities (vlib_main_t *vm, cap_user_data_t *data)
{
  cap_user_header_t hdrp;
  int ret = -1;
  struct cap_user_data
  {
    u32 effective;
    u32 permitted;
    u32 inheritable;
  } cap_data[CAPABILITY_U32S_3];

  hdrp.version = CAPABILITY_VERSION_3;
  hdrp.pid = getpid ();
  ret = syscall (SYS_capget, &hdrp, cap_data);

  if (ret == -1)
    return PROCESS_API_ERROR_GET_CAPABILITIES;

  data->effective =
    (cap_data[0].effective | (u64) cap_data[1].effective << 32);
  data->permitted =
    (cap_data[0].permitted | (u64) cap_data[1].permitted << 32);
  data->inheritable =
    (cap_data[0].inheritable | (u64) cap_data[1].inheritable << 32);

  return 0;
}

int
process_set_capabilities (vlib_main_t *vm, u64 capabilities,
			  u8 change_permitted)
{
  cap_user_header_t hdrp;
  u64 permitted;
  int ret = -1;
  struct cap_user_data
  {
    u32 effective;
    u32 permitted;
    u32 inheritable;
  } cap_data[CAPABILITY_U32S_3];

  hdrp.version = CAPABILITY_VERSION_3;
  hdrp.pid = getpid ();

  ret = syscall (SYS_capget, &hdrp, cap_data);
  if (ret == -1)
    return PROCESS_API_ERROR_GET_CAPABILITIES;
  permitted = (cap_data[0].permitted | (u64) cap_data[1].permitted << 32);

  if (capabilities & ~permitted)
    return PROCESS_API_ERROR_UNSUPPORTED_CAPABILITIES;

  cap_data[0].effective = (u32) capabilities;
  cap_data[1].effective = (u32) (capabilities >> 32);
  if (change_permitted)
    {
      cap_data[0].permitted = (u32) capabilities;
      cap_data[1].permitted = (u32) (capabilities >> 32);
    }

  ret = syscall (SYS_capset, &hdrp, cap_data);
  if (ret == -1)
    return PROCESS_API_ERROR_MODIFY_CAPABILITIES;

  return 0;
}
