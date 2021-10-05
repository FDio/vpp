/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/format.h>

clib_error_t *
vlib_process_drop_privileges (vlib_main_t *vm, u32 gid, u32 uid)
{
  clib_error_t *error = 0;

  ASSERT (gid != 0 || uid != 0);

  if (getuid () == 0)
    {
      if (setgid (gid) != 0)
	return clib_error_return_unix (0, "setgid");
      if (setuid (uid) != 0)
	return clib_error_return_unix (0, "setuid");
    }

  if (setuid (0) != -1)
    return clib_error_return (0, "regain root privileges");

  return error;
}

void
vlib_process_get_privileges (vlib_main_t *vm, u32 *gid, u32 *uid)
{
  *gid = getgid ();
  *uid = getuid ();
}
