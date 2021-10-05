/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <vlib/process/process.h>
#include <vlib/vlib.h>
#include <vppinfra/format.h>

int
vlib_process_drop_privileges (u32 gid, u32 uid, char *chroot_dir)
{
  ASSERT (gid != 0 || uid != 0);

  if (chroot_dir) {
    struct stat st = {0};
    if (stat(chroot_dir, &st) == -1) {
        if (mkdir(chroot_dir, 0700) != 0)
          return VLIB_PROCESS_API_ERROR_MKDIR;
     }
     if (chown(chroot_dir, uid,gid) != 0)
          return VLIB_PROCESS_API_ERROR_CHOWN;
     if (chdir(chroot_dir) != 0)
        return VLIB_PROCESS_API_ERROR_CHDIR;
     if (chroot(chroot_dir) != 0)
        return VLIB_PROCESS_API_ERROR_CHROOT;
  }

  if (getuid () == 0)
    {
      if (setgid (gid) != 0)
	return VLIB_PROCESS_API_ERROR_SETGID;
      if (setuid (uid) != 0)
	return VLIB_PROCESS_API_ERROR_SETUID;
    }

  if (setuid (0) != -1)
    return VLIB_PROCESS_API_ERROR_PRIVILEGES_REGAINED;

  return 0;
}

void
vlib_process_get_privileges (vlib_main_t *vm, u32 *gid, u32 *uid)
{
  *gid = getgid ();
  *uid = getuid ();
}
