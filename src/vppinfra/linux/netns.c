/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>

#include <vppinfra/format.h>

__clib_export int
clib_netns_open (u8 *netns_u8)
{
  char *netns = (char *) netns_u8;
  u8 *s = 0;
  int fd;

  if ((NULL) == netns)
    s = format (0, "/proc/self/ns/net%c", 0);
  else if (strncmp (netns, "pid:", 4) == 0)
    s = format (0, "/proc/%u/ns/net%c", atoi (netns + 4), 0);
  else if (netns[0] == '/')
    s = format (0, "%s%c", netns, 0);
  else
    s = format (0, "/var/run/netns/%s%c", netns, 0);

  fd = open ((char *) s, O_RDONLY);
  vec_free (s);
  return fd;
}

__clib_export int
clib_setns (int nfd)
{
  return setns (nfd, CLONE_NEWNET);
}
