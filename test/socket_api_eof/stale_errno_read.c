/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Cisco and/or its affiliates. */

/* Inject stale EAGAIN on API Unix socket EOF for a deterministic VPP repro. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

ssize_t
read (int fd, void *buf, size_t count)
{
  ssize_t n = syscall (SYS_read, fd, buf, count);
  const char *path = getenv ("VPP_EOF_INJECT_PATH");
  if (n == 0 && count && path)
    {
      struct sockaddr_un addr;
      socklen_t len = sizeof (addr);
      if (getsockname (fd, (struct sockaddr *) &addr, &len) == 0 && addr.sun_family == AF_UNIX &&
	  strncmp (addr.sun_path, path, sizeof (addr.sun_path)) == 0)
	{
	  const char *marker = getenv ("VPP_EOF_INJECT_MARKER");
	  static int marked;
	  if (marker && __sync_bool_compare_and_swap (&marked, 0, 1))
	    {
	      int out = syscall (SYS_openat, AT_FDCWD, marker, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	      if (out >= 0)
		{
		  const char message[] = "injected stale EAGAIN after EOF\n";
		  syscall (SYS_write, out, message, sizeof (message) - 1);
		  syscall (SYS_close, out);
		}
	    }
	  errno = EAGAIN;
	}
    }
  return n;
}
