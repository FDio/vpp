/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <unistd.h>

#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/time.h>

#define RESTART_API_SOCKET "/run/vpp/api.sock"

/* Returns the pid of the process listening on the api socket, or -1 */
static pid_t
vpp_pid (const char *socket_name)
{
  struct sockaddr_un sun = { .sun_family = AF_UNIX };
  struct ucred cred;
  socklen_t len = sizeof (cred);
  int fd;

  fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;

  strncpy (sun.sun_path, socket_name, sizeof (sun.sun_path) - 1);
  if (connect (fd, (struct sockaddr *) &sun, sizeof (sun)) < 0 ||
      getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
    {
      close (fd);
      return -1;
    }

  close (fd);
  return cred.pid;
}

static void
sleep_ms (long ms)
{
  struct timespec req = { .tv_sec = 0, .tv_nsec = ms * 1000 * 1000 };
  struct timespec rem;

  while (nanosleep (&req, &rem) < 0)
    req = rem;
}

int
restart_main_fn (unformat_input_t *i)
{
  const char *socket_name = RESTART_API_SOCKET;
  u8 *socket_arg = 0;
  int verbose = 0;
  pid_t old_pid = -1, new_pid = -1;
  int wait;

  if (geteuid ())
    clib_error ("vpp_restart: must be root...");

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "verbose") || unformat (i, "v"))
	verbose = 1;
      else if (unformat (i, "socket %s", &socket_arg))
	socket_name = (char *) socket_arg;
      else
	{
	  clib_error ("unknown input `%U'", format_unformat_error, i);
	  return 1;
	}
    }

  /*
   * Step 1: look up the current vpp pid, the owner of the api socket.
   * Spin for up to 10 seconds for vpp to start.
   */
  for (wait = 0; wait < 1000; wait++)
    {
      old_pid = vpp_pid (socket_name);
      if (old_pid > 0)
	break;
      sleep_ms (10);
    }

  if (old_pid <= 0)
    {
      clib_error ("VPP not runnning...");
      return 3;
    }

  /*
   * Step 2: sanity check the pid we discovered
   */
  if (verbose)
    fformat (stdout, "Sanity check current vpp pid %d\n", old_pid);

  if (kill (old_pid, 0) < 0)
    {
      clib_error ("vpp current pid %d not running...", old_pid);
      return 2;
    }

  if (verbose)
    fformat (stdout, "Sanity check vpp pid %d OK\n", old_pid);

  /*
   * Step 3: send SIGTERM to vpp.
   * systemd et al. will restart vpp
   */
  if (kill (old_pid, SIGTERM) < 0)
    {
      clib_unix_error ("SIGTERM fail");
      return 3;
    }

  /*
   * Step 4: wait up to 15 seconds for a new incarnation of vpp to
   * listen on the api socket.
   */
  for (wait = 0; wait < 150; wait++)
    {
      new_pid = vpp_pid (socket_name);
      if (new_pid > 0 && new_pid != old_pid)
	break;
      sleep_ms (100);
    }

  if (new_pid <= 0 || new_pid == old_pid)
    {
      clib_error ("Timeout waiting for vpp to restart...");
      return 4;
    }

  if (verbose)
    fformat (stdout, "New PID %d... Restarted...\n", new_pid);

  return 0;
}

int
main (int argc, char **argv)
{
  unformat_input_t i;
  int ret;

  clib_mem_init (0, 64ULL << 20);

  unformat_init_command_line (&i, argv);
  ret = restart_main_fn (&i);
  unformat_free (&i);
  return ret;
}
