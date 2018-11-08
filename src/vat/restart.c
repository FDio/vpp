/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <svm/svmdb.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/time.h>
#include <vppinfra/macros.h>

int
restart_main_fn (unformat_input_t * i)
{
  int verbose = 0;
  int old_pid;
  int wait;
  u8 *chroot_path = 0;
  svmdb_client_t *svmdb_client;
  volatile pid_t *pidp;
  struct stat statb;
  ino_t old_inode;
  int sleeps;
  svmdb_map_args_t _ma, *ma = &_ma;

  struct timespec _req, *req = &_req;
  struct timespec _rem, *rem = &_rem;

  if (geteuid ())
    clib_error ("vpp_restart: must be root...");

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "verbose") || unformat (i, "v"))
	verbose = 1;
      else if (unformat (i, "chroot %s", &chroot_path))
	;
      else
	{
	  clib_error ("unknown input `%U'", format_unformat_error, i);
	  return 1;
	}
    }

  /*
   * Step 1: look up the current VPP pid in the shared-memory database
   */
  memset (ma, 0, sizeof (*ma));
  ma->root_path = (char *) chroot_path;

  svmdb_client = svmdb_map (ma);

  pidp = svmdb_local_get_variable_reference (svmdb_client,
					     SVMDB_NAMESPACE_VEC, "vpp_pid");
  if (pidp == 0)
    {
      clib_error ("'vpp_pid' svm variable not found, vpp has never run?");
      return 2;
    }

  /* Spin for up to 10 seconds for vpp to start */
  for (wait = 0; wait < 1000; wait++)
    {
      req->tv_sec = 0;
      req->tv_nsec = 10000 * 1000;	/* 10 ms */
      while (nanosleep (req, rem) < 0)
	*req = *rem;

      if (*pidp)
	goto found2;
    }

  clib_error ("VPP not runnning...");
  return 3;

found2:

  old_pid = *pidp;

  /*
   * Step 2: sanity check the pid we discovered
   */
  if (verbose)
    fformat (stdout, "Sanity check current vpp pid %d\n", old_pid);

  if (kill (old_pid, 0) < 0)
    {
      svmdb_unmap (svmdb_client);
      clib_error ("vpp current pid %d not running...", old_pid);
      return 2;
    }

  if (verbose)
    fformat (stdout, "Sanity check vpp pid %d OK\n", old_pid);

  /*
   * Step 3: figure out the current vpp <--> client shared-VM file
   * inode number
   */
  if (stat ("/dev/shm/vpe-api", &statb) < 0)
    {
      clib_unix_error ("stat fail");
      return 4;
    }

  old_inode = statb.st_ino;

  if (verbose)
    fformat (stdout, "Old inode %u\n", old_inode);

  /* Note: restart wipes out the shared VM database */
  svmdb_unmap (svmdb_client);

  /*
   * Step 4: send SIGTERM to vpp.
   * systemd et al. will restart vpp after wiping out the shared-VM
   * database and (crucially) the shared API messaging segment
   */

  if (kill (old_pid, SIGTERM) < 0)
    {
      clib_unix_error ("SIGTERM fail");
      return 3;
    }

  sleeps = 0;

  /*
   * Step 5: wait up to 15 seconds for a new incarnation of
   * the shared-VM API segment to appear.
   */
  for (wait = 0; wait < 150; wait++)
    {
      if ((stat ("/dev/shm/vpe-api", &statb) < 0)
	  || statb.st_ino == old_inode)
	{
	  req->tv_sec = 0;
	  req->tv_nsec = 100000 * 1000;	/* 100 ms */
	  while (nanosleep (req, rem) < 0)
	    *req = *rem;
	  sleeps++;
	}
      else
	goto new_inode;
    }

  clib_error ("Timeout waiting for new inode to appear...");
  return 5;

new_inode:
  if (verbose && sleeps > 0)
    fformat (stdout, "Inode sleeps %d\n", sleeps);

  if (verbose)
    fformat (stdout, "New inode %u\n", statb.st_ino);

  /*
   * Step 6: remap the SVM database
   */
  svmdb_client = svmdb_map (ma);

  pidp = svmdb_local_get_variable_reference (svmdb_client,
					     SVMDB_NAMESPACE_VEC, "vpp_pid");
  if (pidp == 0)
    {
      clib_error ("post_restart: 'vpp_pid' svm variable not found,"
		  "vpp did not restart?");
      return 2;
    }

  sleeps = 0;

  /*
   * Step 7: wait for vpp to publish its new PID
   */

  /* Spin for up to 15 seconds */
  for (wait = 0; wait < 150; wait++)
    {
      if (*pidp && (*pidp != old_pid))
	goto restarted;
      req->tv_sec = 0;
      req->tv_nsec = 100000 * 1000;	/* 100 ms */
      while (nanosleep (req, rem) < 0)
	*req = *rem;
      sleeps++;
    }

  clib_error ("Timeout waiting for vpp to publish pid after restart...");
  return 4;

restarted:

  /* Done... */

  if (verbose && sleeps)
    fformat (stdout, "pid sleeps %d\n", sleeps);

  if (verbose)
    fformat (stdout, "New PID %d... Restarted...\n", *pidp);

  svmdb_unmap (svmdb_client);
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
