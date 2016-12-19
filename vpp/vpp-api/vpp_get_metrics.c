/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/api_errno.h>

#include <svm/svmdb.h>

svmdb_client_t *c;
volatile int signal_received;

static void
unix_signal_handler (int signum, siginfo_t * si, ucontext_t * uc)
{
  static int once;

  if (once)
    exit (1);

  once = 1;
  signal_received = 1;
}

static void
setup_signal_handlers (void)
{
  uword i;
  struct sigaction sa;

  for (i = 1; i < 32; i++)
    {
      memset (&sa, 0, sizeof (sa));
      sa.sa_sigaction = (void *) unix_signal_handler;
      sa.sa_flags = SA_SIGINFO;

      switch (i)
	{
	  /* these signals take the default action */
	case SIGABRT:
	case SIGKILL:
	case SIGSTOP:
	case SIGUSR1:
	case SIGUSR2:
	  continue;

	  /* ignore SIGPIPE, SIGCHLD */
	case SIGPIPE:
	case SIGCHLD:
	  sa.sa_sigaction = (void *) SIG_IGN;
	  break;

	  /* catch and handle all other signals */
	default:
	  break;
	}

      if (sigaction (i, &sa, 0) < 0)
	return clib_unix_warning (0, "sigaction %U", format_signal, i);
    }
}

int
main (int argc, char **argv)
{
  unformat_input_t input;
  char *chroot_path = 0;
  u8 *chroot_path_u8;
  int interval = 0;
  f64 *vector_ratep, *rx_ratep, *sig_error_ratep;
  pid_t *vpp_pidp;
  svmdb_map_args_t _ma, *ma = &_ma;
  int uid, gid, rv;
  struct passwd _pw, *pw;
  struct group _grp, *grp;
  char *s, buf[128];

  unformat_init_command_line (&input, argv);

  uid = geteuid ();
  gid = getegid ();

  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&input, "chroot %s", &chroot_path_u8))
	{
	  chroot_path = (char *) chroot_path_u8;
	}
      else if (unformat (&input, "interval %d", &interval))
	;
      else if (unformat (&input, "uid %d", &uid))
	;
      else if (unformat (&input, "gid %d", &gid))
	;
      else if (unformat (&input, "uid %s", &s))
	{
	  /* lookup the username */
	  pw = NULL;
	  rv = getpwnam_r (s, &_pw, buf, sizeof (buf), &pw);
	  if (rv < 0)
	    {
	      fformat (stderr, "cannot fetch username %s", s);
	      exit (1);
	    }
	  if (pw == NULL)
	    {
	      fformat (stderr, "username %s does not exist", s);
	      exit (1);
	    }
	  vec_free (s);
	  uid = pw->pw_uid;
	}
      else if (unformat (&input, "gid %s", &s))
	{
	  /* lookup the group name */
	  grp = NULL;
	  rv = getgrnam_r (s, &_grp, buf, sizeof (buf), &grp);
	  if (rv != 0)
	    {
	      fformat (stderr, "cannot fetch group %s", s);
	      exit (1);
	    }
	  if (grp == NULL)
	    {
	      fformat (stderr, "group %s does not exist", s);
	      exit (1);
	    }
	  vec_free (s);
	  gid = grp->gr_gid;
	}
      else
	{
	  fformat (stderr,
		   "usage: vpp_get_metrics [chroot <path>] [interval <nn>]\n");
	  exit (1);
	}
    }

  setup_signal_handlers ();

  memset (ma, 0, sizeof (*ma));
  ma->root_path = chroot_path;
  ma->uid = uid;
  ma->gid = gid;

  c = svmdb_map (ma);

  vpp_pidp =
    svmdb_local_get_variable_reference (c, SVMDB_NAMESPACE_VEC, "vpp_pid");
  vector_ratep =
    svmdb_local_get_variable_reference (c, SVMDB_NAMESPACE_VEC,
					"vpp_vector_rate");
  rx_ratep =
    svmdb_local_get_variable_reference (c, SVMDB_NAMESPACE_VEC,
					"vpp_input_rate");
  sig_error_ratep =
    svmdb_local_get_variable_reference (c, SVMDB_NAMESPACE_VEC,
					"vpp_sig_error_rate");

  /*
   * Make sure vpp is actually running. Otherwise, there's every
   * chance that the database region will be wiped out by the
   * process monitor script
   */

  if (vpp_pidp == 0 || vector_ratep == 0 || rx_ratep == 0
      || sig_error_ratep == 0)
    {
      fformat (stdout, "vpp not running\n");
      exit (1);
    }

  do
    {
      /*
       * Once vpp exits, the svm db region will be recreated...
       * Can't use kill (*vpp_pidp, 0) if running as non-root /
       * accessing the shared-VM database via group perms.
       */
      if (*vpp_pidp == 0)
	{
	  fformat (stdout, "vpp not running\n");
	  exit (1);
	}
      fformat (stdout,
	       "%d: vpp_vector_rate=%.2f, vpp_input_rate=%f, vpp_sig_error_rate=%f\n",
	       *vpp_pidp, *vector_ratep, *rx_ratep, *sig_error_ratep);

      if (interval)
	sleep (interval);
      if (signal_received)
	break;
    }
  while (interval);

  svmdb_unmap (c);
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
