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
/*
 * main.c: Unix main routine
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/unix/plugin.h>

#include <signal.h>
#include <sys/ucontext.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

/** Default CLI pager limit is not configured in startup.conf */
#define UNIX_CLI_DEFAULT_PAGER_LIMIT 100000

/** Default CLI history depth if not configured in startup.conf */
#define UNIX_CLI_DEFAULT_HISTORY 50

char *vlib_default_runtime_dir __attribute__ ((weak));
char *vlib_default_runtime_dir = "vlib";

unix_main_t unix_main;
clib_file_main_t file_main;

static clib_error_t *
unix_main_init (vlib_main_t * vm)
{
  unix_main_t *um = &unix_main;
  um->vlib_main = vm;
  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (unix_main_init) =
{
  .runs_before = VLIB_INITS ("unix_input_init"),
};
/* *INDENT-ON* */

static int
unsetup_signal_handlers (int sig)
{
  struct sigaction sa;

  sa.sa_handler = SIG_DFL;
  sa.sa_flags = 0;
  sigemptyset (&sa.sa_mask);
  return sigaction (sig, &sa, 0);
}


/* allocate this buffer from mheap when setting up the signal handler.
    dangerous to vec_resize it when crashing, mheap itself might have been
    corrupted already */
static u8 *syslog_msg = 0;
int vlib_last_signum = 0;
uword vlib_last_faulting_address = 0;

static void
unix_signal_handler (int signum, siginfo_t * si, ucontext_t * uc)
{
  uword fatal = 0;

  /* These come in handy when looking at core files from optimized images */
  vlib_last_signum = signum;
  vlib_last_faulting_address = (uword) si->si_addr;

  syslog_msg = format (syslog_msg, "received signal %U, PC %U",
		       format_signal, signum, format_ucontext_pc, uc);

  if (signum == SIGSEGV)
    syslog_msg = format (syslog_msg, ", faulting address %p", si->si_addr);

  switch (signum)
    {
      /* these (caught) signals cause the application to exit */
    case SIGTERM:
      /*
       * Ignore SIGTERM if it's sent before we're ready.
       */
      if (unix_main.vlib_main && unix_main.vlib_main->main_loop_exit_set)
	{
	  syslog (LOG_ERR | LOG_DAEMON, "received SIGTERM, exiting...");
	  unix_main.vlib_main->main_loop_exit_now = 1;
	}
      else
	syslog (LOG_ERR | LOG_DAEMON, "IGNORE early SIGTERM...");
      break;
      /* fall through */
    case SIGQUIT:
    case SIGINT:
    case SIGILL:
    case SIGBUS:
    case SIGSEGV:
    case SIGHUP:
    case SIGFPE:
    case SIGABRT:
      fatal = 1;
      break;

      /* by default, print a message and continue */
    default:
      fatal = 0;
      break;
    }

#ifdef CLIB_GCOV
  /*
   * Test framework sends SIGTERM, so we need to flush the
   * code coverage stats here.
   */
  {
    void __gcov_flush (void);
    __gcov_flush ();
  }
#endif

  /* Null terminate. */
  vec_add1 (syslog_msg, 0);

  if (fatal)
    {
      syslog (LOG_ERR | LOG_DAEMON, "%s", syslog_msg);

      /* Address of callers: outer first, inner last. */
      uword callers[15];
      uword n_callers = clib_backtrace (callers, ARRAY_LEN (callers), 0);
      int i;
      for (i = 0; i < n_callers; i++)
	{
	  vec_reset_length (syslog_msg);

	  syslog_msg =
	    format (syslog_msg, "#%-2d 0x%016lx %U%c", i, callers[i],
		    format_clib_elf_symbol_with_address, callers[i], 0);

	  syslog (LOG_ERR | LOG_DAEMON, "%s", syslog_msg);
	}

      /* have to remove SIGABRT to avoid recursive - os_exit calling abort() */
      unsetup_signal_handlers (SIGABRT);

      /* os_exit(1) causes core generation, skip that for SIGINT, SIGHUP */
      if (signum == SIGINT || signum == SIGHUP)
	os_exit (0);
      else
	os_exit (1);
    }
  else
    clib_warning ("%s", syslog_msg);

}

static clib_error_t *
setup_signal_handlers (unix_main_t * um)
{
  uword i;
  struct sigaction sa;

  /* give a big enough buffer for msg, most likely it can avoid vec_resize  */
  vec_alloc (syslog_msg, 2048);

  for (i = 1; i < 32; i++)
    {
      clib_memset (&sa, 0, sizeof (sa));
      sa.sa_sigaction = (void *) unix_signal_handler;
      sa.sa_flags = SA_SIGINFO;

      switch (i)
	{
	  /* these signals take the default action */
	case SIGKILL:
	case SIGSTOP:
	case SIGUSR1:
	case SIGUSR2:
	case SIGPROF:
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
	return clib_error_return_unix (0, "sigaction %U", format_signal, i);
    }

  return 0;
}

static void
unix_error_handler (void *arg, u8 * msg, int msg_len)
{
  unix_main_t *um = arg;

  /* Echo to stderr when interactive or syslog is disabled. */
  if (um->flags & (UNIX_FLAG_INTERACTIVE | UNIX_FLAG_NOSYSLOG))
    {
      CLIB_UNUSED (int r) = write (2, msg, msg_len);
    }
  else
    {
      char save = msg[msg_len - 1];

      /* Null Terminate. */
      msg[msg_len - 1] = 0;

      syslog (LOG_ERR | LOG_DAEMON, "%s", msg);

      msg[msg_len - 1] = save;
    }
}

void
vlib_unix_error_report (vlib_main_t * vm, clib_error_t * error)
{
  unix_main_t *um = &unix_main;

  if (um->flags & UNIX_FLAG_INTERACTIVE || error == 0)
    return;

  {
    char save;
    u8 *msg;
    u32 msg_len;

    msg = error->what;
    msg_len = vec_len (msg);

    /* Null Terminate. */
    save = msg[msg_len - 1];
    msg[msg_len - 1] = 0;

    syslog (LOG_ERR | LOG_DAEMON, "%s", msg);

    msg[msg_len - 1] = save;
  }
}

static uword
startup_config_process (vlib_main_t * vm,
			vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  unix_main_t *um = &unix_main;
  u8 *buf = 0;
  uword l, n = 1;

  vlib_process_suspend (vm, 2.0);

  while (um->unix_config_complete == 0)
    vlib_process_suspend (vm, 0.1);

  if (um->startup_config_filename)
    {
      unformat_input_t sub_input;
      int fd;
      struct stat s;
      char *fn = (char *) um->startup_config_filename;

      fd = open (fn, O_RDONLY);
      if (fd < 0)
	{
	  clib_warning ("failed to open `%s'", fn);
	  return 0;
	}

      if (fstat (fd, &s) < 0)
	{
	  clib_warning ("failed to stat `%s'", fn);
	bail:
	  close (fd);
	  return 0;
	}

      if (!(S_ISREG (s.st_mode) || S_ISLNK (s.st_mode)))
	{
	  clib_warning ("not a regular file: `%s'", fn);
	  goto bail;
	}

      while (n > 0)
	{
	  l = vec_len (buf);
	  vec_resize (buf, 4096);
	  n = read (fd, buf + l, 4096);
	  if (n > 0)
	    {
	      _vec_len (buf) = l + n;
	      if (n < 4096)
		break;
	    }
	  else
	    break;
	}
      if (um->log_fd && vec_len (buf))
	{
	  u8 *lv = 0;
	  lv = format (lv, "%U: ***** Startup Config *****\n%v",
		       format_timeval, 0 /* current bat-time */ ,
		       0 /* current bat-format */ ,
		       buf);
	  {
	    int rv __attribute__ ((unused)) =
	      write (um->log_fd, lv, vec_len (lv));
	  }
	  vec_reset_length (lv);
	  lv = format (lv, "%U: ***** End Startup Config *****\n",
		       format_timeval, 0 /* current bat-time */ ,
		       0 /* current bat-format */ );
	  {
	    int rv __attribute__ ((unused)) =
	      write (um->log_fd, lv, vec_len (lv));
	  }
	  vec_free (lv);
	}

      if (vec_len (buf))
	{
	  unformat_init_vector (&sub_input, buf);
	  vlib_cli_input (vm, &sub_input, 0, 0);
	  /* frees buf for us */
	  unformat_free (&sub_input);
	}
      close (fd);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (startup_config_node,static) = {
    .function = startup_config_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "startup-config-process",
    .process_log2_n_stack_bytes = 18,
};
/* *INDENT-ON* */

static clib_error_t *
unix_config (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  unix_main_t *um = &unix_main;
  clib_error_t *error = 0;
  gid_t gid;
  int pidfd = -1;

  /* Defaults */
  um->cli_pager_buffer_limit = UNIX_CLI_DEFAULT_PAGER_LIMIT;
  um->cli_history_limit = UNIX_CLI_DEFAULT_HISTORY;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      char *cli_prompt;
      if (unformat (input, "interactive"))
	um->flags |= UNIX_FLAG_INTERACTIVE;
      else if (unformat (input, "nodaemon"))
	um->flags |= UNIX_FLAG_NODAEMON;
      else if (unformat (input, "nosyslog"))
	um->flags |= UNIX_FLAG_NOSYSLOG;
      else if (unformat (input, "nocolor"))
	um->flags |= UNIX_FLAG_NOCOLOR;
      else if (unformat (input, "nobanner"))
	um->flags |= UNIX_FLAG_NOBANNER;
      else if (unformat (input, "cli-prompt %s", &cli_prompt))
	vlib_unix_cli_set_prompt (cli_prompt);
      else
	if (unformat (input, "cli-listen %s", &um->cli_listen_socket.config))
	;
      else if (unformat (input, "runtime-dir %s", &um->runtime_dir))
	;
      else if (unformat (input, "cli-line-mode"))
	um->cli_line_mode = 1;
      else if (unformat (input, "cli-no-banner"))
	um->cli_no_banner = 1;
      else if (unformat (input, "cli-no-pager"))
	um->cli_no_pager = 1;
      else if (unformat (input, "poll-sleep-usec %d", &um->poll_sleep_usec))
	;
      else if (unformat (input, "cli-pager-buffer-limit %d",
			 &um->cli_pager_buffer_limit))
	;
      else
	if (unformat (input, "cli-history-limit %d", &um->cli_history_limit))
	;
      else if (unformat (input, "coredump-size"))
	{
	  uword coredump_size = 0;
	  if (unformat (input, "unlimited"))
	    {
	      coredump_size = RLIM_INFINITY;
	    }
	  else
	    if (!unformat (input, "%U", unformat_memory_size, &coredump_size))
	    {
	      return clib_error_return (0,
					"invalid coredump-size parameter `%U'",
					format_unformat_error, input);
	    }
	  const struct rlimit new_limit = { coredump_size, coredump_size };
	  if (0 != setrlimit (RLIMIT_CORE, &new_limit))
	    {
	      clib_unix_warning ("prlimit() failed");
	    }
	}
      else if (unformat (input, "full-coredump"))
	{
	  int fd;

	  fd = open ("/proc/self/coredump_filter", O_WRONLY);
	  if (fd >= 0)
	    {
	      if (write (fd, "0x6f\n", 5) != 5)
		clib_unix_warning ("coredump filter write failed!");
	      close (fd);
	    }
	  else
	    clib_unix_warning ("couldn't open /proc/self/coredump_filter");
	}
      else if (unformat (input, "startup-config %s",
			 &um->startup_config_filename))
	;
      else if (unformat (input, "exec %s", &um->startup_config_filename))
	;
      else if (unformat (input, "log %s", &um->log_filename))
	{
	  um->log_fd = open ((char *) um->log_filename,
			     O_CREAT | O_WRONLY | O_APPEND, 0644);
	  if (um->log_fd < 0)
	    {
	      clib_warning ("couldn't open log '%s'\n", um->log_filename);
	      um->log_fd = 0;
	    }
	  else
	    {
	      u8 *lv = 0;
	      lv = format (0, "%U: ***** Start: PID %d *****\n",
			   format_timeval, 0 /* current bat-time */ ,
			   0 /* current bat-format */ ,
			   getpid ());
	      {
		int rv __attribute__ ((unused)) =
		  write (um->log_fd, lv, vec_len (lv));
	      }
	      vec_free (lv);
	    }
	}
      else if (unformat (input, "gid %U", unformat_unix_gid, &gid))
	{
	  if (setegid (gid) == -1)
	    return clib_error_return_unix (0, "setegid");
	}
      else if (unformat (input, "pidfile %s", &um->pidfile))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (um->runtime_dir == 0)
    {
      uid_t uid = geteuid ();
      if (uid == 00)
	um->runtime_dir = format (0, "/run/%s%c",
				  vlib_default_runtime_dir, 0);
      else
	um->runtime_dir = format (0, "/run/user/%u/%s%c", uid,
				  vlib_default_runtime_dir, 0);
    }

  /* Ensure the runtime directory is created */
  error = vlib_unix_recursive_mkdir ((char *) um->runtime_dir);
  if (error)
    return error;

  error = setup_signal_handlers (um);
  if (error)
    return error;

  if (um->pidfile)
    {
      if ((error = vlib_unix_validate_runtime_file (um,
						    (char *) um->pidfile,
						    &um->pidfile)))
	return error;

      if (((pidfd = open ((char *) um->pidfile,
			  O_CREAT | O_WRONLY | O_TRUNC, 0644)) < 0))
	{
	  return clib_error_return_unix (0, "open");
	}
    }

  if (!(um->flags & (UNIX_FLAG_INTERACTIVE | UNIX_FLAG_NOSYSLOG)))
    {
      openlog (vgm->name, LOG_CONS | LOG_PERROR | LOG_PID, LOG_DAEMON);
      clib_error_register_handler (unix_error_handler, um);

      if (!(um->flags & UNIX_FLAG_NODAEMON) && daemon ( /* chdir to / */ 0,
						       /* stdin/stdout/stderr -> /dev/null */
						       0) < 0)
	clib_error_return (0, "daemon () fails");
    }

  if (pidfd >= 0)
    {
      u8 *lv = format (0, "%d", getpid ());
      if (write (pidfd, (char *) lv, vec_len (lv)) != vec_len (lv))
	{
	  vec_free (lv);
	  close (pidfd);
	  return clib_error_return_unix (0, "write");
	}
      vec_free (lv);
      close (pidfd);
    }

  um->unix_config_complete = 1;

  return 0;
}

/* unix { ... } configuration. */
/*?
 *
 * @cfgcmd{interactive}
 * Attach CLI to stdin/out and provide a debugging command line interface.
 * Implies @c nodaemon.
 *
 * @cfgcmd{nodaemon}
 * Do not fork or background the VPP process. Typically used when invoking
 * VPP applications from a process monitor.
 *
 * @cfgcmd{nosyslog}
 * Do not send e.g. clib_warning(...) output to syslog. Used
 * when invoking VPP applications from a process monitor which
 * pipe stdout/stderr to a dedicated logger service.
 *
 * @cfgcmd{nocolor}
 * Do not use colors in outputs.
 * *
 * @cfgcmd{nobanner}
 * Do not display startup banner.
 *
 * @cfgcmd{exec, &lt;filename&gt;}
 * @par <code>startup-config &lt;filename&gt;</code>
 * Read startup operational configuration from @c filename.
 * The contents of the file will be performed as though entered at the CLI.
 * The two keywords are aliases for the same function; if both are specified,
 * only the last will have an effect.
 *
 * @cfgcmd{log, &lt;filename&gt;}
 * Logs the startup configuration and all subsequent CLI commands in
 * @c filename.
 * Very useful in situations where folks don't remember or can't be bothered
 * to include CLI commands in bug reports.
 *
 * @cfgcmd{pidfile, &lt;filename&gt;}
 * Writes the pid of the main thread in @c filename.
 *
 * @cfgcmd{full-coredump}
 * Ask the Linux kernel to dump all memory-mapped address regions, instead
 * of just text+data+bss.
 *
 * @cfgcmd{runtime-dir}
 * Define directory where VPP is going to store all runtime files.
 * Default is /run/vpp when running as root, /run/user/<UID>/vpp if running as
 * an unprivileged user.
 *
 * @cfgcmd{cli-listen, &lt;address:port&gt;}
 * Bind the CLI to listen at the address and port given. @c localhost
 * on TCP port @c 5002, given as <tt>cli-listen localhost:5002</tt>,
 * is typical.
 *
 * @cfgcmd{cli-line-mode}
 * Disable character-by-character I/O on stdin. Useful when combined with,
 * for example, <tt>emacs M-x gud-gdb</tt>.
 *
 * @cfgcmd{cli-prompt, &lt;string&gt;}
 * Configure the CLI prompt to be @c string.
 *
 * @cfgcmd{cli-history-limit, &lt;nn&gt;}
 * Limit command history to @c nn  lines. A value of @c 0
 * disables command history. Default value: @c 50
 *
 * @cfgcmd{cli-no-banner}
 * Disable the login banner on stdin and Telnet connections.
 *
 * @cfgcmd{cli-no-pager}
 * Disable the output pager.
 *
 * @cfgcmd{cli-pager-buffer-limit, &lt;nn&gt;}
 * Limit pager buffer to @c nn lines of output.
 * A value of @c 0 disables the pager. Default value: @c 100000
 *
 * @cfgcmd{gid, &lt;nn&gt;}
 * Set the effective gid under which the vpp process is to run.
 *
 * @cfgcmd{poll-sleep-usec, &lt;nn&gt;}
 * Set a fixed poll sleep interval between main loop polls.
?*/
VLIB_EARLY_CONFIG_FUNCTION (unix_config, "unix");

static clib_error_t *
unix_exit (vlib_main_t * vm)
{
  /* Close syslog connection. */
  closelog ();
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (unix_exit);

u8 **vlib_thread_stacks;

static uword
thread0 (uword arg)
{
  vlib_main_t *vm = (vlib_main_t *) arg;
  unformat_input_t input;
  int i;

  vlib_process_finish_switch_stack (vm);

  unformat_init_command_line (&input, (char **) vm->argv);
  i = vlib_main (vm, &input);
  unformat_free (&input);

  return i;
}

u8 *
vlib_thread_stack_init (uword thread_index)
{
  void *stack;
  ASSERT (thread_index < vec_len (vlib_thread_stacks));
  stack = clib_mem_vm_map_stack (VLIB_THREAD_STACK_SIZE,
				 CLIB_MEM_PAGE_SZ_DEFAULT,
				 "thread stack: thread %u", thread_index);

  if (stack == CLIB_MEM_VM_MAP_FAILED)
    clib_panic ("failed to allocate thread %u stack", thread_index);

  vlib_thread_stacks[thread_index] = stack;
  return stack;
}

int
vlib_unix_main (int argc, char *argv[])
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_main_t *vm = vlib_mains[0]; /* one and only time for this! */
  unformat_input_t input;
  clib_error_t *e;
  int i;

  vec_validate_aligned (vlib_mains, 0, CLIB_CACHE_LINE_BYTES);

  vm->argv = (u8 **) argv;
  vgm->name = argv[0];
  vm->heap_base = clib_mem_get_heap ();
  vm->heap_aligned_base = (void *)
    (((uword) vm->heap_base) & ~(VLIB_FRAME_ALIGN - 1));
  ASSERT (vm->heap_base);

  clib_time_init (&vm->clib_time);

  /* Turn on the event logger at the first possible moment */
  vgm->configured_elog_ring_size = 128 << 10;
  elog_init (&vgm->elog_main, vgm->configured_elog_ring_size);
  elog_enable_disable (&vgm->elog_main, 1);

  unformat_init_command_line (&input, (char **) vm->argv);
  if ((e = vlib_plugin_config (vm, &input)))
    {
      clib_error_report (e);
      return 1;
    }
  unformat_free (&input);

  i = vlib_plugin_early_init (vm);
  if (i)
    return i;

  unformat_init_command_line (&input, (char **) vm->argv);
  if (vgm->init_functions_called == 0)
    vgm->init_functions_called = hash_create (0, /* value bytes */ 0);
  e = vlib_call_all_config_functions (vm, &input, 1 /* early */ );
  if (e != 0)
    {
      clib_error_report (e);
      return 1;
    }
  unformat_free (&input);

  /* always load symbols, for signal handler and mheap memory get/put backtrace */
  clib_elf_main_init (vgm->name);

  vec_validate (vlib_thread_stacks, 0);
  vlib_thread_stack_init (0);

  __os_thread_index = 0;
  vm->thread_index = 0;

  vlib_process_start_switch_stack (vm, 0);
  i = clib_calljmp (thread0, (uword) vm,
		    (void *) (vlib_thread_stacks[0] +
			      VLIB_THREAD_STACK_SIZE));
  return i;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
