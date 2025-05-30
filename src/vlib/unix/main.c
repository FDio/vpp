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
#include <vppinfra/unix.h>
#include <vppinfra/stack.h>
#include <vppinfra/format_ansi.h>

#include <limits.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

#ifdef HAVE_LIBIBERTY
#include <libiberty/demangle.h>
#endif

/** Default CLI pager limit is not configured in startup.conf */
#define UNIX_CLI_DEFAULT_PAGER_LIMIT 100000

/** Default CLI history depth if not configured in startup.conf */
#define UNIX_CLI_DEFAULT_HISTORY 50

char *vlib_default_runtime_dir __attribute__ ((weak));
char *vlib_default_runtime_dir = "vlib";

unix_main_t unix_main;

static clib_error_t *
unix_main_init (vlib_main_t * vm)
{
  unix_main_t *um = &unix_main;
  um->vlib_main = vm;
  return 0;
}

VLIB_INIT_FUNCTION (unix_main_init);

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
log_one_line ()
{
  vec_terminate_c_string (syslog_msg);
  if (unix_main.flags & (UNIX_FLAG_INTERACTIVE | UNIX_FLAG_NOSYSLOG))
    fprintf (stderr, "%s\n", syslog_msg);
  else
    syslog (LOG_ERR | LOG_DAEMON, "%s", syslog_msg);
  vec_reset_length (syslog_msg);
}

static void
unix_signal_handler (int signum, siginfo_t * si, ucontext_t * uc)
{
  uword fatal = 0;
  int color =
    (unix_main.flags & (UNIX_FLAG_INTERACTIVE | UNIX_FLAG_NOSYSLOG)) &&
    (unix_main.flags & UNIX_FLAG_NOCOLOR) == 0;

  /* These come in handy when looking at core files from optimized images */
  vlib_last_signum = signum;
  vlib_last_faulting_address = (uword) si->si_addr;

  if (color)
    syslog_msg = format (syslog_msg, ANSI_FG_BR_RED);

  syslog_msg = format (syslog_msg, "received signal %U, PC %U",
		       format_signal, signum, format_ucontext_pc, uc);

  if (signum == SIGSEGV || signum == SIGBUS)
    syslog_msg = format (syslog_msg, ", faulting address %p", si->si_addr);

  if (color)
    syslog_msg = format (syslog_msg, ANSI_FG_DEFAULT);

  log_one_line ();

  switch (signum)
    {
      /* these (caught) signals cause the application to exit */
    case SIGTERM:
      /*
       * Ignore SIGTERM if it's sent before we're ready.
       */
      if (unix_main.vlib_main && unix_main.vlib_main->main_loop_exit_set)
	{
	  syslog_msg = format (
	    syslog_msg, "received SIGTERM from PID %d UID %d, exiting...",
	    si->si_pid, si->si_uid);
	  log_one_line ();
	  unix_main.vlib_main->main_loop_exit_now = 1;
	}
      else
	{
	  syslog_msg = format (syslog_msg, "IGNORE early SIGTERM...");
	  log_one_line ();
	}
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


  if (fatal)
    {
      int skip = 1, index = 0;

      foreach_clib_stack_frame (sf)
	{
	  if (sf->is_signal_frame)
	    {
	      int pipefd[2];
	      const int n_bytes = 20;
	      u8 *ip = (void *) sf->ip;

	      if (pipe (pipefd) == 0)
		{
		  /* check PC points to valid memory */
		  if (write (pipefd[1], ip, n_bytes) == n_bytes)
		    {
		      syslog_msg = format (syslog_msg, "Code: ");
		      if (color)
			syslog_msg = format (syslog_msg, ANSI_FG_CYAN);
		      for (int i = 0; i < n_bytes; i++)
			syslog_msg = format (syslog_msg, " %02x", ip[i]);
		      if (color)
			syslog_msg = format (syslog_msg, ANSI_FG_DEFAULT);
		    }
		  else
		    {
		      syslog_msg = format (
			syslog_msg, "PC contains invalid memory address");
		    }
		  log_one_line ();
		  foreach_int (i, 0, 1)
		    close (pipefd[i]);
		}
	      skip = 0;
	    }

	  if (skip)
	    continue;

	  syslog_msg = format (syslog_msg, "#%-2d ", index++);
	  if (color)
	    syslog_msg = format (syslog_msg, ANSI_FG_BLUE);
	  syslog_msg = format (syslog_msg, "0x%016lx", sf->ip);
	  if (color)
	    syslog_msg = format (syslog_msg, ANSI_FG_DEFAULT);

	  if (sf->name[0])
	    {
	      if (color)
		syslog_msg = format (syslog_msg, ANSI_FG_YELLOW);
#if HAVE_LIBIBERTY
	      if (strncmp (sf->name, "_Z", 2) == 0)
		{
		  char *demangled = cplus_demangle (sf->name, DMGL_AUTO);
		  syslog_msg = format (syslog_msg, " %s",
				       demangled ? demangled : sf->name);
		  if (demangled)
		    free (demangled);
		}
	      else
#endif
		syslog_msg = format (syslog_msg, " %s", sf->name);

	      syslog_msg = format (syslog_msg, " + 0x%x", sf->offset);
	      if (color)
		syslog_msg = format (syslog_msg, ANSI_FG_DEFAULT);
	    }

	  log_one_line ();

	  if (sf->file_name)
	    {
	      if (color)
		syslog_msg = format (syslog_msg, ANSI_FG_GREEN);
	      syslog_msg = format (syslog_msg, "     from %s", sf->file_name);
	      if (color)
		syslog_msg = format (syslog_msg, ANSI_FG_DEFAULT);
	      log_one_line ();
	    }
	}

      /* have to remove SIGABRT to avoid recursive - os_exit calling abort() */
      unsetup_signal_handlers (SIGABRT);

      /* os_exit(1) causes core generation, skip that for SIGINT, SIGHUP */
      if (signum == SIGINT || signum == SIGHUP)
	os_exit (0);
      else
	os_exit (1);
    }
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
	case SIGCONT:
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
      syslog (LOG_ERR | LOG_DAEMON, "%.*s", msg_len, msg);
    }
}

void
vlib_unix_error_report (vlib_main_t * vm, clib_error_t * error)
{
  unix_main_t *um = &unix_main;

  if (um->flags & UNIX_FLAG_INTERACTIVE || error == 0)
    return;

  {
    u8 *msg = error->what;
    u32 len = vec_len (msg);
    int msg_len = (len > INT_MAX) ? INT_MAX : len;
    syslog (LOG_ERR | LOG_DAEMON, "%.*s", msg_len, msg);
  }
}

static uword
startup_config_process (vlib_main_t * vm,
			vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  unix_main_t *um = &unix_main;
  unformat_input_t in;

  vlib_process_suspend (vm, 2.0);

  while (um->unix_config_complete == 0)
    vlib_process_suspend (vm, 0.1);

  if (!um->startup_config_filename)
    {
      return 0;
    }

  unformat_init_vector (&in,
			format (0, "exec %s", um->startup_config_filename));

  vlib_cli_input (vm, &in, 0, 0);

  unformat_free (&in);

  return 0;
}

VLIB_REGISTER_NODE (startup_config_node,static) = {
    .function = startup_config_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "startup-config-process",
    .process_log2_n_stack_bytes = 18,
};

static clib_error_t *
unix_config (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  unix_main_t *um = &unix_main;
  clib_error_t *error = 0;
  gid_t gid;
  int pidfd = -1;
  int use_current_dir = 0;

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
      else if (unformat (input, "use-current-dir"))
	use_current_dir = 1;
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
			   format_timeval, NULL /* current bat-format */,
			   0 /* current bat-time */, getpid ());
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

  if (use_current_dir)
    {
      char cwd[PATH_MAX];
      if (getcwd (cwd, PATH_MAX))
	um->runtime_dir = format (um->runtime_dir, "%s%c", cwd, 0);
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

  if (chdir ((char *) um->runtime_dir) < 0)
    return clib_error_return_unix (0, "chdir('%s')", um->runtime_dir);

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
  vlib_global_main_t *vgm = vlib_get_global_main ();
  unformat_input_t input;
  int i;

  vlib_process_finish_switch_stack (vm);

  unformat_init_command_line (&input, (char **) vgm->argv);
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

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int
vlib_unix_main (int argc, char *argv[])
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_main_t *vm = vlib_get_first_main (); /* one and only time for this! */
  unformat_input_t input;
  clib_error_t *e;
  int i;

  vec_validate_aligned (vgm->vlib_mains, 0, CLIB_CACHE_LINE_BYTES);

  vgm->exec_path = (char *) os_get_exec_path ();

  if (vgm->exec_path)
    {
      for (i = vec_len (vgm->exec_path) - 1; i > 0; i--)
	if (vgm->exec_path[i - 1] == '/')
	  break;

      vgm->name = 0;

      vec_add (vgm->name, vgm->exec_path + i, vec_len (vgm->exec_path) - i);
      vec_add1 (vgm->exec_path, 0);
      vec_add1 (vgm->name, 0);
    }
  else
    vgm->exec_path = vgm->name = argv[0];

  vgm->argv = (u8 **) argv;

  clib_time_init (&vm->clib_time);

  /* Turn on the event logger at the first possible moment */
  vgm->configured_elog_ring_size = 128 << 10;
  elog_init (vlib_get_elog_main (), vgm->configured_elog_ring_size);
  elog_enable_disable (vlib_get_elog_main (), 1);

  unformat_init_command_line (&input, (char **) vgm->argv);
  if ((e = vlib_plugin_config (vm, &input)))
    {
      clib_error_report (e);
      return 1;
    }
  unformat_free (&input);

  i = vlib_plugin_early_init (vm);
  if (i)
    return i;

  unformat_init_command_line (&input, (char **) vgm->argv);
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
  clib_elf_main_init (vgm->exec_path);

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
