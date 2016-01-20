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

unix_main_t unix_main;

static clib_error_t *
unix_main_init (vlib_main_t * vm)
{
  unix_main_t * um = &unix_main;
  um->vlib_main = vm;
  return vlib_call_init_function (vm, unix_input_init);
}

VLIB_INIT_FUNCTION (unix_main_init);

static void unix_signal_handler (int signum, siginfo_t * si, ucontext_t * uc)
{
  uword fatal;
  u8 * msg = 0;

  msg = format (msg, "received signal %U, PC %U",
		format_signal, signum,
		format_ucontext_pc, uc);

  if (signum == SIGSEGV)
    msg = format (msg, ", faulting address %p", si->si_addr);

  switch (signum)
    {
      /* these (caught) signals cause the application to exit */
    case SIGTERM:
      if (unix_main.vlib_main->main_loop_exit_set) 
        {
          syslog (LOG_ERR | LOG_DAEMON, "received SIGTERM, exiting...");

          clib_longjmp (&unix_main.vlib_main->main_loop_exit, 
                        VLIB_MAIN_LOOP_EXIT_CLI);
        }
    case SIGQUIT:
    case SIGINT:
    case SIGILL:
    case SIGBUS:
    case SIGSEGV:
    case SIGHUP:
    case SIGFPE:
      fatal = 1;
      break;

      /* by default, print a message and continue */
    default:
      fatal = 0;
      break;
    }

  /* Null terminate. */
  vec_add1 (msg, 0);

  if (fatal)
    {
      syslog (LOG_ERR | LOG_DAEMON, "%s", msg);
      os_exit (1);
    }
  else
    clib_warning ("%s", msg);

  vec_free (msg);
}

static clib_error_t *
setup_signal_handlers (unix_main_t * um)
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
	return clib_error_return_unix (0, "sigaction %U", format_signal, i);
    }

  return 0;
}

static void unix_error_handler (void * arg, u8 * msg, int msg_len)
{
  unix_main_t * um = arg;

  /* Echo to stderr when interactive. */
  if (um->flags & UNIX_FLAG_INTERACTIVE)
    {
      CLIB_UNUSED (int r) = write (2, msg, msg_len);
    }
  else
    {
      char save = msg[msg_len - 1];

      /* Null Terminate. */
      msg[msg_len-1] = 0;

      syslog (LOG_ERR | LOG_DAEMON, "%s", msg);

      msg[msg_len-1] = save;
    }
}

void vlib_unix_error_report (vlib_main_t * vm, clib_error_t * error)
{
    unix_main_t * um = &unix_main;

    if (um->flags & UNIX_FLAG_INTERACTIVE || error == 0)
      return;

    {
      char save;
      u8 * msg;
      u32 msg_len;

      msg = error->what;
      msg_len = vec_len(msg);

      /* Null Terminate. */
      save = msg[msg_len-1];
      msg[msg_len-1] = 0;

      syslog (LOG_ERR | LOG_DAEMON, "%s", msg);

      msg[msg_len-1] = save;
    }
}

static uword
startup_config_process (vlib_main_t * vm,
                 vlib_node_runtime_t * rt,
                 vlib_frame_t * f)
{
  unix_main_t * um = &unix_main;
  u8 * buf = 0;
  uword l, n = 1;

  vlib_process_suspend (vm, 2.0);

  while (um->unix_config_complete == 0)
    vlib_process_suspend (vm, 0.1);

  if (um->startup_config_filename) {
    unformat_input_t sub_input;
    int fd;
    struct stat s;
    char *fn = (char *)um->startup_config_filename;
        
    fd = open (fn, O_RDONLY);
    if (fd < 0) {
      clib_warning ("failed to open `%s'", fn);
      return 0;
    }

    if (fstat (fd, &s) < 0) {
      clib_warning ("failed to stat `%s'", fn);
    bail:
      close(fd);
      return 0;
    }
    
    if (! (S_ISREG (s.st_mode) || S_ISLNK (s.st_mode))) {
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
        u8 * lv = 0;
        lv = format (lv, "%U: ***** Startup Config *****\n%v", 
                     format_timeval,
                     0 /* current bat-time */,
                     0 /* current bat-format */,
                     buf);
	{
	  int rv __attribute__((unused)) = 
	    write (um->log_fd, lv, vec_len(lv));
	}
        vec_reset_length (lv);
        lv = format (lv, "%U: ***** End Startup Config *****\n", 
                     format_timeval,
                     0 /* current bat-time */,
                     0 /* current bat-format */);
	{
	  int rv __attribute__((unused)) = 
	    write (um->log_fd, lv, vec_len(lv));
	}
        vec_free (lv);
      }

    if (vec_len(buf))
      {
        unformat_init_vector (&sub_input, buf);
        vlib_cli_input (vm, &sub_input, 0, 0);
        /* frees buf for us */
        unformat_free (&sub_input);
      }
    close(fd);
  }
  return 0;
}

VLIB_REGISTER_NODE (startup_config_node,static) = {
    .function = startup_config_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "startup-config-process",
};

static clib_error_t *
unix_config (vlib_main_t * vm, unformat_input_t * input)
{
  unix_main_t * um = &unix_main;
  clib_error_t * error = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      char * cli_prompt;
      if (unformat (input, "interactive"))
	um->flags |= UNIX_FLAG_INTERACTIVE;
      else if (unformat (input, "nodaemon"))
        um->flags |= UNIX_FLAG_NODAEMON;  
      else if (unformat (input, "cli-prompt %s", &cli_prompt))
	vlib_unix_cli_set_prompt (cli_prompt);
      else if (unformat (input, "cli-listen %s", &um->cli_listen_socket.config))
	;
      else if (unformat (input, "cli-line-mode"))
        um->cli_line_mode = 1;
      else if (unformat (input, "cli-history-limit %d", &um->cli_history_limit))
        ;
      else if (unformat (input, "full-coredump"))
        {
          int fd;

          fd = open ("/proc/self/coredump_filter", O_WRONLY);
          if (fd > 0)
            {
              if (write (fd, "0x6f\n", 5) != 5)
                clib_unix_warning ("coredump filter write failed!");
              close(fd);
            }
          else
            clib_unix_warning ("couldn't open /proc/self/coredump_filter");
        }
      else if (unformat (input, "startup-config %s", 
                         &um->startup_config_filename))
        ;
      else if (unformat (input, "exec %s",
                         &um->startup_config_filename))
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
              u8 * lv = 0;
              lv = format (0, "%U: ***** Start: PID %d *****\n", 
                           format_timeval,
                           0 /* current bat-time */,
                           0 /* current bat-format */,
                           getpid());
	      {
		int rv __attribute__((unused)) = 
		  write (um->log_fd, lv, vec_len(lv));
	      }
              vec_free (lv);
            }
        }
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (! (um->flags & UNIX_FLAG_INTERACTIVE))
    {
      error = setup_signal_handlers (um);
      if (error)
	return error;

      openlog (vm->name, LOG_CONS | LOG_PERROR | LOG_PID, LOG_DAEMON);
      clib_error_register_handler (unix_error_handler, um);

      if (! (um->flags & UNIX_FLAG_NODAEMON)
	  && daemon (/* chdir to / */ 0,
		     /* stdin/stdout/stderr -> /dev/null */ 0) < 0)
	clib_error_return (0, "daemon () fails");
    }
  um->unix_config_complete = 1;

  return 0;
}

/* unix { ... } configuration. */
VLIB_CONFIG_FUNCTION (unix_config, "unix");

static clib_error_t *
unix_exit (vlib_main_t * vm)
{
  /* Close syslog connection. */
  closelog ();
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (unix_exit);

u8 **vlib_thread_stacks;

static uword thread0 (uword arg)
{
  vlib_main_t * vm = (vlib_main_t *)arg;
  unformat_input_t input;
  int i;
  
  unformat_init_command_line (&input, vm->argv);
  i = vlib_main (vm, &input);
  unformat_free (&input);
  
  return i;
 }

int vlib_unix_main (int argc, char * argv[])
{
  vlib_main_t * vm = &vlib_global_main; /* one and only time for this! */
  
  clib_smp_main_t * sm = &clib_smp_main;
  vlib_thread_main_t * tm = &vlib_thread_main;
  unformat_input_t input;
  u8 * thread_stacks;
  clib_error_t * e;
  int i;

  vm->argv = (u8 **)argv;
  vm->name = argv[0];
  vm->heap_base = clib_mem_get_heap ();
  ASSERT(vm->heap_base);

  i = vlib_plugin_early_init (vm);
  if (i)
    return i;
  
  unformat_init_command_line (&input, vm->argv);
  vm->init_functions_called = hash_create (0, /* value bytes */ 0);
  e = vlib_call_all_config_functions (vm, &input, 1 /* early */);
  if (e != 0)
    {
      clib_error_report(e);
      return 1;
    }
  unformat_free (&input);

  /* allocate N x 1mb stacks, aligned e.g. to a 16mb boundary */
  thread_stacks = clib_mem_alloc_aligned 
      (tm->n_thread_stacks * VLIB_THREAD_STACK_SIZE,
       (VLIB_MAX_CPUS << VLIB_LOG2_THREAD_STACK_SIZE));

  sm->vm_base = thread_stacks;
  sm->log2_n_per_cpu_vm_bytes = VLIB_LOG2_THREAD_STACK_SIZE;

  vec_validate (vlib_thread_stacks, tm->n_thread_stacks - 1);
  for (i = 0; i < vec_len (vlib_thread_stacks); i++)
    {
      vlib_thread_stacks[i] = thread_stacks;

      /* 
       * Disallow writes to the bottom page of the stack, to
       * catch stack overflows.
       */
      if (mprotect (thread_stacks, clib_mem_get_page_size(), PROT_READ) < 0)
          clib_unix_warning ("thread stack");

      thread_stacks += VLIB_THREAD_STACK_SIZE;
    }
  
  i = clib_calljmp (thread0, (uword) vm, 
                    (void *)(vlib_thread_stacks[0] + VLIB_THREAD_STACK_SIZE));
  return i;
}
