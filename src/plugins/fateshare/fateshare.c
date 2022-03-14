/*
 * fateshare.c - skeleton vpp engine plug-in
 *
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <fateshare/fateshare.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h> // prctl(), PR_SET_PDEATHSIG
#include <limits.h>

fateshare_main_t fateshare_main;

/* Action function shared between message handler and debug CLI */

static void
child_handler (int sig)
{
  pid_t pid;
  int status;
  fateshare_main_t *kmp = &fateshare_main;

  while ((pid = waitpid (-1, &status, WNOHANG)) > 0)
    {
      if (pid == kmp->monitor_pid)
	{
	  clib_warning ("Monitor child %d exited with status %d!", pid,
			status);
	  kmp->vlib_main->main_loop_exit_now = 1;
	}
      else
	{
	  clib_warning ("child %d exited with status %d!", pid, status);
	}
    }
}

clib_error_t *
launch_monitor (fateshare_main_t *kmp)
{
  clib_error_t *error = 0;
  pid_t ppid_before_fork = getpid ();
  pid_t cpid = fork ();
  if (cpid == -1)
    {
      perror (0);
      error = clib_error_return (0, "can not fork");
      goto done;
    }
  clib_warning ("fateshare about to launch monitor %v.", kmp->monitor_cmd);
  int logfd =
    open ((char *) kmp->monitor_logfile, O_APPEND | O_RDWR | O_CREAT, 0777);
  if (logfd < 0)
    {
      error = clib_error_return (0, "can not open log file");
      goto done;
    }
  if (cpid)
    {
      /* parent */
      kmp->monitor_pid = cpid;
      close (logfd);
      return 0;
    }
  else
    {
      dup2 (logfd, 1);
      dup2 (logfd, 2);
      int r = prctl (PR_SET_PDEATHSIG, SIGTERM);
      if (r == -1)
	{
	  perror (0);
	  exit (1);
	}
      pid_t current_ppid = getppid ();
      if (current_ppid != ppid_before_fork)
	{
	  fprintf (stderr, "parent pid changed while starting (%d => %d)\n",
		   ppid_before_fork, current_ppid);
	  if (current_ppid == 1)
	    {
	      fprintf (stderr, "exiting.\n");
	      exit (1);
	    }
	}

      int r1 = setpgid (getpid (), 0);
      if (r1 != 0)
	{
	  perror ("setpgid error");
	  exit (1);
	}

      u8 *scmd = format (0, "%v\0", kmp->monitor_cmd);
      u8 *logfile_base = format (0, "%v\0", kmp->monitor_logfile);
      int fd = logfd - 1;
      while (fd > 2)
	{
	  close (fd);
	  fd--;
	}

      fd = open ("/dev/null", O_RDONLY);
      if (fd < 0)
	{
	  exit (1);
	}
      dup2 (fd, 0);

      char *ppid_str = (char *) format (0, "%lld\0", current_ppid);

      char **argv = 0;
      vec_validate (argv, vec_len (kmp->commands) + 3 - 1);
      argv[0] = (void *) scmd;
      argv[1] = ppid_str;
      argv[2] = (char *) logfile_base;
      int i;
      vec_foreach_index (i, kmp->commands)
	{
	  argv[3 + i] = (char *) kmp->commands[i];
	}

      int res = execv (argv[0], argv);
      clib_warning ("ERROR during execve: %d", res);
      perror ("execve");

      exit (0);
    }
done:

  return error;
}

static clib_error_t *
fateshare_config (vlib_main_t *vm, unformat_input_t *input)
{
  fateshare_main_t *fmp = &fateshare_main;
  u8 *command = 0;
  u8 **new_command = 0;
  clib_error_t *error = 0;

  /* unix config may make vpp fork, we want to run after that. */
  if ((error = vlib_call_config_function (vm, unix_config)))
    return error;

  /* Defaults */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "monitor %s", &fmp->monitor_cmd))
	{
	  clib_warning ("setting monitor to %v", fmp->monitor_cmd);
	}
      else if (unformat (input, "logfile %s", &fmp->monitor_logfile))
	{
	  clib_warning ("setting logfile to %v", fmp->monitor_logfile);
	}
      else if (unformat (input, "command %s", &command))
	{
	  vec_add2 (fmp->commands, new_command, 1);
	  *new_command = command;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  vec_add2 (fmp->commands, new_command, 1);
  *new_command = 0;

  /* Establish handler. */
  struct sigaction sa;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = child_handler;

  sigaction (SIGCHLD, &sa, NULL);

  if (fmp->monitor_cmd == 0)
    {
      char *p, path[PATH_MAX];
      int rv;

      /* find executable path */
      if ((rv = readlink ("/proc/self/exe", path, PATH_MAX - 1)) == -1)
	return clib_error_return (
	  0, "could not stat /proc/self/exe - set monitor manually");

      /* readlink doesn't provide null termination */
      path[rv] = 0;

      /* strip filename */
      if ((p = strrchr (path, '/')) == 0)
	return clib_error_return (
	  0, "could not determine vpp directory - set monitor manually");
      *p = 0;

      fmp->monitor_cmd = format (0, "%s/vpp_fateshare_monitor\0", path);
    }
  if (fmp->monitor_logfile == 0)
    {
      fmp->monitor_logfile =
	format (0, "/tmp/vpp-fateshare-monitor-log.txt\0");
    }
  error = launch_monitor (fmp);

  return error;
}

clib_error_t *
fateshare_init (vlib_main_t *vm)
{
  fateshare_main_t *kmp = &fateshare_main;
  clib_error_t *error = 0;

  kmp->vlib_main = vm;
  kmp->vnet_main = vnet_get_main ();

  return error;
}

static clib_error_t *
fateshare_send_hup_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  fateshare_main_t *kmp = &fateshare_main;

  if (kmp->monitor_pid)
    {
      int rc = kill (kmp->monitor_pid, SIGHUP);
      if (rc)
	{
	  error = clib_error_return (
	    0, "can not send signal to monitor process: %s", strerror (errno));
	}
    }
  else
    {
      error = clib_error_return (0, "can not find monitor process");
    }

  return error;
}

VLIB_EARLY_CONFIG_FUNCTION (fateshare_config, "fateshare");

VLIB_INIT_FUNCTION (fateshare_init);

VLIB_CLI_COMMAND (fateshare_restart_process_command, static) = {
  .path = "fateshare restart-processes",
  .short_help = "restart dependent processes",
  .function = fateshare_send_hup_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Run child processes which will share fate with VPP, restart "
		 "them if they quit",
  .default_disabled = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
