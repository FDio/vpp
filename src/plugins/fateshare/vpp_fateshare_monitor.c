#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h> // prctl(), PR_SET_PDEATHSIG

#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

typedef struct
{
  pid_t pid;
  char *cmd;
} child_record_t;

int n_children = 0;
child_record_t *children = NULL;

static void
child_handler (int sig)
{
  pid_t pid;
  int status;

  while ((pid = waitpid (-1, &status, WNOHANG)) > 0)
    {
      int i;
      printf ("fateshare: pid %d quit with status %d\n", pid, status);
      for (i = 0; i < n_children; i++)
	{
	  if (children[i].pid == pid)
	    {
	      children[i].pid = 0;
	    }
	}
    }
}

static void
term_handler (int sig)
{
  int i;

  printf ("fateshare: terminating!\n");
  for (i = 0; i < n_children; i++)
    {
      kill (-children[i].pid, SIGTERM);
    }
  exit (0);
}

static void
hup_handler (int sig)
{
  int i;

  printf ("fateshare: terminating all the child processes!\n");
  for (i = 0; i < n_children; i++)
    {
      kill (-children[i].pid, SIGTERM);
    }
}

pid_t
launch_command (char *scmd, char *logname_base)
{
  pid_t ppid_before_fork = getpid ();
  pid_t cpid = fork ();
  if (cpid == -1)
    {
      perror ("fork");
      sleep (1);
      return 0;
    }
  if (cpid)
    {
      /* parent */
      return cpid;
    }

  /* child */
  int r = prctl (PR_SET_PDEATHSIG, SIGTERM);
  if (r == -1)
    {
      perror ("prctl");
      sleep (5);
      exit (1);
    }
  if (getppid () != ppid_before_fork)
    {
      sleep (5);
      exit (1);
    }

  int r1 = setpgid (getpid (), 0);
  if (r1 != 0)
    {
      perror ("setpgid error");
      sleep (5);
      exit (1);
    }

  int fd = open ("/dev/null", O_RDONLY);
  if (fd < 0)
    {
      sleep (5);
      exit (1);
    }
  while (fd >= 0)
    {
      close (fd);
      fd--;
    }
  fd = open ("/dev/null", O_RDONLY);
  if (fd < 0)
    {
      sleep (5);
      exit (1);
    }
  dup2 (fd, 0);

  char logname_stdout[PATH_MAX];
  char logname_stderr[PATH_MAX];

  snprintf (logname_stdout, PATH_MAX - 1, "%s-stdout.txt", logname_base);
  snprintf (logname_stderr, PATH_MAX - 1, "%s-stderr.txt", logname_base);

  printf ("LOG STDOUT %s: %s\n", scmd, logname_stdout);
  printf ("LOG STDERR %s: %s\n", scmd, logname_stderr);

  fd = open ((char *) logname_stdout, O_APPEND | O_RDWR | O_CREAT, 0777);
  if (fd < 0)
    {
      sleep (5);
      exit (1);
    }
  dup2 (fd, 1);
  fd = open ((char *) logname_stderr, O_APPEND | O_RDWR | O_CREAT, 0777);
  if (fd < 0)
    {
      sleep (5);
      exit (1);
    }
  dup2 (fd, 2);

  char *argv[] = { (char *) scmd, 0 };
  int res = execv (argv[0], argv);
  if (res != 0)
    {
      perror ("execve");
    }
  sleep (10);

  exit (42);
}

int
main (int argc, char **argv)
{
  pid_t ppid = getppid ();
  int i = 0;
  if (argc < 3)
    {
      printf ("usage: %s <parent_pid> <logfile-basename>\n", argv[0]);
      exit (1);
    }
  char *errptr = 0;
  pid_t parent_pid = strtoll (argv[1], &errptr, 10);
  char *logname_base = argv[2];

  printf ("DEBUG: pid %d starting for parent pid %d\n", getpid (), ppid);
  printf ("DEBUG: parent pid: %d\n", parent_pid);
  printf ("DEBUG: base log name: %s\n", logname_base);
  if (*errptr)
    {
      printf ("%s is not a valid parent pid\n", errptr);
      exit (2);
    }

  int r = prctl (PR_SET_PDEATHSIG, SIGTERM);
  if (r == -1)
    {
      perror (0);
      exit (1);
    }

  /* Establish handler. */
  struct sigaction sa;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = child_handler;

  sigaction (SIGCHLD, &sa, NULL);

  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = term_handler;

  sigaction (SIGTERM, &sa, NULL);

  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = hup_handler;

  sigaction (SIGHUP, &sa, NULL);

  if (getppid () != parent_pid)
    {
      printf ("parent process unexpectedly finished\n");
      exit (3);
    }

  argc -= 3; /* skip over argv0, ppid, and log base */
  argv += 3;

  n_children = argc;
  printf ("DEBUG: total %d children\n", n_children);
  children = calloc (n_children, sizeof (children[0]));
  for (i = 0; i < n_children; i++)
    {
      /* argv persists, so we can just use that pointer */
      children[i].cmd = argv[i];
      children[i].pid = launch_command (children[i].cmd, logname_base);
      printf ("DEBUG: child %d (%s): initial launch pid %d\n", i,
	      children[i].cmd, children[i].pid);
    }

  while (1)
    {
      sleep (1);
      pid_t curr_ppid = getppid ();
      printf ("pid: %d, current ppid %d, original ppid %d\n", getpid (),
	      curr_ppid, ppid);
      if (curr_ppid != ppid)
	{
	  printf ("current ppid %d != original ppid %d - force quit\n",
		  curr_ppid, ppid);
	  fflush (stdout);
	  exit (1);
	}
      int restarted = 0;
      for (i = 0; i < n_children; i++)
	{
	  if (children[i].pid == 0)
	    {
	      printf ("child %s exited, restarting\n", children[i].cmd);
	      restarted = 1;
	      children[i].pid = launch_command (children[i].cmd, logname_base);
	    }
	}
      if (restarted)
	{
	  sleep (1);
	}

      fflush (stdout);
    }
}
