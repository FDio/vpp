#define _XOPEN_SOURCE		/* See feature_test_macros(7) */
#define _XOPEN_SOURCE_EXTENDED
#include <stdlib.h>


#include <dirent.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int
pty_master_open (void)
{
  int fd = open ("/dev/ptmx", O_RDWR);
  grantpt (fd);
  unlockpt (fd);
  return fd;
}

int
pty_run (char *cmd, pid_t * o_child_pid)
{
  int master_fd = pty_master_open ();
  int child_pid = fork ();
  if (child_pid == -1)
    {
      return -1;
    }
  if (child_pid)
    {
      if (o_child_pid)
	*o_child_pid = child_pid;
      return master_fd;
    }
  /* child after fork */
  char *pts_name = ptsname (master_fd);
  int slave_fd = open (pts_name, O_RDWR);
  close (master_fd);
  if (slave_fd < 0)
    {
      fprintf (stderr, "Child can not open pty");
      exit (0);
    }
  dup2 (slave_fd, 0);
  dup2 (slave_fd, 1);
  dup2 (slave_fd, 2);
  execl ("/bin/sh", "sh", "-c", cmd, (char *) 0);
  // not reached
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
