/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#define DEBUG 0

#if DEBUG
#define TELCMDS
#define TELOPTS
#endif

#include <arpa/telnet.h>

#define SOCKET_FILE "/run/vpp/cli.sock"

volatile int window_resized = 0;
struct termios orig_tio;

static void
send_ttype (int sock_fd, int is_interactive)
{
  char *term;
  static char buf[2048];

  /* wipe the buffer so there is no potential
   * for inter-invocation leakage */
  memset (buf, 0, sizeof (buf));

  term = is_interactive ? getenv ("TERM") : "vppctl";
  if (term == NULL)
    term = "dumb";

  int len = snprintf (buf, sizeof (buf),
		      "%c%c%c"
		      "%c%s"
		      "%c%c",
		      IAC, SB, TELOPT_TTYPE, 0, term, IAC, SE);
  if (send (sock_fd, buf, len, 0) < 0)
    {
      perror ("send_ttype");
    }
}

static void
send_naws (int sock_fd)
{
  struct winsize ws;
  static char buf[2048];

  memset (buf, 0, sizeof (buf));
  if (ioctl (STDIN_FILENO, TIOCGWINSZ, &ws) < 0)
    {
      fprintf (stderr, "ioctl(TIOCGWINSZ)");
      return;
    }

  int len = snprintf (buf, sizeof (buf),
		      "%c%c%c"
		      "%c%c%c%c"
		      "%c%c",
		      IAC, SB, TELOPT_NAWS, ws.ws_col >> 8, ws.ws_col & 0xff,
		      ws.ws_row >> 8, ws.ws_row & 0xff, IAC, SE);
  int n_written = write (sock_fd, buf, len);
  if (n_written < len)
    {
      perror ("send_naws");
    }
}

static void
signal_handler_winch (int signum)
{
  window_resized = 1;
}

static void
signal_handler_term (int signum)
{
  tcsetattr (STDIN_FILENO, TCSAFLUSH, &orig_tio);
}

static int
process_input (int sock_fd, unsigned char *rx_buf, int rx_buf_len,
	       int is_interactive, int *sent_ttype)
{
  int i = 0;
  int j = 0;

  while (i < rx_buf_len)
    {
      if (rx_buf[i] == IAC)
	{
	  if (rx_buf[i + 1] == SB)
	    {
	      char opt = rx_buf[i + 2];
	      i += 3;
#if DEBUG
	      if (rx_buf[i] != IAC)
		{
		  fprintf (stderr, "SB ");
		}
	      while (rx_buf[i] != IAC && i < rx_buf_len)
		fprintf (stderr, "%02x ", rx_buf[i++]);
	      fprintf (stderr, "\n");
#else
	      while (rx_buf[i] != IAC && i < rx_buf_len)
		{
		  i++;
		}
#endif
	      i += 2;
	      if (opt == TELOPT_TTYPE)
		{
		  send_ttype (sock_fd, is_interactive);
		  *sent_ttype = 1;
		}
	      else if (is_interactive && opt == TELOPT_NAWS)
		send_naws (sock_fd);
	    }
	  else
	    {
#if DEBUG
	      fprintf (stderr, "IAC at %d, IAC %s %s", i,
		       TELCMD (rx_buf[i + 1]), TELOPT (rx_buf[i + 2]));
#endif
	      i += 3;
	    }
	}
      else
	{
	  /* i is always the same or ahead of j, so at worst this is a no-op */
	  rx_buf[j] = rx_buf[i];
	  i++;
	  j++;
	}
    }
  return j;
}


int
main (int argc, char *argv[])
{
  struct epoll_event event;
  struct sigaction sa;
  struct termios tio;
  int efd = -1;
  char *cmd = 0;
  unsigned long cmd_len = 0;
  int do_quit = 0;
  int is_interactive = 0;
  int acked = 1;		/* counts messages from VPP; starts at 1 */
  int sent_ttype = 0;
  char *sock_fname = SOCKET_FILE;
  int sock_fd = -1;
  int error = 0;
  int arg = 0;

  /* process command line */
  argc--;
  argv++;

  if (argc > 1 && strncmp (argv[0], "-s", 2) == 0)
    {
      sock_fname = argv[1];
      argc -= 2;
      argv += 2;
    }

  struct sockaddr_un saddr = { 0 };
  saddr.sun_family = AF_UNIX;
  strncpy (saddr.sun_path, sock_fname, sizeof (saddr.sun_path) - 1);

  sock_fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sock_fd < 0)
    {
      perror ("socket");
      exit (1);
    }

  if (connect (sock_fd, (struct sockaddr *) &saddr, sizeof (saddr)) < 0)
    {
      perror ("connect");
      exit (1);
    }

  for (arg = 0; arg < argc; arg++)
    {
      cmd_len += strlen (argv[arg]) + 1;
    }
  if (cmd_len > 0)
    {
      cmd_len++; // account for 0 at end
      cmd = malloc (cmd_len);
      if (!cmd)
	{
	  error = errno;
	  perror ("malloc failed");
	  goto done;
	}
      memset (cmd, 0, cmd_len);
      unsigned long space_left = cmd_len - 1; // reserve space for 0 at end
      while (argc--)
	{
	  strncat (cmd, *argv, space_left);
	  space_left -= strlen (*argv);
	  ++argv;
	  strncat (cmd, " ", space_left);
	  --space_left;
	}
      cmd[cmd_len - 2] = '\n';
      cmd[cmd_len - 1] = 0;
    }

  is_interactive = isatty (STDIN_FILENO) && cmd == 0;

  if (is_interactive)
    {
      /* Capture terminal resize events */
      memset (&sa, 0, sizeof (struct sigaction));
      sa.sa_handler = signal_handler_winch;
      if (sigaction (SIGWINCH, &sa, 0) < 0)
	{
	  error = errno;
	  perror ("sigaction for SIGWINCH");
	  goto done;
	}

      /* Capture SIGTERM to reset tty settings */
      sa.sa_handler = signal_handler_term;
      if (sigaction (SIGTERM, &sa, 0) < 0)
	{
	  error = errno;
	  perror ("sigaction for SIGTERM");
	  goto done;
	}

      /* Save the original tty state so we can restore it later */
      if (tcgetattr (STDIN_FILENO, &orig_tio) < 0)
	{
	  error = errno;
	  perror ("tcgetattr");
	  goto done;
	}

      /* Tweak the tty settings */
      tio = orig_tio;
      /* echo off, canonical mode off, ext'd input processing off */
      tio.c_lflag &= ~(ECHO | ICANON | IEXTEN);
      tio.c_cc[VMIN] = 1;	/* 1 byte at a time */
      tio.c_cc[VTIME] = 0;	/* no timer */

      if (tcsetattr (STDIN_FILENO, TCSAFLUSH, &tio) < 0)
	{
	  error = errno;
	  perror ("tcsetattr");
	  goto done;
	}
    }

  efd = epoll_create1 (0);

  /* register STDIN */
  event.events = EPOLLIN | EPOLLPRI | EPOLLERR;
  event.data.fd = STDIN_FILENO;
  if (epoll_ctl (efd, EPOLL_CTL_ADD, STDIN_FILENO, &event) != 0)
    {
      /* ignore EPERM; it means stdin is something like /dev/null */
      if (errno != EPERM)
	{
	  error = errno;
	  fprintf (stderr, "epoll_ctl[%d]", STDIN_FILENO);
	  perror (0);
	  goto done;
	}
    }

  /* register socket */
  event.events = EPOLLIN | EPOLLPRI | EPOLLERR;
  event.data.fd = sock_fd;
  if (epoll_ctl (efd, EPOLL_CTL_ADD, sock_fd, &event) != 0)
    {
      error = errno;
      fprintf (stderr, "epoll_ctl[%d]", sock_fd);
      perror (0);
      goto done;
    }

  while (1)
    {
      int n;
      static int sent_cmd = 0;

      if (window_resized)
	{
	  window_resized = 0;
	  send_naws (sock_fd);
	}

      if ((n = epoll_wait (efd, &event, 1, -1)) < 0)
	{
	  /* maybe we received signal */
	  if (errno == EINTR)
	    continue;

	  error = errno;
	  perror ("epoll_wait");
	  goto done;
	}

      if (n == 0)
	continue;

      if (event.data.fd == STDIN_FILENO)
	{
	  int n;
	  char c[100];

	  if (!sent_ttype)
	    continue;		/* not ready for this yet */

	  n = read (STDIN_FILENO, c, sizeof (c));
	  if (n > 0)
	    {
	      int n_written = write (sock_fd, c, n);
	      if (n_written < n)
		error = errno;
	      if (error)
		goto done;
	    }
	  else if (n < 0)
	    fprintf (stderr, "read rv=%d", n);
	  else /* EOF */
	    do_quit = 1;
	}
      else if (event.data.fd == sock_fd)
	{
	  unsigned char rx_buf[100];
	  memset (rx_buf, 0, sizeof (rx_buf));
	  int nread = recv (sock_fd, rx_buf, sizeof (rx_buf), 0);

	  if (nread < 0)
	    error = errno;
	  if (error)
	    break;

	  if (nread == 0)
	    break;

	  int len = process_input (sock_fd, rx_buf, nread, is_interactive,
				   &sent_ttype);

	  if (len > 0)
	    {
	      unsigned char *p = rx_buf, *q = rx_buf;

	      while (len)
		{
		  /* Search for and skip NUL bytes */
		  while (q < (p + len) && *q)
		    q++;

		  n = write (STDOUT_FILENO, p, q - p);
		  if (n < 0)
		    {
		      error = errno;
		      perror ("write");
		      goto done;
		    }

		  while (q < (p + len) && !*q)
		    {
		      q++;
		      acked++;	/* every NUL is an acknowledgement */
		    }
		  len -= q - p;
		  p = q;
		}
	    }

	  if (do_quit && do_quit < acked)
	    {
	      /* Ask the other end to close the connection */
	      char quit_str[] = "quit\n";
	      int n = write (sock_fd, quit_str, strlen (quit_str));
	      if (n < strlen (quit_str))
		{
		  error = errno;
		  perror ("write quit");
		}
	      do_quit = 0;
	    }
	  if (cmd && sent_ttype && !sent_cmd)
	    {
	      /* We wait until after the TELNET TTYPE option has been sent.
	       * That is to make sure the session at the VPP end has switched
	       * to line-by-line mode, and thus avoid prompts and echoing.
	       * Note that it does also disable further TELNET option processing.
	       */
	      int n_written = write (sock_fd, cmd, strlen (cmd) + 1);
	      sent_cmd = 1;
	      if (n_written < strlen (cmd))
		{
		  error = errno;
		  perror ("write command");
		  goto done;
		}
	      do_quit = acked;	/* quit after the next response */
	    }
	}
      else
	{
	  error = errno;
	  perror ("unknown fd");
	  goto done;
	}
    }

  close (sock_fd);

done:
  free (cmd);
  if (efd > -1)
    close (efd);

  if (is_interactive)
    tcsetattr (STDIN_FILENO, TCSAFLUSH, &orig_tio);

  if (error)
    {
      return 1;
    }

  return 0;
}

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
