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

#define DEBUG 0

#if DEBUG
#define TELCMDS
#define TELOPTS
#endif

#include <arpa/telnet.h>

#include <vppinfra/mem.h>
#include <vppinfra/format.h>
#include <vppinfra/socket.h>

#define SOCKET_FILE "/run/vpp/cli.sock"

volatile int window_resized = 0;
struct termios orig_tio;

static void
send_ttype (clib_socket_t * s, int is_dumb)
{
  clib_socket_tx_add_formatted (s, "%c%c%c" "%c%s" "%c%c",
				IAC, SB, TELOPT_TTYPE,
				0, is_dumb ? "dumb" : getenv ("TERM"),
				IAC, SE);
  clib_socket_tx (s);
}

static void
send_naws (clib_socket_t * s)
{
  struct winsize ws;

  if (ioctl (STDIN_FILENO, TIOCGWINSZ, &ws) < 0)
    {
      clib_unix_warning ("ioctl(TIOCGWINSZ)");
      return;
    }

  clib_socket_tx_add_formatted (s, "%c%c%c" "%c%c%c%c" "%c%c",
				IAC, SB, TELOPT_NAWS,
				ws.ws_col >> 8, ws.ws_col & 0xff,
				ws.ws_row >> 8, ws.ws_row & 0xff, IAC, SE);
  clib_socket_tx (s);
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

static u8 *
process_input (u8 * str, clib_socket_t * s, int is_interactive)
{
  int i = 0;

  while (i < vec_len (s->rx_buffer))
    {
      if (s->rx_buffer[i] == IAC)
	{
	  if (s->rx_buffer[i + 1] == SB)
	    {
	      u8 *sb = 0;
	      char opt = s->rx_buffer[i + 2];
	      i += 3;
	      while (s->rx_buffer[i] != IAC)
		vec_add1 (sb, s->rx_buffer[i++]);

#if DEBUG
	      clib_warning ("SB %s\n  %U", TELOPT (opt),
			    format_hexdump, sb, vec_len (sb));
#endif
	      vec_free (sb);
	      i += 2;
	      if (opt == TELOPT_TTYPE)
		send_ttype (s, !is_interactive);
	      else if (is_interactive && opt == TELOPT_NAWS)
		send_naws (s);
	    }
	  else
	    {
#if DEBUG
	      clib_warning ("IAC at %d, IAC %s %s", i,
			    TELCMD (s->rx_buffer[i + 1]),
			    TELOPT (s->rx_buffer[i + 2]));
#endif
	      i += 3;
	    }
	}
      else
	vec_add1 (str, s->rx_buffer[i++]);
    }
  vec_reset_length (s->rx_buffer);
  return str;
}


int
main (int argc, char *argv[])
{
  clib_socket_t _s = { 0 }, *s = &_s;
  clib_error_t *error = 0;
  struct epoll_event event;
  struct sigaction sa;
  struct termios tio;
  int efd = -1;
  u8 *str = 0;
  u8 *cmd = 0;
  int do_quit = 0;


  clib_mem_init (0, 64ULL << 10);

  /* process command line */
  argc--;
  argv++;

  if (argc > 1 && strcmp (argv[0], "-s") == 0)
    {
      s->config = argv[1];
      argc -= 2;
      argv += 2;
    }
  else
    s->config = SOCKET_FILE;

  while (argc--)
    cmd = format (cmd, "%s%c", (argv++)[0], argc ? ' ' : 0);

  s->flags = CLIB_SOCKET_F_IS_CLIENT;

  error = clib_socket_init (s);
  if (error)
    goto done;

  /* Capture terminal resize events */
  memset (&sa, 0, sizeof (struct sigaction));
  sa.sa_handler = signal_handler_winch;

  if (sigaction (SIGWINCH, &sa, 0) < 0)
    {
      error = clib_error_return_unix (0, "sigaction");
      goto done;
    }

  sa.sa_handler = signal_handler_term;
  if (sigaction (SIGTERM, &sa, 0) < 0)
    {
      error = clib_error_return_unix (0, "sigaction");
      goto done;
    }

  /* Save the original tty state so we can restore it later */
  tcgetattr (STDIN_FILENO, &orig_tio);

  /* Tweak the tty settings */
  tio = orig_tio;
  /* echo off, canonical mode off, ext'd input processing off */
  tio.c_lflag &= ~(ECHO | ICANON | IEXTEN);
  tio.c_cc[VMIN] = 1;		/* 1 byte at a time */
  tio.c_cc[VTIME] = 0;		/* no timer */
  tcsetattr (STDIN_FILENO, TCSAFLUSH, &tio);

  efd = epoll_create1 (0);

  /* register STDIN */
  event.events = EPOLLIN | EPOLLPRI | EPOLLERR;
  event.data.fd = STDIN_FILENO;
  if (epoll_ctl (efd, EPOLL_CTL_ADD, STDIN_FILENO, &event) != 0)
    {
      error = clib_error_return_unix (0, "epoll_ctl[%d]", STDIN_FILENO);
      goto done;
    }

  /* register socket */
  event.events = EPOLLIN | EPOLLPRI | EPOLLERR;
  event.data.fd = s->fd;
  if (epoll_ctl (efd, EPOLL_CTL_ADD, s->fd, &event) != 0)
    {
      error = clib_error_return_unix (0, "epoll_ctl[%d]", s->fd);
      goto done;
    }

  while (1)
    {
      int n;

      if (window_resized)
	{
	  window_resized = 0;
	  send_naws (s);
	}

      if ((n = epoll_wait (efd, &event, 1, -1)) < 0)
	{
	  /* maybe we received signal */
	  if (errno == EINTR)
	    continue;

	  error = clib_error_return_unix (0, "epoll_wait");
	  goto done;
	}

      if (n == 0)
	continue;

      if (event.data.fd == STDIN_FILENO)
	{
	  int n;
	  char c[100];

	  n = read (STDIN_FILENO, c, sizeof (c));
	  if (n > 0)
	    {
	      memcpy (clib_socket_tx_add (s, n), c, n);
	      error = clib_socket_tx (s);
	      if (error)
		goto done;
	    }
	  else if (n < 0)
	    clib_warning ("read rv=%d", n);
	}
      else if (event.data.fd == s->fd)
	{
	  error = clib_socket_rx (s, 100);
	  if (error)
	    break;

	  if (clib_socket_rx_end_of_file (s))
	    break;

	  str = process_input (str, s, cmd == 0);

	  if (vec_len (str) > 0)
	    {
	      n = write (STDOUT_FILENO, str, vec_len (str));
	      if (n < 0)
		{
		  error = clib_error_return_unix (0, "write");
		  goto done;
		}
	      vec_reset_length (str);
	    }

	  if (do_quit)
	    {
	      clib_socket_tx_add_formatted (s, "q\n");
	      clib_socket_tx (s);
	      do_quit = 0;
	    }
	  if (cmd)
	    {
	      clib_socket_tx_add_formatted (s, "%s\n", cmd);
	      clib_socket_tx (s);
	      vec_free (cmd);
	      do_quit = 1;
	    }
	}
      else
	{
	  error = clib_error_return (0, "unknown fd");
	  goto done;
	}
    }

  error = clib_socket_close (s);

done:
  vec_free (cmd);
  vec_free (str);
  if (efd > -1)
    close (efd);

  if (error)
    {
      clib_error_report (error);
      return 1;
    }
  tcsetattr (STDIN_FILENO, TCSAFLUSH, &orig_tio);
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
