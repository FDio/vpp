#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>

#define TELCMDS
#define TELOPTS
#include <arpa/telnet.h>

#include <vppinfra/mem.h>
#include <vppinfra/format.h>
#include <vppinfra/socket.h>

#define SOCKET_FILE "/run/vpp/cli.sock"

static void
send_ttype (clib_socket_t * s)
{
  clib_socket_tx_add_formatted (s, "%c%c%c" "%c%s" "%c%c",
				IAC, SB, TELOPT_TTYPE,
				0, getenv ("TERM"), IAC, SE);
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

int window_resized = 0;
struct termios orig_tio;

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
process_input (u8 * str, clib_socket_t * s)
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

	      clib_warning ("SB %s\n  %U", TELOPT (opt),
			    format_hexdump, sb, vec_len (sb));
	      vec_free (sb);
	      i += 2;
	      if (opt == TELOPT_TTYPE)
		send_ttype (s);
	      else if (opt == TELOPT_NAWS)
		send_naws (s);
	    }
	  else
	    {
	      clib_warning ("IAC at %d, IAC %s %s", i,
			    TELCMD (s->rx_buffer[i + 1]),
			    TELOPT (s->rx_buffer[i + 2]));
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
  struct sigaction sa = { 0 };
  struct termios tio;
  int efd = -1;
  u8 *str = 0;

  clib_mem_init (0, 3ULL << 10);

  s->config = SOCKET_FILE;
  s->flags = SOCKET_IS_CLIENT;

  error = clib_socket_init (s);
  if (error)
    goto done;

  /* Capture terminal resize events */
  sa.sa_handler = signal_handler_winch;
  if (sigaction (SIGWINCH, &sa, 0) < 0)
    {
      error = clib_error_return_unix (0, "sigaction");
    }

  sa.sa_handler = signal_handler_term;
  if (sigaction (SIGTERM, &sa, 0) < 0)
    {
      error = clib_error_return_unix (0, "sigaction");
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
	  else
	    clib_warning ("read rv=%d", n);
	}
      else if (event.data.fd == s->fd)
	{
	  error = clib_socket_rx (s, 100);
	  if (error)
	    break;

	  if (clib_socket_rx_end_of_file (s))
	    break;

	  str = process_input (str, s);

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

	}
      else
	{
	  error = clib_error_return (0, "unknown fd");
	  goto done;
	}
    }

  error = clib_socket_close (s);

done:
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
