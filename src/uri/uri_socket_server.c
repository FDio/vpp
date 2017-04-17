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

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <vppinfra/format.h>
#include <signal.h>
#include <sys/ucontext.h>

volatile int signal_received;

static void
unix_signal_handler (int signum, siginfo_t * si, ucontext_t * uc)
{
  signal_received = 1;
}

static void
setup_signal_handler (void)
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
	clib_unix_warning ("sigaction %U", format_signal, i);
    }
}


int
main (int argc, char *argv[])
{
  int sockfd, portno, n, sent, accfd;
  struct sockaddr_in serv_addr;
  struct hostent *server;
  u8 *rx_buffer = 0;

  if (0 && argc < 3)
    {
      fformat (stderr, "usage %s hostname port\n", argv[0]);
      exit (0);
    }

  setup_signal_handler ();

  portno = 1234;		// atoi(argv[2]);
  sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    {
      clib_unix_error ("socket");
      exit (1);
    }
  server = gethostbyname ("6.0.1.1");
  if (server == NULL)
    {
      clib_unix_warning ("gethostbyname");
      exit (1);
    }
  bzero ((char *) &serv_addr, sizeof (serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy ((char *) server->h_addr,
	 (char *) &serv_addr.sin_addr.s_addr, server->h_length);
  serv_addr.sin_port = htons (portno);
  if (bind (sockfd, (const void *) &serv_addr, sizeof (serv_addr)) < 0)
    {
      clib_unix_warning ("bind");
      exit (1);
    }

  vec_validate (rx_buffer, 8999 /* jumbo mtu */ );

  if (listen (sockfd, 5 /* backlog */ ) < 0)
    {
      clib_unix_warning ("listen");
      close (sockfd);
      return 1;
    }

  while (1)
    {
      if (signal_received)
	break;

      accfd = accept (sockfd, 0 /* don't care */ , 0);
      if (accfd < 0)
	{
	  clib_unix_warning ("accept");
	  continue;
	}
      while (1)
	{
	  n = recv (accfd, rx_buffer, vec_len (rx_buffer), 0 /* flags */ );
	  if (n == 0)
	    {
	      /* Graceful exit */
	      close (accfd);
	      break;
	    }
	  if (n < 0)
	    {
	      clib_unix_warning ("recv");
	      close (accfd);
	      break;
	    }

	  if (signal_received)
	    break;

	  sent = send (accfd, rx_buffer, n, 0 /* flags */ );
	  if (n < 0)
	    {
	      clib_unix_warning ("send");
	      close (accfd);
	      break;
	    }

	  if (sent != n)
	    {
	      clib_warning ("sent %d not %d", sent, n);
	    }

	  if (signal_received)
	    break;
	}
    }

  close (sockfd);

  return 0;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
