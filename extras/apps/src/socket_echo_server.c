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
#include <arpa/inet.h>
#include <netdb.h>
#include <vppinfra/format.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <sys/time.h>

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
  int sockfd, portno, n, sent, accfd, reuse;
  socklen_t client_addr_len;
  struct sockaddr_in serv_addr;
  struct sockaddr_in client;
  struct hostent *server;
  u8 *rx_buffer = 0, no_echo = 0;
  struct timeval start, end;
  long rcvd = 0;
  double deltat;

  if (argc > 1 && argc < 3)
    {
      fformat (stderr, "usage %s host port\n", argv[0]);
      exit (0);
    }

  if (argc >= 4)
    {
      no_echo = atoi (argv[3]);
      portno = atoi (argv[2]);
      server = gethostbyname (argv[1]);
      if (server == NULL)
	{
	  clib_unix_warning ("gethostbyname");
	  exit (1);
	}
    }
  else
    {
      /* Defaults */
      portno = 1234;
      server = gethostbyname ("6.0.1.1");
      if (server == NULL)
	{
	  clib_unix_warning ("gethostbyname");
	  exit (1);
	}
    }


  setup_signal_handler ();

  sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    {
      clib_unix_error ("socket");
      exit (1);
    }

  reuse = 1;
  if (setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse,
		  sizeof (reuse)) < 0)
    {
      clib_unix_error ("setsockopt(SO_REUSEADDR) failed");
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

  vec_validate (rx_buffer, 128 << 10);

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

      client_addr_len = sizeof (struct sockaddr);
      accfd = accept (sockfd, (struct sockaddr *) &client, &client_addr_len);
      if (accfd < 0)
	{
	  clib_unix_warning ("accept");
	  continue;
	}
      fformat (stderr, "Accepted connection from: %s : %d\n",
	       inet_ntoa (client.sin_addr), client.sin_port);
      gettimeofday (&start, NULL);

      while (1)
	{
	  n = recv (accfd, rx_buffer, vec_len (rx_buffer), 0 /* flags */ );
	  if (n == 0)
	    {
	      /* Graceful exit */
	      close (accfd);
	      gettimeofday (&end, NULL);
	      deltat = (end.tv_sec - start.tv_sec);
	      deltat += (end.tv_usec - start.tv_usec) / 1000000.0;
	      clib_warning ("Finished in %.6f", deltat);
	      clib_warning ("%.4f Gbit/second %s",
			    (((f64) rcvd * 8.0) / deltat / 1e9),
			    no_echo ? "half" : "full");
	      rcvd = 0;
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

	  rcvd += n;
	  if (no_echo)
	    continue;

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
