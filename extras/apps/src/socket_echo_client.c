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
#include <sys/time.h>

int
main (int argc, char *argv[])
{
  int sockfd, portno, n;
  struct sockaddr_in serv_addr;
  struct hostent *server;
  u8 *rx_buffer = 0, *tx_buffer = 0, no_echo = 0, test_bytes = 0;
  u32 offset;
  long bytes = 1 << 20, to_send;
  int i;
  struct timeval start, end;
  double deltat;

  if (argc >= 3)
    {
      portno = atoi (argv[2]);
      server = gethostbyname (argv[1]);
      if (server == NULL)
	{
	  clib_unix_warning ("gethostbyname");
	  exit (1);
	}

      argc -= 3;
      argv += 3;

      if (argc)
	{
	  bytes = ((long) atoi (argv[0])) << 20;
	  argc--;
	  argv++;
	}
      if (argc)
	{
	  no_echo = atoi (argv[0]);
	  argc--;
	  argv++;
	}
      if (argc)
	{
	  test_bytes = atoi (argv[0]);
	  argc--;
	  argv++;
	}
    }
  else
    {
      portno = 1234;		// atoi(argv[2]);
      server = gethostbyname ("6.0.1.1" /* argv[1] */ );
      if (server == NULL)
	{
	  clib_unix_warning ("gethostbyname");
	  exit (1);
	}
    }

  to_send = bytes;
  sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    {
      clib_unix_error ("socket");
      exit (1);
    }

  bzero ((char *) &serv_addr, sizeof (serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy ((char *) server->h_addr,
	 (char *) &serv_addr.sin_addr.s_addr, server->h_length);
  serv_addr.sin_port = htons (portno);
  if (connect (sockfd, (const void *) &serv_addr, sizeof (serv_addr)) < 0)
    {
      clib_unix_warning ("connect");
      exit (1);
    }

  vec_validate (rx_buffer, 128 << 10);
  vec_validate (tx_buffer, 128 << 10);

  for (i = 0; i < vec_len (tx_buffer); i++)
    tx_buffer[i] = (i + 1) % 0xff;

  /*
   * Send one packet to warm up the RX pipeline
   */
  n = send (sockfd, tx_buffer, vec_len (tx_buffer), 0 /* flags */ );
  if (n != vec_len (tx_buffer))
    {
      clib_unix_warning ("write");
      exit (0);
    }

  gettimeofday (&start, NULL);
  while (bytes > 0)
    {
      /*
       * TX
       */
      n = send (sockfd, tx_buffer, vec_len (tx_buffer), 0 /* flags */ );
      if (n != vec_len (tx_buffer))
	{
	  clib_unix_warning ("write");
	  exit (0);
	}
      bytes -= n;

      if (no_echo)
	continue;

      /*
       * RX
       */

      offset = 0;
      do
	{
	  n = recv (sockfd, rx_buffer + offset,
		    vec_len (rx_buffer) - offset, 0 /* flags */ );
	  if (n < 0)
	    {
	      clib_unix_warning ("read");
	      exit (0);
	    }
	  offset += n;
	}
      while (offset < vec_len (rx_buffer));

      if (test_bytes)
	{
	  for (i = 0; i < vec_len (rx_buffer); i++)
	    {
	      if (rx_buffer[i] != tx_buffer[i])
		{
		  clib_warning ("[%d] read 0x%x not 0x%x", rx_buffer[i],
				tx_buffer[i]);
		  exit (1);
		}
	    }
	}
    }
  close (sockfd);
  gettimeofday (&end, NULL);

  deltat = (end.tv_sec - start.tv_sec);
  deltat += (end.tv_usec - start.tv_usec) / 1000000.0;	// us to ms
  clib_warning ("Finished in %.6f", deltat);
  clib_warning ("%.4f Gbit/second %s", (((f64) to_send * 8.0) / deltat / 1e9),
		no_echo ? "half" : "full");
  return 0;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
