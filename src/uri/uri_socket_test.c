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

int
main (int argc, char *argv[])
{
  int sockfd, portno, n;
  struct sockaddr_in serv_addr;
  struct hostent *server;
  u8 *rx_buffer = 0, *tx_buffer = 0;
  u32 offset;
  int iter, i;
  if (0 && argc < 3)
    {
      fformat (stderr, "usage %s hostname port\n", argv[0]);
      exit (0);
    }

  portno = 1234;		// atoi(argv[2]);
  sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    {
      clib_unix_error ("socket");
      exit (1);
    }
  server = gethostbyname ("6.0.1.1" /* argv[1] */ );
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
  if (connect (sockfd, (const void *) &serv_addr, sizeof (serv_addr)) < 0)
    {
      clib_unix_warning ("connect");
      exit (1);
    }

  vec_validate (rx_buffer, 1400);
  vec_validate (tx_buffer, 1400);

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

  for (iter = 0; iter < 100000; iter++)
    {
      if (iter < 99999)
	{
	  n = send (sockfd, tx_buffer, vec_len (tx_buffer), 0 /* flags */ );
	  if (n != vec_len (tx_buffer))
	    {
	      clib_unix_warning ("write");
	      exit (0);
	    }
	}
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

      for (i = 0; i < vec_len (rx_buffer); i++)
	{
	  if (rx_buffer[i] != tx_buffer[i])
	    {
	      clib_warning ("[%d] read 0x%x not 0x%x",
			    rx_buffer[i], tx_buffer[i]);
	      exit (1);
	    }
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
