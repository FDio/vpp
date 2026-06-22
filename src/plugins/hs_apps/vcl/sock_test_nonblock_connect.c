/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Regression test for: vcl: allow polling connect() on nonblocking socket.
 *
 * 1. init connect() -> EINPROGRESS
 * 2. repeated connect() while in progress -> EALREADY (no fresh sessions)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define POLLS	    200
#define SERVER_IP   "172.16.1.1"
#define SERVER_PORT 22000

int
main (void)
{
  struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons (SERVER_PORT) };
  int fd, rv;

  inet_pton (AF_INET, SERVER_IP, &sa.sin_addr);

  fd = socket (AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

  rv = connect (fd, (struct sockaddr *) &sa, sizeof (sa));
  if (rv != -1 || errno != EINPROGRESS)
    {
      fprintf (stderr, "first connect: rv=%d errno=%d (%s)\n", rv, errno, strerror (errno));
      return 1;
    }

  for (int i = 0; i < POLLS; i++)
    {
      rv = connect (fd, (struct sockaddr *) &sa, sizeof (sa));
      if (rv != -1 || errno != EALREADY)
	{
	  fprintf (stderr, "poll %d: rv=%d errno=%d (%s)\n", i, rv, errno, strerror (errno));
	  return 1;
	}
    }

  close (fd);
  return 0;
}
