/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Regression test for: vcl: strip ignorable flags.
 *
 * recv()/recvfrom() with stripped flags shouldn't return EAFNOSUPPORT.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define FLAGS	    (MSG_DONTWAIT | MSG_NOSIGNAL)
#define SERVER_IP   "172.16.1.1"
#define SERVER_PORT 22000

int
main (void)
{
  struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons (SERVER_PORT) };
  char buf[16];
  int fd;

  inet_pton (AF_INET, SERVER_IP, &sa.sin_addr);

  fd = socket (AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (fd < 0)
    return 1;

  (void) connect (fd, (struct sockaddr *) &sa, sizeof (sa));

  errno = 0;
  recv (fd, buf, sizeof (buf), FLAGS);
  if (errno == EAFNOSUPPORT)
    {
      fprintf (stderr, "recv: EAFNOSUPPORT (flags not stripped)\n");
      return 1;
    }

  errno = 0;
  recvfrom (fd, buf, sizeof (buf), FLAGS, NULL, NULL);
  if (errno == EAFNOSUPPORT)
    {
      fprintf (stderr, "recvfrom: EAFNOSUPPORT (flags not stripped)\n");
      return 1;
    }

  close (fd);
  return 0;
}
