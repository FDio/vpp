/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#ifndef __sock_test_h__
#define __sock_test_h__

#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <hs_apps/vcl/vcl_test.h>

#define SOCK_TEST_AF_UNIX_FILENAME    "/tmp/ldp_server_af_unix_socket"
#define SOCK_TEST_MIXED_EPOLL_DATA    "Hello, world! (over an AF_UNIX socket)"
#define SOCK_TEST_AF_UNIX_ACCEPT_DATA 0xaf0000af
#define SOCK_TEST_AF_UNIX_FD_MASK     0x00af0000
#define SOCK_TEST_BANNER_STRING \
  "============================================\n"

#define stinf(_fmt, _args...)						\
  printf ("st: " _fmt "\n", ##_args)
#define stwrn(_fmt, _args...)						\
  printf ("WARNING: " _fmt "\n", ##_args)
#define sterr(_fn, _rv)							\
{									\
  errno = -_rv;								\
  printf ("\nERROR: " _fn " failed (errno = %d)!\n", -_rv);		\
}
#define stabrt(_fmt, _args...)						\
{									\
  printf ("\nERROR: " _fmt "\n", ##_args);				\
  exit (1);								\
}
#define stfail(_fn)							\
{									\
  perror ("ERROR when calling " _fn);					\
  printf ("\nERROR: " _fn " failed (errno = %d)!\n", errno);		\
  exit (1);								\
}

static inline int
sock_test_read (int fd, uint8_t * buf, uint32_t nbytes,
		vcl_test_stats_t * stats)
{
  int rx_bytes;

  do
    {
      if (stats)
	stats->rx_xacts++;
      rx_bytes = read (fd, buf, nbytes);
      if (stats)
	{
	  if ((rx_bytes == 0) ||
	      ((rx_bytes < 0)
	       && ((errno == EAGAIN) || (errno == EWOULDBLOCK))))
	    stats->rx_eagain++;
	  else if (rx_bytes < nbytes)
	    stats->rx_incomp++;
	}
    }
  while ((rx_bytes == 0) ||
	 ((rx_bytes < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))));

  if (rx_bytes < 0)
    stfail ("sock_test_read()");

  if (stats)
    stats->rx_bytes += rx_bytes;

  return (rx_bytes);
}

static inline int
sock_test_write (int fd, uint8_t * buf, uint32_t nbytes,
		 vcl_test_stats_t * stats, uint32_t verbose)
{
  int tx_bytes = 0, nbytes_left = nbytes, rv;

  do
    {
      if (stats)
	stats->tx_xacts++;
      rv = write (fd, buf, nbytes_left);
      if (rv < 0)
	{
	  if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
	    {
	      if (stats)
		stats->tx_eagain++;
	      continue;
	    }
	  else
	    break;
	}
      tx_bytes += rv;

      if (tx_bytes != nbytes)
	{
	  nbytes_left = nbytes_left - rv;
	  if (stats)
	    stats->tx_incomp++;
	  if (verbose)
	    {
	      stinf ("bytes written (%d) != bytes to write (%d)!\n", tx_bytes,
		     nbytes);
	    }
	}

    }
  while (tx_bytes != nbytes);

  if (tx_bytes < 0)
    stfail ("sock_test_write()");

  if (stats)
    stats->tx_bytes += tx_bytes;

  return (tx_bytes);
}

#endif /* __sock_test_h__ */
