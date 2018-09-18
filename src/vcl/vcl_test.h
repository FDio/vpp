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

#ifndef __vcl_test_h__
#define __vcl_test_h__

#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <vcl/vppcom.h>
#include <vcl/sock_test_common.h>

#define vtfail(_fn, _rv)						\
{									\
  errno = -_rv;								\
  perror ("ERROR when calling " _fn);					\
  fprintf (stderr, "\nERROR: " _fn " failed (errno = %d)!\n", -_rv);	\
  exit (1);								\
}

#define vterr(_fn, _rv)							\
{									\
  errno = -_rv;								\
  fprintf (stderr, "\nERROR: " _fn " failed (errno = %d)!\n", -_rv);	\
}

#define vtwrn(_fmt, _args...)						\
  fprintf (stderr, "\nERROR: " _fmt "\n", ##_args)			\

#define vtinf(_fmt, _args...)						\
  fprintf (stdout, "vt<w%u>: " _fmt "\n", __wrk_index, ##_args)

#define vt_atomic_add(_ptr, _val) 					\
  __atomic_fetch_add (_ptr, _val, __ATOMIC_RELEASE)

static inline int
vcl_test_read (int fd, uint8_t *buf, uint32_t nbytes,
                sock_test_stats_t *stats)
{
  int rx_bytes, errno_val;
  
  do
    {
      if (stats)
        stats->rx_xacts++;
      rx_bytes = vppcom_session_read (fd, buf, nbytes);

      if (rx_bytes < 0)
        {
          errno = -rx_bytes;
          rx_bytes = -1;
        }
      if (stats)
        {
          if ((rx_bytes == 0) ||
              ((rx_bytes < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))))
            stats->rx_eagain++;
          else if (rx_bytes < nbytes)
            stats->rx_incomp++;
        }
    }
  while ((rx_bytes == 0) ||
         ((rx_bytes < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))));
  
  if (rx_bytes < 0)
    {
      vterr ("vppcom_session_read()", -errno);
    }
  else if (stats)
    stats->rx_bytes += rx_bytes;

  return (rx_bytes);
}

static inline int
vcl_test_read_ds (int fd, vppcom_data_segments_t ds, sock_test_stats_t *stats)
{
  int rx_bytes, errno_val;

  do
    {
      if (stats)
        stats->rx_xacts++;
      rx_bytes = vppcom_session_read_segments (fd, ds);

      if (rx_bytes < 0)
        {
          errno = -rx_bytes;
          rx_bytes = -1;
        }
      if (stats)
        {
          if ((rx_bytes == 0) ||
              ((rx_bytes < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))))
            stats->rx_eagain++;
        }
    }
  while ((rx_bytes == 0) ||
         ((rx_bytes < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))));

  if (rx_bytes < 0)
    {
      vterr ("vppcom_session_read()", -errno);
    }
  else if (stats)
    stats->rx_bytes += rx_bytes;

  return (rx_bytes);
}

static inline int
vcl_test_write (int fd, uint8_t *buf, uint32_t nbytes,
                 sock_test_stats_t *stats, uint32_t verbose)
{
  int tx_bytes = 0, nbytes_left = nbytes, rv;

  do
    {
      if (stats)
        stats->tx_xacts++;
      rv = vppcom_session_write (fd, buf, nbytes_left);
      if (rv < 0)
        {
          errno = -rv;
          rv = -1;
        }
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
        }
     
    } while (tx_bytes != nbytes);

  if (tx_bytes < 0)
    {
      vterr ("vpcom_session_write", -errno);
    }
  else if (stats)
    stats->tx_bytes += tx_bytes;
  
  return (tx_bytes);
}

#endif /* __vcl_test_h__ */
