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

#ifndef __sock_test_h__
#define __sock_test_h__

#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define SOCK_TEST_TOKEN_HELP           "#H"
#define SOCK_TEST_TOKEN_EXIT           "#X"
#define SOCK_TEST_TOKEN_VERBOSE        "#V"
#define SOCK_TEST_TOKEN_TXBUF_SIZE     "#T:"
#define SOCK_TEST_TOKEN_NUM_TEST_SCKTS "#I:"
#define SOCK_TEST_TOKEN_NUM_WRITES     "#N:"
#define SOCK_TEST_TOKEN_RXBUF_SIZE     "#R:"
#define SOCK_TEST_TOKEN_SHOW_CFG       "#C"
#define SOCK_TEST_TOKEN_RUN_UNI        "#U"
#define SOCK_TEST_TOKEN_RUN_BI         "#B"

#define SOCK_TEST_BANNER_STRING \
  "============================================\n"
#define SOCK_TEST_SEPARATOR_STRING \
  "  -----------------------------\n"

#define ONE_GIG                       (1024*1024*1024)
#define SOCK_TEST_SERVER_PORT         22000
#define SOCK_TEST_LOCALHOST_IPADDR    "127.0.0.1"

#define SOCK_TEST_CFG_CTRL_MAGIC      0xfeedface
#define SOCK_TEST_CFG_NUM_WRITES_DEF  1000000
#define SOCK_TEST_CFG_TXBUF_SIZE_DEF  8192
#define SOCK_TEST_CFG_RXBUF_SIZE_DEF  (64*SOCK_TEST_CFG_TXBUF_SIZE_DEF)
#define SOCK_TEST_CFG_BUF_SIZE_MIN    128
#define SOCK_TEST_CFG_MAX_TEST_SCKTS  5

typedef enum
{
  SOCK_TEST_TYPE_NONE,
  SOCK_TEST_TYPE_ECHO,
  SOCK_TEST_TYPE_UNI,
  SOCK_TEST_TYPE_BI,
  SOCK_TEST_TYPE_EXIT,
} sock_test_t;

typedef struct  __attribute__ ((packed))
{
  uint32_t magic;
  uint32_t test;
  uint32_t ctrl_handle;
  uint32_t num_test_sockets;
  uint32_t verbose;
  uint64_t rxbuf_size;
  uint64_t txbuf_size;
  uint64_t num_writes;
  uint64_t total_bytes;
} sock_test_cfg_t;

typedef struct
{
  uint64_t rx_xacts;
  uint64_t rx_bytes;
  uint32_t rx_eagain;
  uint32_t rx_incomp;
  uint64_t tx_xacts;
  uint64_t tx_bytes;
  uint32_t tx_eagain;
  uint32_t tx_incomp;
  struct timespec start;
  struct timespec stop;
} sock_test_stats_t;

typedef struct
{
  int fd;
  uint32_t txbuf_size;
  char *txbuf;
  uint32_t rxbuf_size;
  char *rxbuf;
  sock_test_cfg_t cfg;
  sock_test_stats_t stats;
} sock_test_socket_t;

static inline void
sock_test_stats_accumulate (sock_test_stats_t * accum,
                            sock_test_stats_t * incr)
{
  accum->rx_xacts += incr->rx_xacts;
  accum->rx_bytes += incr->rx_bytes;
  accum->rx_eagain += incr->rx_eagain;
  accum->rx_incomp += incr->rx_incomp;
  accum->tx_xacts += incr->tx_xacts;
  accum->tx_bytes += incr->tx_bytes;
  accum->tx_eagain += incr->tx_eagain;
  accum->tx_incomp += incr->tx_incomp;
}

static inline void
sock_test_cfg_init (sock_test_cfg_t *cfg)
{
  cfg->magic = SOCK_TEST_CFG_CTRL_MAGIC;
  cfg->test = SOCK_TEST_TYPE_NONE;
  cfg->ctrl_handle = ~0;
  cfg->num_test_sockets = 1;
  cfg->verbose = 0;
  cfg->rxbuf_size = SOCK_TEST_CFG_RXBUF_SIZE_DEF;
  cfg->num_writes = SOCK_TEST_CFG_NUM_WRITES_DEF;
  cfg->txbuf_size = SOCK_TEST_CFG_TXBUF_SIZE_DEF;
  cfg->total_bytes = cfg->num_writes * cfg->txbuf_size;
}

static inline int
sock_test_cfg_verify (sock_test_cfg_t *cfg, sock_test_cfg_t *valid_cfg)
{
  /* Note: txbuf & rxbuf on server are the same buffer,
   *       so txbuf_size is not included in this check.
   */
  return ((cfg->magic == valid_cfg->magic)
          && (cfg->test == valid_cfg->test)
          && (cfg->verbose == valid_cfg->verbose)
          && (cfg->rxbuf_size == valid_cfg->rxbuf_size)
          && (cfg->num_writes == valid_cfg->num_writes)
          && (cfg->total_bytes == valid_cfg->total_bytes));
}

static inline void
sock_test_buf_alloc (sock_test_cfg_t *cfg, uint8_t is_rxbuf, uint8_t **buf,
                     uint32_t *bufsize)
{
  uint32_t alloc_size = is_rxbuf ? cfg->rxbuf_size : cfg->txbuf_size;
  uint8_t *lb = realloc (*buf, (size_t) alloc_size);

  if (lb)
    {
      if (is_rxbuf)
        cfg->rxbuf_size = *bufsize = alloc_size;
      else
        cfg->txbuf_size = *bufsize = alloc_size;
      
      *buf = lb;
    }
  else
    {
      int errno_val = errno;
      perror ("ERROR in sock_test_buf_alloc()");
      fprintf (stderr, "ERROR: Buffer allocation failed (errno = %d)!\n"
               "       Using buffer size %d instead of desired"
               " size (%d)\n", errno_val, *bufsize, alloc_size);
    }
}

static inline void
sock_test_socket_buf_alloc (sock_test_socket_t *socket)
{
  socket->rxbuf_size = socket->cfg.rxbuf_size;
  socket->txbuf_size = socket->cfg.txbuf_size;
  sock_test_buf_alloc (&socket->cfg, 0 /* is_rxbuf */ ,
		       (uint8_t **) &socket->txbuf, &socket->txbuf_size);
  sock_test_buf_alloc (&socket->cfg, 1 /* is_rxbuf */ ,
		       (uint8_t **) &socket->rxbuf, &socket->rxbuf_size);
}

static inline char *
sock_test_type_str (sock_test_t t)
{
  switch (t)
    {
    case SOCK_TEST_TYPE_NONE:
      return "NONE";

    case SOCK_TEST_TYPE_ECHO:
      return "ECHO";

    case SOCK_TEST_TYPE_UNI:
      return "UNI";

    case SOCK_TEST_TYPE_BI:
      return "BI";

    case SOCK_TEST_TYPE_EXIT:
      return "EXIT";

    default:
      return "Unknown";
    }
}

static inline void
sock_test_cfg_dump (sock_test_cfg_t * cfg, uint8_t is_client)
{
  char *spc = "     ";
  
  printf ("  test config (%p):\n"
          SOCK_TEST_SEPARATOR_STRING
	  "                 magic:  0x%08x\n"
	  "%-5s             test:  %s (%d)\n"
	  "           ctrl handle:  %d (0x%x)\n"
	  "%-5s num test sockets:  %u (0x%08x)\n"
	  "%-5s          verbose:  %s (%d)\n"
	  "%-5s       rxbuf size:  %lu (0x%08lx)\n"
	  "%-5s       txbuf size:  %lu (0x%08lx)\n"
	  "%-5s       num writes:  %lu (0x%08lx)\n"
	  "       client tx bytes:  %lu (0x%08lx)\n"
          SOCK_TEST_SEPARATOR_STRING,
	  (void *) cfg, cfg->magic,
          is_client && (cfg->test == SOCK_TEST_TYPE_UNI) ?
          "'"SOCK_TEST_TOKEN_RUN_UNI"'" :
          is_client && (cfg->test == SOCK_TEST_TYPE_BI) ?
           "'"SOCK_TEST_TOKEN_RUN_BI"'" : spc,
          sock_test_type_str (cfg->test), cfg->test,
          cfg->ctrl_handle, cfg->ctrl_handle,
          is_client ? "'"SOCK_TEST_TOKEN_NUM_TEST_SCKTS"'" : spc,
          cfg->num_test_sockets, cfg->num_test_sockets,
          is_client ? "'"SOCK_TEST_TOKEN_VERBOSE"'" : spc,
          cfg->verbose ? "on" : "off", cfg->verbose,
          is_client ? "'"SOCK_TEST_TOKEN_RXBUF_SIZE"'" : spc,
          cfg->rxbuf_size, cfg->rxbuf_size,
          is_client ? "'"SOCK_TEST_TOKEN_TXBUF_SIZE"'" : spc,
          cfg->txbuf_size, cfg->txbuf_size,
          is_client ? "'"SOCK_TEST_TOKEN_NUM_WRITES"'" : spc,
          cfg->num_writes, cfg->num_writes,
          cfg->total_bytes, cfg->total_bytes);
}

static inline void
sock_test_stats_dump (char * header, sock_test_stats_t * stats,
                      uint8_t show_rx, uint8_t show_tx,
                      uint8_t verbose)
{
  struct timespec diff;
  double duration, rate;
  uint64_t total_bytes;
  
  if ((stats->stop.tv_nsec - stats->start.tv_nsec) < 0)
    {
      diff.tv_sec = stats->stop.tv_sec - stats->start.tv_sec - 1;
      diff.tv_nsec = stats->stop.tv_nsec - stats->start.tv_nsec + 1000000000;
    }
  else
    {
      diff.tv_sec = stats->stop.tv_sec - stats->start.tv_sec;
      diff.tv_nsec = stats->stop.tv_nsec - stats->start.tv_nsec;
    }
  duration = (double) diff.tv_sec + (1e-9 * diff.tv_nsec);

  total_bytes = stats->tx_bytes + stats->rx_bytes;
  rate = (double) total_bytes * 8 / duration / ONE_GIG;
  printf ("\n%s: Streamed %lu bytes\n"
          "  in %lf seconds (%lf Gbps %s-duplex)!\n",
              header, total_bytes, duration, rate,
          (show_rx && show_tx) ? "full" : "half");

  if (show_tx)
    {
      printf (SOCK_TEST_SEPARATOR_STRING
              "  tx stats (0x%p):\n"
              SOCK_TEST_SEPARATOR_STRING
              "         writes:  %lu (0x%08lx)\n"
              "       tx bytes:  %lu (0x%08lx)\n"
              "      tx eagain:  %u (0x%08x)\n"
              "  tx incomplete:  %u (0x%08x)\n",
              (void *)stats, stats->tx_xacts, stats->tx_xacts,
              stats->tx_bytes, stats->tx_bytes,
              stats->tx_eagain, stats->tx_eagain,
              stats->tx_incomp, stats->tx_incomp);
    }
  if (show_rx)
    {
      printf (SOCK_TEST_SEPARATOR_STRING
              "  rx stats (0x%p):\n"
              SOCK_TEST_SEPARATOR_STRING
              "          reads:  %lu (0x%08lx)\n"
              "       rx bytes:  %lu (0x%08lx)\n"
              "      rx eagain:  %u (0x%08x)\n"
              "  rx incomplete:  %u (0x%08x)\n",
              (void *)stats, stats->rx_xacts, stats->rx_xacts,
              stats->rx_bytes, stats->rx_bytes,
              stats->rx_eagain, stats->rx_eagain,
              stats->rx_incomp, stats->rx_incomp);
    }
  if (verbose)
    printf ("   start.tv_sec:  %ld\n"
            "  start.tv_nsec:  %ld\n"
            "    stop.tv_sec:  %ld\n"
            "   stop.tv_nsec:  %ld\n",
            stats->start.tv_sec, stats->start.tv_nsec,
            stats->stop.tv_sec, stats->stop.tv_nsec);
            
  printf (SOCK_TEST_SEPARATOR_STRING);
}

static inline int
sock_test_read (int fd, uint8_t *buf, uint32_t nbytes,
                sock_test_stats_t *stats)
{
  int rx_bytes, errno_val;
  
  do
    {
      if (stats)
        stats->rx_xacts++;
#ifdef VCL_TEST
      rx_bytes = vppcom_session_read (fd, buf, nbytes);

      if (rx_bytes < 0)
        {
          errno = -rx_bytes;
          rx_bytes = -1;
        }
#else
      rx_bytes = read (fd, buf, nbytes);
#endif
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
      errno_val = errno;
      perror ("ERROR in sock_test_read()");
      fprintf (stderr, "ERROR: socket read failed (errno = %d)!\n",
               errno_val);
      errno = errno_val;
    }
  else if (stats)
    stats->rx_bytes += rx_bytes;

  return (rx_bytes);
}

static inline int
sock_test_write (int fd, uint8_t *buf, uint32_t nbytes,
                 sock_test_stats_t *stats, uint32_t verbose)
{
  int tx_bytes = 0;
  int nbytes_left = nbytes;
  int rv, errno_val;

  do
    {
      if (stats)
        stats->tx_xacts++;
#ifdef VCL_TEST
      rv = vppcom_session_write (fd, buf, nbytes_left);
      if (rv < 0)
        {
          errno = -rv;
          rv = -1;
        }
#else
      rv = write (fd, buf, nbytes_left);
#endif
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
              printf ("WARNING: bytes written (%d) != bytes to write (%d)!\n",
                      tx_bytes, nbytes);
            }
        }
     
    } while (tx_bytes != nbytes);

  if (tx_bytes < 0)
    {
      errno_val = errno;
      perror ("ERROR in sock_test_write()");
      fprintf (stderr, "ERROR: socket write failed (errno = %d)!\n",
               errno_val);
    }
  else if (stats)
    stats->tx_bytes += tx_bytes;
  
  return (tx_bytes);
}

#endif /* __sock_test_h__ */
