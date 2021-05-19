/*
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
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
#include <stdio.h>
#include <string.h>
#include <vcl/vppcom.h>

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

#define VCL_TEST_TOKEN_HELP           	"#H"
#define VCL_TEST_TOKEN_EXIT           	"#X"
#define VCL_TEST_TOKEN_VERBOSE        	"#V"
#define VCL_TEST_TOKEN_TXBUF_SIZE     	"#T:"
#define VCL_TEST_TOKEN_NUM_TEST_SESS 	"#I:"
#define VCL_TEST_TOKEN_NUM_WRITES     	"#N:"
#define VCL_TEST_TOKEN_RXBUF_SIZE     	"#R:"
#define VCL_TEST_TOKEN_SHOW_CFG       	"#C"
#define VCL_TEST_TOKEN_RUN_UNI        	"#U"
#define VCL_TEST_TOKEN_RUN_BI         	"#B"

#define VCL_TEST_SERVER_PORT         	22000
#define VCL_TEST_LOCALHOST_IPADDR    	"127.0.0.1"

#define VCL_TEST_CFG_CTRL_MAGIC      	0xfeedface
#define VCL_TEST_CFG_NUM_WRITES_DEF  	1000000
#define VCL_TEST_CFG_TXBUF_SIZE_DEF  	8192
#define VCL_TEST_CFG_RXBUF_SIZE_DEF  	(64*VCL_TEST_CFG_TXBUF_SIZE_DEF)
#define VCL_TEST_CFG_BUF_SIZE_MIN    	128
#define VCL_TEST_CFG_MAX_TEST_SESS	512
#define VCL_TEST_CFG_MAX_EPOLL_EVENTS 	16

#define VCL_TEST_CTRL_LISTENER		(~0 - 1)
#define VCL_TEST_DATA_LISTENER		(~0)
#define VCL_TEST_DELAY_DISCONNECT	1
#define VCL_TEST_SEPARATOR_STRING 	\
  "  -----------------------------\n"
typedef enum
{
  VCL_TEST_TYPE_NONE,
  VCL_TEST_TYPE_ECHO,
  VCL_TEST_TYPE_UNI,
  VCL_TEST_TYPE_BI,
  VCL_TEST_TYPE_EXIT,
} vcl_test_t;

typedef enum
{
  VCL_TEST_CMD_SYNC,
  VCL_TEST_CMD_START,
  VCL_TEST_CMD_STOP,
} vcl_test_cmd_t;

typedef struct __attribute__ ((packed))
{
  uint32_t magic;
  uint32_t seq_num;
  uint32_t test;
  uint32_t cmd;
  uint32_t ctrl_handle;
  uint32_t num_test_sessions;
  uint32_t num_test_sessions_perq;
  uint32_t num_test_qsessions;
  uint32_t verbose;
  uint32_t address_ip6;
  uint32_t transport_udp;
  uint64_t rxbuf_size;
  uint64_t txbuf_size;
  uint64_t num_writes;
  uint64_t total_bytes;
} vcl_test_cfg_t;

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
} vcl_test_stats_t;

typedef struct vcl_test_session
{
  uint8_t is_alloc;
  uint8_t is_open;
  uint8_t is_done;
  int fd;
  int (*read) (struct vcl_test_session *ts, void *buf, uint32_t buflen);
  int (*write) (struct vcl_test_session *ts, void *buf, uint32_t buflen);
  uint32_t txbuf_size;
  uint32_t rxbuf_size;
  char *txbuf;
  char *rxbuf;
  vcl_test_cfg_t cfg;
  vcl_test_stats_t stats;
  vcl_test_stats_t old_stats;
  int session_index;
  vppcom_endpt_t endpt;
  uint8_t ip[16];
  vppcom_data_segment_t ds[2];
} vcl_test_session_t;

static __thread int __wrk_index = 0;

static inline int
vcl_test_worker_index (void)
{
  return __wrk_index;
}

typedef struct
{
  int (*init) (vcl_test_cfg_t *cfg);
  int (*open) (vcl_test_session_t *ts, vppcom_endpt_t *endpt);
  int (*listen) (vcl_test_session_t *ts, vppcom_endpt_t *endpt);
  int (*accept) (int listen_fd, vcl_test_session_t *ts);
  int (*close) (vcl_test_session_t *ts);
} vcl_test_proto_vft_t;

typedef struct
{
  vcl_test_session_t *qsessions;
  uint32_t n_qsessions;
  uint32_t n_sessions;
} vcl_test_wrk_t;

typedef struct
{
  const vcl_test_proto_vft_t *protos[VPPCOM_PROTO_DTLS + 1];
  uint32_t ckpair_index;
  vcl_test_cfg_t cfg;
  vcl_test_wrk_t *wrk;
} vcl_test_main_t;

extern vcl_test_main_t vcl_test_main;

#define VCL_TEST_REGISTER_PROTO(proto, vft)                                   \
  static void __attribute__ ((constructor)) vcl_test_init_##proto (void)      \
  {                                                                           \
    vcl_test_main.protos[proto] = &vft;                                       \
  }

static inline void
vcl_test_stats_accumulate (vcl_test_stats_t * accum, vcl_test_stats_t * incr)
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
vcl_test_cfg_init (vcl_test_cfg_t * cfg)
{
  cfg->magic = VCL_TEST_CFG_CTRL_MAGIC;
  cfg->test = VCL_TEST_TYPE_NONE;
  cfg->ctrl_handle = ~0;
  cfg->num_test_sessions = 1;
  cfg->num_test_sessions_perq = 1;
  cfg->verbose = 0;
  cfg->rxbuf_size = VCL_TEST_CFG_RXBUF_SIZE_DEF;
  cfg->num_writes = VCL_TEST_CFG_NUM_WRITES_DEF;
  cfg->txbuf_size = VCL_TEST_CFG_TXBUF_SIZE_DEF;
  cfg->total_bytes = cfg->num_writes * cfg->txbuf_size;
}

static inline int
vcl_test_cfg_verify (vcl_test_cfg_t * cfg, vcl_test_cfg_t * valid_cfg)
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
vcl_test_buf_alloc (vcl_test_cfg_t * cfg, uint8_t is_rxbuf, uint8_t ** buf,
		    uint32_t * bufsize)
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
      vtwrn ("realloc failed. using buffer size %d instead of %u",
	     *bufsize, alloc_size);
    }
}

static inline void
vcl_test_session_buf_alloc (vcl_test_session_t *ts)
{
  ts->rxbuf_size = ts->cfg.rxbuf_size;
  ts->txbuf_size = ts->cfg.txbuf_size;
  vcl_test_buf_alloc (&ts->cfg, 0 /* is_rxbuf */, (uint8_t **) &ts->txbuf,
		      &ts->txbuf_size);
  vcl_test_buf_alloc (&ts->cfg, 1 /* is_rxbuf */, (uint8_t **) &ts->rxbuf,
		      &ts->rxbuf_size);
}

static inline void
vcl_test_session_buf_free (vcl_test_session_t *ts)
{
  free (ts->rxbuf);
  free (ts->txbuf);
  ts->rxbuf = 0;
  ts->txbuf = 0;
}

static inline char *
vcl_test_type_str (vcl_test_t t)
{
  switch (t)
    {
    case VCL_TEST_TYPE_NONE:
      return "NONE";

    case VCL_TEST_TYPE_ECHO:
      return "ECHO";

    case VCL_TEST_TYPE_UNI:
      return "UNI";

    case VCL_TEST_TYPE_BI:
      return "BI";

    case VCL_TEST_TYPE_EXIT:
      return "EXIT";

    default:
      return "Unknown";
    }
}

static inline void
vcl_test_cfg_dump (vcl_test_cfg_t * cfg, uint8_t is_client)
{
  char *spc = "     ";

  printf ("  test config (%p):\n"
	  VCL_TEST_SEPARATOR_STRING
	  "                 magic:  0x%08x\n"
	  "               seq_num:  0x%08x\n"
	  "%-5s             test:  %s (%d)\n"
	  "           ctrl handle:  %d (0x%x)\n"
	  "%-5s num test sockets:  %u (0x%08x)\n"
	  "%-5s          verbose:  %s (%d)\n"
	  "%-5s       rxbuf size:  %lu (0x%08lx)\n"
	  "%-5s       txbuf size:  %lu (0x%08lx)\n"
	  "%-5s       num writes:  %lu (0x%08lx)\n"
	  "       client tx bytes:  %lu (0x%08lx)\n"
	  VCL_TEST_SEPARATOR_STRING,
	  (void *) cfg, cfg->magic, cfg->seq_num,
	  is_client && (cfg->test == VCL_TEST_TYPE_UNI) ?
	  "'" VCL_TEST_TOKEN_RUN_UNI "'" :
	  is_client && (cfg->test == VCL_TEST_TYPE_BI) ?
	  "'" VCL_TEST_TOKEN_RUN_BI "'" : spc,
	  vcl_test_type_str (cfg->test), cfg->test,
	  cfg->ctrl_handle, cfg->ctrl_handle,
	  is_client ? "'" VCL_TEST_TOKEN_NUM_TEST_SESS "'" : spc,
	  cfg->num_test_sessions, cfg->num_test_sessions,
	  is_client ? "'" VCL_TEST_TOKEN_VERBOSE "'" : spc,
	  cfg->verbose ? "on" : "off", cfg->verbose,
	  is_client ? "'" VCL_TEST_TOKEN_RXBUF_SIZE "'" : spc,
	  cfg->rxbuf_size, cfg->rxbuf_size,
	  is_client ? "'" VCL_TEST_TOKEN_TXBUF_SIZE "'" : spc,
	  cfg->txbuf_size, cfg->txbuf_size,
	  is_client ? "'" VCL_TEST_TOKEN_NUM_WRITES "'" : spc,
	  cfg->num_writes, cfg->num_writes,
	  cfg->total_bytes, cfg->total_bytes);
}

static inline void
vcl_test_stats_dump (char *header, vcl_test_stats_t * stats,
		     uint8_t show_rx, uint8_t show_tx, uint8_t verbose)
{
  struct timespec diff;
  double duration, rate;
  uint64_t total_bytes;

  if ((stats->stop.tv_nsec - stats->start.tv_nsec) < 0)
    {
      diff.tv_sec = stats->stop.tv_sec - stats->start.tv_sec - 1;
      diff.tv_nsec = stats->stop.tv_nsec - stats->start.tv_nsec + 1e9;
    }
  else
    {
      diff.tv_sec = stats->stop.tv_sec - stats->start.tv_sec;
      diff.tv_nsec = stats->stop.tv_nsec - stats->start.tv_nsec;
    }
  duration = (double) diff.tv_sec + (1e-9 * diff.tv_nsec);

  total_bytes = stats->tx_bytes + stats->rx_bytes;
  rate = (double) total_bytes *8 / duration / 1e9;
  printf ("\n%s: Streamed %lu bytes\n"
	  "  in %lf seconds (%lf Gbps %s-duplex)!\n",
	  header, total_bytes, duration, rate,
	  (show_rx && show_tx) ? "full" : "half");

  if (show_tx)
    {
      printf (VCL_TEST_SEPARATOR_STRING
	      "  tx stats (0x%p):\n"
	      VCL_TEST_SEPARATOR_STRING
	      "         writes:  %lu (0x%08lx)\n"
	      "       tx bytes:  %lu (0x%08lx)\n"
	      "      tx eagain:  %u (0x%08x)\n"
	      "  tx incomplete:  %u (0x%08x)\n",
	      (void *) stats, stats->tx_xacts, stats->tx_xacts,
	      stats->tx_bytes, stats->tx_bytes,
	      stats->tx_eagain, stats->tx_eagain,
	      stats->tx_incomp, stats->tx_incomp);
    }
  if (show_rx)
    {
      printf (VCL_TEST_SEPARATOR_STRING
	      "  rx stats (0x%p):\n"
	      VCL_TEST_SEPARATOR_STRING
	      "          reads:  %lu (0x%08lx)\n"
	      "       rx bytes:  %lu (0x%08lx)\n"
	      "      rx eagain:  %u (0x%08x)\n"
	      "  rx incomplete:  %u (0x%08x)\n",
	      (void *) stats, stats->rx_xacts, stats->rx_xacts,
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

  printf (VCL_TEST_SEPARATOR_STRING);
}

static inline double
vcl_test_time_diff (struct timespec *old, struct timespec *new)
{
  uint64_t sec, nsec;
  if ((new->tv_nsec - old->tv_nsec) < 0)
    {
      sec = new->tv_sec - old->tv_sec - 1;
      nsec = new->tv_nsec - old->tv_nsec + 1e9;
    }
  else
    {
      sec = new->tv_sec - old->tv_sec;
      nsec = new->tv_nsec - old->tv_nsec;
    }
  return (double) sec + (1e-9 * nsec);
}

static inline void
vcl_test_stats_dump_inc (vcl_test_session_t *ts, int is_rx)
{
  vcl_test_stats_t *old, *new;
  double duration, rate;
  uint64_t total_bytes;
  char *dir_str;

  old = &ts->old_stats;
  new = &ts->stats;
  duration = vcl_test_time_diff (&old->stop, &new->stop);

  if (is_rx)
    {
      total_bytes = new->rx_bytes - old->rx_bytes;
      dir_str = "Received";
    }
  else
    {
      total_bytes = new->tx_bytes - old->tx_bytes;
      dir_str = "Sent";
    }

  rate = (double) total_bytes * 8 / duration / 1e9;
  printf ("%d: %s %lu Mbytes in %.2lf seconds %.2lf Gbps\n", ts->fd, dir_str,
	  (uint64_t) (total_bytes / 1e6), duration, rate);
}

static inline int
vcl_comp_tspec (struct timespec *a, struct timespec *b)
{
  if (a->tv_sec < b->tv_sec)
    return -1;
  else if (a->tv_sec > b->tv_sec)
    return 1;
  else if (a->tv_nsec < b->tv_nsec)
    return -1;
  else if (a->tv_nsec > b->tv_nsec)
    return 1;
  else
    return 0;
}

static inline int
vcl_test_read (vcl_test_session_t *ts, void *buf, uint32_t nbytes)
{
  vcl_test_stats_t *stats = &ts->stats;
  int rv, rx_bytes = 0;

  do
    {
      stats->rx_xacts++;
      rv = vppcom_session_read (ts->fd, buf, nbytes);
      if (rv <= 0)
	{
	  errno = -rv;
	  if (errno == EAGAIN || errno == EWOULDBLOCK)
	    {
	      stats->rx_eagain++;
	      continue;
	    }

	  vterr ("vppcom_session_read()", -errno);
	  break;
	}

      rx_bytes = rv;
      if (rv < nbytes)
	stats->rx_incomp++;
    }
  while (!rx_bytes);

  stats->rx_bytes += rx_bytes;

  return (rx_bytes);
}

static inline int
vcl_test_read_ds (vcl_test_session_t *ts)
{
  vcl_test_stats_t *stats = &ts->stats;
  int rx_bytes;

  do
    {
      stats->rx_xacts++;
      rx_bytes = vppcom_session_read_segments (ts->fd, ts->ds, 2, ~0);

      if (rx_bytes < 0)
	{
	  errno = -rx_bytes;
	  rx_bytes = -1;
	}
	  if ((rx_bytes == 0) ||
	      ((rx_bytes < 0)
	       && ((errno == EAGAIN) || (errno == EWOULDBLOCK))))
	    stats->rx_eagain++;
    }
  while ((rx_bytes == 0) ||
	 ((rx_bytes < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))));

  if (rx_bytes < 0)
    {
      vterr ("vppcom_session_read()", -errno);
    }
  else
    stats->rx_bytes += rx_bytes;

  return (rx_bytes);
}

static inline int
vcl_test_write (vcl_test_session_t *ts, void *buf, uint32_t nbytes)
{
  int tx_bytes = 0, nbytes_left = nbytes, rv;
  vcl_test_stats_t *stats = &ts->stats;

  do
    {
      stats->tx_xacts++;
      rv = vppcom_session_write (ts->fd, buf, nbytes_left);
      if (rv < 0)
	{
	  errno = -rv;
	  if ((errno == EAGAIN || errno == EWOULDBLOCK))
	    stats->tx_eagain++;
	  break;
	}
      tx_bytes += rv;

      nbytes_left = nbytes_left - rv;
      buf += rv;
      if (rv < nbytes_left)
	stats->tx_incomp++;
    }
  while (tx_bytes != nbytes);

  if (tx_bytes < 0)
    {
      vterr ("vpcom_session_write", -errno);
    }
  else
    stats->tx_bytes += tx_bytes;

  return (tx_bytes);
}

static inline void
dump_help (void)
{
#define INDENT "\n  "

  printf ("CLIENT: Test configuration commands:"
	  INDENT VCL_TEST_TOKEN_HELP
	  "\t\t\tDisplay help."
	  INDENT VCL_TEST_TOKEN_EXIT
	  "\t\t\tExit test client & server."
	  INDENT VCL_TEST_TOKEN_SHOW_CFG
	  "\t\t\tShow the current test cfg."
	  INDENT VCL_TEST_TOKEN_RUN_UNI
	  "\t\t\tRun the Uni-directional test."
	  INDENT VCL_TEST_TOKEN_RUN_BI
	  "\t\t\tRun the Bi-directional test."
	  INDENT VCL_TEST_TOKEN_VERBOSE
	  "\t\t\tToggle verbose setting."
	  INDENT VCL_TEST_TOKEN_RXBUF_SIZE
	  "<rxbuf size>\tRx buffer size (bytes)."
	  INDENT VCL_TEST_TOKEN_TXBUF_SIZE
	  "<txbuf size>\tTx buffer size (bytes)."
	  INDENT VCL_TEST_TOKEN_NUM_WRITES
	  "<# of writes>\tNumber of txbuf writes to server." "\n");
}

#endif /* __vcl_test_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
