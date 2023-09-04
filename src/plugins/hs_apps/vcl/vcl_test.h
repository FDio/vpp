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

#include <hs_apps/hs_test.h>
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

#define VCL_TEST_SERVER_PORT         	22000
#define VCL_TEST_LOCALHOST_IPADDR    	"127.0.0.1"

#define VCL_TEST_CFG_BUF_SIZE_MIN    	128
#define VCL_TEST_CFG_MAX_TEST_SESS	((uint32_t) 1e6)
#define VCL_TEST_CFG_MAX_SELECT_SESS	512
#define VCL_TEST_CFG_INIT_TEST_SESS	512
#define VCL_TEST_CFG_MAX_EPOLL_EVENTS 	16

#define VCL_TEST_CTRL_LISTENER		(~0 - 1)
#define VCL_TEST_DATA_LISTENER		(~0)
#define VCL_TEST_DELAY_DISCONNECT	1

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
  uint8_t is_done;
  uint8_t is_alloc : 1;
  uint8_t is_open : 1;
  uint8_t noblk_connect : 1;
  int fd;
  int (*read) (struct vcl_test_session *ts, void *buf, uint32_t buflen);
  int (*write) (struct vcl_test_session *ts, void *buf, uint32_t buflen);
  uint32_t txbuf_size;
  uint32_t rxbuf_size;
  char *txbuf;
  char *rxbuf;
  hs_test_cfg_t cfg;
  vcl_test_stats_t stats;
  vcl_test_stats_t old_stats;
  int session_index;
  struct vcl_test_session *next;
  vppcom_endpt_t endpt;
  uint8_t ip[16];
  vppcom_data_segment_t ds[2];
  void *opaque;
} vcl_test_session_t;

static __thread int __wrk_index = 0;

static inline int
vcl_test_worker_index (void)
{
  return __wrk_index;
}

typedef struct
{
  int (*init) (hs_test_cfg_t *cfg);
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
  const vcl_test_proto_vft_t *protos[VPPCOM_PROTO_SRTP + 1];
  uint32_t ckpair_index;
  hs_test_cfg_t cfg;
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
vcl_test_buf_alloc (hs_test_cfg_t *cfg, uint8_t is_rxbuf, uint8_t **buf,
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
      printf (HS_TEST_SEPARATOR_STRING
	      "  tx stats (0x%p):\n" HS_TEST_SEPARATOR_STRING
	      "         writes:  %lu (0x%08lx)\n"
	      "       tx bytes:  %lu (0x%08lx)\n"
	      "      tx eagain:  %u (0x%08x)\n"
	      "  tx incomplete:  %u (0x%08x)\n",
	      (void *) stats, stats->tx_xacts, stats->tx_xacts,
	      stats->tx_bytes, stats->tx_bytes, stats->tx_eagain,
	      stats->tx_eagain, stats->tx_incomp, stats->tx_incomp);
    }
  if (show_rx)
    {
      printf (HS_TEST_SEPARATOR_STRING
	      "  rx stats (0x%p):\n" HS_TEST_SEPARATOR_STRING
	      "          reads:  %lu (0x%08lx)\n"
	      "       rx bytes:  %lu (0x%08lx)\n"
	      "      rx eagain:  %u (0x%08x)\n"
	      "  rx incomplete:  %u (0x%08x)\n",
	      (void *) stats, stats->rx_xacts, stats->rx_xacts,
	      stats->rx_bytes, stats->rx_bytes, stats->rx_eagain,
	      stats->rx_eagain, stats->rx_incomp, stats->rx_incomp);
    }
  if (verbose)
    printf ("   start.tv_sec:  %ld\n"
	    "  start.tv_nsec:  %ld\n"
	    "    stop.tv_sec:  %ld\n"
	    "   stop.tv_nsec:  %ld\n",
	    stats->start.tv_sec, stats->start.tv_nsec,
	    stats->stop.tv_sec, stats->stop.tv_nsec);

  printf (HS_TEST_SEPARATOR_STRING);
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

  printf (
    "CLIENT: Test configuration commands:" INDENT VCL_TEST_TOKEN_HELP
    "\t\t\tDisplay help." INDENT VCL_TEST_TOKEN_EXIT
    "\t\t\tExit test client & server." INDENT VCL_TEST_TOKEN_SHOW_CFG
    "\t\t\tShow the current test cfg." INDENT HS_TEST_TOKEN_RUN_UNI
    "\t\t\tRun the Uni-directional test." INDENT HS_TEST_TOKEN_RUN_BI
    "\t\t\tRun the Bi-directional test." INDENT VCL_TEST_TOKEN_VERBOSE
    "\t\t\tToggle verbose setting." INDENT VCL_TEST_TOKEN_RXBUF_SIZE
    "<rxbuf size>\tRx buffer size (bytes)." INDENT VCL_TEST_TOKEN_TXBUF_SIZE
    "<txbuf size>\tTx buffer size (bytes)." INDENT VCL_TEST_TOKEN_NUM_WRITES
    "<# of writes>\tNumber of txbuf writes to server."
    "\n");
}

#endif /* __vcl_test_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
