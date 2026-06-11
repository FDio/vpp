/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
 */

#ifndef __vperf_h__
#define __vperf_h__

#include <vperf/vperf_test.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vcl/vppcom.h>

#define vperf_fail(_fn, _rv)                                                                       \
  {                                                                                                \
    errno = -_rv;                                                                                  \
    perror ("ERROR when calling " _fn);                                                            \
    fprintf (stderr, "\nERROR: " _fn " failed (errno = %d)!\n", -_rv);                             \
    exit (1);                                                                                      \
  }

#define vperf_err(_fn, _rv)                                                                        \
  {                                                                                                \
    errno = -_rv;                                                                                  \
    fprintf (stderr, "\nERROR: " _fn " failed (errno = %d)!\n", -_rv);                             \
  }

#define vperf_warn(_fmt, _args...) fprintf (stderr, "\nERROR: " _fmt "\n", ##_args)

#define vperf_info(_fmt, _args...) fprintf (stdout, "vt<w%u>: " _fmt "\n", __wrk_index, ##_args)

#define vperf_atomic_add(_ptr, _val) __atomic_fetch_add (_ptr, _val, __ATOMIC_RELEASE)

#define VPERF_SERVER_PORT      22000
#define VPERF_LOCALHOST_IPADDR "127.0.0.1"

#define VPERF_CFG_BUF_SIZE_MIN	   128
#define VPERF_CFG_MAX_TEST_SESS	   ((uint32_t) 1e6)
#define VPERF_CFG_MAX_SELECT_SESS  512
#define VPERF_CFG_INIT_TEST_SESS   512
#define VPERF_CFG_MAX_EPOLL_EVENTS 16

#define VPERF_CTRL_LISTENER    (~0 - 1)
#define VPERF_DATA_LISTENER    (~0)
#define VPERF_DELAY_DISCONNECT 1

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
  uint32_t reset_count; /* received reset from vpp */
  uint32_t close_count; /* received close from vpp */
  struct timespec start;
  struct timespec stop;
} vperf_stats_t;

typedef struct vperf_session
{
  uint8_t is_done;
  uint8_t is_alloc : 1;
  uint8_t is_open : 1;
  uint8_t noblk_connect : 1;
  int fd;
  int (*read) (struct vperf_session *ts, void *buf, uint32_t buflen);
  int (*write) (struct vperf_session *ts, void *buf, uint32_t buflen);
  int (*done) (struct vperf_session *ts, uint8_t check_rx);
  uint32_t txbuf_size;
  uint32_t rxbuf_size;
  char *txbuf;
  char *rxbuf;
  vperf_cfg_t cfg;
  vperf_stats_t stats;
  vperf_stats_t old_stats;
  int session_index;
  struct vperf_session *next;
  struct vperf_session *prev;
  vppcom_endpt_t endpt;
  uint8_t ip[16];
  vppcom_data_segment_t ds[2];
  void *opaque;
} vperf_session_t;

static __thread int __wrk_index = 0;

static inline int
vperf_worker_index (void)
{
  return __wrk_index;
}

typedef struct
{
  int (*init) (vperf_cfg_t *cfg);
  int (*open) (vperf_session_t *ts, vppcom_endpt_t *endpt);
  int (*listen) (vperf_session_t *ts, vppcom_endpt_t *endpt);
  int (*accept) (int listen_fd, vperf_session_t *ts);
  int (*cleanup) (vperf_session_t *ts);
  int (*close) (vperf_session_t *ts, uint32_t events);
  int (*reset) (vperf_session_t *ts);
} vperf_proto_vft_t;

typedef struct
{
  vperf_session_t *qsessions;
  uint32_t n_qsessions;
  uint32_t n_sessions;
} vperf_wrk_t;

typedef enum
{
  VPERF_RX_DATA_SOURCE,
  VPERF_TEST_DATA_SOURCE,
} vperf_data_source_t;

typedef struct
{
  const vperf_proto_vft_t *protos[VPPCOM_PROTO_HTTP + 1];
  uint32_t ckpair_index;
  vperf_cfg_t cfg;
  vperf_wrk_t *wrk;
  vperf_data_source_t server_data_source;
} vperf_main_t;

extern vperf_main_t vperf_main;

#define VPERF_REGISTER_PROTO(proto, vft)                                                           \
  static void __attribute__ ((constructor)) vperf_init_##proto (void)                              \
  {                                                                                                \
    vperf_main.protos[proto] = &vft;                                                               \
  }

static inline void
vperf_stats_accumulate (vperf_stats_t *accum, vperf_stats_t *incr)
{
  accum->rx_xacts += incr->rx_xacts;
  accum->rx_bytes += incr->rx_bytes;
  accum->rx_eagain += incr->rx_eagain;
  accum->rx_incomp += incr->rx_incomp;
  accum->tx_xacts += incr->tx_xacts;
  accum->tx_bytes += incr->tx_bytes;
  accum->tx_eagain += incr->tx_eagain;
  accum->tx_incomp += incr->tx_incomp;
  accum->reset_count += incr->reset_count;
  accum->close_count += incr->close_count;
}

static inline void
vperf_buf_alloc (vperf_cfg_t *cfg, uint8_t is_rxbuf, uint8_t **buf, uint32_t *bufsize)
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
      vperf_warn ("realloc failed. using buffer size %d instead of %u", *bufsize, alloc_size);
    }
}

static inline void
vperf_session_buf_alloc (vperf_session_t *ts)
{
  ts->rxbuf_size = ts->cfg.rxbuf_size;
  ts->txbuf_size = ts->cfg.txbuf_size;
  vperf_buf_alloc (&ts->cfg, 0 /* is_rxbuf */, (uint8_t **) &ts->txbuf, &ts->txbuf_size);
  vperf_buf_alloc (&ts->cfg, 1 /* is_rxbuf */, (uint8_t **) &ts->rxbuf, &ts->rxbuf_size);
}

static inline void
vperf_session_buf_free (vperf_session_t *ts)
{
  free (ts->rxbuf);
  free (ts->txbuf);
  ts->rxbuf = 0;
  ts->txbuf = 0;
}

static inline void
vperf_stats_dump (char *header, vperf_stats_t *stats, uint8_t show_rx, uint8_t show_tx,
		  uint8_t verbose)
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
      printf (VPERF_SEPARATOR_STRING "  tx stats (0x%p):\n" VPERF_SEPARATOR_STRING
				     "         writes:  %lu (0x%08lx)\n"
				     "       tx bytes:  %lu (0x%08lx)\n"
				     "      tx eagain:  %u (0x%08x)\n"
				     "  tx incomplete:  %u (0x%08x)\n",
	      (void *) stats, stats->tx_xacts, stats->tx_xacts, stats->tx_bytes, stats->tx_bytes,
	      stats->tx_eagain, stats->tx_eagain, stats->tx_incomp, stats->tx_incomp);
    }
  if (show_rx)
    {
      printf (VPERF_SEPARATOR_STRING "  rx stats (0x%p):\n" VPERF_SEPARATOR_STRING
				     "          reads:  %lu (0x%08lx)\n"
				     "       rx bytes:  %lu (0x%08lx)\n"
				     "      rx eagain:  %u (0x%08x)\n"
				     "  rx incomplete:  %u (0x%08x)\n",
	      (void *) stats, stats->rx_xacts, stats->rx_xacts, stats->rx_bytes, stats->rx_bytes,
	      stats->rx_eagain, stats->rx_eagain, stats->rx_incomp, stats->rx_incomp);
    }
  printf ("    reset count:  %u\n", stats->reset_count);
  printf ("    close count:  %u\n", stats->close_count);
  if (verbose)
    printf ("   start.tv_sec:  %ld\n"
	    "  start.tv_nsec:  %ld\n"
	    "    stop.tv_sec:  %ld\n"
	    "   stop.tv_nsec:  %ld\n",
	    stats->start.tv_sec, stats->start.tv_nsec,
	    stats->stop.tv_sec, stats->stop.tv_nsec);

  printf (VPERF_SEPARATOR_STRING);
}

static inline double
vperf_time_diff (struct timespec *old, struct timespec *new)
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
vperf_stats_dump_inc (vperf_session_t *ts, int is_rx)
{
  vperf_stats_t *old, *new;
  double duration, rate;
  uint64_t total_bytes;
  char *dir_str;

  old = &ts->old_stats;
  new = &ts->stats;
  duration = vperf_time_diff (&old->stop, &new->stop);

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
vperf_close_nop (vperf_session_t *ts, uint32_t events)
{
  /* just signal that we can close session */
  return 1;
}

static inline int
vperf_reset_nop (vperf_session_t *ts)
{
  /* just signal that this was not expected (error) */
  ts->stats.reset_count = 1;
  return 1;
}

static inline int
vperf_is_done (vperf_session_t *ts, uint8_t check_rx)
{
  if ((!check_rx && ts->stats.tx_bytes >= ts->cfg.total_bytes) ||
      (check_rx && ts->stats.rx_bytes >= ts->cfg.total_bytes))
    {
      clock_gettime (CLOCK_REALTIME, &ts->stats.stop);
      ts->is_done = 1;
      return 1;
    }
  return 0;
}

static inline int
vperf_read (vperf_session_t *ts, void *buf, uint32_t nbytes)
{
  vperf_stats_t *stats = &ts->stats;
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

	  vperf_err ("vppcom_session_read()", -errno);
	  return -1;
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
vperf_read_ds (vperf_session_t *ts)
{
  vperf_stats_t *stats = &ts->stats;
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
      vperf_err ("vppcom_session_read()", -errno);
    }
  else
    stats->rx_bytes += rx_bytes;

  return (rx_bytes);
}

static inline int
vperf_write (vperf_session_t *ts, void *buf, uint32_t nbytes)
{
  int tx_bytes = 0, nbytes_left = nbytes, rv;
  vperf_stats_t *stats = &ts->stats;

  do
    {
      stats->tx_xacts++;
      rv = vppcom_session_write (ts->fd, buf, nbytes_left);
      if (rv < 0)
	{
	  errno = -rv;
	  if ((errno == EAGAIN || errno == EWOULDBLOCK))
	    {
	      stats->tx_eagain++;
	      break;
	    }
	  vperf_err ("vpcom_session_write", -errno);
	  return -1;
	}
      tx_bytes += rv;

      nbytes_left = nbytes_left - rv;
      buf += rv;
      if (rv < nbytes_left)
	stats->tx_incomp++;
    }
  while (tx_bytes != nbytes);

  stats->tx_bytes += tx_bytes;

  return (tx_bytes);
}

static inline int
vperf_write_ds (vperf_session_t *ts)
{
  vperf_stats_t *stats = &ts->stats;
  int tx_bytes;

  do
    {
      stats->tx_xacts++;
      if (ts->ds[1].len)
	tx_bytes = vppcom_session_write_segments (ts->fd, ts->ds, 2);
      else
	tx_bytes = vppcom_session_write_segments (ts->fd, ts->ds, 1);

      if (tx_bytes < 0)
	errno = -tx_bytes;
      if ((tx_bytes == 0) ||
	  ((tx_bytes < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))))
	stats->rx_eagain++;
    }
  while ((tx_bytes == 0) ||
	 ((tx_bytes < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))));

  if (tx_bytes < 0)
    {
      vperf_err ("vppcom_session_write_segments()", -errno);
    }
  else
    stats->tx_bytes += tx_bytes;

  return (tx_bytes);
}

static inline void
dump_help (void)
{
#define INDENT "\n  "

  printf ("CLIENT: Test configuration commands:" INDENT VPERF_TOKEN_HELP
	  "\t\t\tDisplay help." INDENT VPERF_TOKEN_EXIT
	  "\t\t\tExit test client & server." INDENT VPERF_TOKEN_SHOW_CFG
	  "\t\t\tShow the current test cfg." INDENT VPERF_TOKEN_RUN_UNI
	  "\t\t\tRun the Uni-directional test." INDENT VPERF_TOKEN_RUN_BI
	  "\t\t\tRun the Bi-directional test." INDENT VPERF_TOKEN_VERBOSE
	  "\t\t\tToggle verbose setting." INDENT VPERF_TOKEN_RXBUF_SIZE
	  "<rxbuf size>\tRx buffer size (bytes)." INDENT VPERF_TOKEN_TXBUF_SIZE
	  "<txbuf size>\tTx buffer size (bytes)." INDENT VPERF_TOKEN_NUM_WRITES
	  "<# of writes>\tNumber of txbuf writes to server."
	  "\n");
}

#endif /* __vperf_h__ */
