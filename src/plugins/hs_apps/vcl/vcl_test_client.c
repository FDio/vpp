/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
 */

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <hs_apps/vcl/vcl_test.h>
#include <pthread.h>
#include <signal.h>

typedef struct vtc_worker_ vcl_test_client_worker_t;
typedef int (vtc_worker_run_fn) (vcl_test_client_worker_t *wrk);

struct vtc_worker_
{
  vcl_test_session_t *sessions;
  vcl_test_session_t *qsessions;
  uint32_t n_sessions;
  uint32_t wrk_index;
  union
  {
    struct
    {
      fd_set wr_fdset;
      fd_set rd_fdset;
      int max_fd_index;
    };
    struct
    {
      uint32_t epoll_sh;
      struct epoll_event ep_evts[VCL_TEST_CFG_MAX_EPOLL_EVENTS];
      vcl_test_session_t *next_to_send;
    };
  };
  pthread_t thread_handle;
  vtc_worker_run_fn *wrk_run_fn;
  hs_test_cfg_t cfg;
  struct timespec old_stats_stop;
};

typedef struct
{
  vcl_test_client_worker_t *workers;
  vcl_test_session_t ctrl_session;
  vppcom_endpt_t server_endpt;
  uint32_t cfg_seq_num;
  uint8_t dump_cfg;
  hs_test_t post_test;
  uint8_t proto;
  uint8_t incremental_stats;
  uint32_t n_workers;
  volatile int active_workers;
  volatile int test_running;
  union
  {
    struct in_addr v4;
    struct in6_addr v6;
  } server_addr;
} vcl_test_client_main_t;

vcl_test_client_main_t vcl_client_main;

#define vtc_min(a, b) (a < b ? a : b)
#define vtc_max(a, b) (a > b ? a : b)

vcl_test_main_t vcl_test_main;

static int
vtc_cfg_sync (vcl_test_session_t *ts, int post_test)
{
  hs_test_cfg_t *rx_cfg = (hs_test_cfg_t *) ts->rxbuf;
  int rx_bytes, tx_bytes;

  vt_atomic_add (&ts->cfg.seq_num, 1);
  if (ts->cfg.verbose)
    {
      vtinf ("(fd %d): Sending config to server.", ts->fd);
      hs_test_cfg_dump (&ts->cfg, 1 /* is_client */);
    }
  tx_bytes = vppcom_session_write (ts->fd, &ts->cfg, sizeof (ts->cfg));
  if (tx_bytes < 0)
    {
      vtwrn ("(fd %d): write test cfg failed (%d)!", ts->fd, tx_bytes);
      return tx_bytes;
    }

  rx_bytes = vppcom_session_read (ts->fd, ts->rxbuf, sizeof (hs_test_cfg_t));
  if (rx_bytes < 0)
    return rx_bytes;

  if (rx_cfg->magic != HS_TEST_CFG_CTRL_MAGIC)
    {
      vtwrn ("(fd %d): Bad server reply cfg -- aborting!", ts->fd);
      return -1;
    }
  if ((rx_bytes != sizeof (hs_test_cfg_t)))
    {
      vtwrn ("(fd %d): Invalid config received from server!", ts->fd);
      vtinf ("\tRx bytes %d != cfg size %lu", rx_bytes, sizeof (hs_test_cfg_t));
      return -1;
    }
  /* in post test sync server use some fields for rx stats */
  if (!post_test)
    {
      if (!hs_test_cfg_verify (rx_cfg, &ts->cfg))
	{
	  vtwrn ("(fd %d): Invalid config received from server!", ts->fd);
	  hs_test_cfg_dump (rx_cfg, 1 /* is_client */);
	  vtinf ("(fd %d): Valid config sent to server.", ts->fd);
	  hs_test_cfg_dump (&ts->cfg, 1 /* is_client */);
	  return -1;
	}
    }
  if (ts->cfg.verbose)
    {
      vtinf ("(fd %d): Got config back from server.", ts->fd);
      hs_test_cfg_dump (rx_cfg, 1 /* is_client */);
    }

  return 0;
}

static int
vtc_worker_alloc_sessions (vcl_test_client_worker_t *wrk)
{
  vcl_test_session_t *ts;
  uint32_t n_test_sessions;
  struct timespec now;
  int i, j;

  n_test_sessions = wrk->cfg.num_test_sessions;
  if (n_test_sessions < 1)
    {
      errno = EINVAL;
      return -1;
    }

  if (wrk->n_sessions >= n_test_sessions)
    goto done;

  if (wrk->n_sessions)
    wrk->sessions = realloc (wrk->sessions,
			     n_test_sessions * sizeof (vcl_test_session_t));
  else
    wrk->sessions = calloc (n_test_sessions, sizeof (vcl_test_session_t));

  if (!wrk->sessions)
    {
      vterr ("failed to alloc sessions", -errno);
      return errno;
    }

  clock_gettime (CLOCK_REALTIME, &now);

  for (i = 0; i < n_test_sessions; i++)
    {
      ts = &wrk->sessions[i];
      memset (ts, 0, sizeof (*ts));
      ts->session_index = i;
      ts->old_stats.stop = now;
      ts->cfg = wrk->cfg;
      vcl_test_session_buf_alloc (ts);

      switch (ts->cfg.test)
	{
	case HS_TEST_TYPE_UNI:
	case HS_TEST_TYPE_BI:
	  for (j = 0; j < ts->txbuf_size; j++)
	    ts->txbuf[j] = j & 0xff;
	  break;
	default:
	  break;
	}
    }
  wrk->n_sessions = n_test_sessions;

done:

  vtinf ("All test sessions (%d) initialized!", n_test_sessions);

  return 0;
}

static int
vtc_worker_init (vcl_test_client_worker_t * wrk)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  int rv;

  __wrk_index = wrk->wrk_index;

  vtinf ("Initializing worker %u ...", wrk->wrk_index);

  if (wrk->wrk_index)
    {
      if (vppcom_worker_register ())
	{
	  vtwrn ("failed to register worker");
	  return -1;
	}
      vt_atomic_add (&vcm->active_workers, 1);
    }
  rv = vtc_worker_alloc_sessions (wrk);
  if (rv)
    {
      vterr ("vtc_worker_alloc_sessions ()", rv);
      return rv;
    }

  return 0;
}

static int stats_lock = 0;

static void
vtc_accumulate_stats (vcl_test_client_worker_t * wrk,
		      vcl_test_session_t * ctrl)
{
  vcl_test_session_t *ts;
  static char buf[64];
  int i, show_rx = 0;

  while (__sync_lock_test_and_set (&stats_lock, 1))
    ;

  if (ctrl->cfg.test == HS_TEST_TYPE_BI || ctrl->cfg.test == HS_TEST_TYPE_ECHO)
    show_rx = 1;

  for (i = 0; i < wrk->cfg.num_test_sessions; i++)
    {
      ts = &wrk->sessions[i];
      ts->stats.start = ctrl->stats.start;

      if (ctrl->cfg.verbose > 1)
	{
	  snprintf (buf, sizeof (buf), "CLIENT (fd %d) RESULTS", ts->fd);
	  vcl_test_stats_dump (buf, &ts->stats, show_rx, 1 /* show tx */ ,
			       ctrl->cfg.verbose);
	}

      vcl_test_stats_accumulate (&ctrl->stats, &ts->stats);
      if (vcl_comp_tspec (&ctrl->stats.stop, &ts->stats.stop) < 0)
	ctrl->stats.stop = ts->stats.stop;
    }

  __sync_lock_release (&stats_lock);
}

static void
vtc_worker_sessions_exit (vcl_test_client_worker_t * wrk)
{
  vcl_test_session_t *ts;
  int i;

  for (i = 0; i < wrk->cfg.num_test_sessions; i++)
    {
      ts = &wrk->sessions[i];
      vppcom_session_close (ts->fd);
      vcl_test_session_buf_free (ts);
    }

  wrk->n_sessions = 0;
}

static void
vtc_worker_inc_stats_check (vcl_test_client_worker_t *wrk,
			    vcl_test_session_t *ts)
{
  struct timespec now;
  uint32_t i, n_print = 0;
  uint64_t total_bytes = 0;
  double duration, total_rate;

  /* Avoid checking time too often because of syscall cost */
  if (ts->stats.tx_bytes - ts->old_stats.tx_bytes < 1 << 20)
    return;

  clock_gettime (CLOCK_REALTIME, &now);
  if (vcl_test_time_diff (&wrk->old_stats_stop, &now) < 1)
    return;

  for (i = 0; i < wrk->cfg.num_test_sessions; i++)
    {
      ts = &wrk->sessions[i];
      if (ts->is_done)
	continue;

      ts->stats.stop = now;
      if (vcl_test_time_diff (&ts->old_stats.stop, &ts->stats.stop) > 1)
	{
	  vcl_test_stats_dump_inc (ts, 0 /* is_rx */);
	  total_bytes += ts->stats.tx_bytes - ts->old_stats.tx_bytes;
	  ts->old_stats = ts->stats;
	  n_print++;
	}
    }

  if (n_print > 1)
    {
      duration = vcl_test_time_diff (&wrk->old_stats_stop, &now);
      total_rate = (double) total_bytes * 8 / duration / 1e9;
      printf ("Sum: Sent %lu Mbytes in %.2lf seconds %.2lf Gbps\n",
	      (uint64_t) (total_bytes / 1e6), duration, total_rate);
      printf ("-------------------------------------------------\n");
    }

  wrk->old_stats_stop = now;
}

static void
vtc_worker_start_transfer (vcl_test_client_worker_t *wrk)
{
  vtinf ("Worker %u starting transfer ...", wrk->wrk_index);

  if (wrk->wrk_index == 0)
    {
      vcl_test_client_main_t *vcm = &vcl_client_main;
      vcl_test_session_t *ctrl = &vcm->ctrl_session;

      clock_gettime (CLOCK_REALTIME, &ctrl->stats.start);
    }
}

static int
vtc_worker_connect_sessions_select (vcl_test_client_worker_t *wrk)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_main_t *vt = &vcl_test_main;
  const vcl_test_proto_vft_t *tp;
  vcl_test_session_t *ts;
  uint32_t sidx;
  int i, rv;

  tp = vt->protos[vcm->proto];

  FD_ZERO (&wrk->wr_fdset);
  FD_ZERO (&wrk->rd_fdset);

  for (i = 0; i < wrk->cfg.num_test_sessions; i++)
    {
      ts = &wrk->sessions[i];

      rv = tp->open (&wrk->sessions[i], &vcm->server_endpt);
      if (rv < 0)
	return rv;

      FD_SET (vppcom_session_index (ts->fd), &wrk->wr_fdset);
      FD_SET (vppcom_session_index (ts->fd), &wrk->rd_fdset);
      sidx = vppcom_session_index (ts->fd);
      wrk->max_fd_index = vtc_max (sidx, wrk->max_fd_index);
    }
  wrk->max_fd_index += 1;

  vtinf ("All test sessions (%d) connected!", wrk->cfg.num_test_sessions);

  return 0;
}

static void
vtc_abort_test ()
{
  vcl_test_client_main_t *vtcm = &vcl_client_main;
  vtcm->test_running = 0;
  exit (1);
}

static int
vtc_worker_run_select (vcl_test_client_worker_t *wrk)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  fd_set _wfdset, *wfdset = &_wfdset;
  fd_set _rfdset, *rfdset = &_rfdset;
  uint32_t n_active_sessions;
  vcl_test_session_t *ts;
  int i, rv, check_rx = 0;

  rv = vtc_worker_connect_sessions_select (wrk);
  if (rv)
    {
      vterr ("vtc_worker_connect_sessions()", rv);
      return rv;
    }

  check_rx = wrk->cfg.test != HS_TEST_TYPE_UNI;
  n_active_sessions = wrk->cfg.num_test_sessions;

  vtc_worker_start_transfer (wrk);

  while (n_active_sessions && vcm->test_running)
    {
      _wfdset = wrk->wr_fdset;
      _rfdset = wrk->rd_fdset;

      rv = vppcom_select (wrk->max_fd_index, (unsigned long *) rfdset,
			  (unsigned long *) wfdset, NULL, 0);
      if (rv < 0)
	{
	  vterr ("vppcom_select()", rv);
	  break;
	}
      else if (rv == 0)
	continue;

      for (i = 0; i < wrk->cfg.num_test_sessions; i++)
	{
	  ts = &wrk->sessions[i];
	  if (ts->is_done)
	    continue;

	  if (FD_ISSET (vppcom_session_index (ts->fd), rfdset) &&
	      ts->stats.rx_bytes < ts->cfg.total_bytes)
	    {
	      rv = ts->read (ts, ts->rxbuf, ts->rxbuf_size);
	      if (rv < 0)
		{
		  vtwrn ("vppcom_test_read (%d) failed -- aborting test",
			 ts->fd);
		  vtc_abort_test ();
		}
	    }

	  if (FD_ISSET (vppcom_session_index (ts->fd), wfdset) &&
	      ts->stats.tx_bytes < ts->cfg.total_bytes)
	    {
	      rv = ts->write (ts, ts->txbuf, ts->cfg.txbuf_size);
	      if (rv < 0)
		{
		  vtwrn ("vppcom_test_write (%d) failed -- aborting test",
			 ts->fd);
		  vtc_abort_test ();
		}
	      if (vcm->incremental_stats)
		vtc_worker_inc_stats_check (wrk, ts);
	    }
	  if (ts->done (ts, check_rx))
	    n_active_sessions -= 1;
	}
    }

  return 0;
}

static void
vtc_worker_epoll_send_add (vcl_test_client_worker_t *wrk,
			   vcl_test_session_t *ts)
{
  if (ts->next || ts->prev)
    return;

  if (!wrk->next_to_send)
    {
      wrk->next_to_send = ts;
    }
  else
    {
      ts->next = wrk->next_to_send;
      wrk->next_to_send->prev = ts;
      wrk->next_to_send = ts;
    }
}

static void
vtc_worker_epoll_send_del (vcl_test_client_worker_t *wrk,
			   vcl_test_session_t *ts)
{
  if (ts == wrk->next_to_send)
    {
      wrk->next_to_send = wrk->next_to_send->next;
      if (wrk->next_to_send)
	wrk->next_to_send->prev = 0;
    }
  else
    {
      if (ts->next)
	{
	  ts->next->prev = ts->prev;
	}
      if (ts->prev)
	{
	  ts->prev->next = ts->next;
	}
    }
  ts->next = 0;
  ts->prev = 0;
}

static int
vtc_worker_connect_sessions_epoll (vcl_test_client_worker_t *wrk)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_main_t *vt = &vcl_test_main;
  const vcl_test_proto_vft_t *tp;
  struct timespec start, end;
  uint32_t n_connected = 0;
  vcl_test_session_t *ts;
  struct epoll_event ev;
  int i, ci = 0, rv, n_ev;
  double diff;

  tp = vt->protos[vcm->proto];
  wrk->epoll_sh = vppcom_epoll_create ();

  ev.events = EPOLLET | EPOLLOUT;

  clock_gettime (CLOCK_REALTIME, &start);

  while (n_connected < wrk->cfg.num_test_sessions)
    {
      /*
       * Try to connect more sessions if under pending threshold
       */
      while ((ci - n_connected) < 16 && ci < wrk->cfg.num_test_sessions)
	{
	  ts = &wrk->sessions[ci];
	  ts->noblk_connect = 1;
	  rv = tp->open (&wrk->sessions[ci], &vcm->server_endpt);
	  if (rv < 0)
	    {
	      vtwrn ("open: %d", rv);
	      return rv;
	    }

	  ev.data.u64 = ci;
	  rv = vppcom_epoll_ctl (wrk->epoll_sh, EPOLL_CTL_ADD, ts->fd, &ev);
	  if (rv < 0)
	    {
	      vtwrn ("vppcom_epoll_ctl: %d", rv);
	      return rv;
	    }
	  ci += 1;
	}

      /*
       * Handle connected events
       */
      n_ev =
	vppcom_epoll_wait (wrk->epoll_sh, wrk->ep_evts,
			   VCL_TEST_CFG_MAX_EPOLL_EVENTS, 0 /* timeout */);
      if (n_ev < 0)
	{
	  vterr ("vppcom_epoll_wait() returned", n_ev);
	  return -1;
	}
      else if (n_ev == 0)
	{
	  continue;
	}

      for (i = 0; i < n_ev; i++)
	{
	  ts = &wrk->sessions[wrk->ep_evts[i].data.u32];
	  if (!(wrk->ep_evts[i].events & EPOLLOUT))
	    {
	      vtwrn ("connect failed");
	      return -1;
	    }
	  if (ts->is_open)
	    {
	      vtwrn ("connection already open?");
	      return -1;
	    }
	  ts->is_open = 1;
	  n_connected += 1;
	}
    }

  clock_gettime (CLOCK_REALTIME, &end);

  diff = vcl_test_time_diff (&start, &end);
  vtinf ("Connected (%u) connected in %.2f seconds (%u CPS)!",
	 wrk->cfg.num_test_sessions, diff,
	 (uint32_t) ((double) wrk->cfg.num_test_sessions / diff));

  ev.events = EPOLLET | EPOLLIN | EPOLLOUT;

  for (i = 0; i < wrk->cfg.num_test_sessions; i++)
    {
      ts = &wrk->sessions[i];

      /* No data to be sent */
      if (ts->cfg.total_bytes == 0)
	{
	  n_connected -= 1;
	  clock_gettime (CLOCK_REALTIME, &ts->stats.stop);
	  ts->is_done = 1;
	  continue;
	}

      ev.data.u64 = i;
      rv = vppcom_epoll_ctl (wrk->epoll_sh, EPOLL_CTL_MOD, ts->fd, &ev);
      if (rv < 0)
	{
	  vtwrn ("vppcom_epoll_ctl: %d", rv);
	  return rv;
	}
      vtc_worker_epoll_send_add (wrk, ts);
    }

  return n_connected;
}

static int
vtc_worker_run_epoll (vcl_test_client_worker_t *wrk)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  uint32_t n_active_sessions, max_writes = 16, n_writes = 0;
  vcl_test_session_t *ts, *next;
  int i, rv, check_rx = 0, n_ev;
  const vcl_test_proto_vft_t *tp;

  rv = vtc_worker_connect_sessions_epoll (wrk);
  if (rv < 0)
    {
      vterr ("vtc_worker_connect_sessions()", rv);
      return rv;
    }

  n_active_sessions = rv;
  check_rx = wrk->cfg.test != HS_TEST_TYPE_UNI;

  vtc_worker_start_transfer (wrk);
  next = wrk->next_to_send;

  tp = vcl_test_main.protos[vcm->proto];

  while (n_active_sessions && vcm->test_running)
    {
      /*
       * Try to write
       */
      ts = next;
      if (!ts)
	{
	  ts = wrk->next_to_send;
	  if (!ts)
	    goto get_epoll_evts;
	}

      rv = ts->write (ts, ts->txbuf, ts->cfg.txbuf_size);
      if (ts->done (ts, check_rx))
	n_active_sessions -= 1;
      next = ts->next;
      if (rv > 0)
	{
	  if (vcm->incremental_stats)
	    vtc_worker_inc_stats_check (wrk, ts);
	}
      else if (rv == 0)
	{
	  vtc_worker_epoll_send_del (wrk, ts);
	}
      else
	{
	  vtwrn ("vppcom_test_write (%d) failed -- aborting test", ts->fd);
	  return -1;
	}
      n_writes += 1;

      if (rv > 0 && n_writes < max_writes)
	continue;

    get_epoll_evts:

      /*
       * Grab new events
       */

      n_ev =
	vppcom_epoll_wait (wrk->epoll_sh, wrk->ep_evts,
			   VCL_TEST_CFG_MAX_EPOLL_EVENTS, 0 /* timeout */);
      if (n_ev < 0)
	{
	  vterr ("vppcom_epoll_wait()", n_ev);
	  break;
	}
      else if (n_ev == 0)
	{
	  continue;
	}

      for (i = 0; i < n_ev; i++)
	{
	  ts = &wrk->sessions[wrk->ep_evts[i].data.u32];

	  if (ts->is_done)
	    continue;

	  if (wrk->ep_evts[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))
	    {
	      /* if close return 1 we are done, otherwise it was unexpected
	       * close */
	      if (tp->close (ts, wrk->ep_evts[i].events))
		{
		  n_active_sessions -= 1;
		  continue;
		}
	      else
		{
		  vtwrn (
		    "%u finished before reading all data -- aborting test",
		    ts->fd);
		  return -1;
		}
	    }
	  if ((wrk->ep_evts[i].events & EPOLLIN) &&
	      ts->stats.rx_bytes < ts->cfg.total_bytes)
	    {
	      rv = ts->read (ts, ts->rxbuf, ts->rxbuf_size);
	      if (rv < 0)
		break;
	      if (ts->done (ts, check_rx))
		n_active_sessions -= 1;
	    }
	  if ((wrk->ep_evts[i].events & EPOLLOUT) &&
	      ts->stats.tx_bytes < ts->cfg.total_bytes)
	    {
	      vtc_worker_epoll_send_add (wrk, ts);
	    }
	}

      n_writes = 0;
    }

  return 0;
}

static inline int
vtc_worker_run (vcl_test_client_worker_t *wrk)
{
  int rv;

  vtinf ("Worker %u starting test ...", wrk->wrk_index);

  rv = wrk->wrk_run_fn (wrk);

  vtinf ("Worker %d done ...", wrk->wrk_index);

  return rv;
}

static void *
vtc_worker_loop (void *arg)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  vcl_test_client_worker_t *wrk = arg;

  if (vtc_worker_init (wrk))
    goto done;

  if (vtc_worker_run (wrk))
    goto done;

  vtc_accumulate_stats (wrk, ctrl);
  sleep (VCL_TEST_DELAY_DISCONNECT);
  vtc_worker_sessions_exit (wrk);

done:

  if (wrk->wrk_index)
    vt_atomic_add (&vcm->active_workers, -1);

  return 0;
}

static void
vtc_print_stats (vcl_test_session_t * ctrl)
{
  int is_echo = ctrl->cfg.test == HS_TEST_TYPE_ECHO;
  int show_rx = 0;
  char buf[64];

  if (ctrl->cfg.test == HS_TEST_TYPE_BI || ctrl->cfg.test == HS_TEST_TYPE_ECHO)
    show_rx = 1;

  vcl_test_stats_dump ("CLIENT RESULTS", &ctrl->stats,
		       show_rx, 1 /* show tx */ ,
		       ctrl->cfg.verbose);
  hs_test_cfg_dump (&ctrl->cfg, 1 /* is_client */);

  if (ctrl->cfg.verbose)
    {
      vtinf ("  ctrl session info\n" HS_TEST_SEPARATOR_STRING
	     "          fd:  %d (0x%08x)\n"
	     "       rxbuf:  %p\n"
	     "  rxbuf size:  %u (0x%08x)\n"
	     "       txbuf:  %p\n"
	     "  txbuf size:  %u (0x%08x)\n" HS_TEST_SEPARATOR_STRING,
	     ctrl->fd, (uint32_t) ctrl->fd, ctrl->rxbuf, ctrl->rxbuf_size,
	     ctrl->rxbuf_size, ctrl->txbuf, ctrl->txbuf_size,
	     ctrl->txbuf_size);
    }

  if (is_echo)
    snprintf (buf, sizeof (buf), "Echo");
  else
    snprintf (buf, sizeof (buf), "%s-directional Stream",
	      ctrl->cfg.test == HS_TEST_TYPE_BI ? "Bi" : "Uni");
}

static void
vtc_echo_client (vcl_test_client_main_t * vcm)
{
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  hs_test_cfg_t *cfg = &ctrl->cfg;
  int rv;

  cfg->total_bytes = strlen (ctrl->txbuf) + 1;
  memset (&ctrl->stats, 0, sizeof (ctrl->stats));

  rv = ctrl->write (ctrl, ctrl->txbuf, cfg->total_bytes);
  if (rv < 0)
    {
      vtwrn ("vppcom_test_write (%d) failed ", ctrl->fd);
      return;
    }

  (void) ctrl->read (ctrl, ctrl->rxbuf, ctrl->rxbuf_size);
}

static void
vtc_stream_client (vcl_test_client_main_t * vcm)
{
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  hs_test_cfg_t *cfg = &ctrl->cfg;
  vcl_test_client_worker_t *wrk;
  uint32_t i, n_conn, n_conn_per_wrk;

  vtinf ("%s-directional Stream Test Starting!",
	 ctrl->cfg.test == HS_TEST_TYPE_BI ? "Bi" : "Uni");

  memset (&ctrl->stats, 0, sizeof (vcl_test_stats_t));
  cfg->total_bytes = cfg->num_writes * cfg->txbuf_size;
  cfg->ctrl_handle = ctrl->fd;

  n_conn = cfg->num_test_sessions;
  n_conn_per_wrk = n_conn / vcm->n_workers;
  for (i = 0; i < vcm->n_workers; i++)
    {
      wrk = &vcm->workers[i];
      wrk->wrk_index = i;
      wrk->cfg = ctrl->cfg;
      wrk->cfg.num_test_sessions = vtc_min (n_conn_per_wrk, n_conn);
      n_conn -= wrk->cfg.num_test_sessions;
    }

  vcm->test_running = 1;
  ctrl->cfg.cmd = HS_TEST_CMD_START;
  if (vtc_cfg_sync (ctrl, 0))
    {
      vtwrn ("test cfg sync failed -- aborting!");
      return;
    }

  for (i = 1; i < vcm->n_workers; i++)
    {
      wrk = &vcm->workers[i];
      if (pthread_create (&wrk->thread_handle, NULL, vtc_worker_loop,
			  (void *) wrk))
	{
	  vtwrn ("pthread_create failed -- aborting!");
	  return;
	}
    }
  vtc_worker_loop (&vcm->workers[0]);

  while (vcm->active_workers > 0)
    ;

  vtinf ("Sending config on ctrl session (fd %d) for stats...", ctrl->fd);
  ctrl->cfg.cmd = HS_TEST_CMD_STOP;
  if (vtc_cfg_sync (ctrl, 0))
    {
      vtwrn ("test cfg sync failed -- aborting!");
      return;
    }

  vtc_print_stats (ctrl);

  ctrl->cfg.cmd = HS_TEST_CMD_SYNC;
  ctrl->cfg.test = HS_TEST_TYPE_ECHO;
  ctrl->cfg.total_bytes = 0;
  if (vtc_cfg_sync (ctrl, 1))
    vtwrn ("post-test cfg sync failed!");
}

static void
cfg_txbuf_size_set (void)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  char *p = ctrl->txbuf + strlen (VCL_TEST_TOKEN_TXBUF_SIZE);
  uint64_t txbuf_size = strtoull ((const char *) p, NULL, 10);

  if (txbuf_size >= VCL_TEST_CFG_BUF_SIZE_MIN)
    {
      ctrl->cfg.txbuf_size = txbuf_size;
      ctrl->cfg.total_bytes = ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
      vcl_test_buf_alloc (&ctrl->cfg, 0 /* is_rxbuf */ ,
			  (uint8_t **) & ctrl->txbuf, &ctrl->txbuf_size);
      hs_test_cfg_dump (&ctrl->cfg, 1 /* is_client */);
    }
  else
    vtwrn ("Invalid txbuf size (%lu) < minimum buf size (%u)!",
	   txbuf_size, VCL_TEST_CFG_BUF_SIZE_MIN);
}

static void
cfg_num_writes_set (void)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  char *p = ctrl->txbuf + strlen (VCL_TEST_TOKEN_NUM_WRITES);
  uint32_t num_writes = strtoul ((const char *) p, NULL, 10);

  if (num_writes > 0)
    {
      ctrl->cfg.num_writes = num_writes;
      ctrl->cfg.total_bytes = ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
      hs_test_cfg_dump (&ctrl->cfg, 1 /* is_client */);
    }
  else
    {
      vtwrn ("invalid num writes: %u", num_writes);
    }
}

static void
cfg_num_test_sessions_set (void)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  char *p = ctrl->txbuf + strlen (VCL_TEST_TOKEN_NUM_TEST_SESS);
  uint32_t num_test_sessions = strtoul ((const char *) p, NULL, 10);

  if ((num_test_sessions > 0) &&
      (num_test_sessions <= VCL_TEST_CFG_MAX_TEST_SESS))
    {
      ctrl->cfg.num_test_sessions = num_test_sessions;
      hs_test_cfg_dump (&ctrl->cfg, 1 /* is_client */);
    }
  else
    {
      vtwrn ("invalid num test sessions: %u, (%d max)",
	     num_test_sessions, VCL_TEST_CFG_MAX_TEST_SESS);
    }
}

static void
cfg_rxbuf_size_set (void)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  char *p = ctrl->txbuf + strlen (VCL_TEST_TOKEN_RXBUF_SIZE);
  uint64_t rxbuf_size = strtoull ((const char *) p, NULL, 10);

  if (rxbuf_size >= VCL_TEST_CFG_BUF_SIZE_MIN)
    {
      ctrl->cfg.rxbuf_size = rxbuf_size;
      vcl_test_buf_alloc (&ctrl->cfg, 1 /* is_rxbuf */ ,
			  (uint8_t **) & ctrl->rxbuf, &ctrl->rxbuf_size);
      hs_test_cfg_dump (&ctrl->cfg, 1 /* is_client */);
    }
  else
    vtwrn ("Invalid rxbuf size (%lu) < minimum buf size (%u)!",
	   rxbuf_size, VCL_TEST_CFG_BUF_SIZE_MIN);
}

static void
cfg_verbose_toggle (void)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;

  ctrl->cfg.verbose = ctrl->cfg.verbose ? 0 : 1;
  hs_test_cfg_dump (&ctrl->cfg, 1 /* is_client */);
}

static hs_test_t
parse_input ()
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  hs_test_t rv = HS_TEST_TYPE_NONE;

  if (!strncmp (VCL_TEST_TOKEN_EXIT, ctrl->txbuf,
		strlen (VCL_TEST_TOKEN_EXIT)))
    rv = HS_TEST_TYPE_EXIT;

  else if (!strncmp (VCL_TEST_TOKEN_HELP, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_HELP)))
    dump_help ();

  else if (!strncmp (VCL_TEST_TOKEN_SHOW_CFG, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_SHOW_CFG)))
    vcm->dump_cfg = 1;

  else if (!strncmp (VCL_TEST_TOKEN_VERBOSE, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_VERBOSE)))
    cfg_verbose_toggle ();

  else if (!strncmp (VCL_TEST_TOKEN_TXBUF_SIZE, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_TXBUF_SIZE)))
    cfg_txbuf_size_set ();

  else if (!strncmp (VCL_TEST_TOKEN_NUM_TEST_SESS, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_NUM_TEST_SESS)))
    cfg_num_test_sessions_set ();

  else if (!strncmp (VCL_TEST_TOKEN_NUM_WRITES, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_NUM_WRITES)))
    cfg_num_writes_set ();

  else if (!strncmp (VCL_TEST_TOKEN_RXBUF_SIZE, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_RXBUF_SIZE)))
    cfg_rxbuf_size_set ();

  else if (!strncmp (HS_TEST_TOKEN_RUN_UNI, ctrl->txbuf,
		     strlen (HS_TEST_TOKEN_RUN_UNI)))
    rv = ctrl->cfg.test = HS_TEST_TYPE_UNI;

  else if (!strncmp (HS_TEST_TOKEN_RUN_BI, ctrl->txbuf,
		     strlen (HS_TEST_TOKEN_RUN_BI)))
    rv = ctrl->cfg.test = HS_TEST_TYPE_BI;

  else
    rv = HS_TEST_TYPE_ECHO;

  return rv;
}

static int
vtc_unformat_test_param (uint32_t *test_param, char *test_param_str)
{
  if (!strcmp (test_param_str, "server-rst-stream"))
    *test_param = HS_TEST_PARAM_SERVER_RST_STREAM;
  else if (!strcmp (test_param_str, "client-rst-stream"))
    *test_param = HS_TEST_PARAM_CLIENT_RST_STREAM;
  else if (!strcmp (test_param_str, "server-close-conn"))
    *test_param = HS_TEST_PARAM_SERVER_CLOSE_CONN;
  else if (!strcmp (test_param_str, "client-close-conn"))
    *test_param = HS_TEST_PARAM_CLIENT_CLOSE_CONN;
  else
    return 1;
  return 0;
}

void
print_usage_and_exit (void)
{
  fprintf (stderr,
	   "vcl_test_client [OPTIONS] <ipaddr> <port>\n"
	   "  OPTIONS\n"
	   "  -h               Print this message and exit.\n"
	   "  -6               Use IPv6\n"
	   "  -c               Print test config before test.\n"
	   "  -w <dir>         Write test results to <dir>.\n"
	   "  -X               Exit after running test.\n"
	   "  -p <proto>       Use <proto> transport layer\n"
	   "  -D               Use UDP transport layer\n"
	   "  -L               Use TLS transport layer\n"
	   "  -E               Run Echo test.\n"
	   "  -N <num-writes>  Test Cfg: number of writes.\n"
	   "  -R <rxbuf-size>  Test Cfg: rx buffer size.\n"
	   "  -T <txbuf-size>  Test Cfg: tx buffer size.\n"
	   "  -U               Run Uni-directional test.\n"
	   "  -B               Run Bi-directional test.\n"
	   "  -b <bytes>       Total number of bytes transferred\n"
	   "  -V               Verbose mode.\n"
	   "  -I <N>           Use N sessions.\n"
	   "  -s <N>           Use N sessions.\n"
	   "  -S               Print incremental stats per session.\n"
	   "  -q <n>           QUIC : use N Ssessions on top of n Qsessions\n"
	   "  -t <test-param>  QUIC : additional test parameter\n");
  exit (1);
}

static void
vtc_process_opts (vcl_test_client_main_t * vcm, int argc, char **argv)
{
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  int c, v;

  opterr = 0;
  while ((c = getopt (argc, argv, "chnp:w:xXE:I:N:R:T:b:UBV6DLs:q:St:")) != -1)
    switch (c)
      {
      case 'c':
	vcm->dump_cfg = 1;
	break;

      case 'I':		/* deprecated */
      case 's':
	if (sscanf (optarg, "0x%x", &ctrl->cfg.num_test_sessions) != 1)
	  if (sscanf (optarg, "%u", &ctrl->cfg.num_test_sessions) != 1)
	    {
	      vtwrn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (!ctrl->cfg.num_test_sessions ||
	    (ctrl->cfg.num_test_sessions > VCL_TEST_CFG_MAX_TEST_SESS))
	  {
	    vtwrn ("Invalid number of sessions (%d) specified for option -%c!"
		   "\n       Valid range is 1 - %d",
		   ctrl->cfg.num_test_sessions, c,
		   VCL_TEST_CFG_MAX_TEST_SESS);
	    print_usage_and_exit ();
	  }
	break;

      case 'q':
	if (sscanf (optarg, "0x%x", &ctrl->cfg.num_test_sessions_perq) != 1)
	  if (sscanf (optarg, "%u", &ctrl->cfg.num_test_sessions_perq) != 1)
	    {
	      vtwrn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (!ctrl->cfg.num_test_sessions_perq ||
	    (ctrl->cfg.num_test_sessions_perq > VCL_TEST_CFG_MAX_TEST_SESS))
	  {
	    vtwrn ("Invalid number of Stream sessions (%d) per Qsession"
		   "for option -%c!\nValid range is 1 - %d",
		   ctrl->cfg.num_test_sessions_perq, c,
		   VCL_TEST_CFG_MAX_TEST_SESS);
	    print_usage_and_exit ();
	  }
	break;

      case 'w':
	if (sscanf (optarg, "%d", &v) != 1)
	  {
	    vtwrn ("Invalid value for option -%c!", c);
	    print_usage_and_exit ();
	  }
	if (v > 1)
	  vcm->n_workers = v;
	break;

      case 'X':
	vcm->post_test = HS_TEST_TYPE_EXIT;
	break;

      case 'x':
	vcm->post_test = HS_TEST_TYPE_NONE;
	break;

      case 'E':
	if (strlen (optarg) > ctrl->txbuf_size)
	  {
	    vtwrn ("Option -%c value larger than txbuf size (%d)!",
		   optopt, ctrl->txbuf_size);
	    print_usage_and_exit ();
	  }
	strncpy (ctrl->txbuf, optarg, ctrl->txbuf_size);
	ctrl->cfg.test = HS_TEST_TYPE_ECHO;
	break;

      case 'N':
	if (sscanf (optarg, "0x%lx", &ctrl->cfg.num_writes) != 1)
	  if (sscanf (optarg, "%ld", &ctrl->cfg.num_writes) != 1)
	    {
	      vtwrn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	ctrl->cfg.total_bytes = ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
	break;

      case 'R':
	if (sscanf (optarg, "0x%lx", &ctrl->cfg.rxbuf_size) != 1)
	  if (sscanf (optarg, "%ld", &ctrl->cfg.rxbuf_size) != 1)
	    {
	      vtwrn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (ctrl->cfg.rxbuf_size >= VCL_TEST_CFG_BUF_SIZE_MIN)
	  {
	    ctrl->rxbuf_size = ctrl->cfg.rxbuf_size;
	    vcl_test_buf_alloc (&ctrl->cfg, 1 /* is_rxbuf */ ,
				(uint8_t **) & ctrl->rxbuf,
				&ctrl->rxbuf_size);
	  }
	else
	  {
	    vtwrn ("rxbuf size (%lu) less than minumum (%u)",
		   ctrl->cfg.rxbuf_size, VCL_TEST_CFG_BUF_SIZE_MIN);
	    print_usage_and_exit ();
	  }

	break;

      case 'T':
	if (sscanf (optarg, "0x%lx", &ctrl->cfg.txbuf_size) != 1)
	  if (sscanf (optarg, "%ld", &ctrl->cfg.txbuf_size) != 1)
	    {
	      vtwrn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (ctrl->cfg.txbuf_size >= VCL_TEST_CFG_BUF_SIZE_MIN)
	  {
	    ctrl->txbuf_size = ctrl->cfg.txbuf_size;
	    vcl_test_buf_alloc (&ctrl->cfg, 0 /* is_rxbuf */ ,
				(uint8_t **) & ctrl->txbuf,
				&ctrl->txbuf_size);
	    ctrl->cfg.total_bytes =
	      ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
	  }
	else
	  {
	    vtwrn ("txbuf size (%lu) less than minumum (%u)!",
		   ctrl->cfg.txbuf_size, VCL_TEST_CFG_BUF_SIZE_MIN);
	    print_usage_and_exit ();
	  }
	break;
      case 'b':
	if (sscanf (optarg, "0x%lu", &ctrl->cfg.total_bytes) != 1)
	  if (sscanf (optarg, "%ld", &ctrl->cfg.total_bytes) != 1)
	    {
	      vtwrn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (ctrl->cfg.total_bytes % ctrl->cfg.txbuf_size)
	  {
	    vtwrn ("total bytes must be mutliple of txbuf size(0x%lu)!",
		   ctrl->cfg.txbuf_size);
	    print_usage_and_exit ();
	  }
	ctrl->cfg.num_writes = ctrl->cfg.total_bytes / ctrl->cfg.txbuf_size;
	break;

      case 'U':
	ctrl->cfg.test = HS_TEST_TYPE_UNI;
	break;

      case 'B':
	ctrl->cfg.test = HS_TEST_TYPE_BI;
	break;

      case 'V':
	ctrl->cfg.verbose = 1;
	break;

      case '6':
	ctrl->cfg.address_ip6 = 1;
	break;

      case 'p':
	if (vppcom_unformat_proto (&vcm->proto, optarg))
	  vtwrn ("Invalid vppcom protocol %s, defaulting to TCP", optarg);
	break;

      case 'D':		/* deprecated */
	vcm->proto = VPPCOM_PROTO_UDP;
	break;

      case 'L':		/* deprecated */
	vcm->proto = VPPCOM_PROTO_TLS;
	break;

      case 'S':
	vcm->incremental_stats = 1;
	break;

      case 't':
	if (vtc_unformat_test_param (&ctrl->cfg.test_param, optarg))
	  {
	    vtwrn ("Invalid value for option -%c!", c);
	    print_usage_and_exit ();
	  }
	break;

      case '?':
	switch (optopt)
	  {
	  case 'E':
	  case 'I':		/* deprecated */
	  case 'N':
	  case 'R':
	  case 'T':
	  case 'w':
	  case 'p':
	  case 'q':
	  case 't':
	    vtwrn ("Option -%c requires an argument.", optopt);
	    break;

	  default:
	    if (isprint (optopt))
	      vtwrn ("Unknown option `-%c'.", optopt);
	    else
	      vtwrn ("Unknown option character `\\x%x'.", optopt);
	  }
	/* fall thru */
      case 'h':
      default:
	print_usage_and_exit ();
      }

  if (argc < (optind + 1))
    {
      vtwrn ("Invalid number of arguments!");
      print_usage_and_exit ();
    }

  ctrl->cfg.num_test_qsessions = vcm->proto != VPPCOM_PROTO_QUIC ? 0 :
    (ctrl->cfg.num_test_sessions + ctrl->cfg.num_test_sessions_perq - 1) /
    ctrl->cfg.num_test_sessions_perq;

  memset (&vcm->server_addr, 0, sizeof (vcm->server_addr));
  if (ctrl->cfg.address_ip6)
    {
      struct in6_addr *in6 = &vcm->server_addr.v6;
      inet_pton (AF_INET6, argv[optind++], in6);

      vcm->server_endpt.is_ip4 = 0;
      vcm->server_endpt.ip = (uint8_t *) in6;
    }
  else
    {
      struct in_addr *in4 = &vcm->server_addr.v4;
      inet_pton (AF_INET, argv[optind++], in4);

      vcm->server_endpt.is_ip4 = 1;
      vcm->server_endpt.ip = (uint8_t *) in4;
    }

  if (argc == optind + 1)
    vcm->server_endpt.port = htons (atoi (argv[optind]));
  else
    vcm->server_endpt.port = htons (VCL_TEST_SERVER_PORT);
}

static void
vtc_read_user_input (vcl_test_session_t * ctrl)
{
  printf ("\nType some characters and hit <return>\n"
	  "('" VCL_TEST_TOKEN_HELP "' for help): ");

  if (fgets (ctrl->txbuf, ctrl->txbuf_size, stdin) != NULL)
    {
      if (strlen (ctrl->txbuf) == 1)
	{
	  printf ("\nNothing to send!  Please try again...\n");
	  return;
	}
      ctrl->txbuf[strlen (ctrl->txbuf) - 1] = 0;	// chomp the newline.

      /* Parse input for keywords */
      ctrl->cfg.test = parse_input ();
    }
}

static void
vtc_ctrl_session_exit (void)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  int verbose = ctrl->cfg.verbose;

  /* Only clients exits, server can accept new connections */
  if (vcm->post_test == HS_TEST_TYPE_EXIT_CLIENT)
    return;

  ctrl->cfg.test = HS_TEST_TYPE_EXIT;
  vtinf ("(fd %d): Sending exit cfg to server...", ctrl->fd);
  if (verbose)
    hs_test_cfg_dump (&ctrl->cfg, 1 /* is_client */);
  (void) vcl_test_write (ctrl, (uint8_t *) &ctrl->cfg, sizeof (ctrl->cfg));
  sleep (1);
}

static int
vtc_ctrl_session_init (vcl_test_client_main_t *vcm, vcl_test_session_t *ctrl)
{
  int rv;

  ctrl->fd = vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_nonblocking */);
  if (ctrl->fd < 0)
    {
      vterr ("vppcom_session_create()", ctrl->fd);
      return ctrl->fd;
    }

  vtinf ("Connecting to server...");
  rv = vppcom_session_connect (ctrl->fd, &vcm->server_endpt);
  if (rv)
    {
      vterr ("vppcom_session_connect()", rv);
      return rv;
    }
  vtinf ("Control session (fd %d) connected.", ctrl->fd);

  ctrl->read = vcl_test_read;
  ctrl->write = vcl_test_write;

  ctrl->cfg.cmd = HS_TEST_CMD_SYNC;
  rv = vtc_cfg_sync (ctrl, 0);
  if (rv)
    {
      vterr ("vtc_cfg_sync()", rv);
      return rv;
    }

  ctrl->cfg.ctrl_handle = ((hs_test_cfg_t *) ctrl->rxbuf)->ctrl_handle;
  memset (&ctrl->stats, 0, sizeof (ctrl->stats));

  return 0;
}

static void
vt_sigs_handler (int signum, siginfo_t *si, void *uc)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;

  vcm->test_running = 0;
  clock_gettime (CLOCK_REALTIME, &ctrl->stats.stop);
}

static void
vt_incercept_sigs (void)
{
  struct sigaction sa;

  memset (&sa, 0, sizeof (sa));
  sa.sa_sigaction = vt_sigs_handler;
  sa.sa_flags = SA_SIGINFO;
  if (sigaction (SIGINT, &sa, 0))
    {
      vtwrn ("couldn't intercept sigint");
      exit (-1);
    }
}

static void
vtc_alloc_workers (vcl_test_client_main_t *vcm)
{
  vcl_test_main_t *vt = &vcl_test_main;
  vtc_worker_run_fn *run_fn;

  vcm->workers = calloc (vcm->n_workers, sizeof (vcl_test_client_worker_t));
  vt->wrk = calloc (vcm->n_workers, sizeof (vcl_test_wrk_t));

  if (vcm->ctrl_session.cfg.num_test_sessions > VCL_TEST_CFG_MAX_SELECT_SESS ||
      vcm->proto == VPPCOM_PROTO_QUIC)
    run_fn = vtc_worker_run_epoll;
  else
    run_fn = vtc_worker_run_select;

  for (int i = 0; i < vcm->n_workers; i++)
    vcm->workers[i].wrk_run_fn = run_fn;
}

int
main (int argc, char **argv)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  vcl_test_main_t *vt = &vcl_test_main;
  int rv;

  vcm->n_workers = 1;
  vcm->post_test = HS_TEST_TYPE_EXIT_CLIENT;

  hs_test_cfg_init (&ctrl->cfg);
  vt_incercept_sigs ();
  vcl_test_session_buf_alloc (ctrl);
  vtc_process_opts (vcm, argc, argv);

  vtc_alloc_workers (vcm);

  rv = vppcom_app_create ("vcl_test_client");
  if (rv < 0)
    vtfail ("vppcom_app_create()", rv);

  /* Protos like tls/dtls/quic need init */
  if (vt->protos[vcm->proto]->init)
    {
      rv = vt->protos[vcm->proto]->init (&ctrl->cfg);
      if (rv)
	vtfail ("client init failed", rv);
    }

  if ((rv = vtc_ctrl_session_init (vcm, ctrl)))
    vtfail ("vppcom_session_create() ctrl session", rv);

  /* Update ctrl port to data port */
  vcm->server_endpt.port = hs_make_data_port (vcm->server_endpt.port);

  while (ctrl->cfg.test != HS_TEST_TYPE_EXIT)
    {
      if (vcm->dump_cfg)
	{
	  hs_test_cfg_dump (&ctrl->cfg, 1 /* is_client */);
	  vcm->dump_cfg = 0;
	}

      switch (ctrl->cfg.test)
	{
	case HS_TEST_TYPE_ECHO:
	  vtc_echo_client (vcm);
	  break;

	case HS_TEST_TYPE_UNI:
	case HS_TEST_TYPE_BI:
	  vtc_stream_client (vcm);
	  break;

	case HS_TEST_TYPE_EXIT:
	  continue;

	case HS_TEST_TYPE_NONE:
	default:
	  break;
	}
      switch (vcm->post_test)
	{
	case HS_TEST_TYPE_EXIT:
	case HS_TEST_TYPE_EXIT_CLIENT:
	  switch (ctrl->cfg.test)
	    {
	    case HS_TEST_TYPE_EXIT:
	    case HS_TEST_TYPE_UNI:
	    case HS_TEST_TYPE_BI:
	    case HS_TEST_TYPE_ECHO:
	      ctrl->cfg.test = HS_TEST_TYPE_EXIT;
	      continue;

	    case HS_TEST_TYPE_NONE:
	    default:
	      break;
	    }
	  break;

	case HS_TEST_TYPE_NONE:
	case HS_TEST_TYPE_ECHO:
	case HS_TEST_TYPE_UNI:
	case HS_TEST_TYPE_BI:
	default:
	  break;
	}

      memset (ctrl->txbuf, 0, ctrl->txbuf_size);
      memset (ctrl->rxbuf, 0, ctrl->rxbuf_size);

      vtc_read_user_input (ctrl);
    }

  vtc_ctrl_session_exit ();
  vppcom_app_destroy ();
  free (vcm->workers);
  return 0;
}
