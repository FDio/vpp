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
#include <vperf/vcl/vperf.h>
#include <pthread.h>
#include <signal.h>

typedef struct vperf_client_worker_ vperf_client_worker_t;
typedef int (vperf_client_worker_run_fn) (vperf_client_worker_t *wrk);

struct vperf_client_worker_
{
  vperf_session_t *sessions;
  vperf_session_t *qsessions;
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
      struct epoll_event ep_evts[VPERF_CFG_MAX_EPOLL_EVENTS];
      vperf_session_t *next_to_send;
    };
  };
  pthread_t thread_handle;
  vperf_client_worker_run_fn *wrk_run_fn;
  vperf_cfg_t cfg;
  struct timespec old_stats_stop;
};

typedef struct
{
  vperf_client_worker_t *workers;
  vperf_session_t ctrl_session;
  vppcom_endpt_t server_endpt;
  uint32_t cfg_seq_num;
  uint8_t dump_cfg;
  vperf_test_t post_test;
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
} vperf_client_main_t;

vperf_client_main_t vperf_client_main;

#define vperf_client_min(a, b) (a < b ? a : b)
#define vperf_client_max(a, b) (a > b ? a : b)

vperf_main_t vperf_main;

static int
vperf_client_cfg_sync (vperf_session_t *ts)
{
  vperf_cfg_t *rx_cfg = (vperf_cfg_t *) ts->rxbuf;
  int rx_bytes, tx_bytes;

  vperf_atomic_add (&ts->cfg.seq_num, 1);
  if (ts->cfg.verbose)
    {
      vperf_info ("(fd %d): Sending config to server.", ts->fd);
      vperf_cfg_dump (&ts->cfg, 1 /* is_client */);
    }
  tx_bytes = vppcom_session_write (ts->fd, &ts->cfg, sizeof (ts->cfg));
  if (tx_bytes < 0)
    {
      vperf_warn ("(fd %d): write test cfg failed (%d)!", ts->fd, tx_bytes);
      return tx_bytes;
    }

  rx_bytes = vppcom_session_read (ts->fd, ts->rxbuf, sizeof (vperf_cfg_t));
  if (rx_bytes < 0)
    return rx_bytes;

  if (rx_cfg->magic != VPERF_CFG_CTRL_MAGIC)
    {
      vperf_warn ("(fd %d): Bad server reply cfg -- aborting!", ts->fd);
      return -1;
    }
  if ((rx_bytes != sizeof (vperf_cfg_t)))
    {
      vperf_warn ("(fd %d): Invalid config received from server!", ts->fd);
      vperf_info ("\tRx bytes %d != cfg size %lu", rx_bytes, sizeof (vperf_cfg_t));
      return -1;
    }
  /* in post test sync server use some fields for rx stats */
  if (!(ts->cfg.cmd == VPERF_CMD_SYNC && ts->cfg.test == VPERF_TEST_TYPE_ECHO &&
	ts->cfg.total_bytes == 0))
    {
      if (!vperf_cfg_verify (rx_cfg, &ts->cfg))
	{
	  vperf_warn ("(fd %d): Invalid config received from server!", ts->fd);
	  vperf_cfg_dump (rx_cfg, 1 /* is_client */);
	  vperf_info ("(fd %d): Valid config sent to server.", ts->fd);
	  vperf_cfg_dump (&ts->cfg, 1 /* is_client */);
	  return -1;
	}
    }
  if (ts->cfg.verbose)
    {
      vperf_info ("(fd %d): Got config back from server.", ts->fd);
      vperf_cfg_dump (rx_cfg, 1 /* is_client */);
    }

  return 0;
}

static int
vperf_client_worker_alloc_sessions (vperf_client_worker_t *wrk)
{
  vperf_session_t *ts;
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
    wrk->sessions = realloc (wrk->sessions, n_test_sessions * sizeof (vperf_session_t));
  else
    wrk->sessions = calloc (n_test_sessions, sizeof (vperf_session_t));

  if (!wrk->sessions)
    {
      vperf_err ("failed to alloc sessions", -errno);
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
      vperf_session_buf_alloc (ts);

      switch (ts->cfg.test)
	{
	case VPERF_TEST_TYPE_UNI:
	case VPERF_TEST_TYPE_BI:
	  for (j = 0; j < ts->txbuf_size; j++)
	    ts->txbuf[j] = j & 0xff;
	  break;
	default:
	  break;
	}
    }
  wrk->n_sessions = n_test_sessions;

done:

  vperf_info ("All test sessions (%d) initialized!", n_test_sessions);

  return 0;
}

static int
vperf_client_worker_init (vperf_client_worker_t *wrk)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  int rv;

  __wrk_index = wrk->wrk_index;

  vperf_info ("Initializing worker %u ...", wrk->wrk_index);

  if (wrk->wrk_index)
    {
      if (vppcom_worker_register ())
	{
	  vperf_warn ("failed to register worker");
	  return -1;
	}
      vperf_atomic_add (&vcm->active_workers, 1);
    }
  rv = vperf_client_worker_alloc_sessions (wrk);
  if (rv)
    {
      vperf_err ("vperf_client_worker_alloc_sessions ()", rv);
      return rv;
    }

  return 0;
}

static int stats_lock = 0;

static void
vperf_client_accumulate_stats (vperf_client_worker_t *wrk, vperf_session_t *ctrl)
{
  vperf_session_t *ts;
  static char buf[64];
  int i, show_rx = 0;

  while (__sync_lock_test_and_set (&stats_lock, 1))
    ;

  if (ctrl->cfg.test == VPERF_TEST_TYPE_BI || ctrl->cfg.test == VPERF_TEST_TYPE_ECHO)
    show_rx = 1;

  for (i = 0; i < wrk->cfg.num_test_sessions; i++)
    {
      ts = &wrk->sessions[i];
      ts->stats.start = ctrl->stats.start;

      if (ctrl->cfg.verbose > 1)
	{
	  snprintf (buf, sizeof (buf), "CLIENT (fd %d) RESULTS", ts->fd);
	  vperf_stats_dump (buf, &ts->stats, show_rx, 1 /* show tx */, ctrl->cfg.verbose);
	}

      vperf_stats_accumulate (&ctrl->stats, &ts->stats);
      if (vcl_comp_tspec (&ctrl->stats.stop, &ts->stats.stop) < 0)
	ctrl->stats.stop = ts->stats.stop;
    }

  __sync_lock_release (&stats_lock);
}

static void
vperf_client_worker_sessions_exit (vperf_client_worker_t *wrk)
{
  vperf_session_t *ts;
  int i;

  for (i = 0; i < wrk->cfg.num_test_sessions; i++)
    {
      ts = &wrk->sessions[i];
      vppcom_session_close (ts->fd);
      vperf_session_buf_free (ts);
    }

  wrk->n_sessions = 0;
}

static void
vperf_client_worker_inc_stats_check (vperf_client_worker_t *wrk, vperf_session_t *ts)
{
  struct timespec now;
  uint32_t i, n_print = 0;
  uint64_t total_bytes = 0;
  double duration, total_rate;

  /* Avoid checking time too often because of syscall cost */
  if (ts->stats.tx_bytes - ts->old_stats.tx_bytes < 1 << 20)
    return;

  clock_gettime (CLOCK_REALTIME, &now);
  if (vperf_time_diff (&wrk->old_stats_stop, &now) < 1)
    return;

  for (i = 0; i < wrk->cfg.num_test_sessions; i++)
    {
      ts = &wrk->sessions[i];
      if (ts->is_done)
	continue;

      ts->stats.stop = now;
      if (vperf_time_diff (&ts->old_stats.stop, &ts->stats.stop) > 1)
	{
	  vperf_stats_dump_inc (ts, 0 /* is_rx */);
	  total_bytes += ts->stats.tx_bytes - ts->old_stats.tx_bytes;
	  ts->old_stats = ts->stats;
	  n_print++;
	}
    }

  if (n_print > 1)
    {
      duration = vperf_time_diff (&wrk->old_stats_stop, &now);
      total_rate = (double) total_bytes * 8 / duration / 1e9;
      printf ("Sum: Sent %lu Mbytes in %.2lf seconds %.2lf Gbps\n", (uint64_t) (total_bytes / 1e6),
	      duration, total_rate);
      printf ("-------------------------------------------------\n");
    }

  wrk->old_stats_stop = now;
}

static void
vperf_client_worker_start_transfer (vperf_client_worker_t *wrk)
{
  vperf_info ("Worker %u starting transfer ...", wrk->wrk_index);

  if (wrk->wrk_index == 0)
    {
      vperf_client_main_t *vcm = &vperf_client_main;
      vperf_session_t *ctrl = &vcm->ctrl_session;

      clock_gettime (CLOCK_REALTIME, &ctrl->stats.start);
    }
}

static int
vperf_client_worker_connect_sessions_select (vperf_client_worker_t *wrk)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_main_t *vt = &vperf_main;
  const vperf_proto_vft_t *tp;
  vperf_session_t *ts;
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
      wrk->max_fd_index = vperf_client_max (sidx, wrk->max_fd_index);
    }
  wrk->max_fd_index += 1;

  vperf_info ("All test sessions (%d) connected!", wrk->cfg.num_test_sessions);

  return 0;
}

static void
vperf_client_abort_test ()
{
  vperf_client_main_t *vtcm = &vperf_client_main;
  vtcm->test_running = 0;
  exit (1);
}

static int
vperf_client_worker_run_select (vperf_client_worker_t *wrk)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  fd_set _wfdset, *wfdset = &_wfdset;
  fd_set _rfdset, *rfdset = &_rfdset;
  uint32_t n_active_sessions;
  vperf_session_t *ts;
  int i, rv, check_rx = 0;

  rv = vperf_client_worker_connect_sessions_select (wrk);
  if (rv)
    {
      vperf_err ("vperf_client_worker_connect_sessions()", rv);
      return rv;
    }

  check_rx = wrk->cfg.test != VPERF_TEST_TYPE_UNI;
  n_active_sessions = wrk->cfg.num_test_sessions;

  vperf_client_worker_start_transfer (wrk);

  while (n_active_sessions && vcm->test_running)
    {
      _wfdset = wrk->wr_fdset;
      _rfdset = wrk->rd_fdset;

      rv = vppcom_select (wrk->max_fd_index, (unsigned long *) rfdset, (unsigned long *) wfdset,
			  NULL, 0);
      if (rv < 0)
	{
	  vperf_err ("vppcom_select()", rv);
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
		  vperf_warn ("vppcom_test_read (%d) failed -- aborting test", ts->fd);
		  vperf_client_abort_test ();
		}
	    }

	  if (FD_ISSET (vppcom_session_index (ts->fd), wfdset) &&
	      ts->stats.tx_bytes < ts->cfg.total_bytes)
	    {
	      rv = ts->write (ts, ts->txbuf, ts->cfg.txbuf_size);
	      if (rv < 0)
		{
		  vperf_warn ("vppcom_test_write (%d) failed -- aborting test", ts->fd);
		  vperf_client_abort_test ();
		}
	      if (vcm->incremental_stats)
		vperf_client_worker_inc_stats_check (wrk, ts);
	    }
	  if (ts->done (ts, check_rx))
	    n_active_sessions -= 1;
	}
    }

  return 0;
}

static void
vperf_client_worker_epoll_send_add (vperf_client_worker_t *wrk, vperf_session_t *ts)
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
vperf_client_worker_epoll_send_del (vperf_client_worker_t *wrk, vperf_session_t *ts)
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
vperf_client_worker_connect_sessions_epoll (vperf_client_worker_t *wrk)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_main_t *vt = &vperf_main;
  const vperf_proto_vft_t *tp;
  struct timespec start, end;
  uint32_t n_connected = 0;
  vperf_session_t *ts;
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
	      vperf_warn ("open: %d", rv);
	      return rv;
	    }

	  ev.data.u64 = ci;
	  rv = vppcom_epoll_ctl (wrk->epoll_sh, EPOLL_CTL_ADD, ts->fd, &ev);
	  if (rv < 0)
	    {
	      vperf_warn ("vppcom_epoll_ctl: %d", rv);
	      return rv;
	    }
	  ci += 1;
	}

      /*
       * Handle connected events
       */
      n_ev = vppcom_epoll_wait (wrk->epoll_sh, wrk->ep_evts, VPERF_CFG_MAX_EPOLL_EVENTS,
				0 /* timeout */);
      if (n_ev < 0)
	{
	  vperf_err ("vppcom_epoll_wait() returned", n_ev);
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
	      vperf_warn ("connect failed");
	      return -1;
	    }
	  if (ts->is_open)
	    {
	      vperf_warn ("connection already open?");
	      return -1;
	    }
	  ts->is_open = 1;
	  n_connected += 1;
	}
    }

  clock_gettime (CLOCK_REALTIME, &end);

  diff = vperf_time_diff (&start, &end);
  vperf_info ("Connected (%u) connected in %.2f seconds (%u CPS)!", wrk->cfg.num_test_sessions,
	      diff, (uint32_t) ((double) wrk->cfg.num_test_sessions / diff));

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
	  vperf_warn ("vppcom_epoll_ctl: %d", rv);
	  return rv;
	}
      vperf_client_worker_epoll_send_add (wrk, ts);
    }

  return n_connected;
}

static int
vperf_client_worker_run_epoll (vperf_client_worker_t *wrk)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  uint32_t n_active_sessions, max_writes = 16, n_writes = 0;
  vperf_session_t *ts, *next;
  int i, rv, check_rx = 0, n_ev;
  const vperf_proto_vft_t *tp;

  rv = vperf_client_worker_connect_sessions_epoll (wrk);
  if (rv < 0)
    {
      vperf_err ("vperf_client_worker_connect_sessions()", rv);
      return rv;
    }

  n_active_sessions = rv;
  check_rx = wrk->cfg.test != VPERF_TEST_TYPE_UNI;

  vperf_client_worker_start_transfer (wrk);
  next = wrk->next_to_send;

  tp = vperf_main.protos[vcm->proto];

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
	    vperf_client_worker_inc_stats_check (wrk, ts);
	}
      else if (rv == 0)
	{
	  vperf_client_worker_epoll_send_del (wrk, ts);
	}
      else
	{
	  vperf_warn ("vppcom_test_write (%d) failed -- aborting test", ts->fd);
	  return -1;
	}
      n_writes += 1;

      if (rv > 0 && n_writes < max_writes)
	continue;

    get_epoll_evts:

      /*
       * Grab new events
       */

      n_ev = vppcom_epoll_wait (wrk->epoll_sh, wrk->ep_evts, VPERF_CFG_MAX_EPOLL_EVENTS,
				0 /* timeout */);
      if (n_ev < 0)
	{
	  vperf_err ("vppcom_epoll_wait()", n_ev);
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
		  vperf_warn ("%u finished before reading all data -- aborting test", ts->fd);
		  return -1;
		}
	    }
	  if ((wrk->ep_evts[i].events & EPOLLIN) && ts->stats.rx_bytes < ts->cfg.total_bytes)
	    {
	      rv = ts->read (ts, ts->rxbuf, ts->rxbuf_size);
	      if (rv < 0)
		break;
	      if (ts->done (ts, check_rx))
		n_active_sessions -= 1;
	    }
	  if ((wrk->ep_evts[i].events & EPOLLOUT) && ts->stats.tx_bytes < ts->cfg.total_bytes)
	    {
	      vperf_client_worker_epoll_send_add (wrk, ts);
	    }
	}

      n_writes = 0;
    }

  return 0;
}

static inline int
vperf_client_worker_run (vperf_client_worker_t *wrk)
{
  int rv;

  vperf_info ("Worker %u starting test ...", wrk->wrk_index);

  rv = wrk->wrk_run_fn (wrk);

  vperf_info ("Worker %d done ...", wrk->wrk_index);

  return rv;
}

static void *
vperf_client_worker_loop (void *arg)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_session_t *ctrl = &vcm->ctrl_session;
  vperf_client_worker_t *wrk = arg;

  if (vperf_client_worker_init (wrk))
    goto done;

  if (vperf_client_worker_run (wrk))
    goto done;

  vperf_client_accumulate_stats (wrk, ctrl);
  sleep (VPERF_DELAY_DISCONNECT);
  vperf_client_worker_sessions_exit (wrk);

done:

  if (wrk->wrk_index)
    vperf_atomic_add (&vcm->active_workers, -1);

  return 0;
}

static void
vperf_client_print_stats (vperf_session_t *ctrl)
{
  int is_echo = ctrl->cfg.test == VPERF_TEST_TYPE_ECHO;
  int show_rx = 0;
  char buf[64];

  if (ctrl->cfg.test == VPERF_TEST_TYPE_BI || ctrl->cfg.test == VPERF_TEST_TYPE_ECHO)
    show_rx = 1;

  vperf_stats_dump ("CLIENT RESULTS", &ctrl->stats, show_rx, 1 /* show tx */, ctrl->cfg.verbose);
  vperf_cfg_dump (&ctrl->cfg, 1 /* is_client */);

  if (ctrl->cfg.verbose)
    {
      vperf_info ("  ctrl session info\n" VPERF_SEPARATOR_STRING "          fd:  %d (0x%08x)\n"
		  "       rxbuf:  %p\n"
		  "  rxbuf size:  %u (0x%08x)\n"
		  "       txbuf:  %p\n"
		  "  txbuf size:  %u (0x%08x)\n" VPERF_SEPARATOR_STRING,
		  ctrl->fd, (uint32_t) ctrl->fd, ctrl->rxbuf, ctrl->rxbuf_size, ctrl->rxbuf_size,
		  ctrl->txbuf, ctrl->txbuf_size, ctrl->txbuf_size);
    }

  if (is_echo)
    snprintf (buf, sizeof (buf), "Echo");
  else
    snprintf (buf, sizeof (buf), "%s-directional Stream",
	      ctrl->cfg.test == VPERF_TEST_TYPE_BI ? "Bi" : "Uni");
}

static void
vperf_client_echo (vperf_client_main_t *vcm)
{
  vperf_session_t *ctrl = &vcm->ctrl_session;
  vperf_cfg_t *cfg = &ctrl->cfg;
  int rv;

  cfg->total_bytes = strlen (ctrl->txbuf) + 1;
  memset (&ctrl->stats, 0, sizeof (ctrl->stats));

  rv = ctrl->write (ctrl, ctrl->txbuf, cfg->total_bytes);
  if (rv < 0)
    {
      vperf_warn ("vppcom_test_write (%d) failed ", ctrl->fd);
      return;
    }

  (void) ctrl->read (ctrl, ctrl->rxbuf, ctrl->rxbuf_size);
}

static void
vperf_client_stream (vperf_client_main_t *vcm)
{
  vperf_session_t *ctrl = &vcm->ctrl_session;
  vperf_cfg_t *cfg = &ctrl->cfg;
  vperf_client_worker_t *wrk;
  uint32_t i, n_conn, n_conn_per_wrk;

  vperf_info ("%s-directional Stream Test Starting!",
	      ctrl->cfg.test == VPERF_TEST_TYPE_BI ? "Bi" : "Uni");

  memset (&ctrl->stats, 0, sizeof (vperf_stats_t));
  cfg->total_bytes = cfg->num_writes * cfg->txbuf_size;
  cfg->ctrl_handle = ctrl->fd;

  n_conn = cfg->num_test_sessions;
  n_conn_per_wrk = n_conn / vcm->n_workers;
  for (i = 0; i < vcm->n_workers; i++)
    {
      wrk = &vcm->workers[i];
      wrk->wrk_index = i;
      wrk->cfg = ctrl->cfg;
      wrk->cfg.num_test_sessions = vperf_client_min (n_conn_per_wrk, n_conn);
      n_conn -= wrk->cfg.num_test_sessions;
    }

  vcm->test_running = 1;
  ctrl->cfg.cmd = VPERF_CMD_START;
  if (vperf_client_cfg_sync (ctrl))
    {
      vperf_warn ("test cfg sync failed -- aborting!");
      return;
    }

  for (i = 1; i < vcm->n_workers; i++)
    {
      wrk = &vcm->workers[i];
      if (pthread_create (&wrk->thread_handle, NULL, vperf_client_worker_loop, (void *) wrk))
	{
	  vperf_warn ("pthread_create failed -- aborting!");
	  return;
	}
    }
  vperf_client_worker_loop (&vcm->workers[0]);

  while (vcm->active_workers > 0)
    ;

  vperf_info ("Sending config on ctrl session (fd %d) for stats...", ctrl->fd);
  ctrl->cfg.cmd = VPERF_CMD_STOP;
  if (vperf_client_cfg_sync (ctrl))
    {
      vperf_warn ("test cfg sync failed -- aborting!");
      return;
    }

  vperf_client_print_stats (ctrl);

  ctrl->cfg.cmd = VPERF_CMD_SYNC;
  ctrl->cfg.test = VPERF_TEST_TYPE_ECHO;
  ctrl->cfg.total_bytes = 0;
  if (vperf_client_cfg_sync (ctrl))
    vperf_warn ("post-test cfg sync failed!");
}

static void
cfg_txbuf_size_set (void)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_session_t *ctrl = &vcm->ctrl_session;
  char *p = ctrl->txbuf + strlen (VPERF_TOKEN_TXBUF_SIZE);
  uint64_t txbuf_size = strtoull ((const char *) p, NULL, 10);

  if (txbuf_size >= VPERF_CFG_BUF_SIZE_MIN)
    {
      ctrl->cfg.txbuf_size = txbuf_size;
      ctrl->cfg.total_bytes = ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
      vperf_buf_alloc (&ctrl->cfg, 0 /* is_rxbuf */, (uint8_t **) &ctrl->txbuf, &ctrl->txbuf_size);
      vperf_cfg_dump (&ctrl->cfg, 1 /* is_client */);
    }
  else
    vperf_warn ("Invalid txbuf size (%lu) < minimum buf size (%u)!", txbuf_size,
		VPERF_CFG_BUF_SIZE_MIN);
}

static void
cfg_num_writes_set (void)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_session_t *ctrl = &vcm->ctrl_session;
  char *p = ctrl->txbuf + strlen (VPERF_TOKEN_NUM_WRITES);
  uint32_t num_writes = strtoul ((const char *) p, NULL, 10);

  if (num_writes > 0)
    {
      ctrl->cfg.num_writes = num_writes;
      ctrl->cfg.total_bytes = ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
      vperf_cfg_dump (&ctrl->cfg, 1 /* is_client */);
    }
  else
    {
      vperf_warn ("invalid num writes: %u", num_writes);
    }
}

static void
cfg_num_test_sessions_set (void)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_session_t *ctrl = &vcm->ctrl_session;
  char *p = ctrl->txbuf + strlen (VPERF_TOKEN_NUM_TEST_SESS);
  uint32_t num_test_sessions = strtoul ((const char *) p, NULL, 10);

  if ((num_test_sessions > 0) && (num_test_sessions <= VPERF_CFG_MAX_TEST_SESS))
    {
      ctrl->cfg.num_test_sessions = num_test_sessions;
      vperf_cfg_dump (&ctrl->cfg, 1 /* is_client */);
    }
  else
    {
      vperf_warn ("invalid num test sessions: %u, (%d max)", num_test_sessions,
		  VPERF_CFG_MAX_TEST_SESS);
    }
}

static void
cfg_rxbuf_size_set (void)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_session_t *ctrl = &vcm->ctrl_session;
  char *p = ctrl->txbuf + strlen (VPERF_TOKEN_RXBUF_SIZE);
  uint64_t rxbuf_size = strtoull ((const char *) p, NULL, 10);

  if (rxbuf_size >= VPERF_CFG_BUF_SIZE_MIN)
    {
      ctrl->cfg.rxbuf_size = rxbuf_size;
      vperf_buf_alloc (&ctrl->cfg, 1 /* is_rxbuf */, (uint8_t **) &ctrl->rxbuf, &ctrl->rxbuf_size);
      vperf_cfg_dump (&ctrl->cfg, 1 /* is_client */);
    }
  else
    vperf_warn ("Invalid rxbuf size (%lu) < minimum buf size (%u)!", rxbuf_size,
		VPERF_CFG_BUF_SIZE_MIN);
}

static void
cfg_verbose_toggle (void)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_session_t *ctrl = &vcm->ctrl_session;

  ctrl->cfg.verbose = ctrl->cfg.verbose ? 0 : 1;
  vperf_cfg_dump (&ctrl->cfg, 1 /* is_client */);
}

static vperf_test_t
parse_input ()
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_session_t *ctrl = &vcm->ctrl_session;
  vperf_test_t rv = VPERF_TEST_TYPE_NONE;

  if (!strncmp (VPERF_TOKEN_EXIT, ctrl->txbuf, strlen (VPERF_TOKEN_EXIT)))
    rv = VPERF_TEST_TYPE_EXIT;

  else if (!strncmp (VPERF_TOKEN_HELP, ctrl->txbuf, strlen (VPERF_TOKEN_HELP)))
    dump_help ();

  else if (!strncmp (VPERF_TOKEN_SHOW_CFG, ctrl->txbuf, strlen (VPERF_TOKEN_SHOW_CFG)))
    vcm->dump_cfg = 1;

  else if (!strncmp (VPERF_TOKEN_VERBOSE, ctrl->txbuf, strlen (VPERF_TOKEN_VERBOSE)))
    cfg_verbose_toggle ();

  else if (!strncmp (VPERF_TOKEN_TXBUF_SIZE, ctrl->txbuf, strlen (VPERF_TOKEN_TXBUF_SIZE)))
    cfg_txbuf_size_set ();

  else if (!strncmp (VPERF_TOKEN_NUM_TEST_SESS, ctrl->txbuf, strlen (VPERF_TOKEN_NUM_TEST_SESS)))
    cfg_num_test_sessions_set ();

  else if (!strncmp (VPERF_TOKEN_NUM_WRITES, ctrl->txbuf, strlen (VPERF_TOKEN_NUM_WRITES)))
    cfg_num_writes_set ();

  else if (!strncmp (VPERF_TOKEN_RXBUF_SIZE, ctrl->txbuf, strlen (VPERF_TOKEN_RXBUF_SIZE)))
    cfg_rxbuf_size_set ();

  else if (!strncmp (VPERF_TOKEN_RUN_UNI, ctrl->txbuf, strlen (VPERF_TOKEN_RUN_UNI)))
    rv = ctrl->cfg.test = VPERF_TEST_TYPE_UNI;

  else if (!strncmp (VPERF_TOKEN_RUN_BI, ctrl->txbuf, strlen (VPERF_TOKEN_RUN_BI)))
    rv = ctrl->cfg.test = VPERF_TEST_TYPE_BI;

  else
    rv = VPERF_TEST_TYPE_ECHO;

  return rv;
}

static int
vperf_client_unformat_test_param (uint32_t *test_param, char *test_param_str)
{
  if (!strcmp (test_param_str, "server-rst-stream"))
    *test_param = VPERF_PARAM_SERVER_RST_STREAM;
  else if (!strcmp (test_param_str, "client-rst-stream"))
    *test_param = VPERF_PARAM_CLIENT_RST_STREAM;
  else if (!strcmp (test_param_str, "server-close-conn"))
    *test_param = VPERF_PARAM_SERVER_CLOSE_CONN;
  else if (!strcmp (test_param_str, "client-close-conn"))
    *test_param = VPERF_PARAM_CLIENT_CLOSE_CONN;
  else
    return 1;
  return 0;
}

void
print_usage_and_exit (void)
{
  fprintf (stderr, "vperf_client [OPTIONS] <ipaddr> <port>\n"
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
vperf_client_process_opts (vperf_client_main_t *vcm, int argc, char **argv)
{
  vperf_session_t *ctrl = &vcm->ctrl_session;
  int c, v;

  opterr = 0;
  while ((c = getopt (argc, argv, "chnp:w:xXE:I:N:R:T:b:UBV6DLs:q:St:")) != -1)
    switch (c)
      {
      case 'c':
	vcm->dump_cfg = 1;
	break;

      case 'I': /* deprecated */
      case 's':
	if (sscanf (optarg, "0x%x", &ctrl->cfg.num_test_sessions) != 1)
	  if (sscanf (optarg, "%u", &ctrl->cfg.num_test_sessions) != 1)
	    {
	      vperf_warn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (!ctrl->cfg.num_test_sessions || (ctrl->cfg.num_test_sessions > VPERF_CFG_MAX_TEST_SESS))
	  {
	    vperf_warn ("Invalid number of sessions (%d) specified for option -%c!"
			"\n       Valid range is 1 - %d",
			ctrl->cfg.num_test_sessions, c, VPERF_CFG_MAX_TEST_SESS);
	    print_usage_and_exit ();
	  }
	break;

      case 'q':
	if (sscanf (optarg, "0x%x", &ctrl->cfg.num_test_sessions_perq) != 1)
	  if (sscanf (optarg, "%u", &ctrl->cfg.num_test_sessions_perq) != 1)
	    {
	      vperf_warn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (!ctrl->cfg.num_test_sessions_perq ||
	    (ctrl->cfg.num_test_sessions_perq > VPERF_CFG_MAX_TEST_SESS))
	  {
	    vperf_warn ("Invalid number of Stream sessions (%d) per Qsession"
			"for option -%c!\nValid range is 1 - %d",
			ctrl->cfg.num_test_sessions_perq, c, VPERF_CFG_MAX_TEST_SESS);
	    print_usage_and_exit ();
	  }
	break;

      case 'w':
	if (sscanf (optarg, "%d", &v) != 1)
	  {
	    vperf_warn ("Invalid value for option -%c!", c);
	    print_usage_and_exit ();
	  }
	if (v > 1)
	  vcm->n_workers = v;
	break;

      case 'X':
	vcm->post_test = VPERF_TEST_TYPE_EXIT;
	break;

      case 'x':
	vcm->post_test = VPERF_TEST_TYPE_NONE;
	break;

      case 'E':
	if (strlen (optarg) > ctrl->txbuf_size)
	  {
	    vperf_warn ("Option -%c value larger than txbuf size (%d)!", optopt, ctrl->txbuf_size);
	    print_usage_and_exit ();
	  }
	strncpy (ctrl->txbuf, optarg, ctrl->txbuf_size);
	ctrl->cfg.test = VPERF_TEST_TYPE_ECHO;
	break;

      case 'N':
	if (sscanf (optarg, "0x%lx", &ctrl->cfg.num_writes) != 1)
	  if (sscanf (optarg, "%ld", &ctrl->cfg.num_writes) != 1)
	    {
	      vperf_warn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	ctrl->cfg.total_bytes = ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
	break;

      case 'R':
	if (sscanf (optarg, "0x%lx", &ctrl->cfg.rxbuf_size) != 1)
	  if (sscanf (optarg, "%ld", &ctrl->cfg.rxbuf_size) != 1)
	    {
	      vperf_warn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (ctrl->cfg.rxbuf_size >= VPERF_CFG_BUF_SIZE_MIN)
	  {
	    ctrl->rxbuf_size = ctrl->cfg.rxbuf_size;
	    vperf_buf_alloc (&ctrl->cfg, 1 /* is_rxbuf */, (uint8_t **) &ctrl->rxbuf,
			     &ctrl->rxbuf_size);
	  }
	else
	  {
	    vperf_warn ("rxbuf size (%lu) less than minumum (%u)", ctrl->cfg.rxbuf_size,
			VPERF_CFG_BUF_SIZE_MIN);
	    print_usage_and_exit ();
	  }

	break;

      case 'T':
	if (sscanf (optarg, "0x%lx", &ctrl->cfg.txbuf_size) != 1)
	  if (sscanf (optarg, "%ld", &ctrl->cfg.txbuf_size) != 1)
	    {
	      vperf_warn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (ctrl->cfg.txbuf_size >= VPERF_CFG_BUF_SIZE_MIN)
	  {
	    ctrl->txbuf_size = ctrl->cfg.txbuf_size;
	    vperf_buf_alloc (&ctrl->cfg, 0 /* is_rxbuf */, (uint8_t **) &ctrl->txbuf,
			     &ctrl->txbuf_size);
	    ctrl->cfg.total_bytes = ctrl->cfg.num_writes * ctrl->cfg.txbuf_size;
	  }
	else
	  {
	    vperf_warn ("txbuf size (%lu) less than minumum (%u)!", ctrl->cfg.txbuf_size,
			VPERF_CFG_BUF_SIZE_MIN);
	    print_usage_and_exit ();
	  }
	break;
      case 'b':
	if (sscanf (optarg, "0x%lu", &ctrl->cfg.total_bytes) != 1)
	  if (sscanf (optarg, "%ld", &ctrl->cfg.total_bytes) != 1)
	    {
	      vperf_warn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (ctrl->cfg.total_bytes % ctrl->cfg.txbuf_size)
	  {
	    vperf_warn ("total bytes must be mutliple of txbuf size(0x%lu)!", ctrl->cfg.txbuf_size);
	    print_usage_and_exit ();
	  }
	ctrl->cfg.num_writes = ctrl->cfg.total_bytes / ctrl->cfg.txbuf_size;
	break;

      case 'U':
	ctrl->cfg.test = VPERF_TEST_TYPE_UNI;
	break;

      case 'B':
	ctrl->cfg.test = VPERF_TEST_TYPE_BI;
	break;

      case 'V':
	ctrl->cfg.verbose = 1;
	break;

      case '6':
	ctrl->cfg.address_ip6 = 1;
	break;

      case 'p':
	if (vppcom_unformat_proto (&vcm->proto, optarg))
	  vperf_warn ("Invalid vppcom protocol %s, defaulting to TCP", optarg);
	break;

      case 'D': /* deprecated */
	vcm->proto = VPPCOM_PROTO_UDP;
	break;

      case 'L': /* deprecated */
	vcm->proto = VPPCOM_PROTO_TLS;
	break;

      case 'S':
	vcm->incremental_stats = 1;
	break;

      case 't':
	if (vperf_client_unformat_test_param (&ctrl->cfg.test_param, optarg))
	  {
	    vperf_warn ("Invalid value for option -%c!", c);
	    print_usage_and_exit ();
	  }
	break;

      case '?':
	switch (optopt)
	  {
	  case 'E':
	  case 'I': /* deprecated */
	  case 'N':
	  case 'R':
	  case 'T':
	  case 'w':
	  case 'p':
	  case 'q':
	  case 't':
	    vperf_warn ("Option -%c requires an argument.", optopt);
	    break;

	  default:
	    if (isprint (optopt))
	      vperf_warn ("Unknown option `-%c'.", optopt);
	    else
	      vperf_warn ("Unknown option character `\\x%x'.", optopt);
	  }
	/* fall thru */
      case 'h':
      default:
	print_usage_and_exit ();
      }

  if (argc < (optind + 1))
    {
      vperf_warn ("Invalid number of arguments!");
      print_usage_and_exit ();
    }

  ctrl->cfg.num_test_qsessions =
    vcm->proto != VPPCOM_PROTO_QUIC ?
      0 :
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
    vcm->server_endpt.port = htons (VPERF_SERVER_PORT);
}

static void
vperf_client_read_user_input (vperf_session_t *ctrl)
{
  printf ("\nType some characters and hit <return>\n"
	  "('" VPERF_TOKEN_HELP "' for help): ");

  if (fgets (ctrl->txbuf, ctrl->txbuf_size, stdin) != NULL)
    {
      if (strlen (ctrl->txbuf) == 1)
	{
	  printf ("\nNothing to send!  Please try again...\n");
	  return;
	}
      ctrl->txbuf[strlen (ctrl->txbuf) - 1] = 0; // chomp the newline.

      /* Parse input for keywords */
      ctrl->cfg.test = parse_input ();
    }
}

static void
vperf_client_ctrl_session_exit (void)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_session_t *ctrl = &vcm->ctrl_session;
  int verbose = ctrl->cfg.verbose;

  /* Only clients exits, server can accept new connections */
  if (vcm->post_test == VPERF_TEST_TYPE_EXIT_CLIENT)
    return;

  ctrl->cfg.test = VPERF_TEST_TYPE_EXIT;
  vperf_info ("(fd %d): Sending exit cfg to server...", ctrl->fd);
  if (verbose)
    vperf_cfg_dump (&ctrl->cfg, 1 /* is_client */);
  (void) vperf_write (ctrl, (uint8_t *) &ctrl->cfg, sizeof (ctrl->cfg));
  sleep (1);
}

static int
vperf_client_ctrl_session_init (vperf_client_main_t *vcm, vperf_session_t *ctrl)
{
  int rv;

  ctrl->fd = vppcom_session_create (VPPCOM_PROTO_TCP, 0 /* is_nonblocking */);
  if (ctrl->fd < 0)
    {
      vperf_err ("vppcom_session_create()", ctrl->fd);
      return ctrl->fd;
    }

  vperf_info ("Connecting to server...");
  rv = vppcom_session_connect (ctrl->fd, &vcm->server_endpt);
  if (rv)
    {
      vperf_err ("vppcom_session_connect()", rv);
      return rv;
    }
  vperf_info ("Control session (fd %d) connected.", ctrl->fd);

  ctrl->read = vperf_read;
  ctrl->write = vperf_write;

  ctrl->cfg.cmd = VPERF_CMD_SYNC;
  rv = vperf_client_cfg_sync (ctrl);
  if (rv)
    {
      vperf_err ("vperf_client_cfg_sync()", rv);
      return rv;
    }

  ctrl->cfg.ctrl_handle = ((vperf_cfg_t *) ctrl->rxbuf)->ctrl_handle;
  memset (&ctrl->stats, 0, sizeof (ctrl->stats));

  return 0;
}

static void
vperf_sigs_handler (int signum, siginfo_t *si, void *uc)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_session_t *ctrl = &vcm->ctrl_session;

  vcm->test_running = 0;
  clock_gettime (CLOCK_REALTIME, &ctrl->stats.stop);
}

static void
vperf_incercept_sigs (void)
{
  struct sigaction sa;

  memset (&sa, 0, sizeof (sa));
  sa.sa_sigaction = vperf_sigs_handler;
  sa.sa_flags = SA_SIGINFO;
  if (sigaction (SIGINT, &sa, 0))
    {
      vperf_warn ("couldn't intercept sigint");
      exit (-1);
    }
}

static void
vperf_client_alloc_workers (vperf_client_main_t *vcm)
{
  vperf_main_t *vt = &vperf_main;
  vperf_client_worker_run_fn *run_fn;

  vcm->workers = calloc (vcm->n_workers, sizeof (vperf_client_worker_t));
  vt->wrk = calloc (vcm->n_workers, sizeof (vperf_wrk_t));

  if (vcm->ctrl_session.cfg.num_test_sessions > VPERF_CFG_MAX_SELECT_SESS ||
      vcm->proto == VPPCOM_PROTO_QUIC)
    run_fn = vperf_client_worker_run_epoll;
  else
    run_fn = vperf_client_worker_run_select;

  for (int i = 0; i < vcm->n_workers; i++)
    vcm->workers[i].wrk_run_fn = run_fn;
}

int
main (int argc, char **argv)
{
  vperf_client_main_t *vcm = &vperf_client_main;
  vperf_session_t *ctrl = &vcm->ctrl_session;
  vperf_main_t *vt = &vperf_main;
  int rv;

  vcm->n_workers = 1;
  vcm->post_test = VPERF_TEST_TYPE_EXIT_CLIENT;

  vperf_cfg_init (&ctrl->cfg);
  vperf_incercept_sigs ();
  vperf_session_buf_alloc (ctrl);
  vperf_client_process_opts (vcm, argc, argv);

  vperf_client_alloc_workers (vcm);

  rv = vppcom_app_create ("vperf_client");
  if (rv < 0)
    vperf_fail ("vppcom_app_create()", rv);

  /* Protos like tls/dtls/quic need init */
  if (vt->protos[vcm->proto]->init)
    {
      rv = vt->protos[vcm->proto]->init (&ctrl->cfg);
      if (rv)
	vperf_fail ("client init failed", rv);
    }

  if ((rv = vperf_client_ctrl_session_init (vcm, ctrl)))
    vperf_fail ("vppcom_session_create() ctrl session", rv);

  /* Update ctrl port to data port */
  vcm->server_endpt.port = vperf_make_data_port (vcm->server_endpt.port);

  while (ctrl->cfg.test != VPERF_TEST_TYPE_EXIT)
    {
      if (vcm->dump_cfg)
	{
	  vperf_cfg_dump (&ctrl->cfg, 1 /* is_client */);
	  vcm->dump_cfg = 0;
	}

      switch (ctrl->cfg.test)
	{
	case VPERF_TEST_TYPE_ECHO:
	  vperf_client_echo (vcm);
	  break;

	case VPERF_TEST_TYPE_UNI:
	case VPERF_TEST_TYPE_BI:
	  vperf_client_stream (vcm);
	  break;

	case VPERF_TEST_TYPE_EXIT:
	  continue;

	case VPERF_TEST_TYPE_NONE:
	default:
	  break;
	}
      switch (vcm->post_test)
	{
	case VPERF_TEST_TYPE_EXIT:
	case VPERF_TEST_TYPE_EXIT_CLIENT:
	  switch (ctrl->cfg.test)
	    {
	    case VPERF_TEST_TYPE_EXIT:
	    case VPERF_TEST_TYPE_UNI:
	    case VPERF_TEST_TYPE_BI:
	    case VPERF_TEST_TYPE_ECHO:
	      ctrl->cfg.test = VPERF_TEST_TYPE_EXIT;
	      continue;

	    case VPERF_TEST_TYPE_NONE:
	    default:
	      break;
	    }
	  break;

	case VPERF_TEST_TYPE_NONE:
	case VPERF_TEST_TYPE_ECHO:
	case VPERF_TEST_TYPE_UNI:
	case VPERF_TEST_TYPE_BI:
	default:
	  break;
	}

      memset (ctrl->txbuf, 0, ctrl->txbuf_size);
      memset (ctrl->rxbuf, 0, ctrl->rxbuf_size);

      vperf_client_read_user_input (ctrl);
    }

  vperf_client_ctrl_session_exit ();
  vppcom_app_destroy ();
  free (vcm->workers);
  return 0;
}
