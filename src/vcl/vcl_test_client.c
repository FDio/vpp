/*
 * Copyright (c) 2017-2018 Cisco and/or its affiliates.
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

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <vcl/vcl_test.h>
#include <pthread.h>

typedef struct
{
  vcl_test_session_t *sessions;
  uint32_t n_sessions;
  uint32_t wrk_index;
  fd_set wr_fdset;
  fd_set rd_fdset;
  int max_fd_index;
  pthread_t thread_handle;
  vcl_test_cfg_t cfg;
} vcl_test_client_worker_t;

typedef struct
{
  vcl_test_client_worker_t *workers;
  vppcom_endpt_t server_endpt;
  uint32_t cfg_seq_num;
  vcl_test_session_t ctrl_session;
  vcl_test_session_t *sessions;
  uint8_t dump_cfg;
  vcl_test_t post_test;
  uint32_t proto;
  uint32_t n_workers;
  volatile int active_workers;
  struct sockaddr_storage server_addr;
} vcl_test_client_main_t;

static __thread int __wrk_index = 0;

vcl_test_client_main_t vcl_client_main;

#define vtc_min(a, b) (a < b ? a : b)
#define vtc_max(a, b) (a > b ? a : b)

static int
vtc_cfg_sync (vcl_test_session_t * ts)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_cfg_t *rx_cfg = (vcl_test_cfg_t *) ts->rxbuf;
  int rx_bytes, tx_bytes;

  vt_atomic_add (&ts->cfg.seq_num, 1);
  if (ts->cfg.verbose)
    {
      vtinf ("(fd %d): Sending config to server.", ts->fd);
      vcl_test_cfg_dump (&ts->cfg, 1 /* is_client */ );
    }
  tx_bytes = vcl_test_write (ts->fd, (uint8_t *) & ts->cfg,
			     sizeof (ts->cfg), NULL, ts->cfg.verbose);
  if (tx_bytes < 0)
    {
      vtwrn ("(fd %d): write test cfg failed (%d)!", ts->fd, tx_bytes);
      return tx_bytes;
    }

  rx_bytes = vcl_test_read (ts->fd, (uint8_t *) ts->rxbuf,
			    sizeof (vcl_test_cfg_t), NULL);
  if (rx_bytes < 0)
    return rx_bytes;

  if (rx_cfg->magic != VCL_TEST_CFG_CTRL_MAGIC)
    {
      vtwrn ("(fd %d): Bad server reply cfg -- aborting!", ts->fd);
      return -1;
    }
  if ((rx_bytes != sizeof (vcl_test_cfg_t))
      || !vcl_test_cfg_verify (rx_cfg, &ts->cfg))
    {
      vtwrn ("(fd %d): Invalid config received from server!", ts->fd);
      if (rx_bytes != sizeof (vcl_test_cfg_t))
	{
	  vtinf ("\tRx bytes %d != cfg size %lu", rx_bytes,
		 sizeof (vcl_test_cfg_t));
	}
      else
	{
	  vcl_test_cfg_dump (rx_cfg, 1 /* is_client */ );
	  vtinf ("(fd %d): Valid config sent to server.", ts->fd);
	  vcl_test_cfg_dump (&ts->cfg, 1 /* is_client */ );
	}
      return -1;
    }
  if (ts->cfg.verbose)
    {
      vtinf ("(fd %d): Got config back from server.", ts->fd);
      vcl_test_cfg_dump (rx_cfg, 1 /* is_client */ );
    }

  return 0;
}

static int
vtc_connect_test_sessions (vcl_test_client_worker_t * wrk)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ts;
  uint32_t n_test_sessions;
  int i, rv;

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

  for (i = 0; i < n_test_sessions; i++)
    {
      ts = &wrk->sessions[i];
      ts->fd = vppcom_session_create (vcm->proto, 1 /* is_nonblocking */ );
      if (ts->fd < 0)
	{
	  vterr ("vppcom_session_create()", ts->fd);
	  return ts->fd;
	}

      rv = vppcom_session_connect (ts->fd, &vcm->server_endpt);
      if (rv < 0)
	{
	  vterr ("vppcom_session_connect()", rv);
	  return rv;
	}
      vtinf ("Test session %d (fd %d) connected.", i, ts->fd);
    }
  wrk->n_sessions = n_test_sessions;

done:
  vtinf ("All test sessions (%d) connected!", n_test_sessions);
  return 0;
}

static int
vtc_worker_test_setup (vcl_test_client_worker_t * wrk)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  vcl_test_cfg_t *cfg = &wrk->cfg;
  vcl_test_session_t *ts;
  uint32_t sidx;
  int i, j;

  FD_ZERO (&wrk->wr_fdset);
  FD_ZERO (&wrk->rd_fdset);

  for (i = 0; i < cfg->num_test_sessions; i++)
    {
      ts = &wrk->sessions[i];
      ts->cfg = wrk->cfg;
      vcl_test_session_buf_alloc (ts);

      switch (cfg->test)
	{
	case VCL_TEST_TYPE_ECHO:
	  memcpy (ts->txbuf, ctrl->txbuf, cfg->total_bytes);
	  break;
	case VCL_TEST_TYPE_UNI:
	case VCL_TEST_TYPE_BI:
	  for (j = 0; j < ts->txbuf_size; j++)
	    ts->txbuf[j] = j & 0xff;
	  break;
	}

      FD_SET (vppcom_session_index (ts->fd), &wrk->wr_fdset);
      FD_SET (vppcom_session_index (ts->fd), &wrk->rd_fdset);
      sidx = vppcom_session_index (ts->fd);
      wrk->max_fd_index = vtc_max (sidx, wrk->max_fd_index);
    }
  wrk->max_fd_index += 1;

  return 0;
}

static int
vtc_worker_init (vcl_test_client_worker_t * wrk)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  vcl_test_cfg_t *cfg = &wrk->cfg;
  vcl_test_session_t *ts;
  uint32_t i, n;
  int rv, nbytes;

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
  rv = vtc_connect_test_sessions (wrk);
  if (rv)
    {
      vterr ("vtc_connect_test_sessions ()", rv);
      return rv;
    }

  if (vtc_worker_test_setup (wrk))
    return -1;

  vtinf ("Sending config to server on all sessions ...");

  for (n = 0; n < cfg->num_test_sessions; n++)
    {
      ts = &wrk->sessions[n];
      if (vtc_cfg_sync (ts))
	return -1;
      memset (&ts->stats, 0, sizeof (ts->stats));
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

  if (ctrl->cfg.test == VCL_TEST_TYPE_BI
      || ctrl->cfg.test == VCL_TEST_TYPE_ECHO)
    show_rx = 1;

  for (i = 0; i < wrk->cfg.num_test_sessions; i++)
    {
      ts = &wrk->sessions[i];
      ts->stats.start = ctrl->stats.start;

      if (ctrl->cfg.verbose > 1)
	{
	  sprintf (buf, "CLIENT (fd %d) RESULTS", ts->fd);
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
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  vcl_test_session_t *ts;
  int i, verbose = ctrl->cfg.verbose;

  for (i = 0; i < wrk->cfg.num_test_sessions; i++)
    {
      ts = &wrk->sessions[i];
      ts->cfg.test = VCL_TEST_TYPE_EXIT;

      if (verbose)
	{
	  vtinf ("(fd %d): Sending exit cfg to server...", ts->fd);
	  vcl_test_cfg_dump (&ts->cfg, 1 /* is_client */ );
	}
      (void) vcl_test_write (ts->fd, (uint8_t *) & ts->cfg,
			     sizeof (ts->cfg), &ts->stats, verbose);
    }
  wrk->n_sessions = 0;
}

static void *
vtc_worker_loop (void *arg)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  vcl_test_client_worker_t *wrk = arg;
  uint32_t n_active_sessions, n_bytes;
  fd_set _wfdset, *wfdset = &_wfdset;
  fd_set _rfdset, *rfdset = &_rfdset;
  vcl_test_session_t *ts;
  int i, rv, check_rx = 0;

  rv = vtc_worker_init (wrk);
  if (rv)
    {
      vterr ("vtc_worker_init()", rv);
      return 0;
    }

  vtinf ("Starting test ...");

  if (wrk->wrk_index == 0)
    clock_gettime (CLOCK_REALTIME, &ctrl->stats.start);

  check_rx = wrk->cfg.test != VCL_TEST_TYPE_UNI;
  n_active_sessions = wrk->cfg.num_test_sessions;
  while (n_active_sessions)
    {
      _wfdset = wrk->wr_fdset;
      _rfdset = wrk->rd_fdset;

      rv = vppcom_select (wrk->max_fd_index, (unsigned long *) rfdset,
			  (unsigned long *) wfdset, NULL, 0);
      if (rv < 0)
	{
	  vterr ("vppcom_select()", rv);
	  goto exit;
	}
      else if (rv == 0)
	continue;

      for (i = 0; i < wrk->cfg.num_test_sessions; i++)
	{
	  ts = &wrk->sessions[i];
	  if (!((ts->stats.stop.tv_sec == 0) &&
		(ts->stats.stop.tv_nsec == 0)))
	    continue;

	  if (FD_ISSET (vppcom_session_index (ts->fd), rfdset)
	      && ts->stats.rx_bytes < ts->cfg.total_bytes)
	    {
	      (void) vcl_test_read (ts->fd, (uint8_t *) ts->rxbuf,
				    ts->rxbuf_size, &ts->stats);
	    }

	  if (FD_ISSET (vppcom_session_index (ts->fd), wfdset)
	      && ts->stats.tx_bytes < ts->cfg.total_bytes)
	    {
	      n_bytes = ts->cfg.txbuf_size;
	      if (ts->cfg.test == VCL_TEST_TYPE_ECHO)
		n_bytes = strlen (ctrl->txbuf) + 1;
	      rv = vcl_test_write (ts->fd, (uint8_t *) ts->txbuf,
				   n_bytes, &ts->stats, ts->cfg.verbose);
	      if (rv < 0)
		{
		  vtwrn ("vppcom_test_write (%d) failed -- aborting test",
			 ts->fd);
		  goto exit;
		}
	    }

	  if ((!check_rx && ts->stats.tx_bytes >= ts->cfg.total_bytes)
	      || (check_rx && ts->stats.rx_bytes >= ts->cfg.total_bytes))
	    {
	      clock_gettime (CLOCK_REALTIME, &ts->stats.stop);
	      n_active_sessions--;
	    }
	}
    }
exit:
  vtinf ("Worker %d done ...", wrk->wrk_index);
  if (wrk->cfg.test != VCL_TEST_TYPE_ECHO)
    vtc_accumulate_stats (wrk, ctrl);
  sleep (VCL_TEST_DELAY_DISCONNECT);
  vtc_worker_sessions_exit (wrk);
  if (wrk->wrk_index)
    vt_atomic_add (&vcm->active_workers, -1);
  return 0;
}

static void
vtc_print_stats (vcl_test_session_t * ctrl)
{
  int is_echo = ctrl->cfg.test == VCL_TEST_TYPE_ECHO;
  int show_rx = 0;
  char buf[64];

  if (ctrl->cfg.test == VCL_TEST_TYPE_BI
      || ctrl->cfg.test == VCL_TEST_TYPE_ECHO)
    show_rx = 1;

  vcl_test_stats_dump ("CLIENT RESULTS", &ctrl->stats,
		       show_rx, 1 /* show tx */ ,
		       ctrl->cfg.verbose);
  vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );

  if (ctrl->cfg.verbose)
    {
      vtinf ("  ctrl session info\n"
	     VCL_TEST_SEPARATOR_STRING
	     "          fd:  %d (0x%08x)\n"
	     "       rxbuf:  %p\n"
	     "  rxbuf size:  %u (0x%08x)\n"
	     "       txbuf:  %p\n"
	     "  txbuf size:  %u (0x%08x)\n"
	     VCL_TEST_SEPARATOR_STRING,
	     ctrl->fd, (uint32_t) ctrl->fd,
	     ctrl->rxbuf, ctrl->rxbuf_size, ctrl->rxbuf_size,
	     ctrl->txbuf, ctrl->txbuf_size, ctrl->txbuf_size);
    }

  if (is_echo)
    sprintf (buf, "Echo");
  else
    sprintf (buf, "%s-directional Stream",
	     ctrl->cfg.test == VCL_TEST_TYPE_BI ? "Bi" : "Uni");
}

static void
vtc_echo_client (vcl_test_client_main_t * vcm)
{
  vcl_test_client_worker_t *wrk;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  vcl_test_cfg_t *cfg = &ctrl->cfg;

  cfg->total_bytes = strlen (ctrl->txbuf) + 1;
  memset (&ctrl->stats, 0, sizeof (ctrl->stats));

  /* Echo works with only one worker */
  wrk = vcm->workers;
  wrk->wrk_index = 0;
  wrk->cfg = *cfg;

  vtc_worker_loop (wrk);

  /* Not relevant for echo test
     clock_gettime (CLOCK_REALTIME, &ctrl->stats.stop);
     vtc_accumulate_stats (wrk, ctrl);
     vtc_print_stats (ctrl);
   */
}

static void
vtc_stream_client (vcl_test_client_main_t * vcm)
{
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  vcl_test_cfg_t *cfg = &ctrl->cfg;
  vcl_test_client_worker_t *wrk;
  vcl_test_session_t *ts;
  int tx_bytes, rv;
  uint32_t i, n, sidx, n_conn, n_conn_per_wrk;

  vtinf ("%s-directional Stream Test Starting!",
	 ctrl->cfg.test == VCL_TEST_TYPE_BI ? "Bi" : "Uni");

  cfg->total_bytes = cfg->num_writes * cfg->txbuf_size;
  cfg->ctrl_handle = ~0;
  if (vtc_cfg_sync (ctrl))
    {
      vtwrn ("test cfg sync failed -- aborting!");
      return;
    }
  cfg->ctrl_handle = ((vcl_test_cfg_t *) ctrl->rxbuf)->ctrl_handle;
  memset (&ctrl->stats, 0, sizeof (ctrl->stats));

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

  for (i = 1; i < vcm->n_workers; i++)
    {
      wrk = &vcm->workers[i];
      pthread_create (&wrk->thread_handle, NULL, vtc_worker_loop,
		      (void *) wrk);
    }
  vtc_worker_loop (&vcm->workers[0]);

  while (vcm->active_workers > 0)
    ;

  vtinf ("Sending config on ctrl session (fd %d) for stats...", ctrl->fd);
  if (vtc_cfg_sync (ctrl))
    {
      vtwrn ("test cfg sync failed -- aborting!");
      return;
    }

  vtc_print_stats (ctrl);

  ctrl->cfg.test = VCL_TEST_TYPE_ECHO;
  ctrl->cfg.total_bytes = 0;
  if (vtc_cfg_sync (ctrl))
    vtwrn ("post-test cfg sync failed!");
}

static void
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
      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
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
      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
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
      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
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
      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
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
  vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );

}

static vcl_test_t
parse_input ()
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  vcl_test_t rv = VCL_TEST_TYPE_NONE;

  if (!strncmp (VCL_TEST_TOKEN_EXIT, ctrl->txbuf,
		strlen (VCL_TEST_TOKEN_EXIT)))
    rv = VCL_TEST_TYPE_EXIT;

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

  else if (!strncmp (VCL_TEST_TOKEN_RUN_UNI, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_RUN_UNI)))
    rv = ctrl->cfg.test = VCL_TEST_TYPE_UNI;

  else if (!strncmp (VCL_TEST_TOKEN_RUN_BI, ctrl->txbuf,
		     strlen (VCL_TEST_TOKEN_RUN_BI)))
    rv = ctrl->cfg.test = VCL_TEST_TYPE_BI;

  else
    rv = VCL_TEST_TYPE_ECHO;

  return rv;
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
	   "  -D               Use UDP transport layer\n"
	   "  -S               Use TLS transport layer\n"
	   "  -E               Run Echo test.\n"
	   "  -N <num-writes>  Test Cfg: number of writes.\n"
	   "  -R <rxbuf-size>  Test Cfg: rx buffer size.\n"
	   "  -T <txbuf-size>  Test Cfg: tx buffer size.\n"
	   "  -U               Run Uni-directional test.\n"
	   "  -B               Run Bi-directional test.\n"
	   "  -V               Verbose mode.\n");
  exit (1);
}

static void
vtc_process_opts (vcl_test_client_main_t * vcm, int argc, char **argv)
{
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  int c, v;

  opterr = 0;
  while ((c = getopt (argc, argv, "chn:w:XE:I:N:R:T:UBV6DS")) != -1)
    switch (c)
      {
      case 'c':
	vcm->dump_cfg = 1;
	break;

      case 's':
	if (sscanf (optarg, "0x%x", &ctrl->cfg.num_test_sessions) != 1)
	  if (sscanf (optarg, "%u", &ctrl->cfg.num_test_sessions) != 1)
	    {
	      vtwrn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (!ctrl->cfg.num_test_sessions ||
	    (ctrl->cfg.num_test_sessions > FD_SETSIZE))
	  {
	    vtwrn ("Invalid number of sessions (%d) specified for option -%c!"
		   "\n       Valid range is 1 - %d",
		   ctrl->cfg.num_test_sessions, c, FD_SETSIZE);
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
	vcm->post_test = VCL_TEST_TYPE_EXIT;
	break;

      case 'E':
	if (strlen (optarg) > ctrl->txbuf_size)
	  {
	    vtwrn ("Option -%c value larger than txbuf size (%d)!",
		   optopt, ctrl->txbuf_size);
	    print_usage_and_exit ();
	  }
	strcpy (ctrl->txbuf, optarg);
	ctrl->cfg.test = VCL_TEST_TYPE_ECHO;
	break;

      case 'I':
	if (sscanf (optarg, "0x%x", &ctrl->cfg.num_test_sessions) != 1)
	  if (sscanf (optarg, "%d", &ctrl->cfg.num_test_sessions) != 1)
	    {
	      vtwrn ("Invalid value for option -%c!", c);
	      print_usage_and_exit ();
	    }
	if (ctrl->cfg.num_test_sessions > VCL_TEST_CFG_MAX_TEST_SESS)
	  {
	    vtwrn ("value greater than max number test sessions (%d)!",
		   VCL_TEST_CFG_MAX_TEST_SESS);
	    print_usage_and_exit ();
	  }
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

      case 'U':
	ctrl->cfg.test = VCL_TEST_TYPE_UNI;
	break;

      case 'B':
	ctrl->cfg.test = VCL_TEST_TYPE_BI;
	break;

      case 'V':
	ctrl->cfg.verbose = 1;
	break;

      case '6':
	ctrl->cfg.address_ip6 = 1;
	break;

      case 'D':
	ctrl->cfg.transport_udp = 1;
	break;

      case 'S':
	ctrl->cfg.transport_tls = 1;
	break;

      case '?':
	switch (optopt)
	  {
	  case 'E':
	  case 'I':
	  case 'N':
	  case 'R':
	  case 'T':
	  case 'w':
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

  if (argc < (optind + 2))
    {
      vtwrn ("Insufficient number of arguments!");
      print_usage_and_exit ();
    }

  if (ctrl->cfg.transport_udp)
    {
      vcm->proto = VPPCOM_PROTO_UDP;
    }
  else if (ctrl->cfg.transport_tls)
    {
      vcm->proto = VPPCOM_PROTO_TLS;
    }
  else
    {
      vcm->proto = VPPCOM_PROTO_TCP;
    }

  memset (&vcm->server_addr, 0, sizeof (vcm->server_addr));
  if (ctrl->cfg.address_ip6)
    {
      struct sockaddr_in6 *sddr6 = (struct sockaddr_in6 *) &vcm->server_addr;
      sddr6->sin6_family = AF_INET6;
      inet_pton (AF_INET6, argv[optind++], &(sddr6->sin6_addr));
      sddr6->sin6_port = htons (atoi (argv[optind]));

      vcm->server_endpt.is_ip4 = 0;
      vcm->server_endpt.ip = (uint8_t *) & sddr6->sin6_addr;
      vcm->server_endpt.port = (uint16_t) sddr6->sin6_port;
    }
  else
    {
      struct sockaddr_in *saddr4 = (struct sockaddr_in *) &vcm->server_addr;
      saddr4->sin_family = AF_INET;
      inet_pton (AF_INET, argv[optind++], &(saddr4->sin_addr));
      saddr4->sin_port = htons (atoi (argv[optind]));

      vcm->server_endpt.is_ip4 = 1;
      vcm->server_endpt.ip = (uint8_t *) & saddr4->sin_addr;
      vcm->server_endpt.port = (uint16_t) saddr4->sin_port;
    }
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

  ctrl->cfg.test = VCL_TEST_TYPE_EXIT;
  if (verbose)
    {
      vtinf ("(fd %d): Sending exit cfg to server...", ctrl->fd);
      vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
    }
  (void) vcl_test_write (ctrl->fd, (uint8_t *) & ctrl->cfg,
			 sizeof (ctrl->cfg), &ctrl->stats, verbose);
  sleep (1);
}

int
main (int argc, char **argv)
{
  vcl_test_client_main_t *vcm = &vcl_client_main;
  vcl_test_session_t *ctrl = &vcm->ctrl_session;
  int rv, errno_val;

  vcm->n_workers = 1;
  vcl_test_cfg_init (&ctrl->cfg);
  vcl_test_session_buf_alloc (ctrl);
  vtc_process_opts (vcm, argc, argv);

  vcm->workers = calloc (vcm->n_workers, sizeof (vcl_test_client_worker_t));
  rv = vppcom_app_create ("vcl_test_client");
  if (rv < 0)
    vtfail ("vppcom_app_create()", rv);

  ctrl->fd = vppcom_session_create (vcm->proto, 0 /* is_nonblocking */ );
  if (ctrl->fd < 0)
    vtfail ("vppcom_session_create()", ctrl->fd);

  if (vcm->proto == VPPCOM_PROTO_TLS)
    {
      vppcom_session_tls_add_cert (ctrl->fd, vcl_test_crt_rsa,
				   vcl_test_crt_rsa_len);
      vppcom_session_tls_add_key (ctrl->fd, vcl_test_key_rsa,
				  vcl_test_key_rsa_len);
    }


  vtinf ("Connecting to server...");
  rv = vppcom_session_connect (ctrl->fd, &vcm->server_endpt);
  if (rv)
    vtfail ("vppcom_session_connect()", rv);
  vtinf ("Control session (fd %d) connected.", ctrl->fd);

  rv = vtc_cfg_sync (ctrl);
  if (rv)
    vtfail ("vtc_cfg_sync()", rv);

  ctrl->cfg.ctrl_handle = ((vcl_test_cfg_t *) ctrl->rxbuf)->ctrl_handle;
  memset (&ctrl->stats, 0, sizeof (ctrl->stats));

  while (ctrl->cfg.test != VCL_TEST_TYPE_EXIT)
    {
      if (vcm->dump_cfg)
	{
	  vcl_test_cfg_dump (&ctrl->cfg, 1 /* is_client */ );
	  vcm->dump_cfg = 0;
	}

      switch (ctrl->cfg.test)
	{
	case VCL_TEST_TYPE_ECHO:
	  vtc_echo_client (vcm);
	  break;

	case VCL_TEST_TYPE_UNI:
	case VCL_TEST_TYPE_BI:
	  vtc_stream_client (vcm);
	  break;

	case VCL_TEST_TYPE_EXIT:
	  continue;

	case VCL_TEST_TYPE_NONE:
	default:
	  break;
	}
      switch (vcm->post_test)
	{
	case VCL_TEST_TYPE_EXIT:
	  switch (ctrl->cfg.test)
	    {
	    case VCL_TEST_TYPE_EXIT:
	    case VCL_TEST_TYPE_UNI:
	    case VCL_TEST_TYPE_BI:
	    case VCL_TEST_TYPE_ECHO:
	      ctrl->cfg.test = VCL_TEST_TYPE_EXIT;
	      continue;

	    case VCL_TEST_TYPE_NONE:
	    default:
	      break;
	    }
	  break;

	case VCL_TEST_TYPE_NONE:
	case VCL_TEST_TYPE_ECHO:
	case VCL_TEST_TYPE_UNI:
	case VCL_TEST_TYPE_BI:
	default:
	  break;
	}

      memset (ctrl->txbuf, 0, ctrl->txbuf_size);
      memset (ctrl->rxbuf, 0, ctrl->rxbuf_size);

      vtc_read_user_input (ctrl);
    }

  vtc_ctrl_session_exit ();
  vppcom_session_close (ctrl->fd);
  vppcom_app_destroy ();
  free (vcm->workers);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
