/*
 * Copyright (c) 2018-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this
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

#include <vcl/vcl_private.h>

vcl_mq_evt_conn_t *
vcl_mq_evt_conn_alloc (vcl_worker_t * wrk)
{
  vcl_mq_evt_conn_t *mqc;
  pool_get (wrk->mq_evt_conns, mqc);
  memset (mqc, 0, sizeof (*mqc));
  return mqc;
}

u32
vcl_mq_evt_conn_index (vcl_worker_t * wrk, vcl_mq_evt_conn_t * mqc)
{
  return (mqc - wrk->mq_evt_conns);
}

vcl_mq_evt_conn_t *
vcl_mq_evt_conn_get (vcl_worker_t * wrk, u32 mq_conn_idx)
{
  return pool_elt_at_index (wrk->mq_evt_conns, mq_conn_idx);
}

/* Add unix socket to epoll.
 * Used only to get a notification on socket close
 * We can't use eventfd because we don't get notifications on that fds
 */
static int
vcl_mq_epoll_add_api_sock (vcl_worker_t *wrk)
{
  clib_socket_t *cs = &wrk->app_api_sock;
  struct epoll_event e = { 0 };
  int rv;

  e.data.u32 = VCL_EP_SAPIFD_EVT;
  rv = vcm->vcl_epoll_ctl (wrk->mqs_epfd, EPOLL_CTL_ADD, cs->fd, &e);
  if (rv != EEXIST && rv < 0)
    return -1;

  return 0;
}

int
vcl_mq_epoll_add_evfd (vcl_worker_t * wrk, svm_msg_q_t * mq)
{
  struct epoll_event e = { 0 };
  vcl_mq_evt_conn_t *mqc;
  u32 mqc_index;
  int mq_fd;

  mq_fd = svm_msg_q_get_eventfd (mq);

  if (wrk->mqs_epfd < 0 || mq_fd == -1)
    return -1;

  mqc = vcl_mq_evt_conn_alloc (wrk);
  mqc_index = vcl_mq_evt_conn_index (wrk, mqc);
  mqc->mq_fd = mq_fd;
  mqc->mq = mq;

  fcntl (mq_fd, F_SETFL, O_NONBLOCK);

  e.events = EPOLLIN;
  e.data.u32 = mqc_index;
  if (vcm->vcl_epoll_ctl (wrk->mqs_epfd, EPOLL_CTL_ADD, mq_fd, &e) < 0)
    {
      VDBG (0, "failed to add mq eventfd to mq epoll fd");
      return -1;
    }

  if (vcl_mq_epoll_add_api_sock (wrk))
    {
      VDBG (0, "failed to add mq socket to mq epoll fd");
      return -1;
    }

  return mqc_index;
}

int
vcl_mq_epoll_del_evfd (vcl_worker_t * wrk, u32 mqc_index)
{
  vcl_mq_evt_conn_t *mqc;

  if (wrk->mqs_epfd || mqc_index == ~0)
    return -1;

  mqc = vcl_mq_evt_conn_get (wrk, mqc_index);
  if (vcm->vcl_epoll_ctl (wrk->mqs_epfd, EPOLL_CTL_DEL, mqc->mq_fd, 0) < 0)
    {
      VDBG (0, "failed to del mq eventfd to mq epoll fd");
      return -1;
    }
  return 0;
}

static vcl_worker_t *
vcl_worker_alloc (void)
{
  vcl_worker_t *wrk;
  pool_get (vcm->workers, wrk);
  memset (wrk, 0, sizeof (*wrk));
  wrk->wrk_index = wrk - vcm->workers;
  wrk->forked_child = ~0;
  return wrk;
}

static void
vcl_worker_free (vcl_worker_t * wrk)
{
  pool_put (vcm->workers, wrk);
}

void
vcl_worker_cleanup (vcl_worker_t * wrk, u8 notify_vpp)
{
  clib_spinlock_lock (&vcm->workers_lock);
  if (notify_vpp)
    vcl_api_app_worker_del (wrk);

  if (wrk->mqs_epfd > 0)
    close (wrk->mqs_epfd);
  pool_free (wrk->sessions);
  pool_free (wrk->mq_evt_conns);
  hash_free (wrk->session_index_by_vpp_handles);
  vec_free (wrk->mq_events);
  vec_free (wrk->mq_msg_vector);
  vec_free (wrk->unhandled_evts_vector);
  vec_free (wrk->pending_session_wrk_updates);
  clib_bitmap_free (wrk->rd_bitmap);
  clib_bitmap_free (wrk->wr_bitmap);
  clib_bitmap_free (wrk->ex_bitmap);
  vcl_worker_free (wrk);
  clib_spinlock_unlock (&vcm->workers_lock);
}

void
vcl_worker_detached_start_signal_mq (vcl_worker_t *wrk)
{
  /* Generate mq epfd events using pipes to hopefully force
   * calls into epoll_wait which retries attaching to vpp */
  if (!wrk->detached_pipefds[0])
    {
      if (pipe (wrk->detached_pipefds))
	{
	  VDBG (0, "failed to add mq eventfd to mq epoll fd");
	  exit (1);
	}
    }

  struct epoll_event evt = {};
  evt.events = EPOLLIN;
  evt.data.u32 = VCL_EP_PIPEFD_EVT;
  if (vcm->vcl_epoll_ctl (wrk->mqs_epfd, EPOLL_CTL_ADD,
			  wrk->detached_pipefds[0], &evt) < 0)
    {
      VDBG (0, "failed to add mq eventfd to mq epoll fd");
      exit (1);
    }

  int __clib_unused rv;
  u8 sig = 1;
  rv = write (wrk->detached_pipefds[1], &sig, 1);
}

void
vcl_worker_detached_signal_mq (vcl_worker_t *wrk)
{
  int __clib_unused rv;
  u8 buf;
  rv = read (wrk->detached_pipefds[0], &buf, 1);
  rv = write (wrk->detached_pipefds[1], &buf, 1);
}

void
vcl_worker_detached_stop_signal_mq (vcl_worker_t *wrk)
{
  if (vcm->vcl_epoll_ctl (wrk->mqs_epfd, EPOLL_CTL_DEL,
			  wrk->detached_pipefds[0], 0) < 0)
    {
      VDBG (0, "failed to del mq eventfd to mq epoll fd");
      exit (1);
    }
}

void
vcl_worker_detach_sessions (vcl_worker_t *wrk)
{
  session_event_t *e;
  vcl_session_t *s;
  uword *seg_indices_map = 0;
  u32 seg_index, val, *seg_indices = 0;

  close (wrk->app_api_sock.fd);
  pool_foreach (s, wrk->sessions)
    {
      if (s->session_state == VCL_STATE_LISTEN)
	{
	  s->flags |= VCL_SESSION_F_LISTEN_NO_MQ;
	  continue;
	}
      if ((s->flags & VCL_SESSION_F_IS_VEP))
	continue;

      /* App closed, vpp detached, free session */
      if (s->session_state == VCL_STATE_CLOSED)
	{
	  vcl_session_free (wrk, s);
	  continue;
	}

      /* In other states expect close from app */
      if (s->session_state == VCL_STATE_READY)
	{
	  hash_set (seg_indices_map, s->tx_fifo->segment_index, 1);
	  vec_add2 (wrk->unhandled_evts_vector, e, 1);
	  e->event_type = SESSION_CTRL_EVT_DISCONNECTED;
	  e->session_index = s->session_index;
	  e->postponed = 1;
	}

      s->session_state = VCL_STATE_DETACHED;
      s->flags |= VCL_SESSION_F_APP_CLOSING;
    }

  hash_foreach (seg_index, val, seg_indices_map,
		({ vec_add1 (seg_indices, seg_index); }));

  /* If multi-threaded apps, wait for all threads to hopefully finish
   * their blocking operations  */
  if (wrk->pre_wait_fn)
    wrk->pre_wait_fn (VCL_INVALID_SESSION_INDEX);
  sleep (1);
  if (wrk->post_wait_fn)
    wrk->post_wait_fn (VCL_INVALID_SESSION_INDEX);

  vcl_segment_detach_segments (seg_indices);

  /* Detach worker's mqs segment */
  vcl_segment_detach (vcl_vpp_worker_segment_handle (wrk->wrk_index));

  wrk->app_event_queue = 0;
  wrk->ctrl_mq = 0;

  vec_free (seg_indices);
  hash_free (seg_indices_map);

  vcl_worker_detached_start_signal_mq (wrk);
}

void
vcl_worker_set_wait_mq_fns (vcl_worker_wait_mq_fn pre_wait,
			    vcl_worker_wait_mq_fn post_wait)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  wrk->pre_wait_fn = pre_wait;
  wrk->post_wait_fn = post_wait;
}

vcl_worker_t *
vcl_worker_alloc_and_init ()
{
  vcl_worker_t *wrk;

  /* This was initialized already */
  if (vcl_get_worker_index () != ~0)
    return 0;

  /* Grab lock before selecting mem thread index */
  clib_spinlock_lock (&vcm->workers_lock);

  /* Use separate heap map entry for worker */
  clib_mem_set_thread_index ();

  if (pool_elts (vcm->workers) == vcm->cfg.max_workers)
    {
      VDBG (0, "max-workers %u limit reached", vcm->cfg.max_workers);
      wrk = 0;
      goto done;
    }

  wrk = vcl_worker_alloc ();
  vcl_set_worker_index (wrk->wrk_index);
  wrk->api_client_handle = ~0;
  wrk->thread_id = pthread_self ();
  wrk->current_pid = getpid ();

  wrk->mqs_epfd = -1;
  if (vcm->cfg.use_mq_eventfd)
    {
      wrk->mqs_epfd = vcm->vcl_epoll_create1 (0);
      if (wrk->mqs_epfd < 0)
	{
	  clib_unix_warning ("epoll_create() returned");
	  goto done;
	}
    }

  wrk->ep_lt_current = VCL_INVALID_SESSION_INDEX;
  wrk->session_index_by_vpp_handles = hash_create (0, sizeof (uword));
  clib_time_init (&wrk->clib_time);
  vec_validate (wrk->mq_events, 64);
  vec_validate (wrk->mq_msg_vector, 128);
  vec_reset_length (wrk->mq_msg_vector);
  vec_validate (wrk->unhandled_evts_vector, 128);
  vec_reset_length (wrk->unhandled_evts_vector);

done:
  clib_spinlock_unlock (&vcm->workers_lock);
  return wrk;
}

int
vcl_worker_register_with_vpp (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();

  clib_spinlock_lock (&vcm->workers_lock);

  if (vcl_api_app_worker_add ())
    {
      VDBG (0, "failed to add worker to vpp");
      clib_spinlock_unlock (&vcm->workers_lock);
      return -1;
    }

  clib_spinlock_unlock (&vcm->workers_lock);

  VDBG (0, "added worker %u", wrk->wrk_index);
  return 0;
}

svm_msg_q_t *
vcl_worker_ctrl_mq (vcl_worker_t * wrk)
{
  return wrk->ctrl_mq;
}

void
vcl_init_epoll_fns ()
{
  if (!vcm->vcl_epoll_create1)
    vcm->vcl_epoll_create1 = epoll_create1;
  if (!vcm->vcl_epoll_ctl)
    vcm->vcl_epoll_ctl = epoll_ctl;
  if (!vcm->vcl_epoll_wait)
    vcm->vcl_epoll_wait = epoll_wait;
}

int
vcl_session_read_ready (vcl_session_t * s)
{
  if (PREDICT_FALSE (s->flags & VCL_SESSION_F_IS_VEP))
    {
      VDBG (0, "ERROR: session %u: cannot read from an epoll session!",
	    s->session_index);
      return VPPCOM_EBADFD;
    }

  if (vcl_session_is_open (s))
    {
      if (vcl_session_is_ct (s))
	return svm_fifo_max_dequeue_cons (s->ct_rx_fifo);

      if (s->is_dgram)
	{
	  session_dgram_pre_hdr_t ph;
	  u32 max_deq;

	  /* CL listener that's not yet ready */
	  if (vcl_session_is_cl (s) && !s->rx_fifo)
	    return 0;

	  max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
	  if (max_deq <= SESSION_CONN_HDR_LEN)
	    return 0;
	  if (svm_fifo_peek (s->rx_fifo, 0, sizeof (ph), (u8 *) &ph) < 0)
	    return 0;
	  if (ph.data_length + SESSION_CONN_HDR_LEN > max_deq)
	    return 0;

	  /* Allow zero legth datagrams */
	  return ph.data_length ? ph.data_length : 1;
	}

      return svm_fifo_max_dequeue_cons (s->rx_fifo);
    }
  else if (s->session_state == VCL_STATE_LISTEN)
    {
      return clib_fifo_elts (s->accept_evts_fifo);
    }
  else
    {
      return (s->session_state == VCL_STATE_DISCONNECT) ? VPPCOM_ECONNRESET :
							  VPPCOM_ENOTCONN;
    }
}

/**
 * Used as alternative to vcl_session_read_ready to avoid peeking udp sessions.
 * Multi-threaded applications could select the same session from multiple
 * threads */
int
vcl_session_read_ready2 (vcl_session_t *s)
{
  if (vcl_session_is_open (s))
    {
      if (vcl_session_is_ct (s))
	return svm_fifo_max_dequeue_cons (s->ct_rx_fifo);

      if (s->is_dgram)
	{
	  /* CL listener that's not yet ready */
	  if (vcl_session_is_cl (s) && !s->rx_fifo)
	    return 0;

	  if (svm_fifo_max_dequeue_cons (s->rx_fifo) <= SESSION_CONN_HDR_LEN)
	    return 0;

	  /* Return 1 even if not yet sure if a full datagram was received */
	  return 1;
	}

      return svm_fifo_max_dequeue_cons (s->rx_fifo);
    }
  else if (s->session_state == VCL_STATE_LISTEN)
    {
      return clib_fifo_elts (s->accept_evts_fifo);
    }
  else
    {
      return 1;
    }
}

int
vcl_session_write_ready (vcl_session_t * s)
{
  if (PREDICT_FALSE (s->flags & VCL_SESSION_F_IS_VEP))
    {
      VDBG (0, "session %u [0x%llx]: cannot write to an epoll session!",
	    s->session_index, s->vpp_handle);
      return VPPCOM_EBADFD;
    }

  if (vcl_session_is_open (s))
    {
      if (vcl_session_is_ct (s))
	return svm_fifo_max_enqueue_prod (s->ct_tx_fifo);

      if (s->is_dgram)
	{
	  u32 max_enq = svm_fifo_max_enqueue_prod (s->tx_fifo);

	  if (max_enq <= sizeof (session_dgram_hdr_t))
	    return 0;
	  return max_enq - sizeof (session_dgram_hdr_t);
	}

      return svm_fifo_max_enqueue_prod (s->tx_fifo);
    }
  else if (s->session_state == VCL_STATE_LISTEN)
    {
      if (s->tx_fifo)
	return svm_fifo_max_enqueue_prod (s->tx_fifo);
      else
	return VPPCOM_EBADFD;
    }
  else if (s->session_state == VCL_STATE_UPDATED)
    {
      return 0;
    }
  else
    {
      return (s->session_state == VCL_STATE_DISCONNECT) ?
	VPPCOM_ECONNRESET : VPPCOM_ENOTCONN;
    }
}

int
vcl_session_alloc_ext_cfg (vcl_session_t *s,
			   transport_endpt_ext_cfg_type_t type, u32 len)
{
  if (s->ext_config)
    return -1;

  s->ext_config = clib_mem_alloc (len);
  clib_memset (s->ext_config, 0, len);
  s->ext_config->len = len;
  s->ext_config->type = type;

  return 0;
}

int
vcl_segment_attach (u64 segment_handle, char *name, ssvm_segment_type_t type,
		    int fd)
{
  fifo_segment_create_args_t _a, *a = &_a;
  int rv;

  memset (a, 0, sizeof (*a));
  a->segment_name = name;
  a->segment_type = type;

  if (type == SSVM_SEGMENT_MEMFD)
    a->memfd_fd = fd;

  clib_rwlock_writer_lock (&vcm->segment_table_lock);

  if ((rv = fifo_segment_attach (&vcm->segment_main, a)))
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed", name);
      clib_rwlock_writer_unlock (&vcm->segment_table_lock);
      return rv;
    }
  hash_set (vcm->segment_table, segment_handle, a->new_segment_indices[0]);

  clib_rwlock_writer_unlock (&vcm->segment_table_lock);

  vec_free (a->new_segment_indices);
  return 0;
}

u32
vcl_segment_table_lookup (u64 segment_handle)
{
  uword *seg_indexp;

  clib_rwlock_reader_lock (&vcm->segment_table_lock);
  seg_indexp = hash_get (vcm->segment_table, segment_handle);
  clib_rwlock_reader_unlock (&vcm->segment_table_lock);

  if (!seg_indexp)
    return VCL_INVALID_SEGMENT_INDEX;
  return ((u32) * seg_indexp);
}

void
vcl_segment_detach (u64 segment_handle)
{
  fifo_segment_main_t *sm = &vcm->segment_main;
  fifo_segment_t *segment;
  u32 segment_index;

  segment_index = vcl_segment_table_lookup (segment_handle);
  if (segment_index == (u32) ~ 0)
    return;

  clib_rwlock_writer_lock (&vcm->segment_table_lock);

  segment = fifo_segment_get_segment (sm, segment_index);
  fifo_segment_delete (sm, segment);
  hash_unset (vcm->segment_table, segment_handle);

  clib_rwlock_writer_unlock (&vcm->segment_table_lock);

  VDBG (0, "detached segment %u handle %lx", segment_index, segment_handle);
}

void
vcl_segment_detach_segments (u32 *seg_indices)
{
  u64 *seg_handles = 0, *seg_handle, key;
  u32 *seg_index;
  u32 val;

  clib_rwlock_reader_lock (&vcm->segment_table_lock);

  vec_foreach (seg_index, seg_indices)
    {
      /* clang-format off */
      hash_foreach (key, val, vcm->segment_table, ({
        if (val == *seg_index)
          {
            vec_add1 (seg_handles, key);
            break;
          }
      }));
      /* clang-format on */
    }

  clib_rwlock_reader_unlock (&vcm->segment_table_lock);

  vec_foreach (seg_handle, seg_handles)
    vcl_segment_detach (seg_handle[0]);

  vec_free (seg_handles);
}

int
vcl_segment_attach_session (uword segment_handle, uword rxf_offset,
			    uword txf_offset, uword mq_offset, u32 mq_index,
			    u8 is_ct, vcl_session_t *s)
{
  u32 fs_index, eqs_index;
  svm_fifo_t *rxf, *txf;
  fifo_segment_t *fs;
  u64 eqs_handle;

  fs_index = vcl_segment_table_lookup (segment_handle);
  if (fs_index == VCL_INVALID_SEGMENT_INDEX)
    {
      VDBG (0, "ERROR: segment for session %u is not mounted!",
	    s->session_index);
      return -1;
    }

  if (!is_ct && mq_offset != (uword) ~0)
    {
      eqs_handle = vcl_vpp_worker_segment_handle (0);
      eqs_index = vcl_segment_table_lookup (eqs_handle);
      ASSERT (eqs_index != VCL_INVALID_SEGMENT_INDEX);
    }

  clib_rwlock_reader_lock (&vcm->segment_table_lock);

  fs = fifo_segment_get_segment (&vcm->segment_main, fs_index);
  rxf = fifo_segment_alloc_fifo_w_offset (fs, rxf_offset);
  txf = fifo_segment_alloc_fifo_w_offset (fs, txf_offset);
  rxf->segment_index = fs_index;
  txf->segment_index = fs_index;

  if (!is_ct && mq_offset != (uword) ~0)
    {
      fs = fifo_segment_get_segment (&vcm->segment_main, eqs_index);
      s->vpp_evt_q = fifo_segment_msg_q_attach (fs, mq_offset, mq_index);
    }

  clib_rwlock_reader_unlock (&vcm->segment_table_lock);

  if (!is_ct)
    {
      rxf->vpp_session_index = rxf->shr->master_session_index;
      txf->vpp_session_index = txf->shr->master_session_index;
      rxf->shr->client_session_index = s->session_index;
      txf->shr->client_session_index = s->session_index;
      rxf->app_session_index = s->session_index;
      txf->app_session_index = s->session_index;
      rxf->client_thread_index = vcl_get_worker_index ();
      txf->client_thread_index = vcl_get_worker_index ();
      s->rx_fifo = rxf;
      s->tx_fifo = txf;
    }
  else
    {
      s->ct_rx_fifo = rxf;
      s->ct_tx_fifo = txf;
    }

  return 0;
}

void
vcl_session_detach_fifos (vcl_session_t *s)
{
  fifo_segment_t *fs;

  if (!s->rx_fifo)
    return;

  clib_rwlock_reader_lock (&vcm->segment_table_lock);

  fs = fifo_segment_get_segment_if_valid (&vcm->segment_main,
					  s->rx_fifo->segment_index);
  if (!fs)
    goto done;

  fifo_segment_free_client_fifo (fs, s->rx_fifo);
  fifo_segment_free_client_fifo (fs, s->tx_fifo);
  if (s->ct_rx_fifo)
    {
      fs = fifo_segment_get_segment_if_valid (&vcm->segment_main,
					      s->ct_rx_fifo->segment_index);
      if (!fs)
	goto done;

      fifo_segment_free_client_fifo (fs, s->ct_rx_fifo);
      fifo_segment_free_client_fifo (fs, s->ct_tx_fifo);
    }

done:
  clib_rwlock_reader_unlock (&vcm->segment_table_lock);
}

int
vcl_segment_attach_mq (uword segment_handle, uword mq_offset, u32 mq_index,
		       svm_msg_q_t **mq)
{
  fifo_segment_t *fs;
  u32 fs_index;

  fs_index = vcl_segment_table_lookup (segment_handle);
  if (fs_index == VCL_INVALID_SEGMENT_INDEX)
    {
      VDBG (0, "ERROR: mq segment %lx for is not attached!", segment_handle);
      return -1;
    }

  clib_rwlock_reader_lock (&vcm->segment_table_lock);

  fs = fifo_segment_get_segment (&vcm->segment_main, fs_index);
  *mq = fifo_segment_msg_q_attach (fs, mq_offset, mq_index);

  clib_rwlock_reader_unlock (&vcm->segment_table_lock);

  return 0;
}

int
vcl_segment_discover_mqs (uword segment_handle, int *fds, u32 n_fds)
{
  fifo_segment_t *fs;
  u32 fs_index;

  fs_index = vcl_segment_table_lookup (segment_handle);
  if (fs_index == VCL_INVALID_SEGMENT_INDEX)
    {
      VDBG (0, "ERROR: mq segment %lx for is not attached!", segment_handle);
      return -1;
    }

  clib_rwlock_reader_lock (&vcm->segment_table_lock);

  fs = fifo_segment_get_segment (&vcm->segment_main, fs_index);
  fifo_segment_msg_qs_discover (fs, fds, n_fds);

  clib_rwlock_reader_unlock (&vcm->segment_table_lock);

  return 0;
}

svm_fifo_chunk_t *
vcl_segment_alloc_chunk (uword segment_handle, u32 slice_index, u32 size,
			 uword *offset)
{
  svm_fifo_chunk_t *c;
  fifo_segment_t *fs;
  u32 fs_index;

  fs_index = vcl_segment_table_lookup (segment_handle);
  if (fs_index == VCL_INVALID_SEGMENT_INDEX)
    {
      VDBG (0, "ERROR: mq segment %lx for is not attached!", segment_handle);
      return 0;
    }

  clib_rwlock_reader_lock (&vcm->segment_table_lock);

  fs = fifo_segment_get_segment (&vcm->segment_main, fs_index);
  c = fifo_segment_alloc_chunk_w_slice (fs, slice_index, size);
  *offset = fifo_segment_chunk_offset (fs, c);

  clib_rwlock_reader_unlock (&vcm->segment_table_lock);

  return c;
}

int
vcl_session_share_fifos (vcl_session_t *s, svm_fifo_t *rxf, svm_fifo_t *txf)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  fifo_segment_t *fs;

  clib_rwlock_reader_lock (&vcm->segment_table_lock);

  fs = fifo_segment_get_segment (&vcm->segment_main, rxf->segment_index);
  s->rx_fifo = fifo_segment_duplicate_fifo (fs, rxf);
  s->tx_fifo = fifo_segment_duplicate_fifo (fs, txf);

  clib_rwlock_reader_unlock (&vcm->segment_table_lock);

  svm_fifo_add_subscriber (s->rx_fifo, wrk->vpp_wrk_index);
  svm_fifo_add_subscriber (s->tx_fifo, wrk->vpp_wrk_index);

  return 0;
}

const char *
vcl_session_state_str (vcl_session_state_t state)
{
  char *st;

  switch (state)
    {
    case VCL_STATE_CLOSED:
      st = "STATE_CLOSED";
      break;
    case VCL_STATE_LISTEN:
      st = "STATE_LISTEN";
      break;
    case VCL_STATE_READY:
      st = "STATE_READY";
      break;
    case VCL_STATE_VPP_CLOSING:
      st = "STATE_VPP_CLOSING";
      break;
    case VCL_STATE_DISCONNECT:
      st = "STATE_DISCONNECT";
      break;
    case VCL_STATE_DETACHED:
      st = "STATE_DETACHED";
      break;
    case VCL_STATE_UPDATED:
      st = "STATE_UPDATED";
      break;
    default:
      st = "UNKNOWN_STATE";
      break;
    }

  return st;
}

u8 *
vcl_format_ip4_address (u8 *s, va_list *args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

u8 *
vcl_format_ip6_address (u8 *s, va_list *args)
{
  ip6_address_t *a = va_arg (*args, ip6_address_t *);
  u32 i, i_max_n_zero, max_n_zeros, i_first_zero, n_zeros, last_double_colon;

  i_max_n_zero = ARRAY_LEN (a->as_u16);
  max_n_zeros = 0;
  i_first_zero = i_max_n_zero;
  n_zeros = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      u32 is_zero = a->as_u16[i] == 0;
      if (is_zero && i_first_zero >= ARRAY_LEN (a->as_u16))
	{
	  i_first_zero = i;
	  n_zeros = 0;
	}
      n_zeros += is_zero;
      if ((!is_zero && n_zeros > max_n_zeros) ||
	  (i + 1 >= ARRAY_LEN (a->as_u16) && n_zeros > max_n_zeros))
	{
	  i_max_n_zero = i_first_zero;
	  max_n_zeros = n_zeros;
	  i_first_zero = ARRAY_LEN (a->as_u16);
	  n_zeros = 0;
	}
    }

  last_double_colon = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      if (i == i_max_n_zero && max_n_zeros > 1)
	{
	  s = format (s, "::");
	  i += max_n_zeros - 1;
	  last_double_colon = 1;
	}
      else
	{
	  s = format (s, "%s%x", (last_double_colon || i == 0) ? "" : ":",
		      clib_net_to_host_u16 (a->as_u16[i]));
	  last_double_colon = 0;
	}
    }

  return s;
}

/* Format an IP46 address. */
u8 *
vcl_format_ip46_address (u8 *s, va_list *args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  int is_ip4 = 1;

  switch (type)
    {
    case IP46_TYPE_ANY:
      is_ip4 = ip46_address_is_ip4 (ip46);
      break;
    case IP46_TYPE_IP4:
      is_ip4 = 1;
      break;
    case IP46_TYPE_IP6:
      is_ip4 = 0;
      break;
    }

  return is_ip4 ? format (s, "%U", vcl_format_ip4_address, &ip46->ip4) :
		  format (s, "%U", vcl_format_ip6_address, &ip46->ip6);
}

void
vcl_heap_alloc (void)
{
  vcl_cfg_t *vcl_cfg = &vcm->cfg;
  void *vcl_mem;
  void *heap;

  vcl_mem = mmap (0, vcl_cfg->heapsize, PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (vcl_mem == MAP_FAILED)
    {
      VDBG (0,
	    "ERROR: mmap(0, %lu == 0x%lx, "
	    "PROT_READ | PROT_WRITE,MAP_SHARED | MAP_ANONYMOUS, "
	    "-1, 0) failed!",
	    (unsigned long) vcl_cfg->heapsize,
	    (unsigned long) vcl_cfg->heapsize);
      ASSERT (vcl_mem != MAP_FAILED);
      return;
    }
  heap = clib_mem_init_thread_safe (vcl_mem, vcl_cfg->heapsize);
  if (!heap)
    {
      fprintf (stderr, "VCL<%d>: ERROR: clib_mem_init() failed!", getpid ());
      ASSERT (heap);
      return;
    }
  vcl_mem = clib_mem_alloc (sizeof (_vppcom_main));
  if (!vcl_mem)
    {
      clib_warning ("VCL<%d>: ERROR: clib_mem_alloc() failed!", getpid ());
      ASSERT (vcl_mem);
      return;
    }

  clib_memcpy (vcl_mem, &_vppcom_main, sizeof (_vppcom_main));
  vcm = vcl_mem;

  if (vcm->debug > 0)
    fprintf (stderr, "allocated VCL heap = %p, size %lu (0x%lx)", heap,
	     (unsigned long) vcl_cfg->heapsize,
	     (unsigned long) vcl_cfg->heapsize);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
