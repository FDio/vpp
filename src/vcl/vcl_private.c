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

static pthread_key_t vcl_worker_stop_key;

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

int
vcl_mq_epoll_add_evfd (vcl_worker_t * wrk, svm_msg_q_t * mq)
{
  struct epoll_event e = { 0 };
  vcl_mq_evt_conn_t *mqc;
  u32 mqc_index;
  int mq_fd;

  mq_fd = svm_msg_q_get_consumer_eventfd (mq);

  if (wrk->mqs_epfd < 0 || mq_fd == -1)
    return -1;

  mqc = vcl_mq_evt_conn_alloc (wrk);
  mqc_index = vcl_mq_evt_conn_index (wrk, mqc);
  mqc->mq_fd = mq_fd;
  mqc->mq = mq;

  e.events = EPOLLIN;
  e.data.u32 = mqc_index;
  if (epoll_ctl (wrk->mqs_epfd, EPOLL_CTL_ADD, mq_fd, &e) < 0)
    {
      VDBG (0, "failed to add mq eventfd to mq epoll fd");
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
  if (epoll_ctl (wrk->mqs_epfd, EPOLL_CTL_DEL, mqc->mq_fd, 0) < 0)
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

int
vcl_api_app_worker_add (void)
{
  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_app_worker_add ();

  return vcl_bapi_app_worker_add ();
}

void
vcl_api_app_worker_del (vcl_worker_t * wrk)
{
  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_app_worker_del (wrk);

  vcl_bapi_app_worker_del (wrk);
}

void
vcl_worker_cleanup (vcl_worker_t * wrk, u8 notify_vpp)
{
  clib_spinlock_lock (&vcm->workers_lock);
  if (notify_vpp)
    vcl_api_app_worker_del (wrk);

  if (wrk->mqs_epfd > 0)
    close (wrk->mqs_epfd);
  hash_free (wrk->session_index_by_vpp_handles);
  vec_free (wrk->mq_events);
  vec_free (wrk->mq_msg_vector);
  vcl_worker_free (wrk);
  clib_spinlock_unlock (&vcm->workers_lock);
}

static void
vcl_worker_cleanup_cb (void *arg)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  u32 wrk_index = wrk->wrk_index;
  vcl_worker_cleanup (wrk, 1 /* notify vpp */ );
  vcl_set_worker_index (~0);
  VDBG (0, "cleaned up worker %u", wrk_index);
}

vcl_worker_t *
vcl_worker_alloc_and_init ()
{
  vcl_worker_t *wrk;

  /* This was initialized already */
  if (vcl_get_worker_index () != ~0)
    return 0;

  /* Use separate heap map entry for worker */
  clib_mem_set_thread_index ();

  if (pool_elts (vcm->workers) == vcm->cfg.max_workers)
    {
      VDBG (0, "max-workers %u limit reached", vcm->cfg.max_workers);
      return 0;
    }

  clib_spinlock_lock (&vcm->workers_lock);
  wrk = vcl_worker_alloc ();
  vcl_set_worker_index (wrk->wrk_index);
  wrk->thread_id = pthread_self ();
  wrk->current_pid = getpid ();

  wrk->mqs_epfd = -1;
  if (vcm->cfg.use_mq_eventfd)
    {
      wrk->vcl_needs_real_epoll = 1;
      wrk->mqs_epfd = epoll_create (1);
      wrk->vcl_needs_real_epoll = 0;
      if (wrk->mqs_epfd < 0)
	{
	  clib_unix_warning ("epoll_create() returned");
	  goto done;
	}
    }

  wrk->session_index_by_vpp_handles = hash_create (0, sizeof (uword));
  clib_time_init (&wrk->clib_time);
  vec_validate (wrk->mq_events, 64);
  vec_validate (wrk->mq_msg_vector, 128);
  vec_reset_length (wrk->mq_msg_vector);
  vec_validate (wrk->unhandled_evts_vector, 128);
  vec_reset_length (wrk->unhandled_evts_vector);
  clib_spinlock_unlock (&vcm->workers_lock);

done:
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
  if (pthread_key_create (&vcl_worker_stop_key, vcl_worker_cleanup_cb))
    VDBG (0, "failed to add pthread cleanup function");
  if (pthread_setspecific (vcl_worker_stop_key, &wrk->thread_id))
    VDBG (0, "failed to setup key value");

  clib_spinlock_unlock (&vcm->workers_lock);

  VDBG (0, "added worker %u", wrk->wrk_index);
  return 0;
}

svm_msg_q_t *
vcl_worker_ctrl_mq (vcl_worker_t * wrk)
{
  return wrk->ctrl_mq;
}

int
vcl_session_read_ready (vcl_session_t * session)
{
  u32 max_deq;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  if (PREDICT_FALSE (session->is_vep))
    {
      VDBG (0, "ERROR: session %u: cannot read from an epoll session!",
	    session->session_index);
      return VPPCOM_EBADFD;
    }

  if (PREDICT_FALSE (!(session->session_state & (STATE_OPEN | STATE_LISTEN))))
    {
      vcl_session_state_t state = session->session_state;
      int rv;

      rv = ((state & STATE_DISCONNECT) ? VPPCOM_ECONNRESET : VPPCOM_ENOTCONN);

      VDBG (1, "session %u [0x%llx]: not open! state 0x%x (%s), ret %d (%s)",
	    session->session_index, session->vpp_handle, state,
	    vppcom_session_state_str (state), rv, vppcom_retval_str (rv));
      return rv;
    }

  if (session->session_state & STATE_LISTEN)
    return clib_fifo_elts (session->accept_evts_fifo);

  if (vcl_session_is_ct (session))
    return svm_fifo_max_dequeue_cons (session->ct_rx_fifo);

  max_deq = svm_fifo_max_dequeue_cons (session->rx_fifo);

  if (session->is_dgram)
    {
      session_dgram_pre_hdr_t ph;

      if (max_deq <= SESSION_CONN_HDR_LEN)
	return 0;
      if (svm_fifo_peek (session->rx_fifo, 0, sizeof (ph), (u8 *) & ph) < 0)
	return 0;
      if (ph.data_length + SESSION_CONN_HDR_LEN > max_deq)
	return 0;

      return ph.data_length;
    }

  return max_deq;
}

int
vcl_session_write_ready (vcl_session_t * session)
{
  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  if (PREDICT_FALSE (session->is_vep))
    {
      VDBG (0, "session %u [0x%llx]: cannot write to an epoll session!",
	    session->session_index, session->vpp_handle);
      return VPPCOM_EBADFD;
    }

  if (PREDICT_FALSE (session->session_state & STATE_LISTEN))
    {
      if (session->tx_fifo)
	return svm_fifo_max_enqueue_prod (session->tx_fifo);
      else
	return VPPCOM_EBADFD;
    }

  if (PREDICT_FALSE (!(session->session_state & STATE_OPEN)))
    {
      vcl_session_state_t state = session->session_state;
      int rv;

      rv = ((state & STATE_DISCONNECT) ? VPPCOM_ECONNRESET : VPPCOM_ENOTCONN);
      VDBG (0, "session %u [0x%llx]: not open! state 0x%x (%s), ret %d (%s)",
	    session->session_index, session->vpp_handle, state,
	    vppcom_session_state_str (state), rv, vppcom_retval_str (rv));
      return rv;
    }

  if (vcl_session_is_ct (session))
    return svm_fifo_max_enqueue_prod (session->ct_tx_fifo);

  if (session->is_dgram)
    {
      u32 max_enq = svm_fifo_max_enqueue_prod (session->tx_fifo);

      if (max_enq <= sizeof (session_dgram_hdr_t))
	return 0;
      return max_enq - sizeof (session_dgram_hdr_t);
    }

  return svm_fifo_max_enqueue_prod (session->tx_fifo);
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
      return rv;
    }
  hash_set (vcm->segment_table, segment_handle, a->new_segment_indices[0]);

  clib_rwlock_writer_unlock (&vcm->segment_table_lock);

  vec_reset_length (a->new_segment_indices);
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

  VDBG (0, "detached segment %u handle %u", segment_index, segment_handle);
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
