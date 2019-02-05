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

static const char *
vppcom_app_state_str (app_state_t state)
{
  char *st;

  switch (state)
    {
    case STATE_APP_START:
      st = "STATE_APP_START";
      break;

    case STATE_APP_CONN_VPP:
      st = "STATE_APP_CONN_VPP";
      break;

    case STATE_APP_ENABLED:
      st = "STATE_APP_ENABLED";
      break;

    case STATE_APP_ATTACHED:
      st = "STATE_APP_ATTACHED";
      break;

    default:
      st = "UNKNOWN_APP_STATE";
      break;
    }

  return st;
}

int
vcl_wait_for_app_state_change (app_state_t app_state)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  f64 timeout = clib_time_now (&wrk->clib_time) + vcm->cfg.app_timeout;

  while (clib_time_now (&wrk->clib_time) < timeout)
    {
      if (vcm->app_state == app_state)
	return VPPCOM_OK;
      if (vcm->app_state == STATE_APP_FAILED)
	return VPPCOM_ECONNABORTED;
    }
  VDBG (0, "timeout waiting for state %s (%d)",
	vppcom_app_state_str (app_state), app_state);
  vcl_evt (VCL_EVT_SESSION_TIMEOUT, vcm, app_state);

  return VPPCOM_ETIMEDOUT;
}

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

void
vcl_worker_cleanup (vcl_worker_t * wrk, u8 notify_vpp)
{
  clib_spinlock_lock (&vcm->workers_lock);
  if (notify_vpp)
    {
      if (wrk->wrk_index == vcl_get_worker_index ())
	vcl_send_app_worker_add_del (0 /* is_add */ );
      else
	vcl_send_child_worker_del (wrk);
    }
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
      wrk->mqs_epfd = epoll_create (1);
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

  vcm->app_state = STATE_APP_ADDING_WORKER;
  vcl_send_app_worker_add_del (1 /* is_add */ );
  if (vcl_wait_for_app_state_change (STATE_APP_READY))
    {
      VDBG (0, "failed to add worker to vpp");
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

int
vcl_worker_set_bapi (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int i;

  /* Find the first worker with the same pid */
  for (i = 0; i < vec_len (vcm->workers); i++)
    {
      if (i == wrk->wrk_index)
	continue;
      if (vcm->workers[i].current_pid == wrk->current_pid)
	{
	  wrk->vl_input_queue = vcm->workers[i].vl_input_queue;
	  wrk->my_client_index = vcm->workers[i].my_client_index;
	  return 0;
	}
    }
  return -1;
}

void
vcl_segment_table_add (u64 segment_handle, u32 svm_segment_index)
{
  clib_rwlock_writer_lock (&vcm->segment_table_lock);
  hash_set (vcm->segment_table, segment_handle, svm_segment_index);
  clib_rwlock_writer_unlock (&vcm->segment_table_lock);
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
vcl_segment_table_del (u64 segment_handle)
{
  clib_rwlock_writer_lock (&vcm->segment_table_lock);
  hash_unset (vcm->segment_table, segment_handle);
  clib_rwlock_writer_unlock (&vcm->segment_table_lock);
}

void
vcl_cleanup_bapi (void)
{
  socket_client_main_t *scm = &socket_client_main;
  api_main_t *am = &api_main;

  am->my_client_index = ~0;
  am->my_registration = 0;
  am->vl_input_queue = 0;
  am->msg_index_by_name_and_crc = 0;
  scm->socket_fd = 0;

  vl_client_api_unmap ();
}

int
vcl_session_read_ready (vcl_session_t * session)
{
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

  return svm_fifo_max_dequeue_cons (session->rx_fifo);
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

  return svm_fifo_max_enqueue_prod (session->tx_fifo);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
