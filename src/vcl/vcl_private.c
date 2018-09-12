/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
  VDBG (0, "VCL<%d>: timeout waiting for state %s (%d)", getpid (),
	vppcom_app_state_str (app_state), app_state);
  vcl_evt (VCL_EVT_SESSION_TIMEOUT, vcm, app_state);

  return VPPCOM_ETIMEDOUT;
}

vcl_cut_through_registration_t *
vcl_ct_registration_lock_and_alloc (vcl_worker_t * wrk)
{
  vcl_cut_through_registration_t *cr;
  clib_spinlock_lock (&wrk->ct_registration_lock);
  pool_get (wrk->cut_through_registrations, cr);
  memset (cr, 0, sizeof (*cr));
  cr->epoll_evt_conn_index = -1;
  return cr;
}

u32
vcl_ct_registration_index (vcl_worker_t * wrk,
			   vcl_cut_through_registration_t * ctr)
{
  return (ctr - wrk->cut_through_registrations);
}

void
vcl_ct_registration_lock (vcl_worker_t * wrk)
{
  clib_spinlock_lock (&wrk->ct_registration_lock);
}

void
vcl_ct_registration_unlock (vcl_worker_t * wrk)
{
  clib_spinlock_unlock (&wrk->ct_registration_lock);
}

vcl_cut_through_registration_t *
vcl_ct_registration_get (vcl_worker_t * wrk, u32 ctr_index)
{
  if (pool_is_free_index (wrk->cut_through_registrations, ctr_index))
    return 0;
  return pool_elt_at_index (wrk->cut_through_registrations, ctr_index);
}

vcl_cut_through_registration_t *
vcl_ct_registration_lock_and_lookup (vcl_worker_t * wrk, uword mq_addr)
{
  uword *p;
  clib_spinlock_lock (&wrk->ct_registration_lock);
  p = hash_get (wrk->ct_registration_by_mq, mq_addr);
  if (!p)
    return 0;
  return vcl_ct_registration_get (wrk, p[0]);
}

void
vcl_ct_registration_lookup_add (vcl_worker_t * wrk, uword mq_addr,
				u32 ctr_index)
{
  hash_set (wrk->ct_registration_by_mq, mq_addr, ctr_index);
}

void
vcl_ct_registration_lookup_del (vcl_worker_t * wrk, uword mq_addr)
{
  hash_unset (wrk->ct_registration_by_mq, mq_addr);
}

void
vcl_ct_registration_del (vcl_worker_t * wrk,
			 vcl_cut_through_registration_t * ctr)
{
  pool_put (wrk->cut_through_registrations, ctr);
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
      clib_warning ("failed to add mq eventfd to mq epoll fd");
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
      clib_warning ("failed to del mq eventfd to mq epoll fd");
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
  return wrk;
}

static void
vcl_worker_free (vcl_worker_t * wrk)
{
  pool_put (vcm->workers, wrk);
}

static void
vcl_worker_cleanup (void *arg)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();

  VDBG (0, "cleaning up worker %u", wrk->wrk_index);
  vcl_send_app_worker_add_del (0 /* is_add */ );
  close (wrk->mqs_epfd);
  hash_free (wrk->session_index_by_vpp_handles);
  hash_free (wrk->ct_registration_by_mq);
  clib_spinlock_free (&wrk->ct_registration_lock);
  vec_free (wrk->mq_events);
  vec_free (wrk->mq_msg_vector);
  vcl_set_worker_index (~0);
  vcl_worker_free (wrk);
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

  wrk->mqs_epfd = -1;
  if (vcm->cfg.use_mq_eventfd)
    {
      wrk->mqs_epfd = epoll_create (1);
      if (wrk->mqs_epfd < 0)
	{
	  clib_unix_warning ("epoll_create() returned");
	  return 0;
	}
    }

  wrk->session_index_by_vpp_handles = hash_create (0, sizeof (uword));
  wrk->ct_registration_by_mq = hash_create (0, sizeof (uword));
  clib_spinlock_init (&wrk->ct_registration_lock);
  clib_time_init (&wrk->clib_time);
  vec_validate (wrk->mq_events, 64);
  vec_validate (wrk->mq_msg_vector, 128);
  vec_reset_length (wrk->mq_msg_vector);
  vec_validate (wrk->unhandled_evts_vector, 128);
  vec_reset_length (wrk->unhandled_evts_vector);

  if (wrk->wrk_index == 0)
    {
      clib_spinlock_unlock (&vcm->workers_lock);
      return wrk;
    }

  vcm->app_state = STATE_APP_ADDING_WORKER;
  vcl_send_app_worker_add_del (1 /* is_add */ );
  if (vcl_wait_for_app_state_change (STATE_APP_READY))
    {
      clib_warning ("failed to add worker to vpp");
      return 0;
    }

  if (pthread_key_create (&vcl_worker_stop_key, vcl_worker_cleanup))
    clib_warning ("failed to add pthread cleanup function");
  if (pthread_setspecific (vcl_worker_stop_key, &wrk->thread_id))
    clib_warning ("failed to setup key value");
  wrk->thread_id = pthread_self ();

  clib_spinlock_unlock (&vcm->workers_lock);

  VDBG (0, "added worker %u", wrk->wrk_index);

  return wrk;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
