/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vcl/vcl_locked.h>
#include <vcl/vcl_private.h>

typedef struct vcl_locked_session_
{
  clib_spinlock_t lock;
  u32 session_index;
  u32 worker_index;
  u32 vls_index;
  u32 *workers_subscribed;
  clib_bitmap_t *listeners;
} vcl_locked_session_t;

typedef struct vls_local_
{
  int vls_wrk_index;
  volatile int vls_mt_n_threads;
  pthread_mutex_t vls_mt_mq_mlock;
  pthread_mutex_t vls_mt_spool_mlock;
  volatile u8 select_mp_check;
  volatile u8 epoll_mp_check;
} vls_process_local_t;

static vls_process_local_t vls_local;
static vls_process_local_t *vlsl = &vls_local;

typedef struct vls_main_
{
  vcl_locked_session_t *vls_pool;
  clib_rwlock_t vls_table_lock;
  uword *session_index_to_vlsh_table;
} vls_main_t;

vls_main_t *vlsm;

static inline void
vls_table_rlock (void)
{
  clib_rwlock_reader_lock (&vlsm->vls_table_lock);
}

static inline void
vls_table_runlock (void)
{
  clib_rwlock_reader_unlock (&vlsm->vls_table_lock);
}

static inline void
vls_table_wlock (void)
{
  clib_rwlock_writer_lock (&vlsm->vls_table_lock);
}

static inline void
vls_table_wunlock (void)
{
  clib_rwlock_writer_unlock (&vlsm->vls_table_lock);
}

typedef enum
{
  VLS_MT_OP_READ,
  VLS_MT_OP_WRITE,
  VLS_MT_OP_SPOOL,
  VLS_MT_OP_XPOLL,
} vls_mt_ops_t;

typedef enum
{
  VLS_MT_LOCK_MQ = 1 << 0,
  VLS_MT_LOCK_SPOOL = 1 << 1
} vls_mt_lock_type_t;

static void
vls_mt_add (void)
{
  vlsl->vls_mt_n_threads += 1;
  vcl_set_worker_index (vlsl->vls_wrk_index);
}

static inline void
vls_mt_mq_lock (void)
{
  pthread_mutex_lock (&vlsl->vls_mt_mq_mlock);
}

static inline void
vls_mt_mq_unlock (void)
{
  pthread_mutex_unlock (&vlsl->vls_mt_mq_mlock);
}

static inline void
vls_mt_spool_lock (void)
{
  pthread_mutex_lock (&vlsl->vls_mt_spool_mlock);
}

static inline void
vls_mt_create_unlock (void)
{
  pthread_mutex_unlock (&vlsl->vls_mt_spool_mlock);
}

static void
vls_mt_locks_init (void)
{
  pthread_mutex_init (&vlsl->vls_mt_mq_mlock, NULL);
  pthread_mutex_init (&vlsl->vls_mt_spool_mlock, NULL);
}

static inline vcl_session_handle_t
vls_to_sh (vcl_locked_session_t * vls)
{
  return vcl_session_handle_from_index (vls->session_index);
}

static inline vcl_session_handle_t
vls_to_sh_tu (vcl_locked_session_t * vls)
{
  vcl_session_handle_t sh;
  sh = vls_to_sh (vls);
  vls_table_runlock ();
  return sh;
}

static vls_handle_t
vls_alloc (vcl_session_handle_t sh)
{
  vcl_locked_session_t *vls;

  vls_table_wlock ();
  pool_get (vlsm->vls_pool, vls);
  vls->session_index = vppcom_session_index (sh);
  vls->worker_index = vppcom_session_worker (sh);
  vls->vls_index = vls - vlsm->vls_pool;
  hash_set (vlsm->session_index_to_vlsh_table, vls->session_index,
	    vls->vls_index);
  clib_spinlock_init (&vls->lock);
  vls_table_wunlock ();
  return vls->vls_index;
}

static vcl_locked_session_t *
vls_get (vls_handle_t vlsh)
{
  if (pool_is_free_index (vlsm->vls_pool, vlsh))
    return 0;
  return pool_elt_at_index (vlsm->vls_pool, vlsh);
}

static void
vls_free (vcl_locked_session_t * vls)
{
  ASSERT (vls != 0);
  hash_unset (vlsm->session_index_to_vlsh_table, vls->session_index);
  clib_spinlock_free (&vls->lock);
  pool_put (vlsm->vls_pool, vls);
}

static vcl_locked_session_t *
vls_get_and_lock (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;
  if (pool_is_free_index (vlsm->vls_pool, vlsh))
    return 0;
  vls = pool_elt_at_index (vlsm->vls_pool, vlsh);
  clib_spinlock_lock (&vls->lock);
  return vls;
}

static vcl_locked_session_t *
vls_get_w_dlock (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;
  vls_table_rlock ();
  vls = vls_get_and_lock (vlsh);
  if (!vls)
    vls_table_runlock ();
  return vls;
}

static inline void
vls_lock (vcl_locked_session_t * vls)
{
  clib_spinlock_lock (&vls->lock);
}

static inline void
vls_unlock (vcl_locked_session_t * vls)
{
  clib_spinlock_unlock (&vls->lock);
}

static inline void
vls_get_and_unlock (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;
  vls_table_rlock ();
  vls = vls_get (vlsh);
  vls_unlock (vls);
  vls_table_runlock ();
}

static inline void
vls_dunlock (vcl_locked_session_t * vls)
{
  vls_unlock (vls);
  vls_table_runlock ();
}

vcl_session_handle_t
vlsh_to_sh (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;
  int rv;

  vls = vls_get_w_dlock (vlsh);
  if (!vls)
    return INVALID_SESSION_ID;
  rv = vls_to_sh (vls);
  vls_dunlock (vls);
  return rv;
}

vcl_session_handle_t
vlsh_to_session_index (vls_handle_t vlsh)
{
  vcl_session_handle_t sh;
  sh = vlsh_to_sh (vlsh);
  return vppcom_session_index (sh);
}

vls_handle_t
vls_si_to_vlsh (u32 session_index)
{
  uword *vlshp;
  vlshp = hash_get (vlsm->session_index_to_vlsh_table, session_index);
  return vlshp ? *vlshp : VLS_INVALID_HANDLE;
}

vls_handle_t
vls_session_index_to_vlsh (uint32_t session_index)
{
  vls_handle_t vlsh;

  vls_table_rlock ();
  vlsh = vls_si_to_vlsh (session_index);
  vls_table_runlock ();

  return vlsh;
}

u8
vls_is_shared (vcl_locked_session_t * vls)
{
  return vec_len (vls->workers_subscribed);
}

u8
vls_is_shared_by_wrk (vcl_locked_session_t * vls, u32 wrk_index)
{
  int i;
  for (i = 0; i < vec_len (vls->workers_subscribed); i++)
    if (vls->workers_subscribed[i] == wrk_index)
      return 1;
  return 0;
}

static void
vls_listener_wrk_set (vcl_locked_session_t * vls, u32 wrk_index, u8 is_active)
{
  clib_bitmap_set (vls->listeners, wrk_index, is_active);
}

static u8
vls_listener_wrk_is_active (vcl_locked_session_t * vls, u32 wrk_index)
{
  return (clib_bitmap_get (vls->listeners, wrk_index) == 1);
}

static void
vls_listener_wrk_start_listen (vcl_locked_session_t * vls, u32 wrk_index)
{
  vppcom_session_listen (vls_to_sh (vls), ~0);
  vls_listener_wrk_set (vls, wrk_index, 1 /* is_active */ );
}

static void
vls_listener_wrk_stop_listen (vcl_locked_session_t * vls, u32 wrk_index)
{
  vcl_worker_t *wrk;
  vcl_session_t *s;

  wrk = vcl_worker_get (wrk_index);
  s = vcl_session_get (wrk, vls->session_index);
  if (s->session_state != STATE_LISTEN)
    return;
  vppcom_send_unbind_sock (wrk, s->vpp_handle);
  s->session_state = STATE_LISTEN_NO_MQ;
  vls_listener_wrk_set (vls, wrk_index, 0 /* is_active */ );
}

int
vls_unshare_session (vcl_locked_session_t * vls, vcl_worker_t * wrk)
{
  int i, do_disconnect;
  vcl_session_t *s;

  s = vcl_session_get (wrk, vls->session_index);
  if (s->session_state == STATE_LISTEN)
    vls_listener_wrk_set (vls, wrk->wrk_index, 0 /* is_active */ );

  for (i = 0; i < vec_len (vls->workers_subscribed); i++)
    {
      if (vls->workers_subscribed[i] != wrk->wrk_index)
	continue;

      if (s->rx_fifo)
	{
	  svm_fifo_del_subscriber (s->rx_fifo, wrk->vpp_wrk_index);
	  svm_fifo_del_subscriber (s->tx_fifo, wrk->vpp_wrk_index);
	}
      vec_del1 (vls->workers_subscribed, i);
      do_disconnect = s->session_state == STATE_LISTEN;
      vcl_session_cleanup (wrk, s, vcl_session_handle (s), do_disconnect);
      return 0;
    }

  /* Return, if this is not the owning worker */
  if (vls->worker_index != wrk->wrk_index)
    return 0;

  /* Check if we can change owner or close */
  if (vec_len (vls->workers_subscribed))
    {
      vls->worker_index = vls->workers_subscribed[0];
      vec_del1 (vls->workers_subscribed, 0);
      vcl_send_session_worker_update (wrk, s, vls->worker_index);
      if (vec_len (vls->workers_subscribed))
	clib_warning ("more workers need to be updated");
    }
  else
    {
      vcl_session_cleanup (wrk, s, vcl_session_handle (s),
			   1 /* do_disconnect */ );
    }

  return 0;
}

void
vls_share_vcl_session (vcl_worker_t * wrk, vcl_session_t * s)
{
  vcl_locked_session_t *vls;

  vls = vls_get (vls_si_to_vlsh (s->session_index));
  if (!vls)
    return;
  vls_lock (vls);
  vec_add1 (vls->workers_subscribed, wrk->wrk_index);
  if (s->rx_fifo)
    {
      svm_fifo_add_subscriber (s->rx_fifo, wrk->vpp_wrk_index);
      svm_fifo_add_subscriber (s->tx_fifo, wrk->vpp_wrk_index);
    }
  else if (s->session_state == STATE_LISTEN)
    {
      s->session_state = STATE_LISTEN_NO_MQ;
    }

  vls_unlock (vls);
}

void
vls_worker_copy_on_fork (vcl_worker_t * parent_wrk)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *s;

  wrk->vpp_event_queues = vec_dup (parent_wrk->vpp_event_queues);
  wrk->sessions = pool_dup (parent_wrk->sessions);
  wrk->session_index_by_vpp_handles =
    hash_dup (parent_wrk->session_index_by_vpp_handles);
  vls_table_wlock ();

  /* *INDENT-OFF* */
  pool_foreach (s, wrk->sessions, ({
    vls_share_vcl_session (wrk, s);
  }));
  /* *INDENT-ON* */

  vls_table_wunlock ();
}

static void
vls_mt_acq_locks (vcl_locked_session_t * vls, vls_mt_ops_t op, int *locks_acq)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *s = 0;
  int is_nonblk = 0;

  if (vls)
    {
      s = vcl_session_get (wrk, vls->session_index);
      if (PREDICT_FALSE (!s))
	return;
      is_nonblk = VCL_SESS_ATTR_TEST (s->attr, VCL_SESS_ATTR_NONBLOCK);
    }

  switch (op)
    {
    case VLS_MT_OP_READ:
      if (!is_nonblk)
	is_nonblk = vcl_session_read_ready (s) != 0;
      if (!is_nonblk)
	{
	  vls_mt_mq_lock ();
	  *locks_acq |= VLS_MT_LOCK_MQ;
	}
      break;
    case VLS_MT_OP_WRITE:
      ASSERT (s);
      if (!is_nonblk)
	is_nonblk = vcl_session_write_ready (s) != 0;
      if (!is_nonblk)
	{
	  vls_mt_mq_lock ();
	  *locks_acq |= VLS_MT_LOCK_MQ;
	}
      break;
    case VLS_MT_OP_XPOLL:
      vls_mt_mq_lock ();
      *locks_acq |= VLS_MT_LOCK_MQ;
      break;
    case VLS_MT_OP_SPOOL:
      vls_mt_spool_lock ();
      *locks_acq |= VLS_MT_LOCK_SPOOL;
      break;
    default:
      break;
    }
}

static void
vls_mt_rel_locks (int locks_acq)
{
  if (locks_acq & VLS_MT_LOCK_MQ)
    vls_mt_mq_unlock ();
  if (locks_acq & VLS_MT_LOCK_SPOOL)
    vls_mt_create_unlock ();
}

#define vls_mt_guard(_vls, _op)				\
  int _locks_acq = 0;					\
  if (PREDICT_FALSE (vcl_get_worker_index () == ~0))	\
    vls_mt_add ();					\
  if (PREDICT_FALSE (vlsl->vls_mt_n_threads > 1))	\
    vls_mt_acq_locks (_vls, _op, &_locks_acq);		\

#define vls_mt_unguard()				\
  if (PREDICT_FALSE (_locks_acq))			\
    vls_mt_rel_locks (_locks_acq)

int
vls_write (vls_handle_t vlsh, void *buf, size_t nbytes)
{
  vcl_locked_session_t *vls;
  int rv;

  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;

  vls_mt_guard (vls, VLS_MT_OP_WRITE);
  rv = vppcom_session_write (vls_to_sh_tu (vls), buf, nbytes);
  vls_mt_unguard ();
  vls_get_and_unlock (vlsh);
  return rv;
}

int
vls_write_msg (vls_handle_t vlsh, void *buf, size_t nbytes)
{
  vcl_locked_session_t *vls;
  int rv;

  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;
  vls_mt_guard (vls, VLS_MT_OP_WRITE);
  rv = vppcom_session_write_msg (vls_to_sh_tu (vls), buf, nbytes);
  vls_mt_unguard ();
  vls_get_and_unlock (vlsh);
  return rv;
}

int
vls_sendto (vls_handle_t vlsh, void *buf, int buflen, int flags,
	    vppcom_endpt_t * ep)
{
  vcl_locked_session_t *vls;
  int rv;

  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;
  vls_mt_guard (vls, VLS_MT_OP_WRITE);
  rv = vppcom_session_sendto (vls_to_sh_tu (vls), buf, buflen, flags, ep);
  vls_mt_unguard ();
  vls_get_and_unlock (vlsh);
  return rv;
}

ssize_t
vls_read (vls_handle_t vlsh, void *buf, size_t nbytes)
{
  vcl_locked_session_t *vls;
  int rv;

  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;
  vls_mt_guard (vls, VLS_MT_OP_READ);
  rv = vppcom_session_read (vls_to_sh_tu (vls), buf, nbytes);
  vls_mt_unguard ();
  vls_get_and_unlock (vlsh);
  return rv;
}

ssize_t
vls_recvfrom (vls_handle_t vlsh, void *buffer, uint32_t buflen, int flags,
	      vppcom_endpt_t * ep)
{
  vcl_locked_session_t *vls;
  int rv;

  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;
  vls_mt_guard (vls, VLS_MT_OP_READ);
  rv = vppcom_session_recvfrom (vls_to_sh_tu (vls), buffer, buflen, flags,
				ep);
  vls_mt_unguard ();
  vls_get_and_unlock (vlsh);
  return rv;
}

int
vls_attr (vls_handle_t vlsh, uint32_t op, void *buffer, uint32_t * buflen)
{
  vcl_locked_session_t *vls;
  int rv;

  if (PREDICT_FALSE (vcl_get_worker_index () == ~0))
    vls_mt_add ();

  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;
  rv = vppcom_session_attr (vls_to_sh_tu (vls), op, buffer, buflen);
  vls_get_and_unlock (vlsh);
  return rv;
}

int
vls_bind (vls_handle_t vlsh, vppcom_endpt_t * ep)
{
  vcl_locked_session_t *vls;
  int rv;

  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;
  rv = vppcom_session_bind (vls_to_sh_tu (vls), ep);
  vls_get_and_unlock (vlsh);
  return rv;
}

int
vls_listen (vls_handle_t vlsh, int q_len)
{
  vcl_locked_session_t *vls;
  int rv;

  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;
  vls_mt_guard (vls, VLS_MT_OP_XPOLL);
  rv = vppcom_session_listen (vls_to_sh_tu (vls), q_len);
  vls_mt_unguard ();
  vls_get_and_unlock (vlsh);
  return rv;
}

int
vls_connect (vls_handle_t vlsh, vppcom_endpt_t * server_ep)
{
  vcl_locked_session_t *vls;
  int rv;

  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;
  vls_mt_guard (vls, VLS_MT_OP_XPOLL);
  rv = vppcom_session_connect (vls_to_sh_tu (vls), server_ep);
  vls_mt_unguard ();
  vls_get_and_unlock (vlsh);
  return rv;
}

static inline void
vls_mp_checks (vcl_locked_session_t * vls, int is_add)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *s;

  s = vcl_session_get (wrk, vls->session_index);
  switch (s->session_state)
    {
    case STATE_LISTEN:
      if (is_add)
	{
	  if (vls->worker_index == wrk->wrk_index)
	    vls_listener_wrk_set (vls, wrk->wrk_index, 1 /* is_active */ );
	  break;
	}
      vls_listener_wrk_stop_listen (vls, vls->worker_index);
      break;
    case STATE_LISTEN_NO_MQ:
      if (!is_add)
	break;

      /* Register worker as listener */
      vls_listener_wrk_start_listen (vls, wrk->wrk_index);

      /* If owner worker did not attempt to accept/xpoll on the session,
       * force a listen stop for it, since it may not be interested in
       * accepting new sessions.
       * This is pretty much a hack done to give app workers the illusion
       * that it is fine to listen and not accept new sessions for a
       * given listener. Without it, we would accumulate unhandled
       * accepts on the passive worker message queue. */
      if (!vls_listener_wrk_is_active (vls, vls->worker_index))
	vls_listener_wrk_stop_listen (vls, vls->worker_index);
      break;
    default:
      break;
    }
}

vls_handle_t
vls_accept (vls_handle_t listener_vlsh, vppcom_endpt_t * ep, int flags)
{
  vls_handle_t accepted_vlsh;
  vcl_locked_session_t *vls;
  int sh;

  if (!(vls = vls_get_w_dlock (listener_vlsh)))
    return VPPCOM_EBADFD;
  if (vcl_n_workers () > 1)
    vls_mp_checks (vls, 1 /* is_add */ );
  vls_mt_guard (vls, VLS_MT_OP_SPOOL);
  sh = vppcom_session_accept (vls_to_sh_tu (vls), ep, flags);
  vls_mt_unguard ();
  vls_get_and_unlock (listener_vlsh);
  if (sh < 0)
    return sh;
  accepted_vlsh = vls_alloc (sh);
  if (PREDICT_FALSE (accepted_vlsh == VLS_INVALID_HANDLE))
    vppcom_session_close (sh);
  return accepted_vlsh;
}

vls_handle_t
vls_create (uint8_t proto, uint8_t is_nonblocking)
{
  vcl_session_handle_t sh;
  vls_handle_t vlsh;

  vls_mt_guard (0, VLS_MT_OP_SPOOL);
  sh = vppcom_session_create (proto, is_nonblocking);
  vls_mt_unguard ();
  if (sh == INVALID_SESSION_ID)
    return VLS_INVALID_HANDLE;

  vlsh = vls_alloc (sh);
  if (PREDICT_FALSE (vlsh == VLS_INVALID_HANDLE))
    vppcom_session_close (sh);

  return vlsh;
}

int
vls_close (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;
  int rv;

  vls_table_wlock ();

  vls = vls_get_and_lock (vlsh);
  if (!vls)
    {
      vls_table_wunlock ();
      return VPPCOM_EBADFD;
    }

  vls_mt_guard (0, VLS_MT_OP_SPOOL);
  if (vls_is_shared (vls))
    {
      /* At least two workers share the session so vls won't be freed */
      vls_unshare_session (vls, vcl_worker_get_current ());
      vls_unlock (vls);
      vls_mt_unguard ();
      vls_table_wunlock ();
      return VPPCOM_OK;
    }

  rv = vppcom_session_close (vls_to_sh (vls));
  vls_free (vls);
  vls_mt_unguard ();

  vls_table_wunlock ();

  return rv;
}

vls_handle_t
vls_epoll_create (void)
{
  vcl_session_handle_t sh;
  vls_handle_t vlsh;

  if (PREDICT_FALSE (vcl_get_worker_index () == ~0))
    vls_mt_add ();

  sh = vppcom_epoll_create ();
  if (sh == INVALID_SESSION_ID)
    return VLS_INVALID_HANDLE;

  vlsh = vls_alloc (sh);
  if (vlsh == VLS_INVALID_HANDLE)
    vppcom_session_close (sh);

  return vlsh;
}

static void
vls_epoll_ctl_mp_checks (vcl_locked_session_t * vls, int op)
{
  if (vcl_n_workers () <= 1)
    {
      vlsl->epoll_mp_check = 1;
      return;
    }

  if (op == EPOLL_CTL_MOD)
    return;

  vlsl->epoll_mp_check = 1;
  vls_mp_checks (vls, op == EPOLL_CTL_ADD);
}

int
vls_epoll_ctl (vls_handle_t ep_vlsh, int op, vls_handle_t vlsh,
	       struct epoll_event *event)
{
  vcl_locked_session_t *ep_vls, *vls;
  vcl_session_handle_t ep_sh, sh;
  int rv;

  vls_table_rlock ();
  ep_vls = vls_get_and_lock (ep_vlsh);
  vls = vls_get_and_lock (vlsh);
  ep_sh = vls_to_sh (ep_vls);
  sh = vls_to_sh (vls);

  if (PREDICT_FALSE (!vlsl->epoll_mp_check))
    vls_epoll_ctl_mp_checks (vls, op);

  vls_table_runlock ();

  rv = vppcom_epoll_ctl (ep_sh, op, sh, event);

  vls_table_rlock ();
  ep_vls = vls_get (ep_vlsh);
  vls = vls_get (vlsh);
  vls_unlock (vls);
  vls_unlock (ep_vls);
  vls_table_runlock ();
  return rv;
}

int
vls_epoll_wait (vls_handle_t ep_vlsh, struct epoll_event *events,
		int maxevents, double wait_for_time)
{
  vcl_locked_session_t *vls;
  int rv;

  if (!(vls = vls_get_w_dlock (ep_vlsh)))
    return VPPCOM_EBADFD;
  vls_mt_guard (0, VLS_MT_OP_XPOLL);
  rv = vppcom_epoll_wait (vls_to_sh_tu (vls), events, maxevents,
			  wait_for_time);
  vls_mt_unguard ();
  vls_get_and_unlock (ep_vlsh);
  return rv;
}

static void
vls_select_mp_checks (vcl_si_set * read_map)
{
  vcl_locked_session_t *vls;
  vcl_worker_t *wrk;
  vcl_session_t *s;
  u32 si;

  if (vcl_n_workers () <= 1)
    {
      vlsl->select_mp_check = 1;
      return;
    }

  if (!read_map)
    return;

  vlsl->select_mp_check = 1;
  wrk = vcl_worker_get_current ();

  /* *INDENT-OFF* */
  clib_bitmap_foreach (si, read_map, ({
    s = vcl_session_get (wrk, si);
    if (s->session_state == STATE_LISTEN)
      {
	vls = vls_get (vls_session_index_to_vlsh (si));
	vls_mp_checks (vls, 1 /* is_add */);
      }
  }));
  /* *INDENT-ON* */
}

int
vls_select (int n_bits, vcl_si_set * read_map, vcl_si_set * write_map,
	    vcl_si_set * except_map, double wait_for_time)
{
  int rv;

  vls_mt_guard (0, VLS_MT_OP_XPOLL);
  if (PREDICT_FALSE (!vlsl->select_mp_check))
    vls_select_mp_checks (read_map);
  rv = vppcom_select (n_bits, read_map, write_map, except_map, wait_for_time);
  vls_mt_unguard ();
  return rv;
}

static void
vls_unshare_vcl_worker_sessions (vcl_worker_t * wrk)
{
  u32 current_wrk, is_current;
  vcl_locked_session_t *vls;
  vcl_session_t *s;

  if (pool_elts (vcm->workers) <= 1)
    return;

  current_wrk = vcl_get_worker_index ();
  is_current = current_wrk == wrk->wrk_index;
  vls_table_wlock ();

  /* *INDENT-OFF* */
  pool_foreach (s, wrk->sessions, ({
    vls = vls_get (vls_si_to_vlsh (s->session_index));
    if (vls && (is_current || vls_is_shared_by_wrk (vls, current_wrk)))
      vls_unshare_session (vls, wrk);
  }));
  /* *INDENT-ON* */

  vls_table_wunlock ();
}

static void
vls_cleanup_vcl_worker (vcl_worker_t * wrk)
{
  /* Unshare sessions and also cleanup worker since child may have
   * called _exit () and therefore vcl may not catch the event */
  vls_unshare_vcl_worker_sessions (wrk);
  vcl_worker_cleanup (wrk, 1 /* notify vpp */ );
}

static void
vls_cleanup_forked_child (vcl_worker_t * wrk, vcl_worker_t * child_wrk)
{
  vcl_worker_t *sub_child;
  int tries = 0;

  if (child_wrk->forked_child != ~0)
    {
      sub_child = vcl_worker_get_if_valid (child_wrk->forked_child);
      if (sub_child)
	{
	  /* Wait a bit, maybe the process is going away */
	  while (kill (sub_child->current_pid, 0) >= 0 && tries++ < 50)
	    usleep (1e3);
	  if (kill (sub_child->current_pid, 0) < 0)
	    vls_cleanup_forked_child (child_wrk, sub_child);
	}
    }
  vls_cleanup_vcl_worker (child_wrk);
  VDBG (0, "Cleaned up forked child wrk %u", child_wrk->wrk_index);
  wrk->forked_child = ~0;
}

static struct sigaction old_sa;

static void
vls_intercept_sigchld_handler (int signum, siginfo_t * si, void *uc)
{
  vcl_worker_t *wrk, *child_wrk;

  if (vcl_get_worker_index () == ~0)
    return;

  if (sigaction (SIGCHLD, &old_sa, 0))
    {
      VERR ("couldn't restore sigchld");
      exit (-1);
    }

  wrk = vcl_worker_get_current ();
  if (wrk->forked_child == ~0)
    return;

  child_wrk = vcl_worker_get_if_valid (wrk->forked_child);
  if (!child_wrk)
    goto done;

  if (si && si->si_pid != child_wrk->current_pid)
    {
      VDBG (0, "unexpected child pid %u", si->si_pid);
      goto done;
    }
  vls_cleanup_forked_child (wrk, child_wrk);

done:
  if (old_sa.sa_flags & SA_SIGINFO)
    {
      void (*fn) (int, siginfo_t *, void *) = old_sa.sa_sigaction;
      fn (signum, si, uc);
    }
  else
    {
      void (*fn) (int) = old_sa.sa_handler;
      if (fn)
	fn (signum);
    }
}

static void
vls_incercept_sigchld ()
{
  struct sigaction sa;
  clib_memset (&sa, 0, sizeof (sa));
  sa.sa_sigaction = vls_intercept_sigchld_handler;
  sa.sa_flags = SA_SIGINFO;
  if (sigaction (SIGCHLD, &sa, &old_sa))
    {
      VERR ("couldn't intercept sigchld");
      exit (-1);
    }
}

static void
vls_app_pre_fork (void)
{
  vls_incercept_sigchld ();
  vcl_flush_mq_events ();
}

static void
vls_app_fork_child_handler (void)
{
  vcl_worker_t *parent_wrk;
  int rv, parent_wrk_index;
  u8 *child_name;

  parent_wrk_index = vcl_get_worker_index ();
  VDBG (0, "initializing forked child %u with parent wrk %u", getpid (),
	parent_wrk_index);

  /*
   * Allocate worker
   */
  vcl_set_worker_index (~0);
  if (!vcl_worker_alloc_and_init ())
    VERR ("couldn't allocate new worker");

  /*
   * Attach to binary api
   */
  child_name = format (0, "%v-child-%u%c", vcm->app_name, getpid (), 0);
  vcl_cleanup_bapi ();
  vppcom_api_hookup ();
  vcm->app_state = STATE_APP_START;
  rv = vppcom_connect_to_vpp ((char *) child_name);
  vec_free (child_name);
  if (rv)
    {
      VERR ("couldn't connect to VPP!");
      return;
    }

  /*
   * Register worker with vpp and share sessions
   */
  vcl_worker_register_with_vpp ();
  parent_wrk = vcl_worker_get (parent_wrk_index);
  vls_worker_copy_on_fork (parent_wrk);
  parent_wrk->forked_child = vcl_get_worker_index ();

  /* Reset number of threads and set wrk index */
  vlsl->vls_mt_n_threads = 0;
  vlsl->vls_wrk_index = vcl_get_worker_index ();
  vlsl->select_mp_check = 0;
  vlsl->epoll_mp_check = 0;
  vls_mt_locks_init ();

  VDBG (0, "forked child main worker initialized");
  vcm->forking = 0;
}

static void
vls_app_fork_parent_handler (void)
{
  vcm->forking = 1;
  while (vcm->forking)
    ;
}

void
vls_app_exit (void)
{
  /* Unshare the sessions. VCL will clean up the worker */
  vls_unshare_vcl_worker_sessions (vcl_worker_get_current ());
}

int
vls_app_create (char *app_name)
{
  int rv;

  if ((rv = vppcom_app_create (app_name)))
    return rv;
  vlsm = clib_mem_alloc (sizeof (vls_main_t));
  clib_memset (vlsm, 0, sizeof (*vlsm));
  clib_rwlock_init (&vlsm->vls_table_lock);
  pthread_atfork (vls_app_pre_fork, vls_app_fork_parent_handler,
		  vls_app_fork_child_handler);
  atexit (vls_app_exit);
  vlsl->vls_wrk_index = vcl_get_worker_index ();
  vls_mt_locks_init ();
  return VPPCOM_OK;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
