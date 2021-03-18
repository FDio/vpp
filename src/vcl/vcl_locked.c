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

typedef struct vls_shared_data_
{
  clib_spinlock_t lock;
  u32 owner_wrk_index;
  u32 *workers_subscribed;
  clib_bitmap_t *listeners;
} vls_shared_data_t;

typedef struct vcl_locked_session_
{
  clib_spinlock_t lock;
  u32 session_index;
  u32 worker_index;
  u32 vls_index;
  u32 shared_data_index;
  /** VCL session owned by different workers because of migration */
  u32 owner_vcl_wrk_index;
  uword *vcl_wrk_index_to_session_index;
} vcl_locked_session_t;

typedef struct vls_worker_
{
  clib_rwlock_t sh_to_vlsh_table_lock; /** valid for multithread workers */
  vcl_locked_session_t *vls_pool;
  uword *session_handle_to_vlsh_table;
  u32 wrk_index;
} vls_worker_t;

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
  vls_worker_t *workers;
  clib_rwlock_t vls_table_lock;
  /** Pool of data shared by sessions owned by different workers */
  vls_shared_data_t *shared_data_pool;
  clib_rwlock_t shared_data_lock;
  /** Lock to protect rpc among workers */
  clib_spinlock_t worker_rpc_lock;
} vls_main_t;

vls_main_t *vlsm;

typedef enum
{
  VLS_RPC_STATE_INIT,
  VLS_RPC_STATE_SUCCESS,
  VLS_RPC_STATE_SESSION_NOT_EXIST,
} vls_rpc_state_e;

typedef enum vls_rpc_msg_type_
{
  VLS_RPC_CLONE_AND_SHARE,
  VLS_RPC_SESS_CLEANUP,
} vls_rpc_msg_type_e;

typedef struct vls_rpc_msg_
{
  u8 type;
  u8 data[0];
} vls_rpc_msg_t;

typedef struct vls_clone_and_share_msg_
{
  u32 vls_index;		/**< vls to be shared */
  u32 session_index;		/**< vcl session to be shared */
  u32 origin_vls_wrk;		/**< vls worker that initiated the rpc */
  u32 origin_vls_index;		/**< vls session of the originator */
  u32 origin_vcl_wrk;		/**< vcl worker that initiated the rpc */
  u32 origin_session_index;	/**< vcl session of the originator */
} vls_clone_and_share_msg_t;

typedef struct vls_sess_cleanup_msg_
{
  u32 session_index;		/**< vcl session to be cleaned */
  u32 origin_vcl_wrk;		/**< worker that initiated the rpc */
} vls_sess_cleanup_msg_t;

void vls_send_session_cleanup_rpc (vcl_worker_t * wrk,
				   u32 dst_wrk_index, u32 dst_session_index);
void vls_send_clone_and_share_rpc (vcl_worker_t *wrk, u32 origin_vls_index,
				   u32 session_index, u32 vls_wrk_index,
				   u32 dst_wrk_index, u32 dst_vls_index,
				   u32 dst_session_index);

static inline u32
vls_get_worker_index (void)
{
  if (vls_mt_wrk_supported ())
    return vlsl->vls_wrk_index;
  else
    return vcl_get_worker_index ();
}

static u32
vls_shared_data_alloc (void)
{
  vls_shared_data_t *vls_shd;
  u32 shd_index;

  clib_rwlock_writer_lock (&vlsm->shared_data_lock);
  pool_get_zero (vlsm->shared_data_pool, vls_shd);
  clib_spinlock_init (&vls_shd->lock);
  shd_index = vls_shd - vlsm->shared_data_pool;
  clib_rwlock_writer_unlock (&vlsm->shared_data_lock);

  return shd_index;
}

static u32
vls_shared_data_index (vls_shared_data_t * vls_shd)
{
  return vls_shd - vlsm->shared_data_pool;
}

vls_shared_data_t *
vls_shared_data_get (u32 shd_index)
{
  if (pool_is_free_index (vlsm->shared_data_pool, shd_index))
    return 0;
  return pool_elt_at_index (vlsm->shared_data_pool, shd_index);
}

static void
vls_shared_data_free (u32 shd_index)
{
  vls_shared_data_t *vls_shd;

  clib_rwlock_writer_lock (&vlsm->shared_data_lock);
  vls_shd = vls_shared_data_get (shd_index);
  clib_spinlock_free (&vls_shd->lock);
  clib_bitmap_free (vls_shd->listeners);
  vec_free (vls_shd->workers_subscribed);
  pool_put (vlsm->shared_data_pool, vls_shd);
  clib_rwlock_writer_unlock (&vlsm->shared_data_lock);
}

static inline void
vls_shared_data_pool_rlock (void)
{
  clib_rwlock_reader_lock (&vlsm->shared_data_lock);
}

static inline void
vls_shared_data_pool_runlock (void)
{
  clib_rwlock_reader_unlock (&vlsm->shared_data_lock);
}

static inline void
vls_mt_table_rlock (void)
{
  if (vlsl->vls_mt_n_threads > 1)
    clib_rwlock_reader_lock (&vlsm->vls_table_lock);
}

static inline void
vls_mt_table_runlock (void)
{
  if (vlsl->vls_mt_n_threads > 1)
    clib_rwlock_reader_unlock (&vlsm->vls_table_lock);
}

static inline void
vls_mt_table_wlock (void)
{
  if (vlsl->vls_mt_n_threads > 1)
    clib_rwlock_writer_lock (&vlsm->vls_table_lock);
}

static inline void
vls_mt_table_wunlock (void)
{
  if (vlsl->vls_mt_n_threads > 1)
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

  /* If multi-thread workers are supported, for each new thread register a new
   * vcl worker with vpp. Otherwise, all threads use the same vcl worker, so
   * update the vcl worker's thread local worker index variable */
  if (vls_mt_wrk_supported ())
    {
      if (vppcom_worker_register () != VPPCOM_OK)
	VERR ("failed to register worker");
    }
  else
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

u8
vls_is_shared (vcl_locked_session_t * vls)
{
  return (vls->shared_data_index != ~0);
}

static inline void
vls_lock (vcl_locked_session_t * vls)
{
  if ((vlsl->vls_mt_n_threads > 1) || vls_is_shared (vls))
    clib_spinlock_lock (&vls->lock);
}

static inline void
vls_unlock (vcl_locked_session_t * vls)
{
  if ((vlsl->vls_mt_n_threads > 1) || vls_is_shared (vls))
    clib_spinlock_unlock (&vls->lock);
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
  vls_mt_table_runlock ();
  return sh;
}

static vls_worker_t *
vls_worker_get_current (void)
{
  return pool_elt_at_index (vlsm->workers, vls_get_worker_index ());
}

static void
vls_worker_alloc (void)
{
  vls_worker_t *wrk;

  pool_get_zero (vlsm->workers, wrk);
  if (vls_mt_wrk_supported ())
    clib_rwlock_init (&wrk->sh_to_vlsh_table_lock);
  wrk->wrk_index = vcl_get_worker_index ();
}

static void
vls_worker_free (vls_worker_t * wrk)
{
  hash_free (wrk->session_handle_to_vlsh_table);
  if (vls_mt_wrk_supported ())
    clib_rwlock_free (&wrk->sh_to_vlsh_table_lock);
  pool_free (wrk->vls_pool);
  pool_put (vlsm->workers, wrk);
}

static vls_worker_t *
vls_worker_get (u32 wrk_index)
{
  if (pool_is_free_index (vlsm->workers, wrk_index))
    return 0;
  return pool_elt_at_index (vlsm->workers, wrk_index);
}

static void
vls_sh_to_vlsh_table_add (vls_worker_t *wrk, vcl_session_handle_t sh, u32 vlsh)
{
  if (vls_mt_wrk_supported ())
    clib_rwlock_writer_lock (&wrk->sh_to_vlsh_table_lock);
  hash_set (wrk->session_handle_to_vlsh_table, sh, vlsh);
  if (vls_mt_wrk_supported ())
    clib_rwlock_writer_unlock (&wrk->sh_to_vlsh_table_lock);
}

static void
vls_sh_to_vlsh_table_del (vls_worker_t *wrk, vcl_session_handle_t sh)
{
  if (vls_mt_wrk_supported ())
    clib_rwlock_writer_lock (&wrk->sh_to_vlsh_table_lock);
  hash_unset (wrk->session_handle_to_vlsh_table, sh);
  if (vls_mt_wrk_supported ())
    clib_rwlock_writer_unlock (&wrk->sh_to_vlsh_table_lock);
}

static uword *
vls_sh_to_vlsh_table_get (vls_worker_t *wrk, vcl_session_handle_t sh)
{
  if (vls_mt_wrk_supported ())
    clib_rwlock_reader_lock (&wrk->sh_to_vlsh_table_lock);
  uword *vlshp = hash_get (wrk->session_handle_to_vlsh_table, sh);
  if (vls_mt_wrk_supported ())
    clib_rwlock_reader_unlock (&wrk->sh_to_vlsh_table_lock);
  return vlshp;
}

static vls_handle_t
vls_alloc (vcl_session_handle_t sh)
{
  vls_worker_t *wrk = vls_worker_get_current ();
  vcl_locked_session_t *vls;

  vls_mt_table_wlock ();

  pool_get_zero (wrk->vls_pool, vls);
  vls->session_index = vppcom_session_index (sh);
  vls->worker_index = vppcom_session_worker (sh);
  vls->vls_index = vls - wrk->vls_pool;
  vls->shared_data_index = ~0;
  vls_sh_to_vlsh_table_add (wrk, sh, vls->vls_index);
  if (vls_mt_wrk_supported ())
    {
      hash_set (vls->vcl_wrk_index_to_session_index, vls->worker_index,
		vls->session_index);
      vls->owner_vcl_wrk_index = vls->worker_index;
    }
  clib_spinlock_init (&vls->lock);

  vls_mt_table_wunlock ();
  return vls->vls_index;
}

static vcl_locked_session_t *
vls_get (vls_handle_t vlsh)
{
  vls_worker_t *wrk = vls_worker_get_current ();
  if (pool_is_free_index (wrk->vls_pool, vlsh))
    return 0;
  return pool_elt_at_index (wrk->vls_pool, vlsh);
}

static void
vls_free (vcl_locked_session_t * vls)
{
  vls_worker_t *wrk = vls_worker_get_current ();

  ASSERT (vls != 0);
  vls_sh_to_vlsh_table_del (
    wrk, vcl_session_handle_from_index (vls->session_index));
  clib_spinlock_free (&vls->lock);
  pool_put (wrk->vls_pool, vls);
}

static vcl_locked_session_t *
vls_get_and_lock (vls_handle_t vlsh)
{
  vls_worker_t *wrk = vls_worker_get_current ();
  vcl_locked_session_t *vls;
  if (pool_is_free_index (wrk->vls_pool, vlsh))
    return 0;
  vls = pool_elt_at_index (wrk->vls_pool, vlsh);
  vls_lock (vls);
  return vls;
}

static vcl_locked_session_t *
vls_get_w_dlock (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;
  vls_mt_table_rlock ();
  vls = vls_get_and_lock (vlsh);
  if (!vls)
    vls_mt_table_runlock ();
  return vls;
}

static inline void
vls_get_and_unlock (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;
  vls_mt_table_rlock ();
  vls = vls_get (vlsh);
  vls_unlock (vls);
  vls_mt_table_runlock ();
}

static inline void
vls_dunlock (vcl_locked_session_t * vls)
{
  vls_unlock (vls);
  vls_mt_table_runlock ();
}

static vcl_locked_session_t *
vls_session_get (vls_worker_t * wrk, u32 vls_index)
{
  if (pool_is_free_index (wrk->vls_pool, vls_index))
    return 0;
  return pool_elt_at_index (wrk->vls_pool, vls_index);
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
vls_si_wi_to_vlsh (u32 session_index, u32 vcl_wrk_index)
{
  vls_worker_t *wrk = vls_worker_get_current ();
  uword *vlshp = vls_sh_to_vlsh_table_get (
    wrk,
    vcl_session_handle_from_wrk_session_index (session_index, vcl_wrk_index));

  return vlshp ? *vlshp : VLS_INVALID_HANDLE;
}

vls_handle_t
vls_session_index_to_vlsh (uint32_t session_index)
{
  vls_handle_t vlsh;

  vls_mt_table_rlock ();
  vlsh = vls_si_wi_to_vlsh (session_index, vcl_get_worker_index ());
  vls_mt_table_runlock ();

  return vlsh;
}

u8
vls_is_shared_by_wrk (vcl_locked_session_t * vls, u32 wrk_index)
{
  vls_shared_data_t *vls_shd;
  int i;

  if (vls->shared_data_index == ~0)
    return 0;

  vls_shared_data_pool_rlock ();

  vls_shd = vls_shared_data_get (vls->shared_data_index);
  clib_spinlock_lock (&vls_shd->lock);

  for (i = 0; i < vec_len (vls_shd->workers_subscribed); i++)
    if (vls_shd->workers_subscribed[i] == wrk_index)
      {
	clib_spinlock_unlock (&vls_shd->lock);
	vls_shared_data_pool_runlock ();
	return 1;
      }
  clib_spinlock_unlock (&vls_shd->lock);

  vls_shared_data_pool_runlock ();
  return 0;
}

static void
vls_listener_wrk_set (vcl_locked_session_t * vls, u32 wrk_index, u8 is_active)
{
  vls_shared_data_t *vls_shd;

  if (vls->shared_data_index == ~0)
    {
      clib_warning ("not a shared session");
      return;
    }

  vls_shared_data_pool_rlock ();

  vls_shd = vls_shared_data_get (vls->shared_data_index);

  clib_spinlock_lock (&vls_shd->lock);
  clib_bitmap_set (vls_shd->listeners, wrk_index, is_active);
  clib_spinlock_unlock (&vls_shd->lock);

  vls_shared_data_pool_runlock ();
}

static u32
vls_shared_get_owner (vcl_locked_session_t * vls)
{
  vls_shared_data_t *vls_shd;
  u32 owner_wrk;

  vls_shared_data_pool_rlock ();

  vls_shd = vls_shared_data_get (vls->shared_data_index);
  owner_wrk = vls_shd->owner_wrk_index;

  vls_shared_data_pool_runlock ();

  return owner_wrk;
}

static u8
vls_listener_wrk_is_active (vcl_locked_session_t * vls, u32 wrk_index)
{
  vls_shared_data_t *vls_shd;
  u8 is_set;

  if (vls->shared_data_index == ~0)
    {
      clib_warning ("not a shared session");
      return 0;
    }

  vls_shared_data_pool_rlock ();

  vls_shd = vls_shared_data_get (vls->shared_data_index);

  clib_spinlock_lock (&vls_shd->lock);
  is_set = clib_bitmap_get (vls_shd->listeners, wrk_index);
  clib_spinlock_unlock (&vls_shd->lock);

  vls_shared_data_pool_runlock ();

  return (is_set == 1);
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
  if (s->session_state != VCL_STATE_LISTEN)
    return;
  vcl_send_session_unlisten (wrk, s);
  s->session_state = VCL_STATE_LISTEN_NO_MQ;
  vls_listener_wrk_set (vls, wrk_index, 0 /* is_active */ );
}

static int
vls_shared_data_subscriber_position (vls_shared_data_t * vls_shd,
				     u32 wrk_index)
{
  int i;

  for (i = 0; i < vec_len (vls_shd->workers_subscribed); i++)
    {
      if (vls_shd->workers_subscribed[i] == wrk_index)
	return i;
    }
  return -1;
}

int
vls_unshare_session (vcl_locked_session_t * vls, vcl_worker_t * wrk)
{
  vls_shared_data_t *vls_shd;
  int do_disconnect, pos;
  u32 n_subscribers;
  vcl_session_t *s;

  if (vls->shared_data_index == ~0)
    return 0;

  s = vcl_session_get (wrk, vls->session_index);
  if (s->session_state == VCL_STATE_LISTEN)
    vls_listener_wrk_set (vls, wrk->wrk_index, 0 /* is_active */ );

  vls_shared_data_pool_rlock ();

  vls_shd = vls_shared_data_get (vls->shared_data_index);
  clib_spinlock_lock (&vls_shd->lock);

  pos = vls_shared_data_subscriber_position (vls_shd, wrk->wrk_index);
  if (pos < 0)
    {
      clib_warning ("worker %u not subscribed for vls %u", wrk->wrk_index,
		    vls->worker_index);
      goto done;
    }

  /*
   * Unsubscribe from share data and fifos
   */
  if (s->rx_fifo)
    {
      svm_fifo_del_subscriber (s->rx_fifo, wrk->vpp_wrk_index);
      svm_fifo_del_subscriber (s->tx_fifo, wrk->vpp_wrk_index);
    }
  vec_del1 (vls_shd->workers_subscribed, pos);

  /*
   * Cleanup vcl state
   */
  n_subscribers = vec_len (vls_shd->workers_subscribed);
  do_disconnect = s->session_state == VCL_STATE_LISTEN || !n_subscribers;
  vcl_session_cleanup (wrk, s, vcl_session_handle (s), do_disconnect);

  /*
   * No subscriber left, cleanup shared data
   */
  if (!n_subscribers)
    {
      u32 shd_index = vls_shared_data_index (vls_shd);

      clib_spinlock_unlock (&vls_shd->lock);
      vls_shared_data_pool_runlock ();

      vls_shared_data_free (shd_index);

      /* All locks have been dropped */
      return 0;
    }

  /* Return, if this is not the owning worker */
  if (vls_shd->owner_wrk_index != wrk->wrk_index)
    goto done;

  ASSERT (vec_len (vls_shd->workers_subscribed));

  /*
   *  Check if we can change owner or close
   */
  vls_shd->owner_wrk_index = vls_shd->workers_subscribed[0];
  vcl_send_session_worker_update (wrk, s, vls_shd->owner_wrk_index);

  /* XXX is this still needed? */
  if (vec_len (vls_shd->workers_subscribed) > 1)
    clib_warning ("more workers need to be updated");

done:

  clib_spinlock_unlock (&vls_shd->lock);
  vls_shared_data_pool_runlock ();

  return 0;
}

void
vls_init_share_session (vls_worker_t * vls_wrk, vcl_locked_session_t * vls)
{
  vls_shared_data_t *vls_shd;

  u32 vls_shd_index = vls_shared_data_alloc ();

  vls_shared_data_pool_rlock ();

  vls_shd = vls_shared_data_get (vls_shd_index);
  vls_shd->owner_wrk_index = vls_wrk->wrk_index;
  vls->shared_data_index = vls_shd_index;
  vec_add1 (vls_shd->workers_subscribed, vls_wrk->wrk_index);

  vls_shared_data_pool_runlock ();
}

void
vls_share_session (vls_worker_t * vls_wrk, vcl_locked_session_t * vls)
{
  vcl_worker_t *vcl_wrk = vcl_worker_get (vls_wrk->wrk_index);
  vls_shared_data_t *vls_shd;
  vcl_session_t *s;

  s = vcl_session_get (vcl_wrk, vls->session_index);
  if (!s)
    {
      clib_warning ("wrk %u session %u vls %u NOT AVAILABLE",
		    vcl_wrk->wrk_index, vls->session_index, vls->vls_index);
      return;
    }

  ASSERT (vls->shared_data_index != ~0);

  /* Reinit session lock */
  clib_spinlock_init (&vls->lock);

  vls_shared_data_pool_rlock ();

  vls_shd = vls_shared_data_get (vls->shared_data_index);

  clib_spinlock_lock (&vls_shd->lock);
  vec_add1 (vls_shd->workers_subscribed, vls_wrk->wrk_index);
  clib_spinlock_unlock (&vls_shd->lock);

  vls_shared_data_pool_runlock ();

  if (s->rx_fifo)
    {
      svm_fifo_add_subscriber (s->rx_fifo, vcl_wrk->vpp_wrk_index);
      svm_fifo_add_subscriber (s->tx_fifo, vcl_wrk->vpp_wrk_index);
    }
  else if (s->session_state == VCL_STATE_LISTEN)
    {
      s->session_state = VCL_STATE_LISTEN_NO_MQ;
    }
}

static void
vls_share_sessions (vls_worker_t * vls_parent_wrk, vls_worker_t * vls_wrk)
{
  vcl_locked_session_t *vls, *parent_vls;

  /* *INDENT-OFF* */
  pool_foreach (vls, vls_wrk->vls_pool)  {
    /* Initialize sharing on parent session */
    if (vls->shared_data_index == ~0)
      {
	parent_vls = vls_session_get (vls_parent_wrk, vls->vls_index);
	vls_init_share_session (vls_parent_wrk, parent_vls);
	vls->shared_data_index = parent_vls->shared_data_index;
      }
    vls_share_session (vls_wrk, vls);
  }
  /* *INDENT-ON* */
}

void
vls_worker_copy_on_fork (vcl_worker_t * parent_wrk)
{
  vls_worker_t *vls_wrk = vls_worker_get_current (), *vls_parent_wrk;
  vcl_worker_t *wrk = vcl_worker_get_current ();
  u32 vls_index, session_index, wrk_index;
  vcl_session_handle_t sh;

  /*
   * init vcl worker
   */
  wrk->sessions = pool_dup (parent_wrk->sessions);
  wrk->session_index_by_vpp_handles =
    hash_dup (parent_wrk->session_index_by_vpp_handles);

  /*
   * init vls worker
   */
  vls_parent_wrk = vls_worker_get (parent_wrk->wrk_index);
  /* *INDENT-OFF* */
  hash_foreach (sh, vls_index, vls_parent_wrk->session_handle_to_vlsh_table,
    ({
      vcl_session_handle_parse (sh, &wrk_index, &session_index);
      hash_set (vls_wrk->session_handle_to_vlsh_table,
		vcl_session_handle_from_index (session_index), vls_index);
    }));
  /* *INDENT-ON* */
  vls_wrk->vls_pool = pool_dup (vls_parent_wrk->vls_pool);

  vls_share_sessions (vls_parent_wrk, vls_wrk);
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
      is_nonblk = vcl_session_has_attr (s, VCL_SESS_ATTR_NONBLOCK);
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

static inline u8
vls_mt_session_should_migrate (vcl_locked_session_t * vls)
{
  return (vls_mt_wrk_supported ()
	  && vls->worker_index != vcl_get_worker_index ());
}

static vcl_locked_session_t *
vls_mt_session_migrate (vcl_locked_session_t *vls)
{
  u32 wrk_index = vcl_get_worker_index ();
  vcl_worker_t *wrk;
  vls_worker_t *vls_wrk = vls_worker_get_current ();
  u32 src_sid, sid, vls_index, own_vcl_wrk_index;
  vcl_session_t *session;
  uword *p;

  ASSERT (vls_mt_wrk_supported () && vls->worker_index != wrk_index);

  /*
   * VCL session on current vcl worker already allocated. Update current
   * owner worker and index and return
   */
  if ((p = hash_get (vls->vcl_wrk_index_to_session_index, wrk_index)))
    {
      vls->worker_index = wrk_index;
      vls->session_index = (u32) p[0];
      return vls;
    }

  /*
   * Ask vcl worker that owns the original vcl session to clone it into
   * current vcl worker session pool
   */

  if (!(p = hash_get (vls->vcl_wrk_index_to_session_index,
		      vls->owner_vcl_wrk_index)))
    {
      VERR ("session in owner worker(%u) is free", vls->owner_vcl_wrk_index);
      ASSERT (0);
      vls_unlock (vls);
      vls_mt_table_runlock ();
      return 0;
    }

  src_sid = (u32) p[0];
  wrk = vcl_worker_get_current ();
  session = vcl_session_alloc (wrk);
  sid = session->session_index;
  VDBG (1, "migrate session of worker (session): %u (%u) -> %u (%u)",
	vls->owner_vcl_wrk_index, src_sid, wrk_index, sid);

  /* Drop lock to prevent dead lock when dst wrk trying to get lock. */
  vls_index = vls->vls_index;
  own_vcl_wrk_index = vls->owner_vcl_wrk_index;
  vls_unlock (vls);
  vls_mt_table_runlock ();
  vls_send_clone_and_share_rpc (wrk, vls_index, sid, vls_get_worker_index (),
				own_vcl_wrk_index, vls_index, src_sid);

  if (PREDICT_FALSE (wrk->rpc_done == VLS_RPC_STATE_SESSION_NOT_EXIST))
    {
      VWRN ("session %u not exist", src_sid);
      goto err;
    }
  else if (PREDICT_FALSE (wrk->rpc_done == VLS_RPC_STATE_INIT))
    {
      VWRN ("failed to wait rpc response");
      goto err;
    }
  else if (PREDICT_FALSE ((session->flags & VCL_SESSION_F_IS_VEP) &&
			  session->vep.next_sh != ~0))
    {
      VERR ("can't migrate nonempty epoll session");
      ASSERT (0);
      goto err;
    }
  else if (PREDICT_FALSE (!(session->flags & VCL_SESSION_F_IS_VEP) &&
			  session->session_state != VCL_STATE_CLOSED))
    {
      VERR ("migrate NOT supported, session_status (%u)",
	    session->session_state);
      ASSERT (0);
      goto err;
    }

  vls = vls_get_w_dlock (vls_index);
  if (PREDICT_FALSE (!vls))
    {
      VWRN ("failed to get vls %u", vls_index);
      goto err;
    }

  session->session_index = sid;
  vls->worker_index = wrk_index;
  vls->session_index = sid;
  hash_set (vls->vcl_wrk_index_to_session_index, wrk_index, sid);
  vls_sh_to_vlsh_table_add (vls_wrk, vcl_session_handle (session),
			    vls->vls_index);
  return vls;

err:
  vcl_session_free (wrk, session);
  return 0;
}

static inline void
vls_mt_detect (void)
{
  if (PREDICT_FALSE (vcl_get_worker_index () == ~0))
    vls_mt_add ();
}

#define vls_mt_guard(_vls, _op)                                               \
  int _locks_acq = 0;                                                         \
  if (vls_mt_wrk_supported ())                                                \
    {                                                                         \
      if (PREDICT_FALSE (_vls &&                                              \
			 ((vcl_locked_session_t *) _vls)->worker_index !=     \
			   vcl_get_worker_index ()))                          \
	{                                                                     \
	  _vls = vls_mt_session_migrate (_vls);                               \
	  if (PREDICT_FALSE (!_vls))                                          \
	    return VPPCOM_EBADFD;                                             \
	}                                                                     \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      if (PREDICT_FALSE (vlsl->vls_mt_n_threads > 1))                         \
	vls_mt_acq_locks (_vls, _op, &_locks_acq);                            \
    }

#define vls_mt_unguard()						\
  if (PREDICT_FALSE (_locks_acq))					\
    vls_mt_rel_locks (_locks_acq)

int
vls_write (vls_handle_t vlsh, void *buf, size_t nbytes)
{
  vcl_locked_session_t *vls;
  int rv;

  vls_mt_detect ();
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

  vls_mt_detect ();
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

  vls_mt_detect ();
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

  vls_mt_detect ();
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

  vls_mt_detect ();
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

  vls_mt_detect ();
  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;
  if (vls_mt_session_should_migrate (vls))
    {
      vls = vls_mt_session_migrate (vls);
      if (PREDICT_FALSE (!vls))
	return VPPCOM_EBADFD;
    }
  rv = vppcom_session_attr (vls_to_sh_tu (vls), op, buffer, buflen);
  vls_get_and_unlock (vlsh);
  return rv;
}

int
vls_bind (vls_handle_t vlsh, vppcom_endpt_t * ep)
{
  vcl_locked_session_t *vls;
  int rv;

  vls_mt_detect ();
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

  vls_mt_detect ();
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

  vls_mt_detect ();
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
  u32 owner_wrk;

  if (vls_mt_wrk_supported ())
    return;

  s = vcl_session_get (wrk, vls->session_index);
  switch (s->session_state)
    {
    case VCL_STATE_LISTEN:
      if (is_add)
	{
	  vls_listener_wrk_set (vls, vls->worker_index, 1 /* is_active */ );
	  break;
	}
      vls_listener_wrk_stop_listen (vls, vls->worker_index);
      break;
    case VCL_STATE_LISTEN_NO_MQ:
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
      owner_wrk = vls_shared_get_owner (vls);
      if (!vls_listener_wrk_is_active (vls, owner_wrk))
	vls_listener_wrk_stop_listen (vls, owner_wrk);
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

  vls_mt_detect ();
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
  vcl_locked_session_t *vls = NULL;

  vls_mt_detect ();
  vls_mt_guard (vls, VLS_MT_OP_SPOOL);
  sh = vppcom_session_create (proto, is_nonblocking);
  vls_mt_unguard ();
  if (sh == INVALID_SESSION_ID)
    return VLS_INVALID_HANDLE;

  vlsh = vls_alloc (sh);
  if (PREDICT_FALSE (vlsh == VLS_INVALID_HANDLE))
    vppcom_session_close (sh);

  return vlsh;
}

static void
vls_mt_session_cleanup (vcl_locked_session_t * vls)
{
  u32 session_index, wrk_index, current_vcl_wrk;
  vcl_worker_t *wrk = vcl_worker_get_current ();

  ASSERT (vls_mt_wrk_supported ());

  current_vcl_wrk = vcl_get_worker_index ();

  /* *INDENT-OFF* */
  hash_foreach (wrk_index, session_index, vls->vcl_wrk_index_to_session_index,
    ({
      if (current_vcl_wrk != wrk_index)
	vls_send_session_cleanup_rpc (wrk, wrk_index, session_index);
    }));
  /* *INDENT-ON* */
  hash_free (vls->vcl_wrk_index_to_session_index);
}

int
vls_close (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;
  int rv;

  vls_mt_detect ();
  vls_mt_table_wlock ();

  vls = vls_get_and_lock (vlsh);
  if (!vls)
    {
      vls_mt_table_wunlock ();
      return VPPCOM_EBADFD;
    }

  vls_mt_guard (vls, VLS_MT_OP_SPOOL);

  if (vls_is_shared (vls))
    rv = vls_unshare_session (vls, vcl_worker_get_current ());
  else
    rv = vppcom_session_close (vls_to_sh (vls));

  if (vls_mt_wrk_supported ())
    vls_mt_session_cleanup (vls);

  vls_free (vls);
  vls_mt_unguard ();

  vls_mt_table_wunlock ();

  return rv;
}

vls_handle_t
vls_epoll_create (void)
{
  vcl_session_handle_t sh;
  vls_handle_t vlsh;

  vls_mt_detect ();

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

  vls_mt_detect ();
  vls_mt_table_rlock ();
  ep_vls = vls_get_and_lock (ep_vlsh);

  if (vls_mt_session_should_migrate (ep_vls))
    {
      ep_vls = vls_mt_session_migrate (ep_vls);
      if (PREDICT_FALSE (!ep_vls))
	return VPPCOM_EBADFD;
    }

  ep_sh = vls_to_sh (ep_vls);
  vls = vls_get_and_lock (vlsh);
  sh = vls_to_sh (vls);

  if (PREDICT_FALSE (!vlsl->epoll_mp_check))
    vls_epoll_ctl_mp_checks (vls, op);

  vls_mt_table_runlock ();

  rv = vppcom_epoll_ctl (ep_sh, op, sh, event);

  vls_mt_table_rlock ();
  ep_vls = vls_get (ep_vlsh);
  vls = vls_get (vlsh);
  vls_unlock (vls);
  vls_unlock (ep_vls);
  vls_mt_table_runlock ();
  return rv;
}

int
vls_epoll_wait (vls_handle_t ep_vlsh, struct epoll_event *events,
		int maxevents, double wait_for_time)
{
  vcl_locked_session_t *vls, *vls_tmp = NULL;
  int rv;

  vls_mt_detect ();
  if (!(vls = vls_get_w_dlock (ep_vlsh)))
    return VPPCOM_EBADFD;
  vls_mt_guard (vls_tmp, VLS_MT_OP_XPOLL);
  rv = vppcom_epoll_wait (vls_to_sh_tu (vls), events, maxevents,
			  wait_for_time);
  vls_mt_unguard ();
  vls_get_and_unlock (ep_vlsh);
  return rv;
}

int
vls_epoll_prewait (vls_handle_t ep_vlsh, struct epoll_event *events,
		   int maxevents)
{
  vcl_locked_session_t *vls, *vls_tmp = NULL;
  int rv;

  vls_mt_detect ();
  if (!(vls = vls_get_w_dlock (ep_vlsh)))
    return VPPCOM_EBADFD;
  vls_mt_guard (vls_tmp, VLS_MT_OP_XPOLL);
  rv = vppcom_epoll_prewait (vls_to_sh_tu (vls), events, maxevents);
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
  clib_bitmap_foreach (si, read_map)  {
    s = vcl_session_get (wrk, si);
    if (s->session_state == VCL_STATE_LISTEN)
      {
	vls = vls_get (vls_session_index_to_vlsh (si));
	vls_mp_checks (vls, 1 /* is_add */);
      }
  }
  /* *INDENT-ON* */
}

int
vls_select (int n_bits, vcl_si_set * read_map, vcl_si_set * write_map,
	    vcl_si_set * except_map, double wait_for_time)
{
  int rv;
  vcl_locked_session_t *vls = NULL;

  vls_mt_detect ();
  vls_mt_guard (vls, VLS_MT_OP_XPOLL);
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

  /* *INDENT-OFF* */
  pool_foreach (s, wrk->sessions)  {
    vls = vls_get (vls_si_wi_to_vlsh (s->session_index, wrk->wrk_index));
    if (vls && (is_current || vls_is_shared_by_wrk (vls, current_wrk)))
      vls_unshare_session (vls, wrk);
  }
  /* *INDENT-ON* */
}

static void
vls_cleanup_vcl_worker (vcl_worker_t * wrk)
{
  vls_worker_t *vls_wrk = vls_worker_get (wrk->wrk_index);

  /* Unshare sessions and also cleanup worker since child may have
   * called _exit () and therefore vcl may not catch the event */
  vls_unshare_vcl_worker_sessions (wrk);
  vcl_worker_cleanup (wrk, 1 /* notify vpp */ );

  vls_worker_free (vls_wrk);
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
  if (old_sa.sa_sigaction)
    {
      VDBG (0, "have intercepted sigchld");
      return;
    }
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
  int parent_wrk_index;

  parent_wrk_index = vcl_get_worker_index ();
  VDBG (0, "initializing forked child %u with parent wrk %u", getpid (),
	parent_wrk_index);

  /*
   * Clear old state
   */
  vcl_set_worker_index (~0);

  /*
   * Allocate and register vcl worker with vpp
   */
  if (vppcom_worker_register ())
    {
      VERR ("couldn't register new worker!");
      return;
    }

  /*
   * Allocate/initialize vls worker and share sessions
   */
  vls_worker_alloc ();
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
  vls_worker_t *wrk = vls_worker_get_current ();

  /* Unshare the sessions. VCL will clean up the worker */
  vls_unshare_vcl_worker_sessions (vcl_worker_get_current ());
  vls_worker_free (wrk);
}

static void
vls_clone_and_share_rpc_handler (void *args)
{
  vls_clone_and_share_msg_t *msg = (vls_clone_and_share_msg_t *) args;
  vls_worker_t *wrk = vls_worker_get_current (), *dst_wrk;
  vcl_locked_session_t *vls, *dst_vls;
  vcl_worker_t *vcl_wrk = vcl_worker_get_current (), *dst_vcl_wrk;
  vcl_session_t *s, *dst_s;

  VDBG (1, "process session clone of worker (session): %u (%u) -> %u (%u)",
	vcl_wrk->wrk_index, msg->session_index, msg->origin_vcl_wrk,
	msg->origin_session_index);

  /* VCL locked session can't been protected, so DONT touch it.
   * VCL session may been free, check it.
   */
  dst_vcl_wrk = vcl_worker_get (msg->origin_vcl_wrk);
  s = vcl_session_get (vcl_wrk, msg->session_index);
  if (PREDICT_FALSE (!s))
    {
      dst_vcl_wrk->rpc_done = VLS_RPC_STATE_SESSION_NOT_EXIST;
      return;
    }

  if (!vls_mt_wrk_supported ())
    {
      vls = vls_session_get (wrk, msg->vls_index);
      vls_init_share_session (wrk, vls);
      dst_wrk = vls_worker_get (msg->origin_vls_wrk);
      dst_vls = vls_session_get (dst_wrk, msg->origin_vls_index);
      dst_vls->shared_data_index = vls->shared_data_index;
    }
  dst_s = vcl_session_get (dst_vcl_wrk, msg->origin_session_index);
  clib_memcpy (dst_s, s, sizeof (*s));

  dst_vcl_wrk->rpc_done = VLS_RPC_STATE_SUCCESS;
}

static void
vls_session_cleanup_rpc_handler (void *args)
{
  vls_sess_cleanup_msg_t *msg = (vls_sess_cleanup_msg_t *) args;
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vls_worker_t *vls_wrk = vls_worker_get_current ();
  vcl_session_handle_t sh = vcl_session_handle_from_index (msg->session_index);

  VDBG (1, "process session cleanup of worker (session): %u (%u) from %u ()",
	wrk->wrk_index, msg->session_index, msg->origin_vcl_wrk);

  vppcom_session_close (sh);
  vls_sh_to_vlsh_table_del (vls_wrk, sh);
}

static void
vls_rpc_handler (void *args)
{
  vls_rpc_msg_t *msg = (vls_rpc_msg_t *) args;
  switch (msg->type)
    {
    case VLS_RPC_CLONE_AND_SHARE:
      vls_clone_and_share_rpc_handler (msg->data);
      break;
    case VLS_RPC_SESS_CLEANUP:
      vls_session_cleanup_rpc_handler (msg->data);
      break;
    default:
      break;
    }
}

void
vls_send_clone_and_share_rpc (vcl_worker_t *wrk, u32 origin_vls_index,
			      u32 session_index, u32 vls_wrk_index,
			      u32 dst_wrk_index, u32 dst_vls_index,
			      u32 dst_session_index)
{
  u8 data[sizeof (u8) + sizeof (vls_clone_and_share_msg_t)];
  vls_clone_and_share_msg_t *msg;
  vls_rpc_msg_t *rpc;
  int ret;
  f64 timeout = clib_time_now (&wrk->clib_time) + VLS_WORKER_RPC_TIMEOUT;

  rpc = (vls_rpc_msg_t *) & data;
  rpc->type = VLS_RPC_CLONE_AND_SHARE;
  msg = (vls_clone_and_share_msg_t *) & rpc->data;
  msg->origin_vls_wrk = vls_wrk_index;
  msg->origin_vls_index = origin_vls_index;
  msg->origin_vcl_wrk = wrk->wrk_index;
  msg->origin_session_index = session_index;
  msg->vls_index = dst_vls_index;
  msg->session_index = dst_session_index;

  /* Try lock and handle rpcs if two threads send each other
   * clone requests at the same time.
   */
  wrk->rpc_done = VLS_RPC_STATE_INIT;
  while (!clib_spinlock_trylock (&vlsm->worker_rpc_lock))
    vcl_flush_mq_events ();
  ret = vcl_send_worker_rpc (dst_wrk_index, rpc, sizeof (data));

  VDBG (1, "send session clone to wrk (session): %u (%u) -> %u (%u), ret=%d",
	dst_wrk_index, msg->session_index, msg->origin_vcl_wrk,
	msg->origin_session_index, ret);
  while (!ret && wrk->rpc_done == VLS_RPC_STATE_INIT &&
	 clib_time_now (&wrk->clib_time) < timeout)
    ;
  clib_spinlock_unlock (&vlsm->worker_rpc_lock);
}

void
vls_send_session_cleanup_rpc (vcl_worker_t * wrk,
			      u32 dst_wrk_index, u32 dst_session_index)
{
  u8 data[sizeof (u8) + sizeof (vls_sess_cleanup_msg_t)];
  vls_sess_cleanup_msg_t *msg;
  vls_rpc_msg_t *rpc;
  int ret;

  rpc = (vls_rpc_msg_t *) & data;
  rpc->type = VLS_RPC_SESS_CLEANUP;
  msg = (vls_sess_cleanup_msg_t *) & rpc->data;
  msg->origin_vcl_wrk = wrk->wrk_index;
  msg->session_index = dst_session_index;

  ret = vcl_send_worker_rpc (dst_wrk_index, rpc, sizeof (data));

  VDBG (1, "send session cleanup to wrk (session): %u (%u) from %u, ret=%d",
	dst_wrk_index, msg->session_index, msg->origin_vcl_wrk, ret);
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
  clib_rwlock_init (&vlsm->shared_data_lock);
  clib_spinlock_init (&vlsm->worker_rpc_lock);
  pool_alloc (vlsm->workers, vcm->cfg.max_workers);

  pthread_atfork (vls_app_pre_fork, vls_app_fork_parent_handler,
		  vls_app_fork_child_handler);
  atexit (vls_app_exit);
  vls_worker_alloc ();
  vlsl->vls_wrk_index = vcl_get_worker_index ();
  vls_mt_locks_init ();
  vcm->wrk_rpc_fn = vls_rpc_handler;
  return VPPCOM_OK;
}

unsigned char
vls_use_eventfd (void)
{
  return vcm->cfg.use_mq_eventfd;
}

unsigned char
vls_mt_wrk_supported (void)
{
  return vcm->cfg.mt_wrk_supported;
}

int
vls_use_real_epoll (void)
{
  if (vcl_get_worker_index () == ~0)
    return 0;

  return vcl_worker_get_current ()->vcl_needs_real_epoll;
}

void
vls_register_vcl_worker (void)
{
  vls_mt_add ();
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
