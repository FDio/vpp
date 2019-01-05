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

#include <vcl/vppcom.h>
#include <vcl/vcl_private.h>

typedef struct vcl_locked_session_
{
  u32 session_index;
  u32 worker_index;
  u32 vls_index;
  u32 flags;
  clib_spinlock_t lock;
} vcl_locked_session_t;

typedef struct vcl_main_
{
  vcl_locked_session_t *vls_pool;
  clib_rwlock_t vls_table_lock;
  uword *session_index_to_vlsh_table;
} vls_main_t;

vls_main_t vls_main;
vls_main_t *vlsm = &vls_main;

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

static inline vcl_session_handle_t
vls_to_sh (vcl_locked_session_t * vls)
{
  return vppcom_session_handle (vls->session_index);
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
vls_free (vcl_locked_session_t * fde)
{
  ASSERT (fde != 0);
  hash_unset (vlsm->session_index_to_vlsh_table, fde->session_index);
  clib_spinlock_free (&fde->lock);
  pool_put (vlsm->vls_pool, fde);
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

static void
vls_get_and_free (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;

  vls_table_wlock ();
  vls = vls_get (vlsh);
  vls_free (vls);
  vls_table_wunlock ();
}

int
vls_write (vls_handle_t vlsh, void *buf, size_t nbytes)
{
  vcl_locked_session_t *vls;
  int rv;

  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;
  rv = vppcom_session_write (vls_to_sh_tu (vls), buf, nbytes);
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
  rv = vppcom_session_write_msg (vls_to_sh_tu (vls), buf, nbytes);
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
  rv = vppcom_session_sendto (vls_to_sh_tu (vls), buf, buflen, flags, ep);
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
  rv = vppcom_session_read (vls_to_sh_tu (vls), buf, nbytes);
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
  rv = vppcom_session_recvfrom (vls_to_sh_tu (vls), buffer, buflen, flags,
				ep);
  vls_get_and_unlock (vlsh);
  return rv;
}

int
vls_attr (vls_handle_t vlsh, uint32_t op, void *buffer, uint32_t * buflen)
{
  vcl_locked_session_t *vls;
  int rv;

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
  rv = vppcom_session_listen (vls_to_sh_tu (vls), q_len);
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
  rv = vppcom_session_connect (vls_to_sh_tu (vls), server_ep);
  vls_get_and_unlock (vlsh);
  return rv;
}

vls_handle_t
vls_accept (vls_handle_t listener_vlsh, vppcom_endpt_t * ep, int flags)
{
  vls_handle_t accepted_vlsh;
  vcl_locked_session_t *vls;
  int sh;

  if (!(vls = vls_get_w_dlock (listener_vlsh)))
    return VPPCOM_EBADFD;
  sh = vppcom_session_accept (vls_to_sh_tu (vls), ep, flags);
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

  sh = vppcom_session_create (proto, is_nonblocking);
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
  vcl_session_handle_t sh;
  int rv, refcnt;

  if (!(vls = vls_get_w_dlock (vlsh)))
    return VPPCOM_EBADFD;

  sh = vls_to_sh (vls);
  refcnt = vppcom_session_attr (sh, VPPCOM_ATTR_GET_REFCNT, 0, 0);
  if ((rv = vppcom_session_close (sh)))
    {
      vls_dunlock (vls);
      return rv;
    }

  vls_dunlock (vls);
  if (refcnt <= 1)
    vls_get_and_free (vlsh);
  return rv;
}

vls_handle_t
vls_epoll_create (void)
{
  vcl_session_handle_t sh;
  vls_handle_t vlsh;

  sh = vppcom_epoll_create ();
  if (sh == INVALID_SESSION_ID)
    return VLS_INVALID_HANDLE;

  vlsh = vls_alloc (sh);
  if (vlsh == VLS_INVALID_HANDLE)
    vppcom_session_close (sh);

  return vlsh;
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
  rv = vppcom_epoll_wait (vls_to_sh_tu (vls), events, maxevents,
			  wait_for_time);
  vls_get_and_unlock (ep_vlsh);
  return rv;
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
vls_session_index_to_vlsh (uint32_t session_index)
{
  vls_handle_t vlsh;
  uword *vlshp;

  vls_table_rlock ();
  vlshp = hash_get (vlsm->session_index_to_vlsh_table, session_index);
  vlsh = vlshp ? *vlshp : VLS_INVALID_HANDLE;
  vls_table_runlock ();

  return vlsh;
}

void
vls_init ()
{
  clib_rwlock_init (&vlsm->vls_table_lock);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
