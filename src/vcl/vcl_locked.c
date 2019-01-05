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

typedef u32 vls_handle_t;

typedef struct vcl_locked_session_
{
  u32 session_index;
  u32 worker_index;
  u32 fd; /* to remove */
  u32 fd_index;
  u32 flags;
  clib_spinlock_t lock;
} vcl_locked_session_t;

typedef struct vcl_main_
{
  vcl_locked_session_t *fd_pool;
  clib_rwlock_t fd_table_lock;
  uword *session_index_to_fd_table;
} vls_main_t;

#define VLS_INVALID_HANDLE ((u32)~0)

vls_main_t vls_main;
vls_main_t *vlsm = &vls_main;

static inline vcl_session_handle_t
vls_to_sh (vcl_locked_session_t * vls)
{
  return vppcom_session_handle (vls->session_index);
}

vls_handle_t
vls_alloc (vcl_session_handle_t sh)
{
  vcl_locked_session_t *vls;

  clib_rwlock_writer_lock (&vlsm->fd_table_lock);
  pool_get (vlsm->fd_pool, vls);
  vls->session_index = vppcom_session_index (sh);
  vls->worker_index = vppcom_session_worker (sh);
  vls->fd_index = vls - vlsm->fd_pool;
  hash_set (vlsm->session_index_to_fd_table, vls->session_index, vls->fd_index);
  clib_spinlock_init (&vls->lock);
  return vls->fd_index;
}

vcl_locked_session_t *
vls_get (vls_handle_t vlsh)
{
  if (pool_is_free_index (vlsm->fd_pool, vlsh))
    return 0;
  return pool_elt_at_index (vlsm->fd_pool, vlsh);
}

void
vls_free (vcl_locked_session_t * fde)
{
  ASSERT (fde != 0);
  hash_unset (vlsm->session_index_to_fd_table, fde->session_index);
  clib_spinlock_free (&fde->lock);
  pool_put (vlsm->fd_pool, fde);
}

vcl_locked_session_t *
vls_get_and_lock (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;
  clib_rwlock_reader_lock (&vlsm->fd_table_lock);
  if (pool_is_free_index (vlsm->fd_pool, vlsh))
    {
      clib_rwlock_reader_unlock (&vlsm->fd_table_lock);
      return 0;
    }
  vls = pool_elt_at_index (vlsm->fd_pool, vlsh);
  clib_spinlock_lock (&vls->lock);
  return vls;
}

void
vls_unlock (vcl_locked_session_t * vls)
{
  clib_spinlock_unlock (&vls->lock);
  clib_rwlock_reader_unlock (&vlsm->fd_table_lock);
}

vls_handle_t
vls_handle_from_sh (vcl_session_handle_t sh)
{
  vls_handle_t vlsh;
  uword *fdp;

  clib_rwlock_reader_lock (&vlsm->fd_table_lock);
  fdp = hash_get (vlsm->session_index_to_fd_table, vppcom_session_index (sh));
  vlsh = fdp ? *fdp : VLS_INVALID_HANDLE;
  clib_rwlock_reader_unlock (&vlsm->fd_table_lock);

  return vlsh;
}

vcl_session_handle_t
vls_handle_to_sh (vls_handle_t vlsh)
{
  u32 session_index;
  vcl_locked_session_t *vls;

  vls = vls_get_and_lock (vlsh);
  if (!vls)
    return INVALID_SESSION_ID;
  session_index = vls->session_index;
  vls_unlock (vls);

  return vppcom_session_handle (session_index);
}

void
vls_get_and_free (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;

  clib_rwlock_writer_lock (&vlsm->fd_table_lock);
  vls = vls_get (vlsh);
  vls_free (vls);
  clib_rwlock_writer_unlock (&vlsm->fd_table_lock);
}

int
vls_write (vls_handle_t vlsh, void *buf, size_t nbytes)
{
  vcl_locked_session_t *vls;
  int rv;

  vls = vls_get_and_lock (vlsh);
  rv = vppcom_session_write (vls_to_sh (vls), buf, nbytes);
  vls_unlock (vls);
  return rv;
}

int
vls_write_msg (vls_handle_t vlsh, void *buf, size_t nbytes)
{
  vcl_locked_session_t *vls;
  int rv;

  vls = vls_get_and_lock (vlsh);
  rv = vppcom_session_write_msg (vls_to_sh (vls), buf, nbytes);
  vls_unlock (vls);
  return rv;
}

ssize_t
vls_read (vls_handle_t vlsh, void *buf, size_t nbytes)
{
  vcl_locked_session_t *vls;
  int rv;

  vls = vls_get_and_lock (vlsh);
  rv = vppcom_session_read (vls_to_sh (vls), buf, nbytes);
  vls_unlock (vls);
  return rv;
}

int
vls_attr (vls_handle_t vlsh, uint32_t op, void *buffer, uint32_t *buflen)
{
  vcl_locked_session_t *vls;
  int rv;

  vls = vls_get_and_lock (vlsh);
  rv = vppcom_session_attr (vls_to_sh (vls), op, buffer, buflen);
  vls_unlock (vls);
  return rv;
}

int
vls_bind (vls_handle_t vlsh, vppcom_endpt_t * ep)
{
  vcl_locked_session_t *vls;
  int rv;

  vls = vls_get_and_lock (vlsh);
  rv = vppcom_session_bind (vls_to_sh (vls), ep);
  vls_unlock (vls);
  return rv;
}

int
vls_listen (vls_handle_t vlsh, int q_len)
{
  vcl_locked_session_t *vls;
  int rv;

  vls = vls_get_and_lock (vlsh);
  rv = vppcom_session_listen (vls_to_sh (vls), q_len);
  vls_unlock (vls);
  return rv;
}

int
vls_connect (vls_handle_t vlsh, vppcom_endpt_t * server_ep)
{
  vcl_locked_session_t *vls;
  int rv;

  vls = vls_get_and_lock (vlsh);
  rv = vppcom_session_connect (vls_to_sh (vls), server_ep);
  vls_unlock (vls);
  return rv;
}

int
vls_accept (vls_handle_t vlsh, vppcom_endpt_t * ep, int flags)
{
  vcl_locked_session_t *vls;
  int rv;

  vls = vls_get_and_lock (vlsh);
  rv = vppcom_session_accept (vls_to_sh (vls), ep, flags);
  vls_unlock (vls);
  return rv;
}

vls_handle_t
vls_create (uint8_t proto, uint8_t is_nonblocking)
{
  vcl_session_handle_t sh;
  vls_handle_t vlsh;

  sh = vppcom_session_create (proto, is_nonblocking);
  if (sh == INVALID_SESSION_ID)
    return sh;

  vlsh = vls_alloc (sh);
  if (vlsh == VLS_INVALID_HANDLE)
    {
      vppcom_session_close (sh);
      return vlsh;
    }
  return vlsh;
}

int
vls_close (vls_handle_t vlsh)
{
  vcl_locked_session_t *vls;
  vcl_session_handle_t sh;
  int rv, refcnt;

  vls = vls_get_and_lock (vlsh);
  sh = vls_to_sh (vls);

  refcnt = vppcom_session_attr (sh, VPPCOM_ATTR_GET_REFCNT, 0, 0);
  if ((rv = vppcom_session_close (sh)))
    return rv;

  vls_unlock (vls);
  if (refcnt <= 1)
    vls_get_and_free (vlsh);
  return rv;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
