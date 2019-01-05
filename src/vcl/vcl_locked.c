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

vcl_session_handle_t
vls_session_handle (vcl_locked_session_t * vls)
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
vls_free_w_sh (vcl_session_handle_t sh)
{
  vcl_locked_session_t *vls;
  vls_handle_t vlsh;

  vlsh = vls_handle_from_sh (sh);
  if (vlsh == VLS_INVALID_HANDLE)
    return;

  clib_rwlock_writer_lock (&vlsm->fd_table_lock);
  vls = vls_get (vlsh);
  vls_free (vls);
  clib_rwlock_writer_unlock (&vlsm->fd_table_lock);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
