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

#include <vppcom.h>

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

vls_main_t vls_main;
vls_main_t *vlsm = &vls_main;

static inline vcl_session_handle_t
vls_session_handle (vcl_locked_session_t * vls)
{
  return vppcom_session_handle (vls->session_index);
}

static vls_handle_t
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
  clib_rwlock_writer_unlock (&vlsm->fd_table_lock);
  return vls->fd_index;
}

static vcl_locked_session_t *
vls_get (vls_handle_t vlsh)
{
  if (pool_is_free_index (vlsm->fd_pool, vlsh))
    return 0;
  return pool_elt_at_index (vlsm->fd_pool, vlsh);
}

static vcl_locked_session_t *
vls_lock (vls_handle_t vlsh)
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

static void
vls_unlock (vcl_locked_session_t * vls)
{
  clib_spinlock_unlock (&vls->lock);
  clib_rwlock_reader_unlock (&vlsm->fd_table_lock);
}

static vls_handle_t
vls_handle_from_sh (vcl_session_handle_t sh)
{
  vls_handle_t vlsh;
  uword *fdp;

  clib_rwlock_reader_lock (&vlsm->fd_table_lock);
  fdp = hash_get (vlsm->session_index_to_fd_table, vppcom_session_index (sh));
  fd = fdp ? *fdp : -EMFILE;
  clib_rwlock_reader_unlock (&vlsm->fd_table_lock);

  return fd;
}

static inline int
ldp_fd_is_sh (int fd)
{
  return fd >= ldp->sh_bit_val;
}

static inline u32
ldp_sh_from_fd (int fd)
{
  u32 fd_index, session_index;
  ldp_fd_entry_t *fde;

  if (!ldp_fd_is_sh (fd))
    return INVALID_SESSION_ID;

  fd_index = fd - ldp->sh_bit_val;
  fde = ldp_fd_entry_lock (fd_index);
  if (!fde)
    {
      LDBG (0, "unknown fd %d", fd);
      return INVALID_SESSION_ID;
    }
  session_index = fde->session_index;
  ldp_fd_entry_unlock (fde);

  return vppcom_session_handle (session_index);
}

static ldp_fd_entry_t *
ldp_fd_entry_lock_w_fd (int fd)
{
  u32 fd_index;

  if (!ldp_fd_is_sh (fd))
    return 0;

  fd_index = fd - ldp->sh_bit_val;
  return ldp_fd_entry_lock (fd_index);
}

static void
ldp_fd_free_w_sh (vcl_session_handle_t sh)
{
  ldp_fd_entry_t *fde;
  u32 fd_index;
  int fd;

  fd = ldp_fd_from_sh (sh);
  if (!fd)
    return;

  fd_index = fd - ldp->sh_bit_val;
  clib_rwlock_writer_lock (&ldp->fd_table_lock);
  fde = ldp_fd_entry_get (fd_index);
  ASSERT (fde != 0);
  hash_unset (ldp->session_index_to_fd_table, fde->session_index);
  clib_spinlock_free (&fde->lock);
  pool_put (ldp->fd_pool, fde);
  clib_rwlock_writer_unlock (&ldp->fd_table_lock);
}
