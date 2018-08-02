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

vcl_cut_through_registration_t *
vcl_ct_registration_lock_and_alloc (void)
{
  vcl_cut_through_registration_t *cr;
  pool_get (vcm->cut_through_registrations, cr);
  clib_spinlock_lock (&vcm->ct_registration_lock);
  memset (cr, 0, sizeof (*cr));
  cr->epoll_evt_conn_index = -1;
  return cr;
}

u32
vcl_ct_registration_index (vcl_cut_through_registration_t * ctr)
{
  return (ctr - vcm->cut_through_registrations);
}

void
vcl_ct_registration_unlock (void)
{
  clib_spinlock_unlock (&vcm->ct_registration_lock);
}

vcl_cut_through_registration_t *
vcl_ct_registration_get (u32 ctr_index)
{
  if (pool_is_free_index (vcm->cut_through_registrations, ctr_index))
    return 0;
  return pool_elt_at_index (vcm->cut_through_registrations, ctr_index);
}

vcl_cut_through_registration_t *
vcl_ct_registration_lock_and_lookup (uword mq_addr)
{
  uword *p;
  clib_spinlock_lock (&vcm->ct_registration_lock);
  p = hash_get (vcm->ct_registration_by_mq, mq_addr);
  if (!p)
    return 0;
  return vcl_ct_registration_get (p[0]);
}

void
vcl_ct_registration_lookup_add (uword mq_addr, u32 ctr_index)
{
  hash_set (vcm->ct_registration_by_mq, mq_addr, ctr_index);
}

void
vcl_ct_registration_lookup_del (uword mq_addr)
{
  hash_unset (vcm->ct_registration_by_mq, mq_addr);
}

void
vcl_ct_registration_del (vcl_cut_through_registration_t * ctr)
{
  pool_put (vcm->cut_through_registrations, ctr);
}

vcl_mq_evt_conn_t *
vcl_mq_evt_conn_alloc (void)
{
  vcl_mq_evt_conn_t *mqc;
  pool_get (vcm->mq_evt_conns, mqc);
  memset (mqc, 0, sizeof (*mqc));
  return mqc;
}

u32
vcl_mq_evt_conn_index (vcl_mq_evt_conn_t * mqc)
{
  return (mqc - vcm->mq_evt_conns);
}

vcl_mq_evt_conn_t *
vcl_mq_evt_conn_get (u32 mq_conn_idx)
{
  return pool_elt_at_index (vcm->mq_evt_conns, mq_conn_idx);
}

int
vcl_mq_epoll_add_evfd (svm_msg_q_t * mq)
{
  struct epoll_event e = { 0 };
  vcl_mq_evt_conn_t *mqc;
  u32 mqc_index;
  int mq_fd;

  mq_fd = svm_msg_q_get_consumer_eventfd (mq);

  if (vcm->mqs_epfd < 0 || mq_fd == -1)
    return -1;

  mqc = vcl_mq_evt_conn_alloc ();
  mqc_index = vcl_mq_evt_conn_index (mqc);
  mqc->mq_fd = mq_fd;
  mqc->mq = mq;

  e.events = EPOLLIN;
  e.data.u32 = mqc_index;
  if (epoll_ctl (vcm->mqs_epfd, EPOLL_CTL_ADD, mq_fd, &e) < 0)
    {
      clib_warning ("failed to add mq eventfd to mq epoll fd");
      return -1;
    }

  return mqc_index;
}

int
vcl_mq_epoll_del_evfd (u32 mqc_index)
{
  vcl_mq_evt_conn_t *mqc;

  if (vcm->mqs_epfd || mqc_index == ~0)
    return -1;

  mqc = vcl_mq_evt_conn_get (mqc_index);
  if (epoll_ctl (vcm->mqs_epfd, EPOLL_CTL_DEL, mqc->mq_fd, 0) < 0)
    {
      clib_warning ("failed to del mq eventfd to mq epoll fd");
      return -1;
    }
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
