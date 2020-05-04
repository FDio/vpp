/*
 * simple nat plugin
 *
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

#ifndef __included_ed_inlines_h__
#define __included_ed_inlines_h__

#include <float.h>
#include <vppinfra/clib.h>
#include <nat/nat.h>
#include <nat/nat_inlines.h>

static_always_inline int
nat_ed_lru_insert (snat_main_per_thread_data_t * tsm,
		   snat_session_t * s, f64 now, u8 proto)
{
  dlist_elt_t *lru_list_elt;
  pool_get (tsm->lru_pool, lru_list_elt);
  s->lru_index = lru_list_elt - tsm->lru_pool;
  switch (proto)
    {
    case IP_PROTOCOL_UDP:
      s->lru_head_index = tsm->udp_lru_head_index;
      break;
    case IP_PROTOCOL_TCP:
      s->lru_head_index = tsm->tcp_trans_lru_head_index;
      break;
    case IP_PROTOCOL_ICMP:
      s->lru_head_index = tsm->icmp_lru_head_index;
      break;
    default:
      s->lru_head_index = tsm->unk_proto_lru_head_index;
      break;
    }
  clib_dlist_addtail (tsm->lru_pool, s->lru_head_index, s->lru_index);
  lru_list_elt->value = s - tsm->sessions;
  s->last_lru_update = now;
  return 1;
}

always_inline void
nat_ed_session_delete (snat_main_t * sm, snat_session_t * ses,
		       u32 thread_index, int lru_delete
		       /* delete from global LRU list */ )
{
  snat_main_per_thread_data_t *tsm = vec_elt_at_index (sm->per_thread_data,
						       thread_index);

  if (lru_delete)
    {
      clib_dlist_remove (tsm->lru_pool, ses->lru_index);
    }
  pool_put_index (tsm->lru_pool, ses->lru_index);
  pool_put (tsm->sessions, ses);
  vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			   pool_elts (tsm->sessions));

}

static_always_inline int
nat_lru_free_one_with_head (snat_main_t * sm, int thread_index,
			    f64 now, u32 head_index)
{
  snat_session_t *s = NULL;
  dlist_elt_t *oldest_elt;
  f64 sess_timeout_time;
  u32 oldest_index;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  oldest_index = clib_dlist_remove_head (tsm->lru_pool, head_index);
  if (~0 != oldest_index)
    {
      oldest_elt = pool_elt_at_index (tsm->lru_pool, oldest_index);
      s = pool_elt_at_index (tsm->sessions, oldest_elt->value);

      sess_timeout_time =
	s->last_heard + (f64) nat44_session_get_timeout (sm, s);
      if (now >= sess_timeout_time
	  || (s->tcp_closed_timestamp && now >= s->tcp_closed_timestamp))
	{
	  nat_free_session_data (sm, s, thread_index, 0);
	  nat_ed_session_delete (sm, s, thread_index, 0);
	  return 1;
	}
      else
	{
	  clib_dlist_addhead (tsm->lru_pool, head_index, oldest_index);
	}
    }
  return 0;
}

static_always_inline int
nat_lru_free_one (snat_main_t * sm, int thread_index, f64 now)
{
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  int rc = 0;
#define _(p)                                                       \
  if ((rc = nat_lru_free_one_with_head (sm, thread_index, now,     \
                                        tsm->p##_lru_head_index))) \
    {                                                              \
      return rc;                                                   \
    }
  _(tcp_trans);
  _(udp);
  _(unk_proto);
  _(icmp);
  _(tcp_estab);
#undef _
  return 0;
}

static_always_inline snat_session_t *
nat_ed_session_alloc (snat_main_t * sm, u32 thread_index, f64 now, u8 proto)
{
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  nat_lru_free_one (sm, thread_index, now);

  pool_get (tsm->sessions, s);
  clib_memset (s, 0, sizeof (*s));

  nat_ed_lru_insert (tsm, s, now, proto);

  s->ha_last_refreshed = now;
  vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			   pool_elts (tsm->sessions));
  return s;
}

#endif
