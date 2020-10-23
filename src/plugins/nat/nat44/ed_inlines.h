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

static_always_inline void
nat_6t_flow_to_ed_k (clib_bihash_kv_16_8_t * kv, nat_6t_flow_t * f)
{
  init_ed_k (kv, f->match.saddr, f->match.sport,
	     f->match.daddr, f->match.dport,
	     f->match.fib_index, f->match.proto);
}

static_always_inline void
nat_6t_flow_to_ed_kv (clib_bihash_kv_16_8_t * kv, nat_6t_flow_t * f,
		      u32 thread_idx, u32 session_idx)
{
  init_ed_kv (kv, f->match.saddr, f->match.sport,
	      f->match.daddr, f->match.dport,
	      f->match.fib_index, f->match.proto, thread_idx, session_idx);
}

static_always_inline int
nat_ed_ses_i2o_flow_hash_add_del (snat_main_t * sm, u32 thread_idx,
				  snat_session_t * s, int is_add)
{
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_idx);
  clib_bihash_kv_16_8_t kv;
  if (0 == is_add)
    {
      nat_6t_flow_to_ed_k (&kv, &s->i2o);
    }
  else
    {
      nat_6t_flow_to_ed_kv (&kv, &s->i2o, thread_idx, s - tsm->sessions);
    }
  if (is_add)
    clib_warning ("i2o flow hash add: %U", format_nat_6t_flow, &s->i2o);
  else
    clib_warning ("i2o flow hash del: %U", format_nat_6t_flow, &s->i2o);
  return clib_bihash_add_del_16_8 (&sm->flow_hash, &kv, is_add);
}

static_always_inline int
nat_ed_ses_o2i_flow_hash_add_del (snat_main_t * sm, u32 thread_idx,
				  snat_session_t * s, int is_add)
{
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_idx);
  clib_bihash_kv_16_8_t kv;
  if (0 == is_add)
    {
      nat_6t_flow_to_ed_k (&kv, &s->o2i);
    }
  else
    {
      nat_6t_flow_to_ed_kv (&kv, &s->o2i, thread_idx, s - tsm->sessions);
    }
  if (is_add)
    clib_warning ("o2i flow hash add: %U", format_nat_6t_flow, &s->o2i);
  else
    clib_warning ("o2i flow hash del: %U", format_nat_6t_flow, &s->o2i);
  return clib_bihash_add_del_16_8 (&sm->flow_hash, &kv, is_add);
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
  if (nat_ed_ses_i2o_flow_hash_add_del (sm, thread_index, ses, 0))
    nat_elog_warn ("flow hash del failed");
  if (nat_ed_ses_o2i_flow_hash_add_del (sm, thread_index, ses, 0))
    nat_elog_warn ("flow hash del failed");
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

// slow path
static_always_inline void
per_vrf_sessions_cleanup (u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions_t *per_vrf_sessions;
  u32 *to_free = 0, *i;

  vec_foreach (per_vrf_sessions, tsm->per_vrf_sessions_vec)
  {
    if (per_vrf_sessions->expired)
      {
	if (per_vrf_sessions->ses_count == 0)
	  {
	    vec_add1 (to_free, per_vrf_sessions - tsm->per_vrf_sessions_vec);
	  }
      }
  }

  if (vec_len (to_free))
    {
      vec_foreach (i, to_free)
      {
	vec_del1 (tsm->per_vrf_sessions_vec, *i);
      }
    }

  vec_free (to_free);
}

// slow path
static_always_inline void
per_vrf_sessions_register_session (snat_session_t * s, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions_t *per_vrf_sessions;

  per_vrf_sessions_cleanup (thread_index);

  // s->per_vrf_sessions_index == ~0 ... reuse of old session

  vec_foreach (per_vrf_sessions, tsm->per_vrf_sessions_vec)
  {
    // ignore already expired registrations
    if (per_vrf_sessions->expired)
      continue;

    if ((s->in2out.fib_index == per_vrf_sessions->rx_fib_index) &&
	(s->out2in.fib_index == per_vrf_sessions->tx_fib_index))
      {
	goto done;
      }
    if ((s->in2out.fib_index == per_vrf_sessions->tx_fib_index) &&
	(s->out2in.fib_index == per_vrf_sessions->rx_fib_index))
      {
	goto done;
      }
  }

  // create a new registration
  vec_add2 (tsm->per_vrf_sessions_vec, per_vrf_sessions, 1);
  clib_memset (per_vrf_sessions, 0, sizeof (*per_vrf_sessions));

  per_vrf_sessions->rx_fib_index = s->in2out.fib_index;
  per_vrf_sessions->tx_fib_index = s->out2in.fib_index;

done:
  s->per_vrf_sessions_index = per_vrf_sessions - tsm->per_vrf_sessions_vec;
  per_vrf_sessions->ses_count++;
}

// fast path
static_always_inline void
per_vrf_sessions_unregister_session (snat_session_t * s, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  per_vrf_sessions_t *per_vrf_sessions;

  ASSERT (s->per_vrf_sessions_index != ~0);

  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions = vec_elt_at_index (tsm->per_vrf_sessions_vec,
				       s->per_vrf_sessions_index);

  ASSERT (per_vrf_sessions->ses_count != 0);

  per_vrf_sessions->ses_count--;
  s->per_vrf_sessions_index = ~0;
}

// fast path
static_always_inline u8
per_vrf_sessions_is_expired (snat_session_t * s, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  per_vrf_sessions_t *per_vrf_sessions;

  ASSERT (s->per_vrf_sessions_index != ~0);

  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions = vec_elt_at_index (tsm->per_vrf_sessions_vec,
				       s->per_vrf_sessions_index);
  return per_vrf_sessions->expired;
}

static_always_inline void
nat_6t_flow_init (nat_6t_flow_t * f, u32 thread_idx,
		  ip4_address_t saddr, u16 sport, ip4_address_t daddr,
		  u16 dport, u32 fib_index, u8 proto, u32 session_idx)
{
  clib_memset (f, 0, sizeof (*f));
  f->match.saddr = saddr;
  f->match.sport = sport;
  f->match.daddr = daddr;
  f->match.dport = dport;
  f->match.proto = proto;
  f->match.fib_index = fib_index;
}

static_always_inline void
nat_6t_i2o_flow_init (snat_main_t * sm, u32 thread_idx, snat_session_t * s,
		      ip4_address_t saddr, u16 sport, ip4_address_t daddr,
		      u16 dport, u32 fib_index, u8 proto)
{
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_idx);
  nat_6t_flow_init (&s->i2o, thread_idx, saddr, sport, daddr, dport,
		    fib_index, proto, s - tsm->sessions);
}

static_always_inline void
nat_6t_o2i_flow_init (snat_main_t * sm, u32 thread_idx, snat_session_t * s,
		      ip4_address_t saddr, u16 sport, ip4_address_t daddr,
		      u16 dport, u32 fib_index, u8 proto)
{
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_idx);
  nat_6t_flow_init (&s->o2i, thread_idx, saddr, sport, daddr, dport,
		    fib_index, proto, s - tsm->sessions);
}

static_always_inline int
nat_6t_flow_match (nat_6t_flow_t * f, vlib_buffer_t * b, ip4_address_t saddr,
		   u16 sport, ip4_address_t daddr, u16 dport, u8 protocol,
		   u32 fib_index)
{
  return f->match.daddr.as_u32 == daddr.as_u32
    && f->match.dport == vnet_buffer (b)->ip.reass.l4_dst_port
    && f->match.proto == protocol && f->match.fib_index == fib_index
    && f->match.saddr.as_u32 == saddr.as_u32
    && f->match.sport == vnet_buffer (b)->ip.reass.l4_src_port;
}

#endif
