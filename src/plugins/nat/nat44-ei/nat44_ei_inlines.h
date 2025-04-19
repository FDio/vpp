/*
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

#ifndef __included_nat44_ei_inlines_h__
#define __included_nat44_ei_inlines_h__

#include <vppinfra/clib.h>

#include <nat/nat44-ei/nat44_ei.h>
#include <nat/nat44-ei/nat44_ei_ha.h>
#include <nat/lib/nat_proto.h>

always_inline u64
calc_nat_key (ip4_address_t addr, u16 port, u32 fib_index, u8 proto)
{
  ASSERT (fib_index <= (1 << 14) - 1);
  ASSERT (proto <= (1 << 3) - 1);
  return (u64) addr.as_u32 << 32 | (u64) port << 16 | fib_index << 3 |
	 (proto & 0x7);
}

always_inline void
split_nat_key (u64 key, ip4_address_t *addr, u16 *port, u32 *fib_index,
	       nat_protocol_t *proto)
{
  if (addr)
    {
      addr->as_u32 = key >> 32;
    }
  if (port)
    {
      *port = (key >> 16) & (u16) ~0;
    }
  if (fib_index)
    {
      *fib_index = key >> 3 & ((1 << 13) - 1);
    }
  if (proto)
    {
      *proto = key & 0x7;
    }
}

always_inline void
init_nat_k (clib_bihash_kv_8_8_t *kv, ip4_address_t addr, u16 port,
	    u32 fib_index, nat_protocol_t proto)
{
  kv->key = calc_nat_key (addr, port, fib_index, proto);
  kv->value = ~0ULL;
}

always_inline void
init_nat_kv (clib_bihash_kv_8_8_t *kv, ip4_address_t addr, u16 port,
	     u32 fib_index, nat_protocol_t proto,
	     clib_thread_index_t thread_index, u32 session_index)
{
  init_nat_k (kv, addr, port, fib_index, proto);
  kv->value = (u64) thread_index << 32 | session_index;
}

always_inline void
init_nat_i2o_k (clib_bihash_kv_8_8_t *kv, nat44_ei_session_t *s)
{
  return init_nat_k (kv, s->in2out.addr, s->in2out.port, s->in2out.fib_index,
		     s->nat_proto);
}

always_inline void
init_nat_i2o_kv (clib_bihash_kv_8_8_t *kv, nat44_ei_session_t *s,
		 clib_thread_index_t thread_index, u32 session_index)
{
  init_nat_k (kv, s->in2out.addr, s->in2out.port, s->in2out.fib_index,
	      s->nat_proto);
  kv->value = (u64) thread_index << 32 | session_index;
}

always_inline void
init_nat_o2i_k (clib_bihash_kv_8_8_t *kv, nat44_ei_session_t *s)
{
  return init_nat_k (kv, s->out2in.addr, s->out2in.port, s->out2in.fib_index,
		     s->nat_proto);
}

always_inline void
init_nat_o2i_kv (clib_bihash_kv_8_8_t *kv, nat44_ei_session_t *s,
		 clib_thread_index_t thread_index, u32 session_index)
{
  init_nat_k (kv, s->out2in.addr, s->out2in.port, s->out2in.fib_index,
	      s->nat_proto);
  kv->value = (u64) thread_index << 32 | session_index;
}

always_inline u32
nat_value_get_thread_index (clib_bihash_kv_8_8_t *value)
{
  return value->value >> 32;
}

always_inline u32
nat_value_get_session_index (clib_bihash_kv_8_8_t *value)
{
  return value->value & ~(u32) 0;
}

always_inline u8
nat44_ei_is_interface_addr (ip4_main_t *im, vlib_node_runtime_t *node,
			    u32 sw_if_index0, u32 ip4_addr)
{
  nat44_ei_runtime_t *rt = (nat44_ei_runtime_t *) node->runtime_data;
  u8 ip4_addr_exists;

  if (PREDICT_FALSE (rt->cached_sw_if_index != sw_if_index0))
    {
      ip_lookup_main_t *lm = &im->lookup_main;
      ip_interface_address_t *ia;
      ip4_address_t *a;

      rt->cached_sw_if_index = ~0;
      hash_free (rt->cached_presence_by_ip4_address);

      foreach_ip_interface_address (
	lm, ia, sw_if_index0, 1 /* honor unnumbered */, ({
	  a = ip_interface_address_get_address (lm, ia);
	  hash_set (rt->cached_presence_by_ip4_address, a->as_u32, 1);
	  rt->cached_sw_if_index = sw_if_index0;
	}));

      if (rt->cached_sw_if_index == ~0)
	return 0;
    }

  ip4_addr_exists = !!hash_get (rt->cached_presence_by_ip4_address, ip4_addr);
  if (PREDICT_FALSE (ip4_addr_exists))
    return 1;
  else
    return 0;
}

/** \brief Per-user LRU list maintenance */
always_inline void
nat44_ei_session_update_lru (nat44_ei_main_t *nm, nat44_ei_session_t *s,
			     clib_thread_index_t thread_index)
{
  /* don't update too often - timeout is in magnitude of seconds anyway */
  if (s->last_heard > s->last_lru_update + 1)
    {
      clib_dlist_remove (nm->per_thread_data[thread_index].list_pool,
			 s->per_user_index);
      clib_dlist_addtail (nm->per_thread_data[thread_index].list_pool,
			  s->per_user_list_head_index, s->per_user_index);
      s->last_lru_update = s->last_heard;
    }
}

always_inline void
nat44_ei_user_session_increment (nat44_ei_main_t *nm, nat44_ei_user_t *u,
				 u8 is_static)
{
  if (u->nsessions + u->nstaticsessions < nm->max_translations_per_user)
    {
      if (is_static)
	u->nstaticsessions++;
      else
	u->nsessions++;
    }
}

always_inline void
nat44_ei_delete_user_with_no_session (nat44_ei_main_t *nm, nat44_ei_user_t *u,
				      clib_thread_index_t thread_index)
{
  clib_bihash_kv_8_8_t kv;
  nat44_ei_user_key_t u_key;
  nat44_ei_main_per_thread_data_t *tnm =
    vec_elt_at_index (nm->per_thread_data, thread_index);

  if (u->nstaticsessions == 0 && u->nsessions == 0)
    {
      u_key.addr.as_u32 = u->addr.as_u32;
      u_key.fib_index = u->fib_index;
      kv.key = u_key.as_u64;
      pool_put_index (tnm->list_pool, u->sessions_per_user_list_head_index);
      pool_put (tnm->users, u);
      clib_bihash_add_del_8_8 (&tnm->user_hash, &kv, 0);
      vlib_set_simple_counter (&nm->total_users, thread_index, 0,
			       pool_elts (tnm->users));
    }
}

static_always_inline u8
nat44_ei_maximum_sessions_exceeded (nat44_ei_main_t *nm,
				    clib_thread_index_t thread_index)
{
  if (pool_elts (nm->per_thread_data[thread_index].sessions) >=
      nm->max_translations_per_thread)
    return 1;
  return 0;
}

always_inline void
nat44_ei_session_update_counters (nat44_ei_session_t *s, f64 now, uword bytes,
				  clib_thread_index_t thread_index)
{
  s->last_heard = now;
  s->total_pkts++;
  s->total_bytes += bytes;
  nat_ha_sref (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
	       s->ext_host_port, s->nat_proto, s->out2in.fib_index,
	       s->total_pkts, s->total_bytes, thread_index,
	       &s->ha_last_refreshed, now);
}

static_always_inline u32
nat_session_get_timeout (nat_timeouts_t *timeouts, nat_protocol_t proto,
			 u8 state)
{
  switch (proto)
    {
    case NAT_PROTOCOL_ICMP:
      return timeouts->icmp;
    case NAT_PROTOCOL_UDP:
      return timeouts->udp;
    case NAT_PROTOCOL_TCP:
      {
	if (state)
	  return timeouts->tcp.transitory;
	else
	  return timeouts->tcp.established;
      }
    default:
      return timeouts->udp;
    }
  return 0;
}

#endif /* __included_nat44_ei_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
