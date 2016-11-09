/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/ip4_fib.h>
#include <snat/snat.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
} snat_out2in_trace_t;

/* packet trace format function */
static u8 * format_snat_out2in_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snat_out2in_trace_t * t = va_arg (*args, snat_out2in_trace_t *);
  
  s = format (s, "SNAT_OUT2IN: sw_if_index %d, next index %d, session index %d",
              t->sw_if_index, t->next_index, t->session_index);
  return s;
}

static u8 * format_snat_out2in_fast_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snat_out2in_trace_t * t = va_arg (*args, snat_out2in_trace_t *);
  
  s = format (s, "SNAT_OUT2IN_FAST: sw_if_index %d, next index %d",
              t->sw_if_index, t->next_index);
  return s;
}


vlib_node_registration_t snat_out2in_node;
vlib_node_registration_t snat_out2in_fast_node;

#define foreach_snat_out2in_error                       \
_(UNSUPPORTED_PROTOCOL, "Unsupported protocol")         \
_(OUT2IN_PACKETS, "Good out2in packets processed")      \
_(BAD_ICMP_TYPE, "icmp type not echo-reply")            \
_(NO_TRANSLATION, "No translation")
  
typedef enum {
#define _(sym,str) SNAT_OUT2IN_ERROR_##sym,
  foreach_snat_out2in_error
#undef _
  SNAT_OUT2IN_N_ERROR,
} snat_out2in_error_t;

static char * snat_out2in_error_strings[] = {
#define _(sym,string) string,
  foreach_snat_out2in_error
#undef _
};

typedef enum {
  SNAT_OUT2IN_NEXT_DROP,
  SNAT_OUT2IN_N_NEXT,
} snat_out2in_next_t;

/**
 * @brief Create session for static mapping.
 *
 * Create NAT session initiated by host from external network with static
 * mapping.
 *
 * @param sm     SNAT main.
 * @param b0     Vlib buffer.
 * @param in2out In2out SNAT session key.
 * @param out2in Out2in SNAT session key.
 * @param node   Vlib node.
 *
 * @returns SNAT session if successfully created otherwise 0.
 */
static inline snat_session_t *
create_session_for_static_mapping (snat_main_t *sm,
                                   vlib_buffer_t *b0,
                                   snat_session_key_t in2out,
                                   snat_session_key_t out2in,
                                   vlib_node_runtime_t * node)
{
  snat_user_t *u;
  snat_user_key_t user_key;
  snat_session_t *s;
  clib_bihash_kv_8_8_t kv0, value0;
  dlist_elt_t * per_user_translation_list_elt;
  dlist_elt_t * per_user_list_head_elt;

  user_key.addr = in2out.addr;
  user_key.fib_index = in2out.fib_index;
  kv0.key = user_key.as_u64;

  /* Ever heard of the "user" = inside ip4 address before? */
  if (clib_bihash_search_8_8 (&sm->user_hash, &kv0, &value0))
    {
      /* no, make a new one */
      pool_get (sm->users, u);
      memset (u, 0, sizeof (*u));
      u->addr = in2out.addr;

      pool_get (sm->list_pool, per_user_list_head_elt);

      u->sessions_per_user_list_head_index = per_user_list_head_elt -
        sm->list_pool;

      clib_dlist_init (sm->list_pool, u->sessions_per_user_list_head_index);

      kv0.value = u - sm->users;

      /* add user */
      clib_bihash_add_del_8_8 (&sm->user_hash, &kv0, 1 /* is_add */);
    }
  else
    {
      u = pool_elt_at_index (sm->users, value0.value);
    }

  pool_get (sm->sessions, s);
  memset (s, 0, sizeof (*s));

  s->outside_address_index = ~0;
  s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
  u->nstaticsessions++;

  /* Create list elts */
  pool_get (sm->list_pool, per_user_translation_list_elt);
  clib_dlist_init (sm->list_pool, per_user_translation_list_elt -
                   sm->list_pool);

  per_user_translation_list_elt->value = s - sm->sessions;
  s->per_user_index = per_user_translation_list_elt - sm->list_pool;
  s->per_user_list_head_index = u->sessions_per_user_list_head_index;

  clib_dlist_addtail (sm->list_pool, s->per_user_list_head_index,
                      per_user_translation_list_elt - sm->list_pool);

  s->in2out = in2out;
  s->out2in = out2in;
  s->in2out.protocol = out2in.protocol;

  /* Add to translation hashes */
  kv0.key = s->in2out.as_u64;
  kv0.value = s - sm->sessions;
  if (clib_bihash_add_del_8_8 (&sm->in2out, &kv0, 1 /* is_add */))
      clib_warning ("in2out key add failed");

  kv0.key = s->out2in.as_u64;
  kv0.value = s - sm->sessions;

  if (clib_bihash_add_del_8_8 (&sm->out2in, &kv0, 1 /* is_add */))
      clib_warning ("out2in key add failed");

  return s;
}

static inline u32 icmp_out2in_slow_path (snat_main_t *sm,
                                         vlib_buffer_t * b0,
                                         ip4_header_t * ip0,
                                         icmp46_header_t * icmp0,
                                         u32 sw_if_index0,
                                         u32 rx_fib_index0,
                                         vlib_node_runtime_t * node,
                                         u32 next0, f64 now)
{
  snat_session_key_t key0, sm0;
  icmp_echo_header_t *echo0;
  clib_bihash_kv_8_8_t kv0, value0;
  snat_session_t * s0;
  u32 new_addr0, old_addr0;
  u16 old_id0, new_id0;
  ip_csum_t sum0;
  snat_runtime_t * rt = (snat_runtime_t *)node->runtime_data;

  echo0 = (icmp_echo_header_t *)(icmp0+1);

  key0.addr = ip0->dst_address;
  key0.port = echo0->identifier;
  key0.protocol = SNAT_PROTOCOL_ICMP;
  key0.fib_index = rx_fib_index0;
  
  kv0.key = key0.as_u64;
  
  if (clib_bihash_search_8_8 (&sm->out2in, &kv0, &value0))
    {
      /* Try to match static mapping by external address and port,
         destination address and port in packet */
      if (snat_static_mapping_match(sm, key0, &sm0, 1))
        {
           ip4_address_t * first_int_addr;

          if (PREDICT_FALSE(rt->cached_sw_if_index != sw_if_index0))
            {
              first_int_addr = 
                ip4_interface_first_address (sm->ip4_main, sw_if_index0,
                                             0 /* just want the address */);
              rt->cached_sw_if_index = sw_if_index0;
              rt->cached_ip4_address = first_int_addr->as_u32;
            }
          
          /* Don't NAT packet aimed at the intfc address */
          if (PREDICT_FALSE(ip0->dst_address.as_u32 ==
                            rt->cached_ip4_address))
            return next0;

          b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
          return SNAT_OUT2IN_NEXT_DROP;
        }

      /* Create session initiated by host from external network */
      s0 = create_session_for_static_mapping(sm, b0, sm0, key0,
                                             node);
      if (!s0)
        return SNAT_OUT2IN_NEXT_DROP;
    }
  else
    s0 = pool_elt_at_index (sm->sessions, value0.value);

  old_addr0 = ip0->dst_address.as_u32;
  ip0->dst_address = s0->in2out.addr;
  new_addr0 = ip0->dst_address.as_u32;
  vnet_buffer(b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;
  
  sum0 = ip0->checksum;
  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                         ip4_header_t,
                         dst_address /* changed member */);
  ip0->checksum = ip_csum_fold (sum0);
  
  old_id0 = echo0->identifier;
  new_id0 = s0->in2out.port;
  echo0->identifier = new_id0;

  sum0 = icmp0->checksum;
  sum0 = ip_csum_update (sum0, old_id0, new_id0, icmp_echo_header_t,
                         identifier);
  icmp0->checksum = ip_csum_fold (sum0);

  /* Accounting */
  s0->last_heard = now;
  s0->total_pkts++;
  s0->total_bytes += vlib_buffer_length_in_chain (sm->vlib_main, b0);
  /* Per-user LRU list maintenance for dynamic translation */
  if (!snat_is_session_static (s0))
    {
      clib_dlist_remove (sm->list_pool, s0->per_user_index);
      clib_dlist_addtail (sm->list_pool, s0->per_user_list_head_index,
                          s0->per_user_index);
    }

  return next0;
}

static uword
snat_out2in_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  snat_out2in_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t * sm = &snat_main;
  f64 now = vlib_time_now (vm);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          u32 next0 = SNAT_OUT2IN_NEXT_DROP;
          u32 next1 = SNAT_OUT2IN_NEXT_DROP;
          u32 sw_if_index0, sw_if_index1;
          ip4_header_t * ip0, *ip1;
          ip_csum_t sum0, sum1;
          u32 new_addr0, old_addr0;
          u16 new_port0, old_port0;
          u32 new_addr1, old_addr1;
          u16 new_port1, old_port1;
          udp_header_t * udp0, * udp1;
          tcp_header_t * tcp0, * tcp1;
          icmp46_header_t * icmp0, * icmp1;
          snat_session_key_t key0, key1, sm0, sm1;
          u32 rx_fib_index0, rx_fib_index1;
          u32 proto0, proto1;
          snat_session_t * s0 = 0, * s1 = 0;
          clib_bihash_kv_8_8_t kv0, kv1, value0, value1;
          
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;
            
	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
            
	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

          /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
            
          ip0 = vlib_buffer_get_current (b0);
          udp0 = ip4_next_header (ip0);
          tcp0 = (tcp_header_t *) udp0;
          icmp0 = (icmp46_header_t *) udp0;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 = vec_elt (sm->ip4_main->fib_index_by_sw_if_index, 
                                   sw_if_index0);

	  vnet_feature_next (sw_if_index0, &next0, b0);
          proto0 = ~0;
          proto0 = (ip0->protocol == IP_PROTOCOL_UDP) 
            ? SNAT_PROTOCOL_UDP : proto0;
          proto0 = (ip0->protocol == IP_PROTOCOL_TCP) 
            ? SNAT_PROTOCOL_TCP : proto0;
          proto0 = (ip0->protocol == IP_PROTOCOL_ICMP) 
            ? SNAT_PROTOCOL_ICMP : proto0;

          if (PREDICT_FALSE (proto0 == ~0))
              goto trace0;

          if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
            {
              next0 = icmp_out2in_slow_path 
                (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node, 
                 next0, now);
              goto trace0;
            }

          key0.addr = ip0->dst_address;
          key0.port = udp0->dst_port;
          key0.protocol = proto0;
          key0.fib_index = rx_fib_index0;
          
          kv0.key = key0.as_u64;

          if (clib_bihash_search_8_8 (&sm->out2in, &kv0, &value0))
            {
              /* Try to match static mapping by external address and port,
                 destination address and port in packet */
              if (snat_static_mapping_match(sm, key0, &sm0, 1))
                {
                  b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
                  goto trace0;
                }

              /* Create session initiated by host from external network */
              s0 = create_session_for_static_mapping(sm, b0, sm0, key0, node);
              if (!s0)
                goto trace0;
            }
          else
            s0 = pool_elt_at_index (sm->sessions, value0.value);

          old_addr0 = ip0->dst_address.as_u32;
          ip0->dst_address = s0->in2out.addr;
          new_addr0 = ip0->dst_address.as_u32;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;

          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                                 ip4_header_t,
                                 dst_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              old_port0 = tcp0->ports.dst;
              tcp0->ports.dst = s0->in2out.port;
              new_port0 = tcp0->ports.dst;

              sum0 = tcp0->checksum;
              sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                                     ip4_header_t,
                                     dst_address /* changed member */);

              sum0 = ip_csum_update (sum0, old_port0, new_port0,
                                     ip4_header_t /* cheat */,
                                     length /* changed member */);
              tcp0->checksum = ip_csum_fold(sum0);
            }
          else
            {
              old_port0 = udp0->dst_port;
              udp0->dst_port = s0->in2out.port;
              udp0->checksum = 0;
            }

          /* Accounting */
          s0->last_heard = now;
          s0->total_pkts++;
          s0->total_bytes += vlib_buffer_length_in_chain (vm, b0);
          /* Per-user LRU list maintenance for dynamic translation */
          if (!snat_is_session_static (s0))
            {
              clib_dlist_remove (sm->list_pool, s0->per_user_index);
              clib_dlist_addtail (sm->list_pool, s0->per_user_list_head_index,
                                  s0->per_user_index);
            }
        trace0:

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              snat_out2in_trace_t *t = 
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
              t->session_index = ~0;
              if (s0)
                  t->session_index = s0 - sm->sessions;
            }

          pkts_processed += next0 != SNAT_OUT2IN_NEXT_DROP;


          ip1 = vlib_buffer_get_current (b1);
          udp1 = ip4_next_header (ip1);
          tcp1 = (tcp_header_t *) udp1;
          icmp1 = (icmp46_header_t *) udp1;

          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
	  rx_fib_index1 = vec_elt (sm->ip4_main->fib_index_by_sw_if_index, 
                                   sw_if_index1);

	  vnet_feature_next (sw_if_index1, &next1, b1);

          proto1 = ~0;
          proto1 = (ip1->protocol == IP_PROTOCOL_UDP) 
            ? SNAT_PROTOCOL_UDP : proto1;
          proto1 = (ip1->protocol == IP_PROTOCOL_TCP) 
            ? SNAT_PROTOCOL_TCP : proto1;
          proto1 = (ip1->protocol == IP_PROTOCOL_ICMP) 
            ? SNAT_PROTOCOL_ICMP : proto1;

          if (PREDICT_FALSE (proto1 == ~0))
              goto trace1;

          if (PREDICT_FALSE (proto1 == SNAT_PROTOCOL_ICMP))
            {
              next1 = icmp_out2in_slow_path 
                (sm, b1, ip1, icmp1, sw_if_index1, rx_fib_index1, node, 
                 next1, now);
              goto trace1;
            }

          key1.addr = ip1->dst_address;
          key1.port = udp1->dst_port;
          key1.protocol = proto1;
          key1.fib_index = rx_fib_index1;
          
          kv1.key = key1.as_u64;

          if (clib_bihash_search_8_8 (&sm->out2in, &kv1, &value1))
            {
              /* Try to match static mapping by external address and port,
                 destination address and port in packet */
              if (snat_static_mapping_match(sm, key1, &sm1, 1))
                {
                  b1->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
                  goto trace1;
                }

              /* Create session initiated by host from external network */
              s1 = create_session_for_static_mapping(sm, b1, sm1, key1, node);
              if (!s1)
                goto trace1;
            }
          else
            s1 = pool_elt_at_index (sm->sessions, value1.value);

          old_addr1 = ip1->dst_address.as_u32;
          ip1->dst_address = s1->in2out.addr;
          new_addr1 = ip1->dst_address.as_u32;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = s1->in2out.fib_index;

          sum1 = ip1->checksum;
          sum1 = ip_csum_update (sum1, old_addr1, new_addr1,
                                 ip4_header_t,
                                 dst_address /* changed member */);
          ip1->checksum = ip_csum_fold (sum1);

          if (PREDICT_TRUE(proto1 == SNAT_PROTOCOL_TCP))
            {
              old_port1 = tcp1->ports.dst;
              tcp1->ports.dst = s1->in2out.port;
              new_port1 = tcp1->ports.dst;

              sum1 = tcp1->checksum;
              sum1 = ip_csum_update (sum1, old_addr1, new_addr1,
                                     ip4_header_t,
                                     dst_address /* changed member */);

              sum1 = ip_csum_update (sum1, old_port1, new_port1,
                                     ip4_header_t /* cheat */,
                                     length /* changed member */);
              tcp1->checksum = ip_csum_fold(sum1);
            }
          else
            {
              old_port1 = udp1->dst_port;
              udp1->dst_port = s1->in2out.port;
              udp1->checksum = 0;
            }

          /* Accounting */
          s1->last_heard = now;
          s1->total_pkts++;
          s1->total_bytes += vlib_buffer_length_in_chain (vm, b1);
          /* Per-user LRU list maintenance for dynamic translation */
          if (!snat_is_session_static (s1))
            {
              clib_dlist_remove (sm->list_pool, s1->per_user_index);
              clib_dlist_addtail (sm->list_pool, s1->per_user_list_head_index,
                                  s1->per_user_index);
            }
        trace1:

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b1->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              snat_out2in_trace_t *t = 
                 vlib_add_trace (vm, node, b1, sizeof (*t));
              t->sw_if_index = sw_if_index1;
              t->next_index = next1;
              t->session_index = ~0;
              if (s1)
                  t->session_index = s1 - sm->sessions;
            }

          pkts_processed += next0 != SNAT_OUT2IN_NEXT_DROP;
          pkts_processed += next1 != SNAT_OUT2IN_NEXT_DROP;

          /* verify speculative enqueues, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0 = SNAT_OUT2IN_NEXT_DROP;
          u32 sw_if_index0;
          ip4_header_t * ip0;
          ip_csum_t sum0;
          u32 new_addr0, old_addr0;
          u16 new_port0, old_port0;
          udp_header_t * udp0;
          tcp_header_t * tcp0;
          icmp46_header_t * icmp0;
          snat_session_key_t key0, sm0;
          u32 rx_fib_index0;
          u32 proto0;
          snat_session_t * s0 = 0;
          clib_bihash_kv_8_8_t kv0, value0;
          
          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          ip0 = vlib_buffer_get_current (b0);
          udp0 = ip4_next_header (ip0);
          tcp0 = (tcp_header_t *) udp0;
          icmp0 = (icmp46_header_t *) udp0;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 = vec_elt (sm->ip4_main->fib_index_by_sw_if_index, 
                                   sw_if_index0);

	  vnet_feature_next (sw_if_index0, &next0, b0);

          proto0 = ~0;
          proto0 = (ip0->protocol == IP_PROTOCOL_UDP) 
            ? SNAT_PROTOCOL_UDP : proto0;
          proto0 = (ip0->protocol == IP_PROTOCOL_TCP) 
            ? SNAT_PROTOCOL_TCP : proto0;
          proto0 = (ip0->protocol == IP_PROTOCOL_ICMP) 
            ? SNAT_PROTOCOL_ICMP : proto0;

          if (PREDICT_FALSE (proto0 == ~0))
              goto trace00;

          if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
            {
              next0 = icmp_out2in_slow_path 
                (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node, 
                 next0, now);
              goto trace00;
            }

          key0.addr = ip0->dst_address;
          key0.port = udp0->dst_port;
          key0.protocol = proto0;
          key0.fib_index = rx_fib_index0;
          
          kv0.key = key0.as_u64;

          if (clib_bihash_search_8_8 (&sm->out2in, &kv0, &value0))
            {
              /* Try to match static mapping by external address and port,
                 destination address and port in packet */
              if (snat_static_mapping_match(sm, key0, &sm0, 1))
                {
                  b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
                  goto trace00;
                }

              /* Create session initiated by host from external network */
              s0 = create_session_for_static_mapping(sm, b0, sm0, key0, node);
              if (!s0)
                goto trace00;
            }
          else
            s0 = pool_elt_at_index (sm->sessions, value0.value);

          old_addr0 = ip0->dst_address.as_u32;
          ip0->dst_address = s0->in2out.addr;
          new_addr0 = ip0->dst_address.as_u32;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;

          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                                 ip4_header_t,
                                 dst_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              old_port0 = tcp0->ports.dst;
              tcp0->ports.dst = s0->in2out.port;
              new_port0 = tcp0->ports.dst;

              sum0 = tcp0->checksum;
              sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                                     ip4_header_t,
                                     dst_address /* changed member */);

              sum0 = ip_csum_update (sum0, old_port0, new_port0,
                                     ip4_header_t /* cheat */,
                                     length /* changed member */);
              tcp0->checksum = ip_csum_fold(sum0);
            }
          else
            {
              old_port0 = udp0->dst_port;
              udp0->dst_port = s0->in2out.port;
              udp0->checksum = 0;
            }

          /* Accounting */
          s0->last_heard = now;
          s0->total_pkts++;
          s0->total_bytes += vlib_buffer_length_in_chain (vm, b0);
          /* Per-user LRU list maintenance for dynamic translation */
          if (!snat_is_session_static (s0))
            {
              clib_dlist_remove (sm->list_pool, s0->per_user_index);
              clib_dlist_addtail (sm->list_pool, s0->per_user_list_head_index,
                                  s0->per_user_index);
            }
        trace00:

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              snat_out2in_trace_t *t = 
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
              t->session_index = ~0;
              if (s0)
                  t->session_index = s0 - sm->sessions;
            }

          pkts_processed += next0 != SNAT_OUT2IN_NEXT_DROP;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, snat_out2in_node.index, 
                               SNAT_OUT2IN_ERROR_OUT2IN_PACKETS, 
                               pkts_processed);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (snat_out2in_node) = {
  .function = snat_out2in_node_fn,
  .name = "snat-out2in",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_out2in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(snat_out2in_error_strings),
  .error_strings = snat_out2in_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),
  
  .n_next_nodes = SNAT_OUT2IN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_OUT2IN_NEXT_DROP] = "error-drop",
  },
};
VLIB_NODE_FUNCTION_MULTIARCH (snat_out2in_node, snat_out2in_node_fn);

static inline u32 icmp_out2in_fast (snat_main_t *sm,
                                    vlib_buffer_t * b0,
                                    ip4_header_t * ip0,
                                    icmp46_header_t * icmp0,
                                    u32 sw_if_index0,
                                    vlib_node_runtime_t * node,
                                    u32 next0,
                                    u32 rx_fib_index0)
{
  snat_session_key_t key0, sm0;
  icmp_echo_header_t *echo0;
  u32 new_addr0, old_addr0;
  u16 old_id0, new_id0;
  ip_csum_t sum0;
  snat_runtime_t * rt = (snat_runtime_t *)node->runtime_data;

  echo0 = (icmp_echo_header_t *)(icmp0+1);

  key0.addr = ip0->dst_address;
  key0.port = echo0->identifier;
  key0.fib_index = rx_fib_index0;

  if (snat_static_mapping_match(sm, key0, &sm0, 1))
    {
      ip4_address_t * first_int_addr;

      if (PREDICT_FALSE(rt->cached_sw_if_index != sw_if_index0))
        {
          first_int_addr =
            ip4_interface_first_address (sm->ip4_main, sw_if_index0,
                                         0 /* just want the address */);
          rt->cached_sw_if_index = sw_if_index0;
          rt->cached_ip4_address = first_int_addr->as_u32;
        }

      /* Don't NAT packet aimed at the intfc address */
      if (PREDICT_FALSE(ip0->dst_address.as_u32 ==
                        rt->cached_ip4_address))
        return next0;

      b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
      return SNAT_OUT2IN_NEXT_DROP;
    }

  new_addr0 = sm0.addr.as_u32;
  new_id0 = sm0.port;
  vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm0.fib_index;

  old_addr0 = ip0->dst_address.as_u32;
  ip0->dst_address.as_u32 = new_addr0;

  sum0 = ip0->checksum;
  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                         ip4_header_t,
                         dst_address /* changed member */);
  ip0->checksum = ip_csum_fold (sum0);

  if (PREDICT_FALSE(new_id0 != echo0->identifier))
    {
      old_id0 = echo0->identifier;
      echo0->identifier = new_id0;

      sum0 = icmp0->checksum;
      sum0 = ip_csum_update (sum0, old_id0, new_id0, icmp_echo_header_t,
                             identifier);
      icmp0->checksum = ip_csum_fold (sum0);
    }

  return next0;
}

static uword
snat_out2in_fast_node_fn (vlib_main_t * vm,
	        	  vlib_node_runtime_t * node,
		          vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  snat_out2in_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t * sm = &snat_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0 = SNAT_OUT2IN_NEXT_DROP;
          u32 sw_if_index0;
          ip4_header_t * ip0;
          ip_csum_t sum0;
          u32 new_addr0, old_addr0;
          u16 new_port0, old_port0;
          udp_header_t * udp0;
          tcp_header_t * tcp0;
          icmp46_header_t * icmp0;
          snat_session_key_t key0, sm0;
          u32 proto0;
          u32 rx_fib_index0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          ip0 = vlib_buffer_get_current (b0);
          udp0 = ip4_next_header (ip0);
          tcp0 = (tcp_header_t *) udp0;
          icmp0 = (icmp46_header_t *) udp0;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index0);

	  vnet_feature_next (sw_if_index0, &next0, b0);

          proto0 = ~0;
          proto0 = (ip0->protocol == IP_PROTOCOL_UDP)
            ? SNAT_PROTOCOL_UDP : proto0;
          proto0 = (ip0->protocol == IP_PROTOCOL_TCP)
            ? SNAT_PROTOCOL_TCP : proto0;
          proto0 = (ip0->protocol == IP_PROTOCOL_ICMP)
            ? SNAT_PROTOCOL_ICMP : proto0;

          if (PREDICT_FALSE (proto0 == ~0))
              goto trace00;

          if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
            {
              next0 = icmp_out2in_fast
                (sm, b0, ip0, icmp0, sw_if_index0, node, next0, rx_fib_index0);
              goto trace00;
            }

          key0.addr = ip0->dst_address;
          key0.port = udp0->dst_port;
          key0.fib_index = rx_fib_index0;

          if (snat_static_mapping_match(sm, key0, &sm0, 1))
            {
              b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
              goto trace00;
            }

          new_addr0 = sm0.addr.as_u32;
          new_port0 = sm0.port;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm0.fib_index;
          old_addr0 = ip0->dst_address.as_u32;
          ip0->dst_address.as_u32 = new_addr0;

          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                                 ip4_header_t,
                                 dst_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_FALSE(new_port0 != udp0->dst_port))
            {
               if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
                {
                  old_port0 = tcp0->ports.dst;
                  tcp0->ports.dst = new_port0;

                  sum0 = tcp0->checksum;
                  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                                         ip4_header_t,
                                         dst_address /* changed member */);

                  sum0 = ip_csum_update (sum0, old_port0, new_port0,
                                         ip4_header_t /* cheat */,
                                         length /* changed member */);
                  tcp0->checksum = ip_csum_fold(sum0);
                }
              else
                {
                  old_port0 = udp0->dst_port;
                  udp0->dst_port = new_port0;
                  udp0->checksum = 0;
                }
            }
          else
            {
              if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
                {
                  sum0 = tcp0->checksum;
                  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                                         ip4_header_t,
                                         dst_address /* changed member */);

                  tcp0->checksum = ip_csum_fold(sum0);
                }
            }

        trace00:

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_out2in_trace_t *t =
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
            }

          pkts_processed += next0 != SNAT_OUT2IN_NEXT_DROP;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, snat_out2in_fast_node.index,
                               SNAT_OUT2IN_ERROR_OUT2IN_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (snat_out2in_fast_node) = {
  .function = snat_out2in_fast_node_fn,
  .name = "snat-out2in-fast",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_out2in_fast_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(snat_out2in_error_strings),
  .error_strings = snat_out2in_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),
  
  .n_next_nodes = SNAT_OUT2IN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_OUT2IN_NEXT_DROP] = "error-drop",
  },
};
VLIB_NODE_FUNCTION_MULTIARCH (snat_out2in_fast_node, snat_out2in_fast_node_fn);
