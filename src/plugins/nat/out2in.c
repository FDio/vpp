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
#include <vnet/handoff.h>

#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/ip4_fib.h>
#include <nat/nat.h>
#include <nat/nat_ipfix_logging.h>
#include <nat/nat_det.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
} snat_out2in_trace_t;

typedef struct {
  u32 next_worker_index;
  u8 do_handoff;
} snat_out2in_worker_handoff_trace_t;

/* packet trace format function */
static u8 * format_snat_out2in_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snat_out2in_trace_t * t = va_arg (*args, snat_out2in_trace_t *);

  s = format (s, "NAT44_OUT2IN: sw_if_index %d, next index %d, session index %d",
              t->sw_if_index, t->next_index, t->session_index);
  return s;
}

static u8 * format_snat_out2in_fast_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snat_out2in_trace_t * t = va_arg (*args, snat_out2in_trace_t *);

  s = format (s, "NAT44_OUT2IN_FAST: sw_if_index %d, next index %d",
              t->sw_if_index, t->next_index);
  return s;
}

static u8 * format_snat_out2in_worker_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snat_out2in_worker_handoff_trace_t * t =
    va_arg (*args, snat_out2in_worker_handoff_trace_t *);
  char * m;

  m = t->do_handoff ? "next worker" : "same worker";
  s = format (s, "NAT44_OUT2IN_WORKER_HANDOFF: %s %d", m, t->next_worker_index);

  return s;
}

vlib_node_registration_t snat_out2in_node;
vlib_node_registration_t snat_out2in_fast_node;
vlib_node_registration_t snat_out2in_worker_handoff_node;
vlib_node_registration_t snat_det_out2in_node;

#define foreach_snat_out2in_error                       \
_(UNSUPPORTED_PROTOCOL, "Unsupported protocol")         \
_(OUT2IN_PACKETS, "Good out2in packets processed")      \
_(BAD_ICMP_TYPE, "unsupported ICMP type")               \
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
  SNAT_OUT2IN_NEXT_LOOKUP,
  SNAT_OUT2IN_NEXT_ICMP_ERROR,
  SNAT_OUT2IN_N_NEXT,
} snat_out2in_next_t;

/**
 * @brief Create session for static mapping.
 *
 * Create NAT session initiated by host from external network with static
 * mapping.
 *
 * @param sm     NAT main.
 * @param b0     Vlib buffer.
 * @param in2out In2out NAT44 session key.
 * @param out2in Out2in NAT44 session key.
 * @param node   Vlib node.
 *
 * @returns SNAT session if successfully created otherwise 0.
 */
static inline snat_session_t *
create_session_for_static_mapping (snat_main_t *sm,
                                   vlib_buffer_t *b0,
                                   snat_session_key_t in2out,
                                   snat_session_key_t out2in,
                                   vlib_node_runtime_t * node,
                                   u32 thread_index)
{
  snat_user_t *u;
  snat_user_key_t user_key;
  snat_session_t *s;
  clib_bihash_kv_8_8_t kv0, value0;
  dlist_elt_t * per_user_translation_list_elt;
  dlist_elt_t * per_user_list_head_elt;
  ip4_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);

  user_key.addr = in2out.addr;
  user_key.fib_index = in2out.fib_index;
  kv0.key = user_key.as_u64;

  /* Ever heard of the "user" = inside ip4 address before? */
  if (clib_bihash_search_8_8 (&sm->user_hash, &kv0, &value0))
    {
      /* no, make a new one */
      pool_get (sm->per_thread_data[thread_index].users, u);
      memset (u, 0, sizeof (*u));
      u->addr = in2out.addr;
      u->fib_index = in2out.fib_index;

      pool_get (sm->per_thread_data[thread_index].list_pool,
                per_user_list_head_elt);

      u->sessions_per_user_list_head_index = per_user_list_head_elt -
        sm->per_thread_data[thread_index].list_pool;

      clib_dlist_init (sm->per_thread_data[thread_index].list_pool,
                       u->sessions_per_user_list_head_index);

      kv0.value = u - sm->per_thread_data[thread_index].users;

      /* add user */
      clib_bihash_add_del_8_8 (&sm->user_hash, &kv0, 1 /* is_add */);

      /* add non-traslated packets worker lookup */
      kv0.value = thread_index;
      clib_bihash_add_del_8_8 (&sm->worker_by_in, &kv0, 1);
    }
  else
    {
      u = pool_elt_at_index (sm->per_thread_data[thread_index].users,
                             value0.value);
    }

  pool_get (sm->per_thread_data[thread_index].sessions, s);
  memset (s, 0, sizeof (*s));

  s->outside_address_index = ~0;
  s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
  s->ext_host_addr.as_u32 = ip0->dst_address.as_u32;
  u->nstaticsessions++;

  /* Create list elts */
  pool_get (sm->per_thread_data[thread_index].list_pool,
            per_user_translation_list_elt);
  clib_dlist_init (sm->per_thread_data[thread_index].list_pool,
                   per_user_translation_list_elt -
                   sm->per_thread_data[thread_index].list_pool);

  per_user_translation_list_elt->value =
    s - sm->per_thread_data[thread_index].sessions;
  s->per_user_index =
    per_user_translation_list_elt - sm->per_thread_data[thread_index].list_pool;
  s->per_user_list_head_index = u->sessions_per_user_list_head_index;

  clib_dlist_addtail (sm->per_thread_data[thread_index].list_pool,
                      s->per_user_list_head_index,
                      per_user_translation_list_elt -
                      sm->per_thread_data[thread_index].list_pool);

  s->in2out = in2out;
  s->out2in = out2in;
  s->in2out.protocol = out2in.protocol;

  /* Add to translation hashes */
  kv0.key = s->in2out.as_u64;
  kv0.value = s - sm->per_thread_data[thread_index].sessions;
  if (clib_bihash_add_del_8_8 (&sm->in2out, &kv0, 1 /* is_add */))
      clib_warning ("in2out key add failed");

  kv0.key = s->out2in.as_u64;
  kv0.value = s - sm->per_thread_data[thread_index].sessions;

  if (clib_bihash_add_del_8_8 (&sm->out2in, &kv0, 1 /* is_add */))
      clib_warning ("out2in key add failed");

  /* log NAT event */
  snat_ipfix_logging_nat44_ses_create(s->in2out.addr.as_u32,
                                      s->out2in.addr.as_u32,
                                      s->in2out.protocol,
                                      s->in2out.port,
                                      s->out2in.port,
                                      s->in2out.fib_index);
   return s;
}

static_always_inline
snat_out2in_error_t icmp_get_key(ip4_header_t *ip0,
                                 snat_session_key_t *p_key0)
{
  icmp46_header_t *icmp0;
  snat_session_key_t key0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *)(icmp0+1);

  if (!icmp_is_error_message (icmp0))
    {
      key0.protocol = SNAT_PROTOCOL_ICMP;
      key0.addr = ip0->dst_address;
      key0.port = echo0->identifier;
    }
  else
    {
      inner_ip0 = (ip4_header_t *)(echo0+1);
      l4_header = ip4_next_header (inner_ip0);
      key0.protocol = ip_proto_to_snat_proto (inner_ip0->protocol);
      key0.addr = inner_ip0->src_address;
      switch (key0.protocol)
        {
        case SNAT_PROTOCOL_ICMP:
          inner_icmp0 = (icmp46_header_t*)l4_header;
          inner_echo0 = (icmp_echo_header_t *)(inner_icmp0+1);
          key0.port = inner_echo0->identifier;
          break;
        case SNAT_PROTOCOL_UDP:
        case SNAT_PROTOCOL_TCP:
          key0.port = ((tcp_udp_header_t*)l4_header)->src_port;
          break;
        default:
          return SNAT_OUT2IN_ERROR_UNSUPPORTED_PROTOCOL;
        }
    }
  *p_key0 = key0;
  return -1; /* success */
}

/**
 * Get address and port values to be used for ICMP packet translation
 * and create session if needed
 *
 * @param[in,out] sm             NAT main
 * @param[in,out] node           NAT node runtime
 * @param[in] thread_index       thread index
 * @param[in,out] b0             buffer containing packet to be translated
 * @param[out] p_proto           protocol used for matching
 * @param[out] p_value           address and port after NAT translation
 * @param[out] p_dont_translate  if packet should not be translated
 * @param d                      optional parameter
 * @param e                      optional parameter
 */
u32 icmp_match_out2in_slow(snat_main_t *sm, vlib_node_runtime_t *node,
                           u32 thread_index, vlib_buffer_t *b0, u8 *p_proto,
                           snat_session_key_t *p_value,
                           u8 *p_dont_translate, void *d, void *e)
{
  ip4_header_t *ip0;
  icmp46_header_t *icmp0;
  u32 sw_if_index0;
  u32 rx_fib_index0;
  snat_session_key_t key0;
  snat_session_key_t sm0;
  snat_session_t *s0 = 0;
  u8 dont_translate = 0;
  clib_bihash_kv_8_8_t kv0, value0;
  u8 is_addr_only;
  u32 next0 = ~0;
  int err;

  ip0 = vlib_buffer_get_current (b0);
  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  key0.protocol = 0;

  err = icmp_get_key (ip0, &key0);
  if (err != -1)
    {
      b0->error = node->errors[SNAT_OUT2IN_ERROR_UNSUPPORTED_PROTOCOL];
      next0 = SNAT_OUT2IN_NEXT_DROP;
      goto out;
    }
  key0.fib_index = rx_fib_index0;

  kv0.key = key0.as_u64;

  if (clib_bihash_search_8_8 (&sm->out2in, &kv0, &value0))
    {
      /* Try to match static mapping by external address and port,
         destination address and port in packet */
      if (snat_static_mapping_match(sm, key0, &sm0, 1, &is_addr_only))
        {
          /* Don't NAT packet aimed at the intfc address */
          if (PREDICT_FALSE(is_interface_addr(sm, node, sw_if_index0,
                                              ip0->dst_address.as_u32)))
            {
              dont_translate = 1;
              goto out;
            }
          b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
          next0 = SNAT_OUT2IN_NEXT_DROP;
          goto out;
        }

      if (PREDICT_FALSE(icmp0->type != ICMP4_echo_reply &&
                        (icmp0->type != ICMP4_echo_request || !is_addr_only)))
        {
          b0->error = node->errors[SNAT_OUT2IN_ERROR_BAD_ICMP_TYPE];
          next0 = SNAT_OUT2IN_NEXT_DROP;
          goto out;
        }

      /* Create session initiated by host from external network */
      s0 = create_session_for_static_mapping(sm, b0, sm0, key0,
                                             node, thread_index);

      if (!s0)
        {
          next0 = SNAT_OUT2IN_NEXT_DROP;
          goto out;
        }
    }
  else
    {
      if (PREDICT_FALSE(icmp0->type != ICMP4_echo_reply &&
                        icmp0->type != ICMP4_echo_request &&
                        !icmp_is_error_message (icmp0)))
        {
          b0->error = node->errors[SNAT_OUT2IN_ERROR_BAD_ICMP_TYPE];
          next0 = SNAT_OUT2IN_NEXT_DROP;
          goto out;
        }

      s0 = pool_elt_at_index (sm->per_thread_data[thread_index].sessions,
                              value0.value);
    }

out:
  *p_proto = key0.protocol;
  if (s0)
    *p_value = s0->in2out;
  *p_dont_translate = dont_translate;
  if (d)
    *(snat_session_t**)d = s0;
  return next0;
}

/**
 * Get address and port values to be used for ICMP packet translation
 *
 * @param[in] sm                 NAT main
 * @param[in,out] node           NAT node runtime
 * @param[in] thread_index       thread index
 * @param[in,out] b0             buffer containing packet to be translated
 * @param[out] p_proto           protocol used for matching
 * @param[out] p_value           address and port after NAT translation
 * @param[out] p_dont_translate  if packet should not be translated
 * @param d                      optional parameter
 * @param e                      optional parameter
 */
u32 icmp_match_out2in_fast(snat_main_t *sm, vlib_node_runtime_t *node,
                           u32 thread_index, vlib_buffer_t *b0, u8 *p_proto,
                           snat_session_key_t *p_value,
                           u8 *p_dont_translate, void *d, void *e)
{
  ip4_header_t *ip0;
  icmp46_header_t *icmp0;
  u32 sw_if_index0;
  u32 rx_fib_index0;
  snat_session_key_t key0;
  snat_session_key_t sm0;
  u8 dont_translate = 0;
  u8 is_addr_only;
  u32 next0 = ~0;
  int err;

  ip0 = vlib_buffer_get_current (b0);
  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  err = icmp_get_key (ip0, &key0);
  if (err != -1)
    {
      b0->error = node->errors[err];
      next0 = SNAT_OUT2IN_NEXT_DROP;
      goto out2;
    }
  key0.fib_index = rx_fib_index0;

  if (snat_static_mapping_match(sm, key0, &sm0, 1, &is_addr_only))
    {
      /* Don't NAT packet aimed at the intfc address */
      if (is_interface_addr(sm, node, sw_if_index0, ip0->dst_address.as_u32))
        {
          dont_translate = 1;
          goto out;
        }
      b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
      next0 = SNAT_OUT2IN_NEXT_DROP;
      goto out;
    }

  if (PREDICT_FALSE(icmp0->type != ICMP4_echo_reply &&
                    (icmp0->type != ICMP4_echo_request || !is_addr_only) &&
                    !icmp_is_error_message (icmp0)))
    {
      b0->error = node->errors[SNAT_OUT2IN_ERROR_BAD_ICMP_TYPE];
      next0 = SNAT_OUT2IN_NEXT_DROP;
      goto out;
    }

out:
  *p_value = sm0;
out2:
  *p_proto = key0.protocol;
  *p_dont_translate = dont_translate;
  return next0;
}

static inline u32 icmp_out2in (snat_main_t *sm,
                               vlib_buffer_t * b0,
                               ip4_header_t * ip0,
                               icmp46_header_t * icmp0,
                               u32 sw_if_index0,
                               u32 rx_fib_index0,
                               vlib_node_runtime_t * node,
                               u32 next0,
                               u32 thread_index,
                               void *d,
                               void *e)
{
  snat_session_key_t sm0;
  u8 protocol;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0 = 0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;
  u8 dont_translate;
  u32 new_addr0, old_addr0;
  u16 old_id0, new_id0;
  ip_csum_t sum0;
  u16 checksum0;
  u32 next0_tmp;

  echo0 = (icmp_echo_header_t *)(icmp0+1);

  next0_tmp = sm->icmp_match_out2in_cb(sm, node, thread_index, b0,
                                       &protocol, &sm0, &dont_translate, d, e);
  if (next0_tmp != ~0)
    next0 = next0_tmp;
  if (next0 == SNAT_OUT2IN_NEXT_DROP || dont_translate)
    goto out;

  sum0 = ip_incremental_checksum (0, icmp0,
                                  ntohs(ip0->length) - ip4_header_bytes (ip0));
  checksum0 = ~ip_csum_fold (sum0);
  if (checksum0 != 0 && checksum0 != 0xffff)
    {
      next0 = SNAT_OUT2IN_NEXT_DROP;
      goto out;
    }

  old_addr0 = ip0->dst_address.as_u32;
  new_addr0 = ip0->dst_address.as_u32 = sm0.addr.as_u32;
  vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm0.fib_index;

  sum0 = ip0->checksum;
  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                         dst_address /* changed member */);
  ip0->checksum = ip_csum_fold (sum0);

  if (!icmp_is_error_message (icmp0))
    {
      new_id0 = sm0.port;
      if (PREDICT_FALSE(new_id0 != echo0->identifier))
        {
          old_id0 = echo0->identifier;
          new_id0 = sm0.port;
          echo0->identifier = new_id0;

          sum0 = icmp0->checksum;
          sum0 = ip_csum_update (sum0, old_id0, new_id0, icmp_echo_header_t,
                                 identifier /* changed member */);
          icmp0->checksum = ip_csum_fold (sum0);
        }
    }
  else
    {
      inner_ip0 = (ip4_header_t *)(echo0+1);
      l4_header = ip4_next_header (inner_ip0);

      if (!ip4_header_checksum_is_valid (inner_ip0))
        {
          next0 = SNAT_OUT2IN_NEXT_DROP;
          goto out;
        }

      old_addr0 = inner_ip0->src_address.as_u32;
      inner_ip0->src_address = sm0.addr;
      new_addr0 = inner_ip0->src_address.as_u32;

      sum0 = icmp0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                             src_address /* changed member */);
      icmp0->checksum = ip_csum_fold (sum0);

      switch (protocol)
        {
        case SNAT_PROTOCOL_ICMP:
          inner_icmp0 = (icmp46_header_t*)l4_header;
          inner_echo0 = (icmp_echo_header_t *)(inner_icmp0+1);

          old_id0 = inner_echo0->identifier;
          new_id0 = sm0.port;
          inner_echo0->identifier = new_id0;

          sum0 = icmp0->checksum;
          sum0 = ip_csum_update (sum0, old_id0, new_id0, icmp_echo_header_t,
                                 identifier);
          icmp0->checksum = ip_csum_fold (sum0);
          break;
        case SNAT_PROTOCOL_UDP:
        case SNAT_PROTOCOL_TCP:
          old_id0 = ((tcp_udp_header_t*)l4_header)->src_port;
          new_id0 = sm0.port;
          ((tcp_udp_header_t*)l4_header)->src_port = new_id0;

          sum0 = icmp0->checksum;
          sum0 = ip_csum_update (sum0, old_id0, new_id0, tcp_udp_header_t,
                                 src_port);
          icmp0->checksum = ip_csum_fold (sum0);
          break;
        default:
          ASSERT(0);
        }
    }

out:
  return next0;
}


static inline u32 icmp_out2in_slow_path (snat_main_t *sm,
                                         vlib_buffer_t * b0,
                                         ip4_header_t * ip0,
                                         icmp46_header_t * icmp0,
                                         u32 sw_if_index0,
                                         u32 rx_fib_index0,
                                         vlib_node_runtime_t * node,
                                         u32 next0, f64 now,
                                         u32 thread_index,
                                         snat_session_t ** p_s0)
{
  next0 = icmp_out2in(sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
                      next0, thread_index, p_s0, 0);
  snat_session_t * s0 = *p_s0;
  if (PREDICT_TRUE(next0 != SNAT_OUT2IN_NEXT_DROP && s0))
    {
      /* Accounting */
      s0->last_heard = now;
      s0->total_pkts++;
      s0->total_bytes += vlib_buffer_length_in_chain (sm->vlib_main, b0);
      /* Per-user LRU list maintenance for dynamic translation */
      if (!snat_is_session_static (s0))
        {
          clib_dlist_remove (sm->per_thread_data[thread_index].list_pool,
                             s0->per_user_index);
          clib_dlist_addtail (sm->per_thread_data[thread_index].list_pool,
                              s0->per_user_list_head_index,
                              s0->per_user_index);
        }
    }
  return next0;
}

static void
snat_out2in_unknown_proto (snat_main_t *sm,
                           vlib_buffer_t * b,
                           ip4_header_t * ip,
                           u32 rx_fib_index,
                           u32 thread_index,
                           f64 now,
                           vlib_main_t * vm)
{
  clib_bihash_kv_8_8_t kv, value;
  clib_bihash_kv_16_8_t s_kv, s_value;
  snat_static_mapping_t *m;
  snat_session_key_t m_key;
  u32 old_addr, new_addr;
  ip_csum_t sum;
  nat_ed_ses_key_t key;
  snat_session_t * s;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_user_key_t u_key;
  snat_user_t *u;
  dlist_elt_t *head, *elt;

  old_addr = ip->dst_address.as_u32;

  key.l_addr = ip->dst_address;
  key.r_addr = ip->src_address;
  key.fib_index = rx_fib_index;
  key.proto = ip->protocol;
  key.rsvd = 0;
  key.l_port = 0;
  s_kv.key[0] = key.as_u64[0];
  s_kv.key[1] = key.as_u64[1];

  if (!clib_bihash_search_16_8 (&sm->out2in_ed, &s_kv, &s_value))
    {
      s = pool_elt_at_index (tsm->sessions, s_value.value);
      new_addr = ip->dst_address.as_u32 = s->in2out.addr.as_u32;
    }
  else
    {
      m_key.addr = ip->dst_address;
      m_key.port = 0;
      m_key.protocol = 0;
      m_key.fib_index = rx_fib_index;
      kv.key = m_key.as_u64;
      if (clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
        return;

      m = pool_elt_at_index (sm->static_mappings, value.value);

      new_addr = ip->dst_address.as_u32 = m->local_addr.as_u32;

      u_key.addr = ip->src_address;
      u_key.fib_index = m->fib_index;
      kv.key = u_key.as_u64;

      /* Ever heard of the "user" = src ip4 address before? */
      if (clib_bihash_search_8_8 (&sm->user_hash, &kv, &value))
        {
          /* no, make a new one */
          pool_get (tsm->users, u);
          memset (u, 0, sizeof (*u));
          u->addr = ip->src_address;
          u->fib_index = rx_fib_index;

          pool_get (tsm->list_pool, head);
          u->sessions_per_user_list_head_index = head - tsm->list_pool;

          clib_dlist_init (tsm->list_pool,
                           u->sessions_per_user_list_head_index);

          kv.value = u - tsm->users;

          /* add user */
          clib_bihash_add_del_8_8 (&sm->user_hash, &kv, 1);
        }
      else
        {
          u = pool_elt_at_index (tsm->users, value.value);
        }

      /* Create a new session */
      pool_get (tsm->sessions, s);
      memset (s, 0, sizeof (*s));

      s->ext_host_addr.as_u32 = ip->src_address.as_u32;
      s->flags |= SNAT_SESSION_FLAG_UNKNOWN_PROTO;
      s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
      s->outside_address_index = ~0;
      s->out2in.addr.as_u32 = old_addr;
      s->out2in.fib_index = rx_fib_index;
      s->in2out.addr.as_u32 = new_addr;
      s->in2out.fib_index = m->fib_index;
      s->in2out.port = s->out2in.port = ip->protocol;
      u->nstaticsessions++;

      /* Create list elts */
      pool_get (tsm->list_pool, elt);
      clib_dlist_init (tsm->list_pool, elt - tsm->list_pool);
      elt->value = s - tsm->sessions;
      s->per_user_index = elt - tsm->list_pool;
      s->per_user_list_head_index = u->sessions_per_user_list_head_index;
      clib_dlist_addtail (tsm->list_pool, s->per_user_list_head_index,
                          s->per_user_index);

      /* Add to lookup tables */
      s_kv.value = s - tsm->sessions;
      if (clib_bihash_add_del_16_8 (&sm->out2in_ed, &s_kv, 1))
        clib_warning ("out2in key add failed");

      key.l_addr = ip->dst_address;
      key.fib_index = m->fib_index;
      s_kv.key[0] = key.as_u64[0];
      s_kv.key[1] = key.as_u64[1];
      if (clib_bihash_add_del_16_8 (&sm->in2out_ed, &s_kv, 1))
        clib_warning ("in2out key add failed");
   }

  /* Update IP checksum */
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
  ip->checksum = ip_csum_fold (sum);

  vnet_buffer(b)->sw_if_index[VLIB_TX] = s->in2out.fib_index;

  /* Accounting */
  s->last_heard = now;
  s->total_pkts++;
  s->total_bytes += vlib_buffer_length_in_chain (vm, b);
  /* Per-user LRU list maintenance */
  clib_dlist_remove (tsm->list_pool, s->per_user_index);
  clib_dlist_addtail (tsm->list_pool, s->per_user_list_head_index,
                      s->per_user_index);
}

static snat_session_t *
snat_out2in_lb (snat_main_t *sm,
                vlib_buffer_t * b,
                ip4_header_t * ip,
                u32 rx_fib_index,
                u32 thread_index,
                f64 now,
                vlib_main_t * vm)
{
  nat_ed_ses_key_t key;
  clib_bihash_kv_16_8_t s_kv, s_value;
  udp_header_t *udp = ip4_next_header (ip);
  tcp_header_t *tcp = (tcp_header_t *) udp;
  snat_session_t *s = 0;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_session_key_t e_key, l_key;
  clib_bihash_kv_8_8_t kv, value;
  u32 old_addr, new_addr;
  u32 proto = ip_proto_to_snat_proto (ip->protocol);
  u16 new_port, old_port;
  ip_csum_t sum;
  snat_user_key_t u_key;
  snat_user_t *u;
  dlist_elt_t *head, *elt;

  old_addr = ip->dst_address.as_u32;

  key.l_addr = ip->dst_address;
  key.r_addr = ip->src_address;
  key.fib_index = rx_fib_index;
  key.proto = ip->protocol;
  key.rsvd = 0;
  key.l_port = udp->dst_port;
  s_kv.key[0] = key.as_u64[0];
  s_kv.key[1] = key.as_u64[1];

  if (!clib_bihash_search_16_8 (&sm->out2in_ed, &s_kv, &s_value))
    {
      s = pool_elt_at_index (tsm->sessions, s_value.value);
    }
  else
    {
      e_key.addr = ip->dst_address;
      e_key.port = udp->dst_port;
      e_key.protocol = proto;
      e_key.fib_index = rx_fib_index;
      if (snat_static_mapping_match(sm, e_key, &l_key, 1, 0))
        return 0;

      u_key.addr = l_key.addr;
      u_key.fib_index = l_key.fib_index;
      kv.key = u_key.as_u64;

      /* Ever heard of the "user" = src ip4 address before? */
      if (clib_bihash_search_8_8 (&sm->user_hash, &kv, &value))
        {
          /* no, make a new one */
          pool_get (tsm->users, u);
          memset (u, 0, sizeof (*u));
          u->addr = l_key.addr;
          u->fib_index = l_key.fib_index;

          pool_get (tsm->list_pool, head);
          u->sessions_per_user_list_head_index = head - tsm->list_pool;

          clib_dlist_init (tsm->list_pool,
                           u->sessions_per_user_list_head_index);

          kv.value = u - tsm->users;

          /* add user */
          if (clib_bihash_add_del_8_8 (&sm->user_hash, &kv, 1))
            clib_warning ("user key add failed");
        }
      else
        {
          u = pool_elt_at_index (tsm->users, value.value);
        }

      /* Create a new session */
      pool_get (tsm->sessions, s);
      memset (s, 0, sizeof (*s));

      s->ext_host_addr.as_u32 = ip->src_address.as_u32;
      s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
      s->flags |= SNAT_SESSION_FLAG_LOAD_BALANCING;
      s->outside_address_index = ~0;
      s->out2in = e_key;
      s->in2out = l_key;
      u->nstaticsessions++;

      /* Create list elts */
      pool_get (tsm->list_pool, elt);
      clib_dlist_init (tsm->list_pool, elt - tsm->list_pool);
      elt->value = s - tsm->sessions;
      s->per_user_index = elt - tsm->list_pool;
      s->per_user_list_head_index = u->sessions_per_user_list_head_index;
      clib_dlist_addtail (tsm->list_pool, s->per_user_list_head_index,
                          s->per_user_index);

      /* Add to lookup tables */
      s_kv.value = s - tsm->sessions;
      if (clib_bihash_add_del_16_8 (&sm->out2in_ed, &s_kv, 1))
        clib_warning ("out2in-ed key add failed");

      key.l_addr = l_key.addr;
      key.fib_index = l_key.fib_index;
      key.l_port = l_key.port;
      s_kv.key[0] = key.as_u64[0];
      s_kv.key[1] = key.as_u64[1];
      if (clib_bihash_add_del_16_8 (&sm->in2out_ed, &s_kv, 1))
        clib_warning ("in2out-ed key add failed");
    }

  new_addr = ip->dst_address.as_u32 = s->in2out.addr.as_u32;

  /* Update IP checksum */
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
  ip->checksum = ip_csum_fold (sum);

  if (PREDICT_TRUE(proto == SNAT_PROTOCOL_TCP))
    {
      old_port = tcp->dst_port;
      tcp->dst_port = s->in2out.port;
      new_port = tcp->dst_port;

      sum = tcp->checksum;
      sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
      sum = ip_csum_update (sum, old_port, new_port, ip4_header_t, length);
      tcp->checksum = ip_csum_fold(sum);
    }
  else
    {
      udp->dst_port = s->in2out.port;
      udp->checksum = 0;
    }

  vnet_buffer(b)->sw_if_index[VLIB_TX] = s->in2out.fib_index;

  /* Accounting */
  s->last_heard = now;
  s->total_pkts++;
  s->total_bytes += vlib_buffer_length_in_chain (vm, b);
  return s;
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
  u32 thread_index = vlib_get_thread_index ();

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
          u32 next0 = SNAT_OUT2IN_NEXT_LOOKUP;
          u32 next1 = SNAT_OUT2IN_NEXT_LOOKUP;
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

          vnet_buffer (b0)->snat.flags = 0;
          vnet_buffer (b1)->snat.flags = 0;

          ip0 = vlib_buffer_get_current (b0);
          udp0 = ip4_next_header (ip0);
          tcp0 = (tcp_header_t *) udp0;
          icmp0 = (icmp46_header_t *) udp0;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 = vec_elt (sm->ip4_main->fib_index_by_sw_if_index,
                                   sw_if_index0);

          if (PREDICT_FALSE(ip0->ttl == 1))
            {
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next0 = SNAT_OUT2IN_NEXT_ICMP_ERROR;
              goto trace0;
            }

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          if (PREDICT_FALSE (proto0 == ~0))
            {
              snat_out2in_unknown_proto(sm, b0, ip0, rx_fib_index0,
                                        thread_index, now, vm);
              goto trace0;
            }

          if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
            {
              next0 = icmp_out2in_slow_path
                (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
                 next0, now, thread_index, &s0);
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
              if (snat_static_mapping_match(sm, key0, &sm0, 1, 0))
                {
                  b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
                  /*
                   * Send DHCP packets to the ipv4 stack, or we won't
                   * be able to use dhcp client on the outside interface
                   */
                  if (proto0 != SNAT_PROTOCOL_UDP
                      || (udp0->dst_port
                          != clib_host_to_net_u16(UDP_DST_PORT_dhcp_to_client)))
                    next0 = SNAT_OUT2IN_NEXT_DROP;
                  goto trace0;
                }

              /* Create session initiated by host from external network */
              s0 = create_session_for_static_mapping(sm, b0, sm0, key0, node,
                                                     thread_index);
              if (!s0)
                {
                  b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
                  next0 = SNAT_OUT2IN_NEXT_DROP;
                  goto trace0;
                }
            }
          else
            {
              if (PREDICT_FALSE (value0.value == ~0ULL))
                {
                  s0 = snat_out2in_lb(sm, b0, ip0, rx_fib_index0, thread_index, now,
                                 vm);
                  goto trace0;
                }
              else
                {
                  s0 = pool_elt_at_index (
                    sm->per_thread_data[thread_index].sessions,
                    value0.value);
                }
            }

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
              old_port0 = tcp0->dst_port;
              tcp0->dst_port = s0->in2out.port;
              new_port0 = tcp0->dst_port;

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
              clib_dlist_remove (sm->per_thread_data[thread_index].list_pool,
                                 s0->per_user_index);
              clib_dlist_addtail (sm->per_thread_data[thread_index].list_pool,
                                  s0->per_user_list_head_index,
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
                t->session_index = s0 - sm->per_thread_data[thread_index].sessions;
            }

          pkts_processed += next0 != SNAT_OUT2IN_NEXT_DROP;


          ip1 = vlib_buffer_get_current (b1);
          udp1 = ip4_next_header (ip1);
          tcp1 = (tcp_header_t *) udp1;
          icmp1 = (icmp46_header_t *) udp1;

          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
	  rx_fib_index1 = vec_elt (sm->ip4_main->fib_index_by_sw_if_index,
                                   sw_if_index1);

          if (PREDICT_FALSE(ip1->ttl == 1))
            {
              vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b1, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next1 = SNAT_OUT2IN_NEXT_ICMP_ERROR;
              goto trace1;
            }

          proto1 = ip_proto_to_snat_proto (ip1->protocol);

          if (PREDICT_FALSE (proto1 == ~0))
            {
              snat_out2in_unknown_proto(sm, b1, ip1, rx_fib_index1,
                                        thread_index, now, vm);
              goto trace1;
            }

          if (PREDICT_FALSE (proto1 == SNAT_PROTOCOL_ICMP))
            {
              next1 = icmp_out2in_slow_path
                (sm, b1, ip1, icmp1, sw_if_index1, rx_fib_index1, node,
                 next1, now, thread_index, &s1);
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
              if (snat_static_mapping_match(sm, key1, &sm1, 1, 0))
                {
                  b1->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
                  /*
                   * Send DHCP packets to the ipv4 stack, or we won't
                   * be able to use dhcp client on the outside interface
                   */
                  if (proto1 != SNAT_PROTOCOL_UDP
                      || (udp1->dst_port
                          != clib_host_to_net_u16(UDP_DST_PORT_dhcp_to_client)))
                    next1 = SNAT_OUT2IN_NEXT_DROP;
                  goto trace1;
                }

              /* Create session initiated by host from external network */
              s1 = create_session_for_static_mapping(sm, b1, sm1, key1, node,
                                                     thread_index);
              if (!s1)
                {
                  b1->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
                  next1 = SNAT_OUT2IN_NEXT_DROP;
                  goto trace1;
                }
            }
          else
            {
              if (PREDICT_FALSE (value1.value == ~0ULL))
                {
                  s1 = snat_out2in_lb(sm, b1, ip1, rx_fib_index1, thread_index, now,
                                 vm);
                  goto trace1;
                }
              else
                {
                  s1 = pool_elt_at_index (
                    sm->per_thread_data[thread_index].sessions,
                    value1.value);
                }
            }

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
              old_port1 = tcp1->dst_port;
              tcp1->dst_port = s1->in2out.port;
              new_port1 = tcp1->dst_port;

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
              clib_dlist_remove (sm->per_thread_data[thread_index].list_pool,
                                 s1->per_user_index);
              clib_dlist_addtail (sm->per_thread_data[thread_index].list_pool,
                                  s1->per_user_list_head_index,
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
                t->session_index = s1 - sm->per_thread_data[thread_index].sessions;
            }

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
          u32 next0 = SNAT_OUT2IN_NEXT_LOOKUP;
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

          vnet_buffer (b0)->snat.flags = 0;

          ip0 = vlib_buffer_get_current (b0);
          udp0 = ip4_next_header (ip0);
          tcp0 = (tcp_header_t *) udp0;
          icmp0 = (icmp46_header_t *) udp0;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 = vec_elt (sm->ip4_main->fib_index_by_sw_if_index,
                                   sw_if_index0);

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          if (PREDICT_FALSE (proto0 == ~0))
            {
              snat_out2in_unknown_proto(sm, b0, ip0, rx_fib_index0,
                                        thread_index, now, vm);
              goto trace00;
            }

          if (PREDICT_FALSE(ip0->ttl == 1))
            {
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next0 = SNAT_OUT2IN_NEXT_ICMP_ERROR;
              goto trace00;
            }

          if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
            {
              next0 = icmp_out2in_slow_path
                (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
                 next0, now, thread_index, &s0);
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
              if (snat_static_mapping_match(sm, key0, &sm0, 1, 0))
                {
                  b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
                  /*
                   * Send DHCP packets to the ipv4 stack, or we won't
                   * be able to use dhcp client on the outside interface
                   */
                  if (proto0 != SNAT_PROTOCOL_UDP
                      || (udp0->dst_port
                          != clib_host_to_net_u16(UDP_DST_PORT_dhcp_to_client)))

                    next0 = SNAT_OUT2IN_NEXT_DROP;
                  goto trace00;
                }

              /* Create session initiated by host from external network */
              s0 = create_session_for_static_mapping(sm, b0, sm0, key0, node,
                                                     thread_index);
              if (!s0)
                {
                  b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
                    next0 = SNAT_OUT2IN_NEXT_DROP;
                  goto trace00;
                }
            }
          else
            {
              if (PREDICT_FALSE (value0.value == ~0ULL))
                {
                  s0 = snat_out2in_lb(sm, b0, ip0, rx_fib_index0, thread_index, now,
                                 vm);
                  goto trace00;
                }
              else
                {
                  s0 = pool_elt_at_index (
                    sm->per_thread_data[thread_index].sessions,
                    value0.value);
                }
            }

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
              old_port0 = tcp0->dst_port;
              tcp0->dst_port = s0->in2out.port;
              new_port0 = tcp0->dst_port;

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
              clib_dlist_remove (sm->per_thread_data[thread_index].list_pool,
                                 s0->per_user_index);
              clib_dlist_addtail (sm->per_thread_data[thread_index].list_pool,
                                  s0->per_user_list_head_index,
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
                t->session_index = s0 - sm->per_thread_data[thread_index].sessions;
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
  .name = "nat44-out2in",
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
    [SNAT_OUT2IN_NEXT_LOOKUP] = "ip4-lookup",
    [SNAT_OUT2IN_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },
};
VLIB_NODE_FUNCTION_MULTIARCH (snat_out2in_node, snat_out2in_node_fn);

/**************************/
/*** deterministic mode ***/
/**************************/
static uword
snat_det_out2in_node_fn (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  snat_out2in_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t * sm = &snat_main;
  u32 thread_index = vlib_get_thread_index ();

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
          u32 next0 = SNAT_OUT2IN_NEXT_LOOKUP;
          u32 next1 = SNAT_OUT2IN_NEXT_LOOKUP;
          u32 sw_if_index0, sw_if_index1;
          ip4_header_t * ip0, * ip1;
          ip_csum_t sum0, sum1;
          ip4_address_t new_addr0, old_addr0, new_addr1, old_addr1;
          u16 new_port0, old_port0, old_port1, new_port1;
          udp_header_t * udp0, * udp1;
          tcp_header_t * tcp0, * tcp1;
          u32 proto0, proto1;
          snat_det_out_key_t key0, key1;
          snat_det_map_t * dm0, * dm1;
          snat_det_session_t * ses0 = 0, * ses1 = 0;
          u32 rx_fib_index0, rx_fib_index1;
          icmp46_header_t * icmp0, * icmp1;

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

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          if (PREDICT_FALSE(ip0->ttl == 1))
            {
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next0 = SNAT_OUT2IN_NEXT_ICMP_ERROR;
              goto trace0;
            }

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          if (PREDICT_FALSE(proto0 == SNAT_PROTOCOL_ICMP))
            {
              rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index0);
              icmp0 = (icmp46_header_t *) udp0;

              next0 = icmp_out2in(sm, b0, ip0, icmp0, sw_if_index0,
                                  rx_fib_index0, node, next0, thread_index,
                                  &ses0, &dm0);
              goto trace0;
            }

          key0.ext_host_addr = ip0->src_address;
          key0.ext_host_port = tcp0->src;
          key0.out_port = tcp0->dst;

          dm0 = snat_det_map_by_out(sm, &ip0->dst_address);
          if (PREDICT_FALSE(!dm0))
            {
              clib_warning("unknown dst address:  %U",
                           format_ip4_address, &ip0->dst_address);
              next0 = SNAT_OUT2IN_NEXT_DROP;
              b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
              goto trace0;
            }

          snat_det_reverse(dm0, &ip0->dst_address,
                           clib_net_to_host_u16(tcp0->dst), &new_addr0);

          ses0 = snat_det_get_ses_by_out (dm0, &new_addr0, key0.as_u64);
          if (PREDICT_FALSE(!ses0))
            {
              clib_warning("no match src %U:%d dst %U:%d for user %U",
                           format_ip4_address, &ip0->src_address,
                           clib_net_to_host_u16 (tcp0->src),
                           format_ip4_address, &ip0->dst_address,
                           clib_net_to_host_u16 (tcp0->dst),
                           format_ip4_address, &new_addr0);
              next0 = SNAT_OUT2IN_NEXT_DROP;
              b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
              goto trace0;
            }
          new_port0 = ses0->in_port;

          old_addr0 = ip0->dst_address;
          ip0->dst_address = new_addr0;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm->inside_fib_index;

          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
                                 ip4_header_t,
                                 dst_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              if (tcp0->flags & TCP_FLAG_FIN && ses0->state == SNAT_SESSION_TCP_ESTABLISHED)
                ses0->state = SNAT_SESSION_TCP_CLOSE_WAIT;
              else if (tcp0->flags & TCP_FLAG_ACK && ses0->state == SNAT_SESSION_TCP_LAST_ACK)
                snat_det_ses_close(dm0, ses0);

              old_port0 = tcp0->dst;
              tcp0->dst = new_port0;

              sum0 = tcp0->checksum;
              sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
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

        trace0:

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_out2in_trace_t *t =
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
              t->session_index = ~0;
              if (ses0)
                t->session_index = ses0 - dm0->sessions;
            }

          pkts_processed += next0 != SNAT_OUT2IN_NEXT_DROP;

	  b1 = vlib_get_buffer (vm, bi1);

          ip1 = vlib_buffer_get_current (b1);
          udp1 = ip4_next_header (ip1);
          tcp1 = (tcp_header_t *) udp1;

          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

          if (PREDICT_FALSE(ip1->ttl == 1))
            {
              vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b1, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next1 = SNAT_OUT2IN_NEXT_ICMP_ERROR;
              goto trace1;
            }

          proto1 = ip_proto_to_snat_proto (ip1->protocol);

          if (PREDICT_FALSE(proto1 == SNAT_PROTOCOL_ICMP))
            {
              rx_fib_index1 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index1);
              icmp1 = (icmp46_header_t *) udp1;

              next1 = icmp_out2in(sm, b1, ip1, icmp1, sw_if_index1,
                                  rx_fib_index1, node, next1, thread_index,
                                  &ses1, &dm1);
              goto trace1;
            }

          key1.ext_host_addr = ip1->src_address;
          key1.ext_host_port = tcp1->src;
          key1.out_port = tcp1->dst;

          dm1 = snat_det_map_by_out(sm, &ip1->dst_address);
          if (PREDICT_FALSE(!dm1))
            {
              clib_warning("unknown dst address:  %U",
                           format_ip4_address, &ip1->dst_address);
              next1 = SNAT_OUT2IN_NEXT_DROP;
              b1->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
              goto trace1;
            }

          snat_det_reverse(dm1, &ip1->dst_address,
                           clib_net_to_host_u16(tcp1->dst), &new_addr1);

          ses1 = snat_det_get_ses_by_out (dm1, &new_addr1, key1.as_u64);
          if (PREDICT_FALSE(!ses1))
            {
              clib_warning("no match src %U:%d dst %U:%d for user %U",
                           format_ip4_address, &ip1->src_address,
                           clib_net_to_host_u16 (tcp1->src),
                           format_ip4_address, &ip1->dst_address,
                           clib_net_to_host_u16 (tcp1->dst),
                           format_ip4_address, &new_addr1);
              next1 = SNAT_OUT2IN_NEXT_DROP;
              b1->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
              goto trace1;
            }
          new_port1 = ses1->in_port;

          old_addr1 = ip1->dst_address;
          ip1->dst_address = new_addr1;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = sm->inside_fib_index;

          sum1 = ip1->checksum;
          sum1 = ip_csum_update (sum1, old_addr1.as_u32, new_addr1.as_u32,
                                 ip4_header_t,
                                 dst_address /* changed member */);
          ip1->checksum = ip_csum_fold (sum1);

          if (PREDICT_TRUE(proto1 == SNAT_PROTOCOL_TCP))
            {
              if (tcp1->flags & TCP_FLAG_FIN && ses1->state == SNAT_SESSION_TCP_ESTABLISHED)
                ses1->state = SNAT_SESSION_TCP_CLOSE_WAIT;
              else if (tcp1->flags & TCP_FLAG_ACK && ses1->state == SNAT_SESSION_TCP_LAST_ACK)
                snat_det_ses_close(dm1, ses1);

              old_port1 = tcp1->dst;
              tcp1->dst = new_port1;

              sum1 = tcp1->checksum;
              sum1 = ip_csum_update (sum1, old_addr1.as_u32, new_addr1.as_u32,
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
              udp1->dst_port = new_port1;
              udp1->checksum = 0;
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
              if (ses1)
                t->session_index = ses1 - dm1->sessions;
            }

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
          u32 next0 = SNAT_OUT2IN_NEXT_LOOKUP;
          u32 sw_if_index0;
          ip4_header_t * ip0;
          ip_csum_t sum0;
          ip4_address_t new_addr0, old_addr0;
          u16 new_port0, old_port0;
          udp_header_t * udp0;
          tcp_header_t * tcp0;
          u32 proto0;
          snat_det_out_key_t key0;
          snat_det_map_t * dm0;
          snat_det_session_t * ses0 = 0;
          u32 rx_fib_index0;
          icmp46_header_t * icmp0;

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

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          if (PREDICT_FALSE(ip0->ttl == 1))
            {
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next0 = SNAT_OUT2IN_NEXT_ICMP_ERROR;
              goto trace00;
            }

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          if (PREDICT_FALSE(proto0 == SNAT_PROTOCOL_ICMP))
            {
              rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index0);
              icmp0 = (icmp46_header_t *) udp0;

              next0 = icmp_out2in(sm, b0, ip0, icmp0, sw_if_index0,
                                  rx_fib_index0, node, next0, thread_index,
                                  &ses0, &dm0);
              goto trace00;
            }

          key0.ext_host_addr = ip0->src_address;
          key0.ext_host_port = tcp0->src;
          key0.out_port = tcp0->dst;

          dm0 = snat_det_map_by_out(sm, &ip0->dst_address);
          if (PREDICT_FALSE(!dm0))
            {
              clib_warning("unknown dst address:  %U",
                           format_ip4_address, &ip0->dst_address);
              next0 = SNAT_OUT2IN_NEXT_DROP;
              b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
              goto trace00;
            }

          snat_det_reverse(dm0, &ip0->dst_address,
                           clib_net_to_host_u16(tcp0->dst), &new_addr0);

          ses0 = snat_det_get_ses_by_out (dm0, &new_addr0, key0.as_u64);
          if (PREDICT_FALSE(!ses0))
            {
              clib_warning("no match src %U:%d dst %U:%d for user %U",
                           format_ip4_address, &ip0->src_address,
                           clib_net_to_host_u16 (tcp0->src),
                           format_ip4_address, &ip0->dst_address,
                           clib_net_to_host_u16 (tcp0->dst),
                           format_ip4_address, &new_addr0);
              next0 = SNAT_OUT2IN_NEXT_DROP;
              b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
              goto trace00;
            }
          new_port0 = ses0->in_port;

          old_addr0 = ip0->dst_address;
          ip0->dst_address = new_addr0;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm->inside_fib_index;

          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
                                 ip4_header_t,
                                 dst_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              if (tcp0->flags & TCP_FLAG_FIN && ses0->state == SNAT_SESSION_TCP_ESTABLISHED)
                ses0->state = SNAT_SESSION_TCP_CLOSE_WAIT;
              else if (tcp0->flags & TCP_FLAG_ACK && ses0->state == SNAT_SESSION_TCP_LAST_ACK)
                snat_det_ses_close(dm0, ses0);

              old_port0 = tcp0->dst;
              tcp0->dst = new_port0;

              sum0 = tcp0->checksum;
              sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
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

        trace00:

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_out2in_trace_t *t =
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
              t->session_index = ~0;
              if (ses0)
                t->session_index = ses0 - dm0->sessions;
            }

          pkts_processed += next0 != SNAT_OUT2IN_NEXT_DROP;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, snat_det_out2in_node.index,
                               SNAT_OUT2IN_ERROR_OUT2IN_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (snat_det_out2in_node) = {
  .function = snat_det_out2in_node_fn,
  .name = "nat44-det-out2in",
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
    [SNAT_OUT2IN_NEXT_LOOKUP] = "ip4-lookup",
    [SNAT_OUT2IN_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },
};
VLIB_NODE_FUNCTION_MULTIARCH (snat_det_out2in_node, snat_det_out2in_node_fn);

/**
 * Get address and port values to be used for ICMP packet translation
 * and create session if needed
 *
 * @param[in,out] sm             NAT main
 * @param[in,out] node           NAT node runtime
 * @param[in] thread_index       thread index
 * @param[in,out] b0             buffer containing packet to be translated
 * @param[out] p_proto           protocol used for matching
 * @param[out] p_value           address and port after NAT translation
 * @param[out] p_dont_translate  if packet should not be translated
 * @param d                      optional parameter
 * @param e                      optional parameter
 */
u32 icmp_match_out2in_det(snat_main_t *sm, vlib_node_runtime_t *node,
                          u32 thread_index, vlib_buffer_t *b0, u8 *p_proto,
                          snat_session_key_t *p_value,
                          u8 *p_dont_translate, void *d, void *e)
{
  ip4_header_t *ip0;
  icmp46_header_t *icmp0;
  u32 sw_if_index0;
  u8 protocol;
  snat_det_out_key_t key0;
  u8 dont_translate = 0;
  u32 next0 = ~0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;
  snat_det_map_t * dm0 = 0;
  ip4_address_t new_addr0 = {{0}};
  snat_det_session_t * ses0 = 0;
  ip4_address_t out_addr;

  ip0 = vlib_buffer_get_current (b0);
  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *)(icmp0+1);
  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

  if (!icmp_is_error_message (icmp0))
    {
      protocol = SNAT_PROTOCOL_ICMP;
      key0.ext_host_addr = ip0->src_address;
      key0.ext_host_port = 0;
      key0.out_port = echo0->identifier;
      out_addr = ip0->dst_address;
    }
  else
    {
      inner_ip0 = (ip4_header_t *)(echo0+1);
      l4_header = ip4_next_header (inner_ip0);
      protocol = ip_proto_to_snat_proto (inner_ip0->protocol);
      key0.ext_host_addr = inner_ip0->dst_address;
      out_addr = inner_ip0->src_address;
      switch (protocol)
        {
        case SNAT_PROTOCOL_ICMP:
          inner_icmp0 = (icmp46_header_t*)l4_header;
          inner_echo0 = (icmp_echo_header_t *)(inner_icmp0+1);
          key0.ext_host_port = 0;
          key0.out_port = inner_echo0->identifier;
          break;
        case SNAT_PROTOCOL_UDP:
        case SNAT_PROTOCOL_TCP:
          key0.ext_host_port = ((tcp_udp_header_t*)l4_header)->dst_port;
          key0.out_port = ((tcp_udp_header_t*)l4_header)->src_port;
          break;
        default:
          b0->error = node->errors[SNAT_OUT2IN_ERROR_UNSUPPORTED_PROTOCOL];
          next0 = SNAT_OUT2IN_NEXT_DROP;
          goto out;
        }
    }

  dm0 = snat_det_map_by_out(sm, &out_addr);
  if (PREDICT_FALSE(!dm0))
    {
      /* Don't NAT packet aimed at the intfc address */
      if (PREDICT_FALSE(is_interface_addr(sm, node, sw_if_index0,
                                          ip0->dst_address.as_u32)))
        {
          dont_translate = 1;
          goto out;
        }
      clib_warning("unknown dst address:  %U",
                   format_ip4_address, &ip0->dst_address);
      goto out;
    }

  snat_det_reverse(dm0, &ip0->dst_address,
                   clib_net_to_host_u16(key0.out_port), &new_addr0);

  ses0 = snat_det_get_ses_by_out (dm0, &new_addr0, key0.as_u64);
  if (PREDICT_FALSE(!ses0))
    {
      /* Don't NAT packet aimed at the intfc address */
      if (PREDICT_FALSE(is_interface_addr(sm, node, sw_if_index0,
                                          ip0->dst_address.as_u32)))
        {
          dont_translate = 1;
          goto out;
        }
      clib_warning("no match src %U:%d dst %U:%d for user %U",
                   format_ip4_address, &key0.ext_host_addr,
                   clib_net_to_host_u16 (key0.ext_host_port),
                   format_ip4_address, &out_addr,
                   clib_net_to_host_u16 (key0.out_port),
                   format_ip4_address, &new_addr0);
      b0->error = node->errors[SNAT_OUT2IN_ERROR_NO_TRANSLATION];
      next0 = SNAT_OUT2IN_NEXT_DROP;
      goto out;
    }

  if (PREDICT_FALSE(icmp0->type != ICMP4_echo_reply &&
                    !icmp_is_error_message (icmp0)))
    {
      b0->error = node->errors[SNAT_OUT2IN_ERROR_BAD_ICMP_TYPE];
      next0 = SNAT_OUT2IN_NEXT_DROP;
      goto out;
    }

  goto out;

out:
  *p_proto = protocol;
  if (ses0)
    {
      p_value->addr = new_addr0;
      p_value->fib_index = sm->inside_fib_index;
      p_value->port = ses0->in_port;
    }
  *p_dont_translate = dont_translate;
  if (d)
    *(snat_det_session_t**)d = ses0;
  if (e)
    *(snat_det_map_t**)e = dm0;
  return next0;
}

/**********************/
/*** worker handoff ***/
/**********************/
static uword
snat_out2in_worker_handoff_fn (vlib_main_t * vm,
                               vlib_node_runtime_t * node,
                               vlib_frame_t * frame)
{
  snat_main_t *sm = &snat_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 n_left_from, *from, *to_next = 0;
  static __thread vlib_frame_queue_elt_t **handoff_queue_elt_by_worker_index;
  static __thread vlib_frame_queue_t **congested_handoff_queue_by_worker_index
    = 0;
  vlib_frame_queue_elt_t *hf = 0;
  vlib_frame_t *f = 0;
  int i;
  u32 n_left_to_next_worker = 0, *to_next_worker = 0;
  u32 next_worker_index = 0;
  u32 current_worker_index = ~0;
  u32 thread_index = vlib_get_thread_index ();

  ASSERT (vec_len (sm->workers));

  if (PREDICT_FALSE (handoff_queue_elt_by_worker_index == 0))
    {
      vec_validate (handoff_queue_elt_by_worker_index, tm->n_vlib_mains - 1);

      vec_validate_init_empty (congested_handoff_queue_by_worker_index,
			       sm->first_worker_index + sm->num_workers - 1,
			       (vlib_frame_queue_t *) (~0));
    }

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 sw_if_index0;
      u32 rx_fib_index0;
      ip4_header_t * ip0;
      u8 do_handoff;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index0);

      ip0 = vlib_buffer_get_current (b0);

      next_worker_index = sm->worker_out2in_cb(ip0, rx_fib_index0);

      if (PREDICT_FALSE (next_worker_index != thread_index))
        {
          do_handoff = 1;

          if (next_worker_index != current_worker_index)
            {
              if (hf)
                hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;

              hf = vlib_get_worker_handoff_queue_elt (sm->fq_out2in_index,
                                                      next_worker_index,
                                                      handoff_queue_elt_by_worker_index);

              n_left_to_next_worker = VLIB_FRAME_SIZE - hf->n_vectors;
              to_next_worker = &hf->buffer_index[hf->n_vectors];
              current_worker_index = next_worker_index;
            }

          /* enqueue to correct worker thread */
          to_next_worker[0] = bi0;
          to_next_worker++;
          n_left_to_next_worker--;

          if (n_left_to_next_worker == 0)
            {
              hf->n_vectors = VLIB_FRAME_SIZE;
              vlib_put_frame_queue_elt (hf);
              current_worker_index = ~0;
              handoff_queue_elt_by_worker_index[next_worker_index] = 0;
              hf = 0;
            }
        }
      else
        {
          do_handoff = 0;
          /* if this is 1st frame */
          if (!f)
            {
              f = vlib_get_frame_to_node (vm, sm->out2in_node_index);
              to_next = vlib_frame_vector_args (f);
            }

          to_next[0] = bi0;
          to_next += 1;
          f->n_vectors++;
        }

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
          snat_out2in_worker_handoff_trace_t *t =
            vlib_add_trace (vm, node, b0, sizeof (*t));
          t->next_worker_index = next_worker_index;
          t->do_handoff = do_handoff;
        }
    }

  if (f)
    vlib_put_frame_to_node (vm, sm->out2in_node_index, f);

  if (hf)
    hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;

  /* Ship frames to the worker nodes */
  for (i = 0; i < vec_len (handoff_queue_elt_by_worker_index); i++)
    {
      if (handoff_queue_elt_by_worker_index[i])
	{
	  hf = handoff_queue_elt_by_worker_index[i];
	  /*
	   * It works better to let the handoff node
	   * rate-adapt, always ship the handoff queue element.
	   */
	  if (1 || hf->n_vectors == hf->last_n_vectors)
	    {
	      vlib_put_frame_queue_elt (hf);
	      handoff_queue_elt_by_worker_index[i] = 0;
	    }
	  else
	    hf->last_n_vectors = hf->n_vectors;
	}
      congested_handoff_queue_by_worker_index[i] =
	(vlib_frame_queue_t *) (~0);
    }
  hf = 0;
  current_worker_index = ~0;
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (snat_out2in_worker_handoff_node) = {
  .function = snat_out2in_worker_handoff_fn,
  .name = "nat44-out2in-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_out2in_worker_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (snat_out2in_worker_handoff_node, snat_out2in_worker_handoff_fn);

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

          if (PREDICT_FALSE(ip0->ttl == 1))
            {
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next0 = SNAT_OUT2IN_NEXT_ICMP_ERROR;
              goto trace00;
            }

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          if (PREDICT_FALSE (proto0 == ~0))
              goto trace00;

          if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
            {
              next0 = icmp_out2in(sm, b0, ip0, icmp0, sw_if_index0,
                                  rx_fib_index0, node, next0, ~0, 0, 0);
              goto trace00;
            }

          key0.addr = ip0->dst_address;
          key0.port = udp0->dst_port;
          key0.fib_index = rx_fib_index0;

          if (snat_static_mapping_match(sm, key0, &sm0, 1, 0))
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
                  old_port0 = tcp0->dst_port;
                  tcp0->dst_port = new_port0;

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
  .name = "nat44-out2in-fast",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_out2in_fast_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_out2in_error_strings),
  .error_strings = snat_out2in_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),

  .n_next_nodes = SNAT_OUT2IN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_OUT2IN_NEXT_LOOKUP] = "ip4-lookup",
    [SNAT_OUT2IN_NEXT_DROP] = "error-drop",
    [SNAT_OUT2IN_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },
};
VLIB_NODE_FUNCTION_MULTIARCH (snat_out2in_fast_node, snat_out2in_fast_node_fn);
