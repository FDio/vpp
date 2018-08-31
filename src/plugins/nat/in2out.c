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
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/ip4_fib.h>
#include <nat/nat.h>
#include <nat/nat_ipfix_logging.h>
#include <nat/nat_det.h>
#include <nat/nat_reass.h>
#include <nat/nat_inlines.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
  u32 is_slow_path;
} snat_in2out_trace_t;

typedef struct {
  u32 next_worker_index;
  u8 do_handoff;
} snat_in2out_worker_handoff_trace_t;

/* packet trace format function */
static u8 * format_snat_in2out_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snat_in2out_trace_t * t = va_arg (*args, snat_in2out_trace_t *);
  char * tag;

  tag = t->is_slow_path ? "NAT44_IN2OUT_SLOW_PATH" : "NAT44_IN2OUT_FAST_PATH";

  s = format (s, "%s: sw_if_index %d, next index %d, session %d", tag,
              t->sw_if_index, t->next_index, t->session_index);

  return s;
}

static u8 * format_snat_in2out_fast_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snat_in2out_trace_t * t = va_arg (*args, snat_in2out_trace_t *);

  s = format (s, "NAT44_IN2OUT_FAST: sw_if_index %d, next index %d",
              t->sw_if_index, t->next_index);

  return s;
}

static u8 * format_snat_in2out_worker_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snat_in2out_worker_handoff_trace_t * t =
    va_arg (*args, snat_in2out_worker_handoff_trace_t *);
  char * m;

  m = t->do_handoff ? "next worker" : "same worker";
  s = format (s, "NAT44_IN2OUT_WORKER_HANDOFF: %s %d", m, t->next_worker_index);

  return s;
}

typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u8 cached;
} nat44_in2out_reass_trace_t;

static u8 * format_nat44_in2out_reass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat44_in2out_reass_trace_t * t = va_arg (*args, nat44_in2out_reass_trace_t *);

  s = format (s, "NAT44_IN2OUT_REASS: sw_if_index %d, next index %d, status %s",
              t->sw_if_index, t->next_index,
              t->cached ? "cached" : "translated");

  return s;
}

vlib_node_registration_t snat_in2out_node;
vlib_node_registration_t snat_in2out_slowpath_node;
vlib_node_registration_t snat_in2out_fast_node;
vlib_node_registration_t snat_in2out_worker_handoff_node;
vlib_node_registration_t snat_det_in2out_node;
vlib_node_registration_t snat_in2out_output_node;
vlib_node_registration_t snat_in2out_output_slowpath_node;
vlib_node_registration_t snat_in2out_output_worker_handoff_node;
vlib_node_registration_t snat_hairpin_dst_node;
vlib_node_registration_t snat_hairpin_src_node;
vlib_node_registration_t nat44_hairpinning_node;
vlib_node_registration_t nat44_in2out_reass_node;
vlib_node_registration_t nat44_ed_in2out_node;
vlib_node_registration_t nat44_ed_in2out_slowpath_node;
vlib_node_registration_t nat44_ed_in2out_output_node;
vlib_node_registration_t nat44_ed_in2out_output_slowpath_node;
vlib_node_registration_t nat44_ed_hairpin_dst_node;
vlib_node_registration_t nat44_ed_hairpin_src_node;
vlib_node_registration_t nat44_ed_hairpinning_node;

#define foreach_snat_in2out_error                       \
_(UNSUPPORTED_PROTOCOL, "Unsupported protocol")         \
_(IN2OUT_PACKETS, "Good in2out packets processed")      \
_(OUT_OF_PORTS, "Out of ports")                         \
_(BAD_OUTSIDE_FIB, "Outside VRF ID not found")          \
_(BAD_ICMP_TYPE, "unsupported ICMP type")               \
_(NO_TRANSLATION, "No translation")                     \
_(MAX_SESSIONS_EXCEEDED, "Maximum sessions exceeded")   \
_(DROP_FRAGMENT, "Drop fragment")                       \
_(MAX_REASS, "Maximum reassemblies exceeded")           \
_(MAX_FRAG, "Maximum fragments per reassembly exceeded")\
_(FQ_CONGESTED, "Handoff frame queue congested")

typedef enum {
#define _(sym,str) SNAT_IN2OUT_ERROR_##sym,
  foreach_snat_in2out_error
#undef _
  SNAT_IN2OUT_N_ERROR,
} snat_in2out_error_t;

static char * snat_in2out_error_strings[] = {
#define _(sym,string) string,
  foreach_snat_in2out_error
#undef _
};

typedef enum {
  SNAT_IN2OUT_NEXT_LOOKUP,
  SNAT_IN2OUT_NEXT_DROP,
  SNAT_IN2OUT_NEXT_ICMP_ERROR,
  SNAT_IN2OUT_NEXT_SLOW_PATH,
  SNAT_IN2OUT_NEXT_REASS,
  SNAT_IN2OUT_N_NEXT,
} snat_in2out_next_t;

typedef enum {
  SNAT_HAIRPIN_SRC_NEXT_DROP,
  SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT,
  SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT_WH,
  SNAT_HAIRPIN_SRC_NEXT_INTERFACE_OUTPUT,
  SNAT_HAIRPIN_SRC_N_NEXT,
} snat_hairpin_next_t;

/**
 * @brief Check if packet should be translated
 *
 * Packets aimed at outside interface and external address with active session
 * should be translated.
 *
 * @param sm            NAT main
 * @param rt            NAT runtime data
 * @param sw_if_index0  index of the inside interface
 * @param ip0           IPv4 header
 * @param proto0        NAT protocol
 * @param rx_fib_index0 RX FIB index
 *
 * @returns 0 if packet should be translated otherwise 1
 */
static inline int
snat_not_translate_fast (snat_main_t * sm, vlib_node_runtime_t *node,
                         u32 sw_if_index0, ip4_header_t * ip0, u32 proto0,
                         u32 rx_fib_index0)
{
  if (sm->out2in_dpo)
    return 0;

  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  nat_outside_fib_t *outside_fib;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
        .ip4.as_u32 = ip0->dst_address.as_u32,
    },
  };

  /* Don't NAT packet aimed at the intfc address */
  if (PREDICT_FALSE(is_interface_addr(sm, node, sw_if_index0,
                                      ip0->dst_address.as_u32)))
    return 1;

  fei = fib_table_lookup (rx_fib_index0, &pfx);
  if (FIB_NODE_INDEX_INVALID != fei)
    {
      u32 sw_if_index = fib_entry_get_resolving_interface (fei);
      if (sw_if_index == ~0)
        {
          vec_foreach (outside_fib, sm->outside_fibs)
            {
              fei = fib_table_lookup (outside_fib->fib_index, &pfx);
              if (FIB_NODE_INDEX_INVALID != fei)
                {
                  sw_if_index = fib_entry_get_resolving_interface (fei);
                  if (sw_if_index != ~0)
                    break;
                }
            }
        }
      if (sw_if_index == ~0)
        return 1;

      snat_interface_t *i;
      pool_foreach (i, sm->interfaces,
      ({
        /* NAT packet aimed at outside interface */
        if ((nat_interface_is_outside(i)) && (sw_if_index == i->sw_if_index))
          return 0;
      }));
    }

  return 1;
}

static inline int
snat_not_translate (snat_main_t * sm, vlib_node_runtime_t *node,
                    u32 sw_if_index0, ip4_header_t * ip0, u32 proto0,
                    u32 rx_fib_index0, u32 thread_index)
{
  udp_header_t * udp0 = ip4_next_header (ip0);
  snat_session_key_t key0, sm0;
  clib_bihash_kv_8_8_t kv0, value0;

  key0.addr = ip0->dst_address;
  key0.port = udp0->dst_port;
  key0.protocol = proto0;
  key0.fib_index = sm->outside_fib_index;
  kv0.key = key0.as_u64;

  /* NAT packet aimed at external address if */
  /* has active sessions */
  if (clib_bihash_search_8_8 (&sm->per_thread_data[thread_index].out2in, &kv0,
                              &value0))
    {
      /* or is static mappings */
      if (!snat_static_mapping_match(sm, key0, &sm0, 1, 0, 0, 0))
        return 0;
    }
  else
    return 0;

  if (sm->forwarding_enabled)
    return 1;

  return snat_not_translate_fast(sm, node, sw_if_index0, ip0, proto0,
                                 rx_fib_index0);
}

static inline int
nat_not_translate_output_feature (snat_main_t * sm, ip4_header_t * ip0,
                                  u32 proto0, u16 src_port, u16 dst_port,
                                  u32 thread_index, u32 sw_if_index)
{
  snat_session_key_t key0;
  clib_bihash_kv_8_8_t kv0, value0;
  snat_interface_t *i;

  /* src NAT check */
  key0.addr = ip0->src_address;
  key0.port = src_port;
  key0.protocol = proto0;
  key0.fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);
  kv0.key = key0.as_u64;

  if (!clib_bihash_search_8_8 (&sm->per_thread_data[thread_index].out2in, &kv0,
                               &value0))
    return 1;

  /* dst NAT check */
  key0.addr = ip0->dst_address;
  key0.port = dst_port;
  key0.protocol = proto0;
  kv0.key = key0.as_u64;
  if (!clib_bihash_search_8_8 (&sm->per_thread_data[thread_index].in2out, &kv0,
                               &value0))
  {
    /* hairpinning */
    pool_foreach (i, sm->output_feature_interfaces,
    ({
      if ((nat_interface_is_inside(i)) && (sw_if_index == i->sw_if_index))
        return 0;
    }));
    return 1;
  }

  return 0;
}

static u32 slow_path (snat_main_t *sm, vlib_buffer_t *b0,
                      ip4_header_t * ip0,
                      u32 rx_fib_index0,
                      snat_session_key_t * key0,
                      snat_session_t ** sessionp,
                      vlib_node_runtime_t * node,
                      u32 next0,
                      u32 thread_index)
{
  snat_user_t *u;
  snat_session_t *s;
  clib_bihash_kv_8_8_t kv0;
  snat_session_key_t key1;
  u32 address_index = ~0;
  udp_header_t * udp0 = ip4_next_header (ip0);
  u8 is_sm = 0;
  nat_outside_fib_t *outside_fib;
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
        .ip4.as_u32 = ip0->dst_address.as_u32,
    },
  };

  if (PREDICT_FALSE (maximum_sessions_exceeded(sm, thread_index)))
    {
      b0->error = node->errors[SNAT_IN2OUT_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_ipfix_logging_max_sessions(sm->max_translations);
      nat_log_notice ("maximum sessions exceeded");
      return SNAT_IN2OUT_NEXT_DROP;
    }

  key1.protocol = key0->protocol;

  u = nat_user_get_or_create (sm, &ip0->src_address, rx_fib_index0,
                              thread_index);
  if (!u)
    {
      nat_log_warn ("create NAT user failed");
      return SNAT_IN2OUT_NEXT_DROP;
    }

  /* First try to match static mapping by local address and port */
  if (snat_static_mapping_match (sm, *key0, &key1, 0, 0, 0, 0))
    {
      /* Try to create dynamic translation */
      if (snat_alloc_outside_address_and_port (sm->addresses, rx_fib_index0,
                                               thread_index, &key1,
                                               &address_index,
                                               sm->port_per_thread,
                                               sm->per_thread_data[thread_index].snat_thread_index))
        {
          b0->error = node->errors[SNAT_IN2OUT_ERROR_OUT_OF_PORTS];
          return SNAT_IN2OUT_NEXT_DROP;
        }
    }
  else
    is_sm = 1;

  s = nat_session_alloc_or_recycle (sm, u, thread_index);
  if (!s)
    {
      nat_log_warn ("create NAT session failed");
      return SNAT_IN2OUT_NEXT_DROP;
    }

  if (is_sm)
    s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
  user_session_increment (sm, u, is_sm);
  s->outside_address_index = address_index;
  s->in2out = *key0;
  s->out2in = key1;
  s->out2in.protocol = key0->protocol;
  s->out2in.fib_index = sm->outside_fib_index;
  switch (vec_len (sm->outside_fibs))
    {
    case 0:
      s->out2in.fib_index = sm->outside_fib_index;
      break;
    case 1:
      s->out2in.fib_index = sm->outside_fibs[0].fib_index;
      break;
    default:
      vec_foreach (outside_fib, sm->outside_fibs)
        {
          fei = fib_table_lookup (outside_fib->fib_index, &pfx);
          if (FIB_NODE_INDEX_INVALID != fei)
            {
              if (fib_entry_get_resolving_interface (fei) != ~0)
                {
                  s->out2in.fib_index = outside_fib->fib_index;
                  break;
                }
            }
        }
      break;
    }
  s->ext_host_addr.as_u32 = ip0->dst_address.as_u32;
  s->ext_host_port = udp0->dst_port;
  *sessionp = s;

  /* Add to translation hashes */
  kv0.key = s->in2out.as_u64;
  kv0.value = s - sm->per_thread_data[thread_index].sessions;
  if (clib_bihash_add_del_8_8 (&sm->per_thread_data[thread_index].in2out, &kv0,
                               1 /* is_add */))
      nat_log_notice ("in2out key add failed");

  kv0.key = s->out2in.as_u64;
  kv0.value = s - sm->per_thread_data[thread_index].sessions;

  if (clib_bihash_add_del_8_8 (&sm->per_thread_data[thread_index].out2in, &kv0,
                               1 /* is_add */))
      nat_log_notice ("out2in key add failed");

  /* log NAT event */
  snat_ipfix_logging_nat44_ses_create(s->in2out.addr.as_u32,
                                      s->out2in.addr.as_u32,
                                      s->in2out.protocol,
                                      s->in2out.port,
                                      s->out2in.port,
                                      s->in2out.fib_index);
  return next0;
}

static_always_inline
snat_in2out_error_t icmp_get_key(ip4_header_t *ip0,
                                 snat_session_key_t *p_key0)
{
  icmp46_header_t *icmp0;
  snat_session_key_t key0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0 = 0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *)(icmp0+1);

  if (!icmp_is_error_message (icmp0))
    {
      key0.protocol = SNAT_PROTOCOL_ICMP;
      key0.addr = ip0->src_address;
      key0.port = echo0->identifier;
    }
  else
    {
      inner_ip0 = (ip4_header_t *)(echo0+1);
      l4_header = ip4_next_header (inner_ip0);
      key0.protocol = ip_proto_to_snat_proto (inner_ip0->protocol);
      key0.addr = inner_ip0->dst_address;
      switch (key0.protocol)
        {
        case SNAT_PROTOCOL_ICMP:
          inner_icmp0 = (icmp46_header_t*)l4_header;
          inner_echo0 = (icmp_echo_header_t *)(inner_icmp0+1);
          key0.port = inner_echo0->identifier;
          break;
        case SNAT_PROTOCOL_UDP:
        case SNAT_PROTOCOL_TCP:
          key0.port = ((tcp_udp_header_t*)l4_header)->dst_port;
          break;
        default:
          return SNAT_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL;
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
u32 icmp_match_in2out_slow(snat_main_t *sm, vlib_node_runtime_t *node,
                           u32 thread_index, vlib_buffer_t *b0,
                           ip4_header_t *ip0, u8 *p_proto,
                           snat_session_key_t *p_value,
                           u8 *p_dont_translate, void *d, void *e)
{
  icmp46_header_t *icmp0;
  u32 sw_if_index0;
  u32 rx_fib_index0;
  snat_session_key_t key0;
  snat_session_t *s0 = 0;
  u8 dont_translate = 0;
  clib_bihash_kv_8_8_t kv0, value0;
  u32 next0 = ~0;
  int err;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  err = icmp_get_key (ip0, &key0);
  if (err != -1)
    {
      b0->error = node->errors[err];
      next0 = SNAT_IN2OUT_NEXT_DROP;
      goto out;
    }
  key0.fib_index = rx_fib_index0;

  kv0.key = key0.as_u64;

  if (clib_bihash_search_8_8 (&sm->per_thread_data[thread_index].in2out, &kv0,
                              &value0))
    {
      if (vnet_buffer(b0)->sw_if_index[VLIB_TX] != ~0)
        {
          if (PREDICT_FALSE(nat_not_translate_output_feature(sm, ip0,
              key0.protocol, key0.port, key0.port, thread_index, sw_if_index0)))
            {
              dont_translate = 1;
              goto out;
            }
        }
      else
        {
          if (PREDICT_FALSE(snat_not_translate(sm, node, sw_if_index0,
              ip0, SNAT_PROTOCOL_ICMP, rx_fib_index0, thread_index)))
            {
              dont_translate = 1;
              goto out;
            }
        }

      if (PREDICT_FALSE(icmp_is_error_message (icmp0)))
        {
          b0->error = node->errors[SNAT_IN2OUT_ERROR_BAD_ICMP_TYPE];
          next0 = SNAT_IN2OUT_NEXT_DROP;
          goto out;
        }

      next0 = slow_path (sm, b0, ip0, rx_fib_index0, &key0,
                         &s0, node, next0, thread_index);

      if (PREDICT_FALSE (next0 == SNAT_IN2OUT_NEXT_DROP))
        goto out;
    }
  else
    {
      if (PREDICT_FALSE(icmp0->type != ICMP4_echo_request &&
                        icmp0->type != ICMP4_echo_reply &&
                        !icmp_is_error_message (icmp0)))
        {
          b0->error = node->errors[SNAT_IN2OUT_ERROR_BAD_ICMP_TYPE];
          next0 = SNAT_IN2OUT_NEXT_DROP;
          goto out;
        }

      s0 = pool_elt_at_index (sm->per_thread_data[thread_index].sessions,
                              value0.value);
    }

out:
  *p_proto = key0.protocol;
  if (s0)
    *p_value = s0->out2in;
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
u32 icmp_match_in2out_fast(snat_main_t *sm, vlib_node_runtime_t *node,
                           u32 thread_index, vlib_buffer_t *b0,
                           ip4_header_t *ip0, u8 *p_proto,
                           snat_session_key_t *p_value,
                           u8 *p_dont_translate, void *d, void *e)
{
  icmp46_header_t *icmp0;
  u32 sw_if_index0;
  u32 rx_fib_index0;
  snat_session_key_t key0;
  snat_session_key_t sm0;
  u8 dont_translate = 0;
  u8 is_addr_only;
  u32 next0 = ~0;
  int err;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  err = icmp_get_key (ip0, &key0);
  if (err != -1)
    {
      b0->error = node->errors[err];
      next0 = SNAT_IN2OUT_NEXT_DROP;
      goto out2;
    }
  key0.fib_index = rx_fib_index0;

  if (snat_static_mapping_match(sm, key0, &sm0, 0, &is_addr_only, 0, 0))
    {
      if (PREDICT_FALSE(snat_not_translate_fast(sm, node, sw_if_index0, ip0,
          IP_PROTOCOL_ICMP, rx_fib_index0)))
        {
          dont_translate = 1;
          goto out;
        }

      if (icmp_is_error_message (icmp0))
        {
          next0 = SNAT_IN2OUT_NEXT_DROP;
          goto out;
        }

      b0->error = node->errors[SNAT_IN2OUT_ERROR_NO_TRANSLATION];
      next0 = SNAT_IN2OUT_NEXT_DROP;
      goto out;
    }

  if (PREDICT_FALSE(icmp0->type != ICMP4_echo_request &&
                    (icmp0->type != ICMP4_echo_reply || !is_addr_only) &&
                    !icmp_is_error_message (icmp0)))
    {
      b0->error = node->errors[SNAT_IN2OUT_ERROR_BAD_ICMP_TYPE];
      next0 = SNAT_IN2OUT_NEXT_DROP;
      goto out;
    }

out:
  *p_value = sm0;
out2:
  *p_proto = key0.protocol;
  *p_dont_translate = dont_translate;
  return next0;
}

static inline u32 icmp_in2out (snat_main_t *sm,
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
  ip4_header_t *inner_ip0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;
  u8 dont_translate;
  u32 new_addr0, old_addr0;
  u16 old_id0, new_id0;
  ip_csum_t sum0;
  u16 checksum0;
  u32 next0_tmp;

  echo0 = (icmp_echo_header_t *)(icmp0+1);

  next0_tmp = sm->icmp_match_in2out_cb(sm, node, thread_index, b0, ip0,
                                       &protocol, &sm0, &dont_translate, d, e);
  if (next0_tmp != ~0)
    next0 = next0_tmp;
  if (next0 == SNAT_IN2OUT_NEXT_DROP || dont_translate)
    goto out;

  sum0 = ip_incremental_checksum (0, icmp0,
                                  ntohs(ip0->length) - ip4_header_bytes (ip0));
  checksum0 = ~ip_csum_fold (sum0);
  if (PREDICT_FALSE(checksum0 != 0 && checksum0 != 0xffff))
    {
      next0 = SNAT_IN2OUT_NEXT_DROP;
      goto out;
    }

  old_addr0 = ip0->src_address.as_u32;
  new_addr0 = ip0->src_address.as_u32 = sm0.addr.as_u32;
  if (vnet_buffer(b0)->sw_if_index[VLIB_TX] == ~0)
    vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm0.fib_index;

  sum0 = ip0->checksum;
  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                         src_address /* changed member */);
  ip0->checksum = ip_csum_fold (sum0);

  if (icmp0->checksum == 0)
    icmp0->checksum = 0xffff;

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
                                 identifier);
          icmp0->checksum = ip_csum_fold (sum0);
        }
    }
  else
    {
      inner_ip0 = (ip4_header_t *)(echo0+1);
      l4_header = ip4_next_header (inner_ip0);

      if (!ip4_header_checksum_is_valid (inner_ip0))
        {
          next0 = SNAT_IN2OUT_NEXT_DROP;
          goto out;
        }

      old_addr0 = inner_ip0->dst_address.as_u32;
      inner_ip0->dst_address = sm0.addr;
      new_addr0 = inner_ip0->dst_address.as_u32;

      sum0 = icmp0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                             dst_address /* changed member */);
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
            old_id0 = ((tcp_udp_header_t*)l4_header)->dst_port;
            new_id0 = sm0.port;
            ((tcp_udp_header_t*)l4_header)->dst_port = new_id0;

            sum0 = icmp0->checksum;
            sum0 = ip_csum_update (sum0, old_id0, new_id0, tcp_udp_header_t,
                                   dst_port);
            icmp0->checksum = ip_csum_fold (sum0);
            break;
          default:
            ASSERT(0);
        }
    }

out:
  return next0;
}

/**
 * @brief Hairpinning
 *
 * Hairpinning allows two endpoints on the internal side of the NAT to
 * communicate even if they only use each other's external IP addresses
 * and ports.
 *
 * @param sm     NAT main.
 * @param b0     Vlib buffer.
 * @param ip0    IP header.
 * @param udp0   UDP header.
 * @param tcp0   TCP header.
 * @param proto0 NAT protocol.
 */
static inline int
snat_hairpinning (snat_main_t *sm,
                  vlib_buffer_t * b0,
                  ip4_header_t * ip0,
                  udp_header_t * udp0,
                  tcp_header_t * tcp0,
                  u32 proto0,
                  int is_ed)
{
  snat_session_key_t key0, sm0;
  snat_session_t * s0;
  clib_bihash_kv_8_8_t kv0, value0;
  ip_csum_t sum0;
  u32 new_dst_addr0 = 0, old_dst_addr0, ti = 0, si;
  u16 new_dst_port0, old_dst_port0;
  int rv;

  key0.addr = ip0->dst_address;
  key0.port = udp0->dst_port;
  key0.protocol = proto0;
  key0.fib_index = sm->outside_fib_index;
  kv0.key = key0.as_u64;

  /* Check if destination is static mappings */
  if (!snat_static_mapping_match(sm, key0, &sm0, 1, 0, 0, 0))
    {
      new_dst_addr0 = sm0.addr.as_u32;
      new_dst_port0 = sm0.port;
      vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm0.fib_index;
    }
  /* or active session */
  else
    {
      if (sm->num_workers > 1)
        ti = (clib_net_to_host_u16 (udp0->dst_port) - 1024) / sm->port_per_thread;
      else
        ti = sm->num_workers;

      if (is_ed)
        {
          clib_bihash_kv_16_8_t ed_kv, ed_value;
          make_ed_kv (&ed_kv, &ip0->dst_address, &ip0->src_address,
                      ip0->protocol, sm->outside_fib_index, udp0->dst_port,
                      udp0->src_port);
          rv = clib_bihash_search_16_8 (&sm->per_thread_data[ti].out2in_ed,
                                        &ed_kv, &ed_value);
          si = ed_value.value;
        }
      else
        {
          rv = clib_bihash_search_8_8 (&sm->per_thread_data[ti].out2in, &kv0,
                                       &value0);
          si = value0.value;
        }
      if (rv)
        return 0;

      s0 = pool_elt_at_index (sm->per_thread_data[ti].sessions, si);
      new_dst_addr0 = s0->in2out.addr.as_u32;
      new_dst_port0 = s0->in2out.port;
      vnet_buffer(b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;
    }

  /* Destination is behind the same NAT, use internal address and port */
  if (new_dst_addr0)
    {
      old_dst_addr0 = ip0->dst_address.as_u32;
      ip0->dst_address.as_u32 = new_dst_addr0;
      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
                             ip4_header_t, dst_address);
      ip0->checksum = ip_csum_fold (sum0);

      old_dst_port0 = tcp0->dst;
      if (PREDICT_TRUE(new_dst_port0 != old_dst_port0))
        {
          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              tcp0->dst = new_dst_port0;
              sum0 = tcp0->checksum;
              sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
                                     ip4_header_t, dst_address);
              sum0 = ip_csum_update (sum0, old_dst_port0, new_dst_port0,
                                     ip4_header_t /* cheat */, length);
              tcp0->checksum = ip_csum_fold(sum0);
            }
          else
            {
              udp0->dst_port = new_dst_port0;
              udp0->checksum = 0;
            }
        }
      else
        {
          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              sum0 = tcp0->checksum;
              sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
                                     ip4_header_t, dst_address);
              tcp0->checksum = ip_csum_fold(sum0);
            }
        }
      return 1;
    }
  return 0;
}

static inline void
snat_icmp_hairpinning (snat_main_t *sm,
                       vlib_buffer_t * b0,
                       ip4_header_t * ip0,
                       icmp46_header_t * icmp0,
                       int is_ed)
{
  snat_session_key_t key0, sm0;
  clib_bihash_kv_8_8_t kv0, value0;
  u32 new_dst_addr0 = 0, old_dst_addr0, si, ti = 0;
  ip_csum_t sum0;
  snat_session_t *s0;
  int rv;

  if (!icmp_is_error_message (icmp0))
    {
      icmp_echo_header_t *echo0 = (icmp_echo_header_t *)(icmp0+1);
      u16 icmp_id0 = echo0->identifier;
      key0.addr = ip0->dst_address;
      key0.port = icmp_id0;
      key0.protocol = SNAT_PROTOCOL_ICMP;
      key0.fib_index = sm->outside_fib_index;
      kv0.key = key0.as_u64;

      if (sm->num_workers > 1)
        ti = (clib_net_to_host_u16 (icmp_id0) - 1024) / sm->port_per_thread;
      else
        ti = sm->num_workers;

      /* Check if destination is in active sessions */
      if (is_ed)
        {
          clib_bihash_kv_16_8_t ed_kv, ed_value;
          make_ed_kv (&ed_kv, &ip0->dst_address, &ip0->src_address,
                      IP_PROTOCOL_ICMP, sm->outside_fib_index, icmp_id0, 0);
          rv = clib_bihash_search_16_8 (&sm->per_thread_data[ti].out2in_ed,
                                        &ed_kv, &ed_value);
          si = ed_value.value;
        }
      else
        {
          rv = clib_bihash_search_8_8 (&sm->per_thread_data[ti].out2in, &kv0,
                                       &value0);
          si = value0.value;
        }
      if (rv)
        {
          /* or static mappings */
          if (!snat_static_mapping_match(sm, key0, &sm0, 1, 0, 0, 0))
            {
              new_dst_addr0 = sm0.addr.as_u32;
              vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm0.fib_index;
            }
        }
      else
        {
          s0 = pool_elt_at_index (sm->per_thread_data[ti].sessions, si);
          new_dst_addr0 = s0->in2out.addr.as_u32;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;
          echo0->identifier = s0->in2out.port;
          sum0 = icmp0->checksum;
          sum0 = ip_csum_update (sum0, icmp_id0, s0->in2out.port,
                                 icmp_echo_header_t, identifier);
          icmp0->checksum = ip_csum_fold (sum0);
        }

      /* Destination is behind the same NAT, use internal address and port */
      if (new_dst_addr0)
        {
          old_dst_addr0 = ip0->dst_address.as_u32;
          ip0->dst_address.as_u32 = new_dst_addr0;
          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
                                 ip4_header_t, dst_address);
          ip0->checksum = ip_csum_fold (sum0);
        }
    }

}

static inline u32 icmp_in2out_slow_path (snat_main_t *sm,
                                         vlib_buffer_t * b0,
                                         ip4_header_t * ip0,
                                         icmp46_header_t * icmp0,
                                         u32 sw_if_index0,
                                         u32 rx_fib_index0,
                                         vlib_node_runtime_t * node,
                                         u32 next0,
                                         f64 now,
                                         u32 thread_index,
                                         snat_session_t ** p_s0)
{
  next0 = icmp_in2out(sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
                      next0, thread_index, p_s0, 0);
  snat_session_t * s0 = *p_s0;
  if (PREDICT_TRUE(next0 != SNAT_IN2OUT_NEXT_DROP && s0))
    {
      /* Hairpinning */
      if (vnet_buffer(b0)->sw_if_index[VLIB_TX] == 0)
        snat_icmp_hairpinning(sm, b0, ip0, icmp0, sm->endpoint_dependent);
      /* Accounting */
      nat44_session_update_counters (s0, now,
                                     vlib_buffer_length_in_chain (sm->vlib_main, b0));
      /* Per-user LRU list maintenance */
      nat44_session_update_lru (sm, s0, thread_index);
    }
  return next0;
}

static inline void
nat_hairpinning_sm_unknown_proto (snat_main_t * sm,
                                  vlib_buffer_t * b,
                                  ip4_header_t * ip)
{
  clib_bihash_kv_8_8_t kv, value;
  snat_static_mapping_t *m;
  u32 old_addr, new_addr;
  ip_csum_t sum;

  make_sm_kv (&kv, &ip->dst_address, 0, 0, 0);
  if (clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    return;

  m = pool_elt_at_index (sm->static_mappings, value.value);

  old_addr = ip->dst_address.as_u32;
  new_addr = ip->dst_address.as_u32 = m->local_addr.as_u32;
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
  ip->checksum = ip_csum_fold (sum);

  if (vnet_buffer(b)->sw_if_index[VLIB_TX] == ~0)
    vnet_buffer(b)->sw_if_index[VLIB_TX] = m->fib_index;
}

static int
nat_in2out_sm_unknown_proto (snat_main_t *sm,
                             vlib_buffer_t * b,
                             ip4_header_t * ip,
                             u32 rx_fib_index)
{
  clib_bihash_kv_8_8_t kv, value;
  snat_static_mapping_t *m;
  snat_session_key_t m_key;
  u32 old_addr, new_addr;
  ip_csum_t sum;

  m_key.addr = ip->src_address;
  m_key.port = 0;
  m_key.protocol = 0;
  m_key.fib_index = rx_fib_index;
  kv.key = m_key.as_u64;
  if (clib_bihash_search_8_8 (&sm->static_mapping_by_local, &kv, &value))
    return 1;

  m = pool_elt_at_index (sm->static_mappings, value.value);

  old_addr = ip->src_address.as_u32;
  new_addr = ip->src_address.as_u32 = m->external_addr.as_u32;
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, src_address);
  ip->checksum = ip_csum_fold (sum);


  /* Hairpinning */
  if (vnet_buffer(b)->sw_if_index[VLIB_TX] == ~0)
    {
      vnet_buffer(b)->sw_if_index[VLIB_TX] = m->fib_index;
      nat_hairpinning_sm_unknown_proto (sm, b, ip);
    }

  return 0;
}

static inline uword
snat_in2out_node_fn_inline (vlib_main_t * vm,
                            vlib_node_runtime_t * node,
                            vlib_frame_t * frame, int is_slow_path,
                            int is_output_feature)
{
  u32 n_left_from, * from, * to_next;
  snat_in2out_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t * sm = &snat_main;
  f64 now = vlib_time_now (vm);
  u32 stats_node_index;
  u32 thread_index = vm->thread_index;

  stats_node_index = is_slow_path ? snat_in2out_slowpath_node.index :
    snat_in2out_node.index;

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
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;
          ip4_header_t * ip0, * ip1;
          ip_csum_t sum0, sum1;
          u32 new_addr0, old_addr0, new_addr1, old_addr1;
          u16 old_port0, new_port0, old_port1, new_port1;
          udp_header_t * udp0, * udp1;
          tcp_header_t * tcp0, * tcp1;
          icmp46_header_t * icmp0, * icmp1;
          snat_session_key_t key0, key1;
          u32 rx_fib_index0, rx_fib_index1;
          u32 proto0, proto1;
          snat_session_t * s0 = 0, * s1 = 0;
          clib_bihash_kv_8_8_t kv0, value0, kv1, value1;
          u32 iph_offset0 = 0, iph_offset1 = 0;

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

          if (is_output_feature)
            iph_offset0 = vnet_buffer (b0)->ip.save_rewrite_length;

          ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
                 iph_offset0);

          udp0 = ip4_next_header (ip0);
          tcp0 = (tcp_header_t *) udp0;
          icmp0 = (icmp46_header_t *) udp0;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 = vec_elt (sm->ip4_main->fib_index_by_sw_if_index,
                                   sw_if_index0);

          next0 = next1 = SNAT_IN2OUT_NEXT_LOOKUP;

          if (PREDICT_FALSE(ip0->ttl == 1))
            {
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next0 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
              goto trace00;
            }

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          /* Next configured feature, probably ip4-lookup */
          if (is_slow_path)
            {
              if (PREDICT_FALSE (proto0 == ~0))
                {
                  if (nat_in2out_sm_unknown_proto (sm, b0, ip0, rx_fib_index0))
                    {
                      next0 = SNAT_IN2OUT_NEXT_DROP;
                      b0->error = node->errors[SNAT_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
                    }
                  goto trace00;
                }

              if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
                {
                  next0 = icmp_in2out_slow_path
                    (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0,
                     node, next0, now, thread_index, &s0);
                  goto trace00;
                }
            }
          else
            {
              if (PREDICT_FALSE (proto0 == ~0 || proto0 == SNAT_PROTOCOL_ICMP))
                {
                  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace00;
                }

              if (ip4_is_fragment (ip0))
                {
                  next0 = SNAT_IN2OUT_NEXT_REASS;
                  goto trace00;
                }
            }

          key0.addr = ip0->src_address;
          key0.port = udp0->src_port;
          key0.protocol = proto0;
          key0.fib_index = rx_fib_index0;

          kv0.key = key0.as_u64;

          if (PREDICT_FALSE (clib_bihash_search_8_8 (
              &sm->per_thread_data[thread_index].in2out, &kv0, &value0) != 0))
            {
              if (is_slow_path)
                {
                  if (is_output_feature)
                    {
                      if (PREDICT_FALSE(nat_not_translate_output_feature(sm,
                          ip0, proto0, udp0->src_port, udp0->dst_port, thread_index, sw_if_index0)))
                        goto trace00;
                    }
                  else
                    {
                      if (PREDICT_FALSE(snat_not_translate(sm, node, sw_if_index0,
                          ip0, proto0, rx_fib_index0, thread_index)))
                        goto trace00;
                    }

                  next0 = slow_path (sm, b0, ip0, rx_fib_index0, &key0,
                                     &s0, node, next0, thread_index);
                  if (PREDICT_FALSE (next0 == SNAT_IN2OUT_NEXT_DROP))
                    goto trace00;
                }
              else
                {
                  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace00;
                }
            }
          else
            s0 = pool_elt_at_index (sm->per_thread_data[thread_index].sessions,
                                    value0.value);

          b0->flags |= VNET_BUFFER_F_IS_NATED;

          old_addr0 = ip0->src_address.as_u32;
          ip0->src_address = s0->out2in.addr;
          new_addr0 = ip0->src_address.as_u32;
          if (!is_output_feature)
            vnet_buffer(b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                                 ip4_header_t,
                                 src_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              old_port0 = tcp0->src_port;
              tcp0->src_port = s0->out2in.port;
              new_port0 = tcp0->src_port;

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
              old_port0 = udp0->src_port;
              udp0->src_port = s0->out2in.port;
              udp0->checksum = 0;
            }

          /* Accounting */
          nat44_session_update_counters (s0, now,
                                         vlib_buffer_length_in_chain (vm, b0));
          /* Per-user LRU list maintenance */
          nat44_session_update_lru (sm, s0, thread_index);
        trace00:

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_in2out_trace_t *t =
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->is_slow_path = is_slow_path;
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
                  t->session_index = ~0;
              if (s0)
                t->session_index = s0 - sm->per_thread_data[thread_index].sessions;
            }

          pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;

          if (is_output_feature)
            iph_offset1 = vnet_buffer (b1)->ip.save_rewrite_length;

          ip1 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b1) +
                 iph_offset1);

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
              next1 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
              goto trace01;
            }

          proto1 = ip_proto_to_snat_proto (ip1->protocol);

          /* Next configured feature, probably ip4-lookup */
          if (is_slow_path)
            {
              if (PREDICT_FALSE (proto1 == ~0))
                {
                  if (nat_in2out_sm_unknown_proto (sm, b1, ip1, rx_fib_index1))
                    {
                      next1 = SNAT_IN2OUT_NEXT_DROP;
                      b1->error = node->errors[SNAT_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
                    }
                  goto trace01;
                }

              if (PREDICT_FALSE (proto1 == SNAT_PROTOCOL_ICMP))
                {
                  next1 = icmp_in2out_slow_path
                    (sm, b1, ip1, icmp1, sw_if_index1, rx_fib_index1, node,
                     next1, now, thread_index, &s1);
                  goto trace01;
                }
            }
          else
            {
              if (PREDICT_FALSE (proto1 == ~0 || proto1 == SNAT_PROTOCOL_ICMP))
                {
                  next1 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace01;
                }

              if (ip4_is_fragment (ip1))
                {
                  next1 = SNAT_IN2OUT_NEXT_REASS;
                  goto trace01;
                }
            }

          key1.addr = ip1->src_address;
          key1.port = udp1->src_port;
          key1.protocol = proto1;
          key1.fib_index = rx_fib_index1;

          kv1.key = key1.as_u64;

            if (PREDICT_FALSE(clib_bihash_search_8_8 (
                &sm->per_thread_data[thread_index].in2out, &kv1, &value1) != 0))
            {
              if (is_slow_path)
                {
                  if (is_output_feature)
                    {
                      if (PREDICT_FALSE(nat_not_translate_output_feature(sm,
                          ip1, proto1, udp1->src_port, udp1->dst_port, thread_index, sw_if_index1)))
                        goto trace01;
                    }
                  else
                    {
                      if (PREDICT_FALSE(snat_not_translate(sm, node, sw_if_index1,
                          ip1, proto1, rx_fib_index1, thread_index)))
                        goto trace01;
                    }

                  next1 = slow_path (sm, b1, ip1, rx_fib_index1, &key1,
                                     &s1, node, next1, thread_index);
                  if (PREDICT_FALSE (next1 == SNAT_IN2OUT_NEXT_DROP))
                    goto trace01;
                }
              else
                {
                  next1 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace01;
                }
            }
          else
            s1 = pool_elt_at_index (sm->per_thread_data[thread_index].sessions,
                                    value1.value);

          b1->flags |= VNET_BUFFER_F_IS_NATED;

          old_addr1 = ip1->src_address.as_u32;
          ip1->src_address = s1->out2in.addr;
          new_addr1 = ip1->src_address.as_u32;
          if (!is_output_feature)
            vnet_buffer(b1)->sw_if_index[VLIB_TX] = s1->out2in.fib_index;

          sum1 = ip1->checksum;
          sum1 = ip_csum_update (sum1, old_addr1, new_addr1,
                                 ip4_header_t,
                                 src_address /* changed member */);
          ip1->checksum = ip_csum_fold (sum1);

          if (PREDICT_TRUE(proto1 == SNAT_PROTOCOL_TCP))
            {
              old_port1 = tcp1->src_port;
              tcp1->src_port = s1->out2in.port;
              new_port1 = tcp1->src_port;

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
              old_port1 = udp1->src_port;
              udp1->src_port = s1->out2in.port;
              udp1->checksum = 0;
            }

          /* Accounting */
          nat44_session_update_counters (s1, now,
                                         vlib_buffer_length_in_chain (vm, b1));
          /* Per-user LRU list maintenance */
          nat44_session_update_lru (sm, s1, thread_index);
        trace01:

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b1->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_in2out_trace_t *t =
                 vlib_add_trace (vm, node, b1, sizeof (*t));
              t->sw_if_index = sw_if_index1;
              t->next_index = next1;
              t->session_index = ~0;
              if (s1)
                t->session_index = s1 - sm->per_thread_data[thread_index].sessions;
            }

          pkts_processed += next1 != SNAT_IN2OUT_NEXT_DROP;

          /* verify speculative enqueues, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0;
          u32 sw_if_index0;
          ip4_header_t * ip0;
          ip_csum_t sum0;
          u32 new_addr0, old_addr0;
          u16 old_port0, new_port0;
          udp_header_t * udp0;
          tcp_header_t * tcp0;
          icmp46_header_t * icmp0;
          snat_session_key_t key0;
          u32 rx_fib_index0;
          u32 proto0;
          snat_session_t * s0 = 0;
          clib_bihash_kv_8_8_t kv0, value0;
          u32 iph_offset0 = 0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          next0 = SNAT_IN2OUT_NEXT_LOOKUP;

          if (is_output_feature)
            iph_offset0 = vnet_buffer (b0)->ip.save_rewrite_length;

          ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
                 iph_offset0);

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
              next0 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
              goto trace0;
            }

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          /* Next configured feature, probably ip4-lookup */
          if (is_slow_path)
            {
              if (PREDICT_FALSE (proto0 == ~0))
                {
                  if (nat_in2out_sm_unknown_proto (sm, b0, ip0, rx_fib_index0))
                    {
                      next0 = SNAT_IN2OUT_NEXT_DROP;
                      b0->error = node->errors[SNAT_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
                    }
                  goto trace0;
                }

              if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
                {
                  next0 = icmp_in2out_slow_path
                    (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
                     next0, now, thread_index, &s0);
                  goto trace0;
                }
            }
          else
            {
              if (PREDICT_FALSE (proto0 == ~0 || proto0 == SNAT_PROTOCOL_ICMP))
                {
                  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace0;
                }

              if (ip4_is_fragment (ip0))
                {
                  next0 = SNAT_IN2OUT_NEXT_REASS;
                  goto trace0;
                }
            }

          key0.addr = ip0->src_address;
          key0.port = udp0->src_port;
          key0.protocol = proto0;
          key0.fib_index = rx_fib_index0;

          kv0.key = key0.as_u64;

          if (clib_bihash_search_8_8 (&sm->per_thread_data[thread_index].in2out,
                                      &kv0, &value0))
            {
              if (is_slow_path)
                {
                  if (is_output_feature)
                    {
                      if (PREDICT_FALSE(nat_not_translate_output_feature(sm,
                          ip0, proto0, udp0->src_port, udp0->dst_port, thread_index, sw_if_index0)))
                        goto trace0;
                    }
                  else
                    {
                      if (PREDICT_FALSE(snat_not_translate(sm, node, sw_if_index0,
                          ip0, proto0, rx_fib_index0, thread_index)))
                        goto trace0;
                    }

                  next0 = slow_path (sm, b0, ip0, rx_fib_index0, &key0,
                                     &s0, node, next0, thread_index);

                  if (PREDICT_FALSE (next0 == SNAT_IN2OUT_NEXT_DROP))
                    goto trace0;
                }
              else
                {
                  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace0;
                }
            }
          else
          s0 = pool_elt_at_index (sm->per_thread_data[thread_index].sessions,
                                  value0.value);

          b0->flags |= VNET_BUFFER_F_IS_NATED;

          old_addr0 = ip0->src_address.as_u32;
          ip0->src_address = s0->out2in.addr;
          new_addr0 = ip0->src_address.as_u32;
          if (!is_output_feature)
            vnet_buffer(b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                                 ip4_header_t,
                                 src_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              old_port0 = tcp0->src_port;
              tcp0->src_port = s0->out2in.port;
              new_port0 = tcp0->src_port;

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
              old_port0 = udp0->src_port;
              udp0->src_port = s0->out2in.port;
              udp0->checksum = 0;
            }

          /* Accounting */
          nat44_session_update_counters (s0, now,
                                         vlib_buffer_length_in_chain (vm, b0));
          /* Per-user LRU list maintenance */
          nat44_session_update_lru (sm, s0, thread_index);

        trace0:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_in2out_trace_t *t =
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->is_slow_path = is_slow_path;
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
                  t->session_index = ~0;
              if (s0)
                t->session_index = s0 - sm->per_thread_data[thread_index].sessions;
            }

          pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
                               SNAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

static uword
snat_in2out_fast_path_fn (vlib_main_t * vm,
                          vlib_node_runtime_t * node,
                          vlib_frame_t * frame)
{
  return snat_in2out_node_fn_inline (vm, node, frame, 0 /* is_slow_path */, 0);
}

VLIB_REGISTER_NODE (snat_in2out_node) = {
  .function = snat_in2out_fast_path_fn,
  .name = "nat44-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),

  .n_next_nodes = SNAT_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [SNAT_IN2OUT_NEXT_SLOW_PATH] = "nat44-in2out-slowpath",
    [SNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [SNAT_IN2OUT_NEXT_REASS] = "nat44-in2out-reass",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_node, snat_in2out_fast_path_fn);

static uword
snat_in2out_output_fast_path_fn (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  return snat_in2out_node_fn_inline (vm, node, frame, 0 /* is_slow_path */, 1);
}

VLIB_REGISTER_NODE (snat_in2out_output_node) = {
  .function = snat_in2out_output_fast_path_fn,
  .name = "nat44-in2out-output",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),

  .n_next_nodes = SNAT_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "interface-output",
    [SNAT_IN2OUT_NEXT_SLOW_PATH] = "nat44-in2out-output-slowpath",
    [SNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [SNAT_IN2OUT_NEXT_REASS] = "nat44-in2out-reass",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_output_node,
                              snat_in2out_output_fast_path_fn);

static uword
snat_in2out_slow_path_fn (vlib_main_t * vm,
                          vlib_node_runtime_t * node,
                          vlib_frame_t * frame)
{
  return snat_in2out_node_fn_inline (vm, node, frame, 1 /* is_slow_path */, 0);
}

VLIB_REGISTER_NODE (snat_in2out_slowpath_node) = {
  .function = snat_in2out_slow_path_fn,
  .name = "nat44-in2out-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),

  .n_next_nodes = SNAT_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [SNAT_IN2OUT_NEXT_SLOW_PATH] = "nat44-in2out-slowpath",
    [SNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [SNAT_IN2OUT_NEXT_REASS] = "nat44-in2out-reass",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_slowpath_node,
                              snat_in2out_slow_path_fn);

static uword
snat_in2out_output_slow_path_fn (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  return snat_in2out_node_fn_inline (vm, node, frame, 1 /* is_slow_path */, 1);
}

VLIB_REGISTER_NODE (snat_in2out_output_slowpath_node) = {
  .function = snat_in2out_output_slow_path_fn,
  .name = "nat44-in2out-output-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),

  .n_next_nodes = SNAT_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "interface-output",
    [SNAT_IN2OUT_NEXT_SLOW_PATH] = "nat44-in2out-output-slowpath",
    [SNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [SNAT_IN2OUT_NEXT_REASS] = "nat44-in2out-reass",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_output_slowpath_node,
                              snat_in2out_output_slow_path_fn);

extern vnet_feature_arc_registration_t vnet_feat_arc_ip4_local;

static inline uword
nat44_hairpinning_fn_inline (vlib_main_t * vm,
                             vlib_node_runtime_t * node,
                             vlib_frame_t * frame,
                             int is_ed)
{
  u32 n_left_from, * from, * to_next, stats_node_index;
  snat_in2out_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t * sm = &snat_main;
  vnet_feature_main_t *fm = &feature_main;
  u8 arc_index = vnet_feat_arc_ip4_local.feature_arc_index;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc_index];

  stats_node_index = is_ed ? nat44_ed_hairpinning_node.index :
    nat44_hairpinning_node.index;
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
          u32 next0;
          ip4_header_t * ip0;
          u32 proto0;
          udp_header_t * udp0;
          tcp_header_t * tcp0;

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

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          vnet_get_config_data (&cm->config_main, &b0->current_config_index,
                                &next0, 0);

          if (snat_hairpinning (sm, b0, ip0, udp0, tcp0, proto0, is_ed))
            next0 = SNAT_IN2OUT_NEXT_LOOKUP;

          pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
         }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
                               SNAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

static uword
nat44_hairpinning_fn (vlib_main_t * vm,
                      vlib_node_runtime_t * node,
                      vlib_frame_t * frame)
{
  return nat44_hairpinning_fn_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (nat44_hairpinning_node) = {
  .function = nat44_hairpinning_fn,
  .name = "nat44-hairpinning",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,
  .n_next_nodes = 2,
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_hairpinning_node,
                              nat44_hairpinning_fn);

static uword
nat44_ed_hairpinning_fn (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame)
{
  return nat44_hairpinning_fn_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (nat44_ed_hairpinning_node) = {
  .function = nat44_ed_hairpinning_fn,
  .name = "nat44-ed-hairpinning",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,
  .n_next_nodes = 2,
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_hairpinning_node,
                              nat44_ed_hairpinning_fn);

static inline void
nat44_reass_hairpinning (snat_main_t *sm,
                         vlib_buffer_t * b0,
                         ip4_header_t * ip0,
                         u16 sport,
                         u16 dport,
                         u32 proto0)
{
  snat_session_key_t key0, sm0;
  snat_session_t * s0;
  clib_bihash_kv_8_8_t kv0, value0;
  ip_csum_t sum0;
  u32 new_dst_addr0 = 0, old_dst_addr0, ti = 0, si;
  u16 new_dst_port0, old_dst_port0;
  udp_header_t * udp0;
  tcp_header_t * tcp0;

  key0.addr = ip0->dst_address;
  key0.port = dport;
  key0.protocol = proto0;
  key0.fib_index = sm->outside_fib_index;
  kv0.key = key0.as_u64;

  udp0 = ip4_next_header (ip0);

  /* Check if destination is static mappings */
  if (!snat_static_mapping_match(sm, key0, &sm0, 1, 0, 0, 0))
    {
      new_dst_addr0 = sm0.addr.as_u32;
      new_dst_port0 = sm0.port;
      vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm0.fib_index;
    }
  /* or active sessions */
  else
    {
      if (sm->num_workers > 1)
        ti = (clib_net_to_host_u16 (udp0->dst_port) - 1024) / sm->port_per_thread;
      else
        ti = sm->num_workers;

      if (!clib_bihash_search_8_8 (&sm->per_thread_data[ti].out2in, &kv0, &value0))
        {
          si = value0.value;
          s0 = pool_elt_at_index (sm->per_thread_data[ti].sessions, si);
          new_dst_addr0 = s0->in2out.addr.as_u32;
          new_dst_port0 = s0->in2out.port;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;
        }
    }

  /* Destination is behind the same NAT, use internal address and port */
  if (new_dst_addr0)
    {
      old_dst_addr0 = ip0->dst_address.as_u32;
      ip0->dst_address.as_u32 = new_dst_addr0;
      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
                             ip4_header_t, dst_address);
      ip0->checksum = ip_csum_fold (sum0);

      old_dst_port0 = dport;
      if (PREDICT_TRUE(new_dst_port0 != old_dst_port0 &&
                       ip4_is_first_fragment (ip0)))
        {
          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              tcp0 = ip4_next_header (ip0);
              tcp0->dst = new_dst_port0;
              sum0 = tcp0->checksum;
              sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
                                     ip4_header_t, dst_address);
              sum0 = ip_csum_update (sum0, old_dst_port0, new_dst_port0,
                                     ip4_header_t /* cheat */, length);
              tcp0->checksum = ip_csum_fold(sum0);
            }
          else
            {
              udp0->dst_port = new_dst_port0;
              udp0->checksum = 0;
            }
        }
      else
        {
          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              tcp0 = ip4_next_header (ip0);
              sum0 = tcp0->checksum;
              sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
                                     ip4_header_t, dst_address);
              tcp0->checksum = ip_csum_fold(sum0);
            }
        }
    }
}

static uword
nat44_in2out_reass_node_fn (vlib_main_t * vm,
                            vlib_node_runtime_t * node,
                            vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  snat_in2out_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t *sm = &snat_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  snat_main_per_thread_data_t *per_thread_data =
    &sm->per_thread_data[thread_index];
  u32 *fragments_to_drop = 0;
  u32 *fragments_to_loopback = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
       {
          u32 bi0, sw_if_index0, proto0, rx_fib_index0, new_addr0, old_addr0;
	  vlib_buffer_t *b0;
          u32 next0;
          u8 cached0 = 0;
          ip4_header_t *ip0;
          nat_reass_ip4_t *reass0;
          udp_header_t * udp0;
          tcp_header_t * tcp0;
          snat_session_key_t key0;
          clib_bihash_kv_8_8_t kv0, value0;
          snat_session_t * s0 = 0;
          u16 old_port0, new_port0;
          ip_csum_t sum0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          next0 = SNAT_IN2OUT_NEXT_LOOKUP;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          rx_fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
                                                               sw_if_index0);

          if (PREDICT_FALSE (nat_reass_is_drop_frag(0)))
            {
              next0 = SNAT_IN2OUT_NEXT_DROP;
              b0->error = node->errors[SNAT_IN2OUT_ERROR_DROP_FRAGMENT];
              goto trace0;
            }

          ip0 = (ip4_header_t *) vlib_buffer_get_current (b0);
          udp0 = ip4_next_header (ip0);
          tcp0 = (tcp_header_t *) udp0;
          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          reass0 = nat_ip4_reass_find_or_create (ip0->src_address,
                                                 ip0->dst_address,
                                                 ip0->fragment_id,
                                                 ip0->protocol,
                                                 1,
                                                 &fragments_to_drop);

          if (PREDICT_FALSE (!reass0))
            {
              next0 = SNAT_IN2OUT_NEXT_DROP;
              b0->error = node->errors[SNAT_IN2OUT_ERROR_MAX_REASS];
              nat_log_notice ("maximum reassemblies exceeded");
              goto trace0;
            }

          if (PREDICT_FALSE (ip4_is_first_fragment (ip0)))
            {
              key0.addr = ip0->src_address;
              key0.port = udp0->src_port;
              key0.protocol = proto0;
              key0.fib_index = rx_fib_index0;
              kv0.key = key0.as_u64;

              if (clib_bihash_search_8_8 (&per_thread_data->in2out, &kv0, &value0))
                {
                  if (PREDICT_FALSE(snat_not_translate(sm, node, sw_if_index0,
                      ip0, proto0, rx_fib_index0, thread_index)))
                    goto trace0;

                  next0 = slow_path (sm, b0, ip0, rx_fib_index0, &key0,
                                     &s0, node, next0, thread_index);

                  if (PREDICT_FALSE (next0 == SNAT_IN2OUT_NEXT_DROP))
                    goto trace0;

                  reass0->sess_index = s0 - per_thread_data->sessions;
                }
              else
                {
                  s0 = pool_elt_at_index (per_thread_data->sessions,
                                          value0.value);
                  reass0->sess_index = value0.value;
                }
              nat_ip4_reass_get_frags (reass0, &fragments_to_loopback);
            }
          else
            {
              if (PREDICT_FALSE (reass0->sess_index == (u32) ~0))
                {
                  if (nat_ip4_reass_add_fragment (reass0, bi0))
                    {
                      b0->error = node->errors[SNAT_IN2OUT_ERROR_MAX_FRAG];
                      nat_log_notice ("maximum fragments per reassembly exceeded");
                      next0 = SNAT_IN2OUT_NEXT_DROP;
                      goto trace0;
                    }
                  cached0 = 1;
                  goto trace0;
                }
              s0 = pool_elt_at_index (per_thread_data->sessions,
                                      reass0->sess_index);
            }

          old_addr0 = ip0->src_address.as_u32;
          ip0->src_address = s0->out2in.addr;
          new_addr0 = ip0->src_address.as_u32;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                                 ip4_header_t,
                                 src_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_FALSE (ip4_is_first_fragment (ip0)))
            {
              if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
                {
                  old_port0 = tcp0->src_port;
                  tcp0->src_port = s0->out2in.port;
                  new_port0 = tcp0->src_port;

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
                  old_port0 = udp0->src_port;
                  udp0->src_port = s0->out2in.port;
                  udp0->checksum = 0;
                }
            }

          /* Hairpinning */
          nat44_reass_hairpinning (sm, b0, ip0, s0->out2in.port,
                                   s0->ext_host_port, proto0);

          /* Accounting */
          nat44_session_update_counters (s0, now,
                                         vlib_buffer_length_in_chain (vm, b0));
          /* Per-user LRU list maintenance */
          nat44_session_update_lru (sm, s0, thread_index);

        trace0:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              nat44_in2out_reass_trace_t *t =
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->cached = cached0;
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
            }

          if (cached0)
            {
              n_left_to_next++;
              to_next--;
            }
          else
            {
              pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;

              /* verify speculative enqueue, maybe switch current next frame */
              vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                               to_next, n_left_to_next,
                                               bi0, next0);
            }

	  if (n_left_from == 0 && vec_len (fragments_to_loopback))
	    {
	      from = vlib_frame_vector_args (frame);
	      u32 len = vec_len (fragments_to_loopback);
	      if (len <= VLIB_FRAME_SIZE)
		{
		  clib_memcpy (from, fragments_to_loopback, sizeof (u32) * len);
		  n_left_from = len;
		  vec_reset_length (fragments_to_loopback);
		}
	      else
		{
		  clib_memcpy (from,
                               fragments_to_loopback + (len - VLIB_FRAME_SIZE),
                               sizeof (u32) * VLIB_FRAME_SIZE);
		  n_left_from = VLIB_FRAME_SIZE;
		  _vec_len (fragments_to_loopback) = len - VLIB_FRAME_SIZE;
		}
	    }
       }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, nat44_in2out_reass_node.index,
                               SNAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);

  nat_send_all_to_node (vm, fragments_to_drop, node,
                        &node->errors[SNAT_IN2OUT_ERROR_DROP_FRAGMENT],
                        SNAT_IN2OUT_NEXT_DROP);

  vec_free (fragments_to_drop);
  vec_free (fragments_to_loopback);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (nat44_in2out_reass_node) = {
  .function = nat44_in2out_reass_node_fn,
  .name = "nat44-in2out-reass",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_in2out_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .n_next_nodes = SNAT_IN2OUT_N_NEXT,
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [SNAT_IN2OUT_NEXT_SLOW_PATH] = "nat44-in2out-slowpath",
    [SNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [SNAT_IN2OUT_NEXT_REASS] = "nat44-in2out-reass",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_in2out_reass_node,
                              nat44_in2out_reass_node_fn);

/*******************************/
/*** endpoint-dependent mode ***/
/*******************************/

static_always_inline int
icmp_get_ed_key(ip4_header_t *ip0, nat_ed_ses_key_t *p_key0)
{
  icmp46_header_t *icmp0;
  nat_ed_ses_key_t key0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0 = 0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *)(icmp0+1);

  if (!icmp_is_error_message (icmp0))
    {
      key0.proto = IP_PROTOCOL_ICMP;
      key0.l_addr = ip0->src_address;
      key0.r_addr = ip0->dst_address;
      key0.l_port = echo0->identifier;
      key0.r_port = 0;
    }
  else
    {
      inner_ip0 = (ip4_header_t *)(echo0+1);
      l4_header = ip4_next_header (inner_ip0);
      key0.proto = inner_ip0->protocol;
      key0.r_addr = inner_ip0->src_address;
      key0.l_addr = inner_ip0->dst_address;
      switch (ip_proto_to_snat_proto (inner_ip0->protocol))
        {
        case SNAT_PROTOCOL_ICMP:
          inner_icmp0 = (icmp46_header_t*)l4_header;
          inner_echo0 = (icmp_echo_header_t *)(inner_icmp0+1);
          key0.r_port = 0;
          key0.l_port = inner_echo0->identifier;
          break;
        case SNAT_PROTOCOL_UDP:
        case SNAT_PROTOCOL_TCP:
          key0.l_port = ((tcp_udp_header_t*)l4_header)->dst_port;
          key0.r_port = ((tcp_udp_header_t*)l4_header)->src_port;
          break;
        default:
          return SNAT_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL;
        }
    }
  *p_key0 = key0;
  return 0;
}

static u32
slow_path_ed (snat_main_t *sm,
              vlib_buffer_t *b,
              u32 rx_fib_index,
              clib_bihash_kv_16_8_t *kv,
              snat_session_t ** sessionp,
              vlib_node_runtime_t * node,
              u32 next,
              u32 thread_index)
{
  snat_session_t *s;
  snat_user_t *u;
  snat_session_key_t key0, key1;
  u8 lb = 0, is_sm = 0;
  u32 address_index = ~0;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  nat_ed_ses_key_t *key = (nat_ed_ses_key_t *) kv->key;
  u32 proto = ip_proto_to_snat_proto (key->proto);
  nat_outside_fib_t *outside_fib;
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
        .ip4.as_u32 = key->r_addr.as_u32,
    },
  };

  if (PREDICT_FALSE (maximum_sessions_exceeded (sm, thread_index)))
    {
      b->error = node->errors[SNAT_IN2OUT_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_ipfix_logging_max_sessions(sm->max_translations);
      nat_log_notice ("maximum sessions exceeded");
      return SNAT_IN2OUT_NEXT_DROP;
    }

  key0.addr = key->l_addr;
  key0.port = key->l_port;
  key1.protocol = key0.protocol = proto;
  key0.fib_index = rx_fib_index;
  key1.fib_index = sm->outside_fib_index;
  /* First try to match static mapping by local address and port */
  if (snat_static_mapping_match (sm, key0, &key1, 0, 0, 0, &lb))
    {
      /* Try to create dynamic translation */
      if (snat_alloc_outside_address_and_port (sm->addresses, rx_fib_index,
                                               thread_index, &key1,
                                               &address_index,
                                               sm->port_per_thread,
                                               tsm->snat_thread_index))
        {
          nat_log_notice ("addresses exhausted");
          b->error = node->errors[SNAT_IN2OUT_ERROR_OUT_OF_PORTS];
          return SNAT_IN2OUT_NEXT_DROP;
        }
    }
  else
    is_sm = 1;

  u = nat_user_get_or_create (sm, &key->l_addr, rx_fib_index, thread_index);
  if (!u)
    {
      nat_log_warn ("create NAT user failed");
      return SNAT_IN2OUT_NEXT_DROP;
    }

  s = nat_session_alloc_or_recycle (sm, u, thread_index);
  if (!s)
    {
      nat_log_warn ("create NAT session failed");
      return SNAT_IN2OUT_NEXT_DROP;
    }

  user_session_increment (sm, u, is_sm);
  if (is_sm)
    s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
  if (lb)
    s->flags |= SNAT_SESSION_FLAG_LOAD_BALANCING;
  s->flags |= SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT;
  s->outside_address_index = address_index;
  s->ext_host_addr = key->r_addr;
  s->ext_host_port = key->r_port;
  s->in2out = key0;
  s->out2in = key1;
  s->out2in.protocol = key0.protocol;

  switch (vec_len (sm->outside_fibs))
    {
    case 0:
      s->out2in.fib_index = sm->outside_fib_index;
      break;
    case 1:
      s->out2in.fib_index = sm->outside_fibs[0].fib_index;
      break;
    default:
      vec_foreach (outside_fib, sm->outside_fibs)
        {
          fei = fib_table_lookup (outside_fib->fib_index, &pfx);
          if (FIB_NODE_INDEX_INVALID != fei)
            {
              if (fib_entry_get_resolving_interface (fei) != ~0)
                {
                  s->out2in.fib_index = outside_fib->fib_index;
                  break;
                }
            }
        }
      break;
    }

  /* Add to lookup tables */
  kv->value = s - tsm->sessions;
  if (clib_bihash_add_del_16_8 (&tsm->in2out_ed, kv, 1))
    nat_log_notice ("in2out-ed key add failed");

  make_ed_kv (kv, &key1.addr, &key->r_addr, key->proto, s->out2in.fib_index,
              key1.port, key->r_port);
  kv->value = s - tsm->sessions;
  if (clib_bihash_add_del_16_8 (&tsm->out2in_ed, kv, 1))
    nat_log_notice ("out2in-ed key add failed");

  *sessionp = s;

  /* log NAT event */
  snat_ipfix_logging_nat44_ses_create(s->in2out.addr.as_u32,
                                      s->out2in.addr.as_u32,
                                      s->in2out.protocol,
                                      s->in2out.port,
                                      s->out2in.port,
                                      s->in2out.fib_index);
  return next;
}

static_always_inline int
nat44_ed_not_translate (snat_main_t * sm, vlib_node_runtime_t *node,
                        u32 sw_if_index, ip4_header_t * ip, u32 proto,
                        u32 rx_fib_index, u32 thread_index)
{
  udp_header_t *udp = ip4_next_header (ip);
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  clib_bihash_kv_16_8_t kv, value;
  snat_session_key_t key0, key1;

  make_ed_kv (&kv, &ip->dst_address, &ip->src_address, ip->protocol,
              sm->outside_fib_index, udp->dst_port, udp->src_port);

  /* NAT packet aimed at external address if */
  /* has active sessions */
  if (clib_bihash_search_16_8 (&tsm->out2in_ed, &kv, &value))
    {
      key0.addr = ip->dst_address;
      key0.port = udp->dst_port;
      key0.protocol = proto;
      key0.fib_index = sm->outside_fib_index;
      /* or is static mappings */
      if (!snat_static_mapping_match(sm, key0, &key1, 1, 0, 0, 0))
        return 0;
    }
  else
    return 0;

  if (sm->forwarding_enabled)
    return 1;

  return snat_not_translate_fast(sm, node, sw_if_index, ip, proto, rx_fib_index);
}

static_always_inline int
nat_not_translate_output_feature_fwd (snat_main_t * sm, ip4_header_t * ip,
                                      u32 thread_index, f64 now,
                                      vlib_main_t * vm, vlib_buffer_t * b)
{
  nat_ed_ses_key_t key;
  clib_bihash_kv_16_8_t kv, value;
  udp_header_t *udp;
  snat_session_t *s = 0;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  if (!sm->forwarding_enabled)
    return 0;

  if (ip->protocol == IP_PROTOCOL_ICMP)
    {
      key.as_u64[0] = key.as_u64[1] = 0;
      if (icmp_get_ed_key (ip, &key))
        return 0;
      key.fib_index = 0;
      kv.key[0] = key.as_u64[0];
      kv.key[1] = key.as_u64[1];
    }
  else if (ip->protocol == IP_PROTOCOL_UDP || ip->protocol == IP_PROTOCOL_TCP)
    {
      udp = ip4_next_header(ip);
      make_ed_kv (&kv, &ip->src_address, &ip->dst_address, ip->protocol, 0,
                  udp->src_port, udp->dst_port);
    }
  else
    {
      make_ed_kv (&kv, &ip->src_address, &ip->dst_address, ip->protocol, 0, 0,
                  0);
    }

  if (!clib_bihash_search_16_8 (&tsm->in2out_ed, &kv, &value))
    {
      s = pool_elt_at_index (tsm->sessions, value.value);
      if (is_fwd_bypass_session (s))
        {
          if (ip->protocol == IP_PROTOCOL_TCP)
            {
              tcp_header_t *tcp = ip4_next_header(ip);
              if (nat44_set_tcp_session_state_i2o (sm, s, tcp, thread_index))
                return 1;
            }
          /* Per-user LRU list maintenance */
          nat44_session_update_lru (sm, s, thread_index);
          /* Accounting */
          nat44_session_update_counters (s, now,
                                         vlib_buffer_length_in_chain (vm, b));
          return 1;
        }
      else
        return 0;
    }

  return 0;
}

static_always_inline int
nat44_ed_not_translate_output_feature (snat_main_t * sm, ip4_header_t * ip,
                                       u8 proto, u16 src_port, u16 dst_port,
                                       u32 thread_index, u32 rx_sw_if_index,
                                       u32 tx_sw_if_index)
{
  clib_bihash_kv_16_8_t kv, value;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_interface_t *i;
  snat_session_t *s;
  u32 rx_fib_index = ip4_fib_table_get_index_for_sw_if_index (rx_sw_if_index);
  u32 tx_fib_index = ip4_fib_table_get_index_for_sw_if_index (tx_sw_if_index);

  /* src NAT check */
  make_ed_kv (&kv, &ip->src_address, &ip->dst_address, proto, tx_fib_index,
              src_port, dst_port);
  if (!clib_bihash_search_16_8 (&tsm->out2in_ed, &kv, &value))
    return 1;

  /* dst NAT check */
  make_ed_kv (&kv, &ip->dst_address, &ip->src_address, proto, rx_fib_index,
              dst_port, src_port);
  if (!clib_bihash_search_16_8 (&tsm->in2out_ed, &kv, &value))
  {
    s = pool_elt_at_index (tsm->sessions, value.value);
    if (is_fwd_bypass_session (s))
      return 0;

    /* hairpinning */
    pool_foreach (i, sm->output_feature_interfaces,
    ({
      if ((nat_interface_is_inside(i)) && (rx_sw_if_index == i->sw_if_index))
        return 0;
    }));
    return 1;
  }

  return 0;
}

u32
icmp_match_in2out_ed(snat_main_t *sm, vlib_node_runtime_t *node,
                     u32 thread_index, vlib_buffer_t *b, ip4_header_t *ip,
                     u8 *p_proto, snat_session_key_t *p_value,
                     u8 *p_dont_translate, void *d, void *e)
{
  icmp46_header_t *icmp;
  u32 sw_if_index;
  u32 rx_fib_index;
  nat_ed_ses_key_t key;
  snat_session_t *s = 0;
  u8 dont_translate = 0;
  clib_bihash_kv_16_8_t kv, value;
  u32 next = ~0;
  int err;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  icmp = (icmp46_header_t *) ip4_next_header (ip);
  sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_RX];
  rx_fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  key.as_u64[0] = key.as_u64[1] = 0;
  err = icmp_get_ed_key (ip, &key);
  if (err != 0)
    {
      b->error = node->errors[err];
      next = SNAT_IN2OUT_NEXT_DROP;
      goto out;
    }
  key.fib_index = rx_fib_index;

  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];

  if (clib_bihash_search_16_8 (&tsm->in2out_ed, &kv, &value))
    {
      if (vnet_buffer(b)->sw_if_index[VLIB_TX] != ~0)
        {
          if (PREDICT_FALSE(nat44_ed_not_translate_output_feature(sm, ip,
              key.proto, key.l_port, key.r_port, thread_index, sw_if_index,
              vnet_buffer(b)->sw_if_index[VLIB_TX])))
            {
              dont_translate = 1;
              goto out;
            }
        }
      else
        {
          if (PREDICT_FALSE(nat44_ed_not_translate(sm, node, sw_if_index,
              ip, SNAT_PROTOCOL_ICMP, rx_fib_index, thread_index)))
            {
              dont_translate = 1;
              goto out;
            }
        }

      if (PREDICT_FALSE(icmp_is_error_message (icmp)))
        {
          b->error = node->errors[SNAT_IN2OUT_ERROR_BAD_ICMP_TYPE];
          next = SNAT_IN2OUT_NEXT_DROP;
          goto out;
        }

      next = slow_path_ed (sm, b, rx_fib_index, &kv, &s, node, next,
                           thread_index);

      if (PREDICT_FALSE (next == SNAT_IN2OUT_NEXT_DROP))
        goto out;
    }
  else
    {
      if (PREDICT_FALSE(icmp->type != ICMP4_echo_request &&
                        icmp->type != ICMP4_echo_reply &&
                        !icmp_is_error_message (icmp)))
        {
          b->error = node->errors[SNAT_IN2OUT_ERROR_BAD_ICMP_TYPE];
          next = SNAT_IN2OUT_NEXT_DROP;
          goto out;
        }

      s = pool_elt_at_index (tsm->sessions, value.value);
    }

  *p_proto = ip_proto_to_snat_proto (key.proto);
out:
  if (s)
    *p_value = s->out2in;
  *p_dont_translate = dont_translate;
  if (d)
    *(snat_session_t**)d = s;
  return next;
}

static inline void
nat44_ed_hairpinning_unknown_proto (snat_main_t *sm,
                                    vlib_buffer_t * b,
                                    ip4_header_t * ip)
{
  u32 old_addr, new_addr = 0, ti = 0;
  clib_bihash_kv_8_8_t kv, value;
  clib_bihash_kv_16_8_t s_kv, s_value;
  snat_static_mapping_t *m;
  ip_csum_t sum;
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm;

  if (sm->num_workers > 1)
    ti = sm->worker_out2in_cb (ip, sm->outside_fib_index);
  else
    ti = sm->num_workers;
  tsm = &sm->per_thread_data[ti];

  old_addr = ip->dst_address.as_u32;
  make_ed_kv (&s_kv, &ip->dst_address, &ip->src_address, ip->protocol,
              sm->outside_fib_index, 0, 0);
  if (clib_bihash_search_16_8 (&tsm->out2in_ed, &s_kv, &s_value))
    {
      make_sm_kv (&kv, &ip->dst_address, 0, 0, 0);
      if (clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
        return;

      m = pool_elt_at_index (sm->static_mappings, value.value);
      if (vnet_buffer(b)->sw_if_index[VLIB_TX] == ~0)
        vnet_buffer(b)->sw_if_index[VLIB_TX] = m->fib_index;
      new_addr = ip->dst_address.as_u32 = m->local_addr.as_u32;
    }
  else
    {
      s = pool_elt_at_index (sm->per_thread_data[ti].sessions, s_value.value);
      if (vnet_buffer(b)->sw_if_index[VLIB_TX] == ~0)
        vnet_buffer(b)->sw_if_index[VLIB_TX] = s->in2out.fib_index;
      new_addr = ip->dst_address.as_u32 = s->in2out.addr.as_u32;
    }
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
  ip->checksum = ip_csum_fold (sum);
}

static snat_session_t *
nat44_ed_in2out_unknown_proto (snat_main_t *sm,
                               vlib_buffer_t * b,
                               ip4_header_t * ip,
                               u32 rx_fib_index,
                               u32 thread_index,
                               f64 now,
                               vlib_main_t * vm,
                               vlib_node_runtime_t * node)
{
  clib_bihash_kv_8_8_t kv, value;
  clib_bihash_kv_16_8_t s_kv, s_value;
  snat_static_mapping_t *m;
  u32 old_addr, new_addr = 0;
  ip_csum_t sum;
  snat_user_t *u;
  dlist_elt_t *head, *elt;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  u32 elt_index, head_index, ses_index;
  snat_session_t * s;
  u32 address_index = ~0, outside_fib_index = sm->outside_fib_index;
  int i;
  u8 is_sm = 0;
  nat_outside_fib_t *outside_fib;
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
        .ip4.as_u32 = ip->dst_address.as_u32,
    },
  };

  switch (vec_len (sm->outside_fibs))
    {
    case 0:
      outside_fib_index = sm->outside_fib_index;
      break;
    case 1:
      outside_fib_index = sm->outside_fibs[0].fib_index;
      break;
    default:
      vec_foreach (outside_fib, sm->outside_fibs)
        {
          fei = fib_table_lookup (outside_fib->fib_index, &pfx);
          if (FIB_NODE_INDEX_INVALID != fei)
            {
              if (fib_entry_get_resolving_interface (fei) != ~0)
                {
                  outside_fib_index = outside_fib->fib_index;
                  break;
                }
            }
        }
      break;
    }
  old_addr = ip->src_address.as_u32;

  make_ed_kv (&s_kv, &ip->src_address, &ip->dst_address, ip->protocol,
              rx_fib_index, 0, 0);

  if (!clib_bihash_search_16_8 (&tsm->in2out_ed, &s_kv, &s_value))
    {
      s = pool_elt_at_index (tsm->sessions, s_value.value);
      new_addr = ip->src_address.as_u32 = s->out2in.addr.as_u32;
    }
  else
    {
      if (PREDICT_FALSE (maximum_sessions_exceeded(sm, thread_index)))
        {
          b->error = node->errors[SNAT_IN2OUT_ERROR_MAX_SESSIONS_EXCEEDED];
          nat_ipfix_logging_max_sessions(sm->max_translations);
          nat_log_notice ("maximum sessions exceeded");
          return 0;
        }

      u = nat_user_get_or_create (sm, &ip->src_address, rx_fib_index,
                                  thread_index);
      if (!u)
        {
          nat_log_warn ("create NAT user failed");
          return 0;
        }

      make_sm_kv (&kv, &ip->src_address, 0, rx_fib_index, 0);

      /* Try to find static mapping first */
      if (!clib_bihash_search_8_8 (&sm->static_mapping_by_local, &kv, &value))
        {
          m = pool_elt_at_index (sm->static_mappings, value.value);
          new_addr = ip->src_address.as_u32 = m->external_addr.as_u32;
          is_sm = 1;
          goto create_ses;
        }
      /* Fallback to 3-tuple key */
      else
        {
          /* Choose same out address as for TCP/UDP session to same destination */
          head_index = u->sessions_per_user_list_head_index;
          head = pool_elt_at_index (tsm->list_pool, head_index);
          elt_index = head->next;
	  if (PREDICT_FALSE (elt_index == ~0))
	    ses_index = ~0;
	  else
	    {
	      elt = pool_elt_at_index (tsm->list_pool, elt_index);
	      ses_index = elt->value;
	    }

          while (ses_index != ~0)
            {
              s =  pool_elt_at_index (tsm->sessions, ses_index);
              elt_index = elt->next;
              elt = pool_elt_at_index (tsm->list_pool, elt_index);
              ses_index = elt->value;

              if (s->ext_host_addr.as_u32 == ip->dst_address.as_u32)
                {
                  new_addr = ip->src_address.as_u32 = s->out2in.addr.as_u32;
                  address_index = s->outside_address_index;

                  make_ed_kv (&s_kv, &s->out2in.addr, &ip->dst_address,
                              ip->protocol, outside_fib_index, 0, 0);
                  if (clib_bihash_search_16_8 (&tsm->out2in_ed, &s_kv, &s_value))
                    goto create_ses;

                  break;
                }
            }

          for (i = 0; i < vec_len (sm->addresses); i++)
            {
              make_ed_kv (&s_kv, &sm->addresses[i].addr, &ip->dst_address,
                          ip->protocol, outside_fib_index, 0, 0);
              if (clib_bihash_search_16_8 (&tsm->out2in_ed, &s_kv, &s_value))
                {
                  new_addr = ip->src_address.as_u32 =
                    sm->addresses[i].addr.as_u32;
                  address_index = i;
                  goto create_ses;
                }
            }
          return 0;
        }

create_ses:
      s = nat_session_alloc_or_recycle (sm, u, thread_index);
      if (!s)
        {
          nat_log_warn ("create NAT session failed");
          return 0;
        }

      s->ext_host_addr.as_u32 = ip->dst_address.as_u32;
      s->flags |= SNAT_SESSION_FLAG_UNKNOWN_PROTO;
      s->flags |= SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT;
      s->outside_address_index = address_index;
      s->out2in.addr.as_u32 = new_addr;
      s->out2in.fib_index = outside_fib_index;
      s->in2out.addr.as_u32 = old_addr;
      s->in2out.fib_index = rx_fib_index;
      s->in2out.port = s->out2in.port = ip->protocol;
      if (is_sm)
	s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
      user_session_increment (sm, u, is_sm);

      /* Add to lookup tables */
      make_ed_kv (&s_kv, &s->in2out.addr, &ip->dst_address, ip->protocol,
                  rx_fib_index, 0, 0);
      s_kv.value = s - tsm->sessions;
      if (clib_bihash_add_del_16_8 (&tsm->in2out_ed, &s_kv, 1))
        nat_log_notice ("in2out key add failed");

      make_ed_kv (&s_kv, &s->out2in.addr, &ip->dst_address, ip->protocol,
                  outside_fib_index, 0, 0);
      s_kv.value = s - tsm->sessions;
      if (clib_bihash_add_del_16_8 (&tsm->out2in_ed, &s_kv, 1))
        nat_log_notice ("out2in key add failed");
  }

  /* Update IP checksum */
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, src_address);
  ip->checksum = ip_csum_fold (sum);

  /* Accounting */
  nat44_session_update_counters (s, now, vlib_buffer_length_in_chain (vm, b));
  /* Per-user LRU list maintenance */
  nat44_session_update_lru (sm, s, thread_index);

  /* Hairpinning */
  if (vnet_buffer(b)->sw_if_index[VLIB_TX] == ~0)
    nat44_ed_hairpinning_unknown_proto(sm, b, ip);

  if (vnet_buffer(b)->sw_if_index[VLIB_TX] == ~0)
    vnet_buffer(b)->sw_if_index[VLIB_TX] = outside_fib_index;

  return s;
}

static inline uword
nat44_ed_in2out_node_fn_inline (vlib_main_t * vm,
                                vlib_node_runtime_t * node,
                                vlib_frame_t * frame, int is_slow_path,
                                int is_output_feature)
{
  u32 n_left_from, *from, *to_next, pkts_processed = 0, stats_node_index;
  snat_in2out_next_t next_index;
  snat_main_t *sm = &snat_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  stats_node_index = is_slow_path ? nat44_ed_in2out_slowpath_node.index :
    nat44_ed_in2out_node.index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
          u32 next0, sw_if_index0, rx_fib_index0, iph_offset0 = 0, proto0,
              new_addr0, old_addr0;
          u32 next1, sw_if_index1, rx_fib_index1, iph_offset1 = 0, proto1,
              new_addr1, old_addr1;
          u16 old_port0, new_port0, old_port1, new_port1;
          ip4_header_t *ip0, *ip1;
          udp_header_t *udp0, *udp1;
          tcp_header_t *tcp0, *tcp1;
          icmp46_header_t *icmp0, *icmp1;
          snat_session_t *s0 = 0, *s1 = 0;
          clib_bihash_kv_16_8_t kv0, value0, kv1, value1;
          ip_csum_t sum0, sum1;

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

          next0 = SNAT_IN2OUT_NEXT_LOOKUP;

          if (is_output_feature)
            iph_offset0 = vnet_buffer (b0)->ip.save_rewrite_length;

          ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
                 iph_offset0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
                                                               sw_if_index0);

          if (PREDICT_FALSE(ip0->ttl == 1))
            {
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next0 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
              goto trace00;
            }

          udp0 = ip4_next_header (ip0);
          tcp0 = (tcp_header_t *) udp0;
          icmp0 = (icmp46_header_t *) udp0;
          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          if (is_slow_path)
            {
              if (PREDICT_FALSE (proto0 == ~0))
                {
                  s0 = nat44_ed_in2out_unknown_proto (sm, b0, ip0,
                                                      rx_fib_index0,
                                                      thread_index, now, vm,
                                                      node);
                  if (!s0)
                    next0 = SNAT_IN2OUT_NEXT_DROP;
                  goto trace00;
                }

              if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
                {
                  next0 = icmp_in2out_slow_path
                    (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
                     next0, now, thread_index, &s0);
                  goto trace00;
                }
            }
          else
            {
               if (is_output_feature)
                {
                  if (PREDICT_FALSE(nat_not_translate_output_feature_fwd(
                      sm, ip0, thread_index, now, vm, b0)))
                    goto trace00;
                }

              if (PREDICT_FALSE (proto0 == ~0 || proto0 == SNAT_PROTOCOL_ICMP))
                {
                  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace00;
                }

              if (ip4_is_fragment (ip0))
                {
                  b0->error = node->errors[SNAT_IN2OUT_ERROR_DROP_FRAGMENT];
                  next0 = SNAT_IN2OUT_NEXT_DROP;
                  goto trace00;
                }
            }

          make_ed_kv (&kv0, &ip0->src_address, &ip0->dst_address, ip0->protocol,
                      rx_fib_index0, udp0->src_port, udp0->dst_port);

          if (clib_bihash_search_16_8 (&tsm->in2out_ed, &kv0, &value0))
            {
              if (is_slow_path)
                {
                  if (is_output_feature)
                    {
                      if (PREDICT_FALSE(nat44_ed_not_translate_output_feature(
                          sm, ip0, ip0->protocol, udp0->src_port,
                          udp0->dst_port, thread_index, sw_if_index0,
                          vnet_buffer(b0)->sw_if_index[VLIB_TX])))
                        goto trace00;
                    }
                  else
                    {
                      if (PREDICT_FALSE(nat44_ed_not_translate(sm, node,
                          sw_if_index0, ip0, proto0, rx_fib_index0,
                          thread_index)))
                        goto trace00;
                    }

                  next0 = slow_path_ed (sm, b0, rx_fib_index0, &kv0, &s0, node,
                                        next0, thread_index);

                  if (PREDICT_FALSE (next0 == SNAT_IN2OUT_NEXT_DROP))
                    goto trace00;
                }
              else
                {
                  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace00;
                }
            }
          else
            {
              s0 = pool_elt_at_index (tsm->sessions, value0.value);
            }

          b0->flags |= VNET_BUFFER_F_IS_NATED;

          if (!is_output_feature)
            vnet_buffer(b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

          old_addr0 = ip0->src_address.as_u32;
          new_addr0 = ip0->src_address.as_u32 = s0->out2in.addr.as_u32;
          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                                 src_address);
          if (PREDICT_FALSE (is_twice_nat_session (s0)))
            sum0 = ip_csum_update (sum0, ip0->dst_address.as_u32,
                                   s0->ext_host_addr.as_u32, ip4_header_t,
                                   dst_address);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_TRUE (proto0 == SNAT_PROTOCOL_TCP))
            {
              old_port0 = tcp0->src_port;
              new_port0 = tcp0->src_port = s0->out2in.port;

              sum0 = tcp0->checksum;
              sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                                     dst_address);
              sum0 = ip_csum_update (sum0, old_port0, new_port0, ip4_header_t,
                                     length);
              if (PREDICT_FALSE (is_twice_nat_session (s0)))
                {
                  sum0 = ip_csum_update (sum0, ip0->dst_address.as_u32,
                                         s0->ext_host_addr.as_u32,
                                         ip4_header_t, dst_address);
                  sum0 = ip_csum_update (sum0, tcp0->dst_port,
                                         s0->ext_host_port, ip4_header_t,
                                         length);
                  tcp0->dst_port = s0->ext_host_port;
                  ip0->dst_address.as_u32 = s0->ext_host_addr.as_u32;
                }
              tcp0->checksum = ip_csum_fold(sum0);
              if (nat44_set_tcp_session_state_i2o (sm, s0, tcp0, thread_index))
                goto trace00;
            }
          else
            {
              udp0->src_port = s0->out2in.port;
              udp0->checksum = 0;
              if (PREDICT_FALSE (is_twice_nat_session (s0)))
                {
                  udp0->dst_port = s0->ext_host_port;
                  ip0->dst_address.as_u32 = s0->ext_host_addr.as_u32;
                }
            }

          /* Accounting */
          nat44_session_update_counters (s0, now,
                                         vlib_buffer_length_in_chain (vm, b0));
          /* Per-user LRU list maintenance */
          nat44_session_update_lru (sm, s0, thread_index);

        trace00:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_in2out_trace_t *t =
                vlib_add_trace (vm, node, b0, sizeof (*t));
              t->is_slow_path = is_slow_path;
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
              t->session_index = ~0;
              if (s0)
                t->session_index = s0 - tsm->sessions;
            }

          pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;


          next1 = SNAT_IN2OUT_NEXT_LOOKUP;

          if (is_output_feature)
            iph_offset1 = vnet_buffer (b1)->ip.save_rewrite_length;

          ip1 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b1) +
                 iph_offset1);

          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
	  rx_fib_index1 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
                                                               sw_if_index1);

          if (PREDICT_FALSE(ip1->ttl == 1))
            {
              vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b1, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next1 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
              goto trace01;
            }

          udp1 = ip4_next_header (ip1);
          tcp1 = (tcp_header_t *) udp1;
          icmp1 = (icmp46_header_t *) udp1;
          proto1 = ip_proto_to_snat_proto (ip1->protocol);

          if (is_slow_path)
            {
              if (PREDICT_FALSE (proto1 == ~0))
                {
                  s1 = nat44_ed_in2out_unknown_proto (sm, b1, ip1,
                                                      rx_fib_index1,
                                                      thread_index, now, vm,
                                                      node);
                  if (!s1)
                    next1 = SNAT_IN2OUT_NEXT_DROP;
                  goto trace01;
                }

              if (PREDICT_FALSE (proto1 == SNAT_PROTOCOL_ICMP))
                {
                  next1 = icmp_in2out_slow_path
                    (sm, b1, ip1, icmp1, sw_if_index1, rx_fib_index1, node,
                     next1, now, thread_index, &s1);
                  goto trace01;
                }
            }
          else
            {
               if (is_output_feature)
                {
                  if (PREDICT_FALSE(nat_not_translate_output_feature_fwd(
                      sm, ip1, thread_index, now, vm, b1)))
                    goto trace01;
                }

              if (PREDICT_FALSE (proto1 == ~0 || proto1 == SNAT_PROTOCOL_ICMP))
                {
                  next1 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace01;
                }

              if (ip4_is_fragment (ip1))
                {
                  b1->error = node->errors[SNAT_IN2OUT_ERROR_DROP_FRAGMENT];
                  next1 = SNAT_IN2OUT_NEXT_DROP;
                  goto trace01;
                }
            }

          make_ed_kv (&kv1, &ip1->src_address, &ip1->dst_address, ip1->protocol,
                      rx_fib_index1, udp1->src_port, udp1->dst_port);

          if (clib_bihash_search_16_8 (&tsm->in2out_ed, &kv1, &value1))
            {
              if (is_slow_path)
                {
                  if (is_output_feature)
                    {
                      if (PREDICT_FALSE(nat44_ed_not_translate_output_feature(
                          sm, ip1, ip1->protocol, udp1->src_port,
                          udp1->dst_port, thread_index, sw_if_index1,
                          vnet_buffer(b1)->sw_if_index[VLIB_TX])))
                        goto trace01;
                    }
                  else
                    {
                      if (PREDICT_FALSE(nat44_ed_not_translate(sm, node,
                          sw_if_index1, ip1, proto1, rx_fib_index1,
                          thread_index)))
                        goto trace01;
                    }

                  next1 = slow_path_ed (sm, b1, rx_fib_index1, &kv1, &s1, node,
                                        next1, thread_index);

                  if (PREDICT_FALSE (next1 == SNAT_IN2OUT_NEXT_DROP))
                    goto trace01;
                }
              else
                {
                  next1 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace01;
                }
            }
          else
            {
              s1 = pool_elt_at_index (tsm->sessions, value1.value);
            }

          b1->flags |= VNET_BUFFER_F_IS_NATED;

          if (!is_output_feature)
            vnet_buffer(b1)->sw_if_index[VLIB_TX] = s1->out2in.fib_index;

          old_addr1 = ip1->src_address.as_u32;
          new_addr1 = ip1->src_address.as_u32 = s1->out2in.addr.as_u32;
          sum1 = ip1->checksum;
          sum1 = ip_csum_update (sum1, old_addr1, new_addr1, ip4_header_t,
                                 src_address);
          if (PREDICT_FALSE (is_twice_nat_session (s1)))
            sum1 = ip_csum_update (sum1, ip1->dst_address.as_u32,
                                   s1->ext_host_addr.as_u32, ip4_header_t,
                                   dst_address);
          ip1->checksum = ip_csum_fold (sum1);

          if (PREDICT_TRUE (proto1 == SNAT_PROTOCOL_TCP))
            {
              old_port1 = tcp1->src_port;
              new_port1 = tcp1->src_port = s1->out2in.port;

              sum1 = tcp1->checksum;
              sum1 = ip_csum_update (sum1, old_addr1, new_addr1, ip4_header_t,
                                     dst_address);
              sum1 = ip_csum_update (sum1, old_port1, new_port1, ip4_header_t,
                                     length);
              if (PREDICT_FALSE (is_twice_nat_session (s1)))
                {
                  sum1 = ip_csum_update (sum1, ip1->dst_address.as_u32,
                                         s1->ext_host_addr.as_u32,
                                         ip4_header_t, dst_address);
                  sum1 = ip_csum_update (sum1, tcp1->dst_port,
                                         s1->ext_host_port, ip4_header_t,
                                         length);
                  tcp1->dst_port = s1->ext_host_port;
                  ip1->dst_address.as_u32 = s1->ext_host_addr.as_u32;
                }
              tcp1->checksum = ip_csum_fold(sum1);
              if (nat44_set_tcp_session_state_i2o (sm, s1, tcp1, thread_index))
                goto trace01;
            }
          else
            {
              udp1->src_port = s1->out2in.port;
              udp1->checksum = 0;
              if (PREDICT_FALSE (is_twice_nat_session (s1)))
                {
                  udp1->dst_port = s1->ext_host_port;
                  ip1->dst_address.as_u32 = s1->ext_host_addr.as_u32;
                }
            }

          /* Accounting */
          nat44_session_update_counters (s1, now,
                                         vlib_buffer_length_in_chain (vm, b1));
          /* Per-user LRU list maintenance */
          nat44_session_update_lru (sm, s1, thread_index);

        trace01:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b1->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_in2out_trace_t *t =
                vlib_add_trace (vm, node, b1, sizeof (*t));
              t->is_slow_path = is_slow_path;
              t->sw_if_index = sw_if_index1;
              t->next_index = next1;
              t->session_index = ~0;
              if (s1)
                t->session_index = s1 - tsm->sessions;
            }

          pkts_processed += next1 != SNAT_IN2OUT_NEXT_DROP;

          /* verify speculative enqueues, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t *b0;
          u32 next0, sw_if_index0, rx_fib_index0, iph_offset0 = 0, proto0,
              new_addr0, old_addr0;
          u16 old_port0, new_port0;
          ip4_header_t *ip0;
          udp_header_t *udp0;
          tcp_header_t *tcp0;
          icmp46_header_t * icmp0;
          snat_session_t *s0 = 0;
          clib_bihash_kv_16_8_t kv0, value0;
          ip_csum_t sum0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          next0 = SNAT_IN2OUT_NEXT_LOOKUP;

          if (is_output_feature)
            iph_offset0 = vnet_buffer (b0)->ip.save_rewrite_length;

          ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
                 iph_offset0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
                                                               sw_if_index0);

          if (PREDICT_FALSE(ip0->ttl == 1))
            {
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next0 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
              goto trace0;
            }

          udp0 = ip4_next_header (ip0);
          tcp0 = (tcp_header_t *) udp0;
          icmp0 = (icmp46_header_t *) udp0;
          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          if (is_slow_path)
            {
              if (PREDICT_FALSE (proto0 == ~0))
                {
                  s0 = nat44_ed_in2out_unknown_proto (sm, b0, ip0,
                                                      rx_fib_index0,
                                                      thread_index, now, vm,
                                                      node);
                  if (!s0)
                    next0 = SNAT_IN2OUT_NEXT_DROP;
                  goto trace0;
                }

              if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
                {
                  next0 = icmp_in2out_slow_path
                    (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
                     next0, now, thread_index, &s0);
                  goto trace0;
                }
            }
          else
            {
               if (is_output_feature)
                {
                  if (PREDICT_FALSE(nat_not_translate_output_feature_fwd(
                      sm, ip0, thread_index, now, vm, b0)))
                    goto trace0;
                }

              if (PREDICT_FALSE (proto0 == ~0 || proto0 == SNAT_PROTOCOL_ICMP))
                {
                  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace0;
                }

              if (ip4_is_fragment (ip0))
                {
                  b0->error = node->errors[SNAT_IN2OUT_ERROR_DROP_FRAGMENT];
                  next0 = SNAT_IN2OUT_NEXT_DROP;
                  goto trace0;
                }
            }

          make_ed_kv (&kv0, &ip0->src_address, &ip0->dst_address, ip0->protocol,
                      rx_fib_index0, udp0->src_port, udp0->dst_port);

          if (clib_bihash_search_16_8 (&tsm->in2out_ed, &kv0, &value0))
            {
              if (is_slow_path)
                {
                  if (is_output_feature)
                    {
                      if (PREDICT_FALSE(nat44_ed_not_translate_output_feature(
                          sm, ip0, ip0->protocol, udp0->src_port,
                          udp0->dst_port, thread_index, sw_if_index0,
                          vnet_buffer(b0)->sw_if_index[VLIB_TX])))
                        goto trace0;
                    }
                  else
                    {
                      if (PREDICT_FALSE(nat44_ed_not_translate(sm, node,
                          sw_if_index0, ip0, proto0, rx_fib_index0,
                          thread_index)))
                        goto trace0;
                    }

                  next0 = slow_path_ed (sm, b0, rx_fib_index0, &kv0, &s0, node,
                                        next0, thread_index);

                  if (PREDICT_FALSE (next0 == SNAT_IN2OUT_NEXT_DROP))
                    goto trace0;
                }
              else
                {
                  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
                  goto trace0;
                }
            }
          else
            {
              s0 = pool_elt_at_index (tsm->sessions, value0.value);
            }

          b0->flags |= VNET_BUFFER_F_IS_NATED;

          if (!is_output_feature)
            vnet_buffer(b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

          old_addr0 = ip0->src_address.as_u32;
          new_addr0 = ip0->src_address.as_u32 = s0->out2in.addr.as_u32;
          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                                 src_address);
          if (PREDICT_FALSE (is_twice_nat_session (s0)))
            sum0 = ip_csum_update (sum0, ip0->dst_address.as_u32,
                                   s0->ext_host_addr.as_u32, ip4_header_t,
                                   dst_address);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_TRUE (proto0 == SNAT_PROTOCOL_TCP))
            {
              old_port0 = tcp0->src_port;
              new_port0 = tcp0->src_port = s0->out2in.port;

              sum0 = tcp0->checksum;
              sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
                                     dst_address);
              sum0 = ip_csum_update (sum0, old_port0, new_port0, ip4_header_t,
                                     length);
              if (PREDICT_FALSE (is_twice_nat_session (s0)))
                {
                  sum0 = ip_csum_update (sum0, ip0->dst_address.as_u32,
                                         s0->ext_host_addr.as_u32,
                                         ip4_header_t, dst_address);
                  sum0 = ip_csum_update (sum0, tcp0->dst_port,
                                         s0->ext_host_port, ip4_header_t,
                                         length);
                  tcp0->dst_port = s0->ext_host_port;
                  ip0->dst_address.as_u32 = s0->ext_host_addr.as_u32;
                }
              tcp0->checksum = ip_csum_fold(sum0);
              if (nat44_set_tcp_session_state_i2o (sm, s0, tcp0, thread_index))
                goto trace0;
            }
          else
            {
              udp0->src_port = s0->out2in.port;
              udp0->checksum = 0;
              if (PREDICT_FALSE (is_twice_nat_session (s0)))
                {
                  udp0->dst_port = s0->ext_host_port;
                  ip0->dst_address.as_u32 = s0->ext_host_addr.as_u32;
                }
            }

          /* Accounting */
          nat44_session_update_counters (s0, now,
                                         vlib_buffer_length_in_chain (vm, b0));
          /* Per-user LRU list maintenance */
          nat44_session_update_lru (sm, s0, thread_index);

        trace0:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_in2out_trace_t *t =
                vlib_add_trace (vm, node, b0, sizeof (*t));
              t->is_slow_path = is_slow_path;
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
              t->session_index = ~0;
              if (s0)
                t->session_index = s0 - tsm->sessions;
            }

          pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
                               SNAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

static uword
nat44_ed_in2out_fast_path_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
  return nat44_ed_in2out_node_fn_inline (vm, node, frame, 0, 0);
}

VLIB_REGISTER_NODE (nat44_ed_in2out_node) = {
  .function = nat44_ed_in2out_fast_path_fn,
  .name = "nat44-ed-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),

  .n_next_nodes = SNAT_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [SNAT_IN2OUT_NEXT_SLOW_PATH] = "nat44-ed-in2out-slowpath",
    [SNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [SNAT_IN2OUT_NEXT_REASS] = "nat44-in2out-reass",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_in2out_node, nat44_ed_in2out_fast_path_fn);

static uword
nat44_ed_in2out_output_fast_path_fn (vlib_main_t * vm,
                                     vlib_node_runtime_t * node,
                                     vlib_frame_t * frame)
{
  return nat44_ed_in2out_node_fn_inline (vm, node, frame, 0, 1);
}

VLIB_REGISTER_NODE (nat44_ed_in2out_output_node) = {
  .function = nat44_ed_in2out_output_fast_path_fn,
  .name = "nat44-ed-in2out-output",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),

  .n_next_nodes = SNAT_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "interface-output",
    [SNAT_IN2OUT_NEXT_SLOW_PATH] = "nat44-ed-in2out-output-slowpath",
    [SNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [SNAT_IN2OUT_NEXT_REASS] = "nat44-in2out-reass",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_in2out_output_node,
                              nat44_ed_in2out_output_fast_path_fn);

static uword
nat44_ed_in2out_slow_path_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
  return nat44_ed_in2out_node_fn_inline (vm, node, frame, 1, 0);
}

VLIB_REGISTER_NODE (nat44_ed_in2out_slowpath_node) = {
  .function = nat44_ed_in2out_slow_path_fn,
  .name = "nat44-ed-in2out-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),

  .n_next_nodes = SNAT_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [SNAT_IN2OUT_NEXT_SLOW_PATH] = "nat44-ed-in2out-slowpath",
    [SNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [SNAT_IN2OUT_NEXT_REASS] = "nat44-in2out-reass",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_in2out_slowpath_node,
                              nat44_ed_in2out_slow_path_fn);

static uword
nat44_ed_in2out_output_slow_path_fn (vlib_main_t * vm,
                                     vlib_node_runtime_t * node,
                                     vlib_frame_t * frame)
{
  return nat44_ed_in2out_node_fn_inline (vm, node, frame, 1, 1);
}

VLIB_REGISTER_NODE (nat44_ed_in2out_output_slowpath_node) = {
  .function = nat44_ed_in2out_output_slow_path_fn,
  .name = "nat44-ed-in2out-output-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),

  .n_next_nodes = SNAT_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "interface-output",
    [SNAT_IN2OUT_NEXT_SLOW_PATH] = "nat44-ed-in2out-output-slowpath",
    [SNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [SNAT_IN2OUT_NEXT_REASS] = "nat44-in2out-reass",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_in2out_output_slowpath_node,
                              nat44_ed_in2out_output_slow_path_fn);

/**************************/
/*** deterministic mode ***/
/**************************/
static uword
snat_det_in2out_node_fn (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  snat_in2out_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t * sm = &snat_main;
  u32 now = (u32) vlib_time_now (vm);
  u32 thread_index = vm->thread_index;

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
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;
          ip4_header_t * ip0, * ip1;
          ip_csum_t sum0, sum1;
          ip4_address_t new_addr0, old_addr0, new_addr1, old_addr1;
          u16 old_port0, new_port0, lo_port0, i0;
          u16 old_port1, new_port1, lo_port1, i1;
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

          next0 = SNAT_IN2OUT_NEXT_LOOKUP;
          next1 = SNAT_IN2OUT_NEXT_LOOKUP;

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
              next0 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
              goto trace0;
            }

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          if (PREDICT_FALSE(proto0 == SNAT_PROTOCOL_ICMP))
            {
              rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index0);
              icmp0 = (icmp46_header_t *) udp0;

              next0 = icmp_in2out(sm, b0, ip0, icmp0, sw_if_index0,
                                  rx_fib_index0, node, next0, thread_index,
                                  &ses0, &dm0);
              goto trace0;
            }

          dm0 = snat_det_map_by_user(sm, &ip0->src_address);
          if (PREDICT_FALSE(!dm0))
            {
              nat_log_info ("no match for internal host %U",
                            format_ip4_address, &ip0->src_address);
              next0 = SNAT_IN2OUT_NEXT_DROP;
              b0->error = node->errors[SNAT_IN2OUT_ERROR_NO_TRANSLATION];
              goto trace0;
            }

          snat_det_forward(dm0, &ip0->src_address, &new_addr0, &lo_port0);

          key0.ext_host_addr = ip0->dst_address;
          key0.ext_host_port = tcp0->dst;

          ses0 = snat_det_find_ses_by_in(dm0, &ip0->src_address, tcp0->src, key0);
          if (PREDICT_FALSE(!ses0))
            {
              for (i0 = 0; i0 < dm0->ports_per_host; i0++)
                {
                  key0.out_port = clib_host_to_net_u16 (lo_port0 +
                    ((i0 + clib_net_to_host_u16 (tcp0->src)) % dm0->ports_per_host));

                  if (snat_det_get_ses_by_out (dm0, &ip0->src_address, key0.as_u64))
                    continue;

                  ses0 = snat_det_ses_create(dm0, &ip0->src_address, tcp0->src, &key0);
                  break;
                }
              if (PREDICT_FALSE(!ses0))
                {
                  /* too many sessions for user, send ICMP error packet */

                  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
                  icmp4_error_set_vnet_buffer (b0, ICMP4_destination_unreachable,
                                               ICMP4_destination_unreachable_destination_unreachable_host,
                                               0);
                  next0 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
                  goto trace0;
                }
            }

          new_port0 = ses0->out.out_port;

          old_addr0.as_u32 = ip0->src_address.as_u32;
          ip0->src_address.as_u32 = new_addr0.as_u32;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm->outside_fib_index;

          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
                                 ip4_header_t,
                                 src_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              if (tcp0->flags & TCP_FLAG_SYN)
                ses0->state = SNAT_SESSION_TCP_SYN_SENT;
              else if (tcp0->flags & TCP_FLAG_ACK && ses0->state == SNAT_SESSION_TCP_SYN_SENT)
                ses0->state = SNAT_SESSION_TCP_ESTABLISHED;
              else if (tcp0->flags & TCP_FLAG_FIN && ses0->state == SNAT_SESSION_TCP_ESTABLISHED)
                ses0->state = SNAT_SESSION_TCP_FIN_WAIT;
              else if (tcp0->flags & TCP_FLAG_ACK && ses0->state == SNAT_SESSION_TCP_FIN_WAIT)
                snat_det_ses_close(dm0, ses0);
              else if (tcp0->flags & TCP_FLAG_FIN && ses0->state == SNAT_SESSION_TCP_CLOSE_WAIT)
                ses0->state = SNAT_SESSION_TCP_LAST_ACK;
              else if (tcp0->flags == 0 && ses0->state == SNAT_SESSION_UNKNOWN)
                ses0->state = SNAT_SESSION_TCP_ESTABLISHED;

              old_port0 = tcp0->src;
              tcp0->src = new_port0;

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
              ses0->state = SNAT_SESSION_UDP_ACTIVE;
              old_port0 = udp0->src_port;
              udp0->src_port = new_port0;
              udp0->checksum = 0;
            }

          switch(ses0->state)
            {
            case SNAT_SESSION_UDP_ACTIVE:
                ses0->expire = now + sm->udp_timeout;
                break;
            case SNAT_SESSION_TCP_SYN_SENT:
            case SNAT_SESSION_TCP_FIN_WAIT:
            case SNAT_SESSION_TCP_CLOSE_WAIT:
            case SNAT_SESSION_TCP_LAST_ACK:
                ses0->expire = now + sm->tcp_transitory_timeout;
                break;
            case SNAT_SESSION_TCP_ESTABLISHED:
                ses0->expire = now + sm->tcp_established_timeout;
                break;
            }

        trace0:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_in2out_trace_t *t =
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->is_slow_path = 0;
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
              t->session_index = ~0;
              if (ses0)
                t->session_index = ses0 - dm0->sessions;
            }

          pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;

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
              next1 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
              goto trace1;
            }

          proto1 = ip_proto_to_snat_proto (ip1->protocol);

          if (PREDICT_FALSE(proto1 == SNAT_PROTOCOL_ICMP))
            {
              rx_fib_index1 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index1);
              icmp1 = (icmp46_header_t *) udp1;

              next1 = icmp_in2out(sm, b1, ip1, icmp1, sw_if_index1,
                                  rx_fib_index1, node, next1, thread_index,
                                  &ses1, &dm1);
              goto trace1;
            }

          dm1 = snat_det_map_by_user(sm, &ip1->src_address);
          if (PREDICT_FALSE(!dm1))
            {
              nat_log_info ("no match for internal host %U",
                            format_ip4_address, &ip0->src_address);
              next1 = SNAT_IN2OUT_NEXT_DROP;
              b1->error = node->errors[SNAT_IN2OUT_ERROR_NO_TRANSLATION];
              goto trace1;
            }

          snat_det_forward(dm1, &ip1->src_address, &new_addr1, &lo_port1);

          key1.ext_host_addr = ip1->dst_address;
          key1.ext_host_port = tcp1->dst;

          ses1 = snat_det_find_ses_by_in(dm1, &ip1->src_address, tcp1->src, key1);
          if (PREDICT_FALSE(!ses1))
            {
              for (i1 = 0; i1 < dm1->ports_per_host; i1++)
                {
                  key1.out_port = clib_host_to_net_u16 (lo_port1 +
                    ((i1 + clib_net_to_host_u16 (tcp1->src)) % dm1->ports_per_host));

                  if (snat_det_get_ses_by_out (dm1, &ip1->src_address, key1.as_u64))
                    continue;

                  ses1 = snat_det_ses_create(dm1, &ip1->src_address, tcp1->src, &key1);
                  break;
                }
              if (PREDICT_FALSE(!ses1))
                {
                  /* too many sessions for user, send ICMP error packet */

                  vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;
                  icmp4_error_set_vnet_buffer (b1, ICMP4_destination_unreachable,
                                               ICMP4_destination_unreachable_destination_unreachable_host,
                                               0);
                  next1 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
                  goto trace1;
                }
            }

          new_port1 = ses1->out.out_port;

          old_addr1.as_u32 = ip1->src_address.as_u32;
          ip1->src_address.as_u32 = new_addr1.as_u32;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = sm->outside_fib_index;

          sum1 = ip1->checksum;
          sum1 = ip_csum_update (sum1, old_addr1.as_u32, new_addr1.as_u32,
                                 ip4_header_t,
                                 src_address /* changed member */);
          ip1->checksum = ip_csum_fold (sum1);

          if (PREDICT_TRUE(proto1 == SNAT_PROTOCOL_TCP))
            {
              if (tcp1->flags & TCP_FLAG_SYN)
                ses1->state = SNAT_SESSION_TCP_SYN_SENT;
              else if (tcp1->flags & TCP_FLAG_ACK && ses1->state == SNAT_SESSION_TCP_SYN_SENT)
                ses1->state = SNAT_SESSION_TCP_ESTABLISHED;
              else if (tcp1->flags & TCP_FLAG_FIN && ses1->state == SNAT_SESSION_TCP_ESTABLISHED)
                ses1->state = SNAT_SESSION_TCP_FIN_WAIT;
              else if (tcp1->flags & TCP_FLAG_ACK && ses1->state == SNAT_SESSION_TCP_FIN_WAIT)
                snat_det_ses_close(dm1, ses1);
              else if (tcp1->flags & TCP_FLAG_FIN && ses1->state == SNAT_SESSION_TCP_CLOSE_WAIT)
                ses1->state = SNAT_SESSION_TCP_LAST_ACK;
              else if (tcp1->flags == 0 && ses1->state == SNAT_SESSION_UNKNOWN)
                ses1->state = SNAT_SESSION_TCP_ESTABLISHED;

              old_port1 = tcp1->src;
              tcp1->src = new_port1;

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
              ses1->state = SNAT_SESSION_UDP_ACTIVE;
              old_port1 = udp1->src_port;
              udp1->src_port = new_port1;
              udp1->checksum = 0;
            }

          switch(ses1->state)
            {
            case SNAT_SESSION_UDP_ACTIVE:
                ses1->expire = now + sm->udp_timeout;
                break;
            case SNAT_SESSION_TCP_SYN_SENT:
            case SNAT_SESSION_TCP_FIN_WAIT:
            case SNAT_SESSION_TCP_CLOSE_WAIT:
            case SNAT_SESSION_TCP_LAST_ACK:
                ses1->expire = now + sm->tcp_transitory_timeout;
                break;
            case SNAT_SESSION_TCP_ESTABLISHED:
                ses1->expire = now + sm->tcp_established_timeout;
                break;
            }

        trace1:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b1->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_in2out_trace_t *t =
                 vlib_add_trace (vm, node, b1, sizeof (*t));
              t->is_slow_path = 0;
              t->sw_if_index = sw_if_index1;
              t->next_index = next1;
              t->session_index = ~0;
              if (ses1)
                t->session_index = ses1 - dm1->sessions;
            }

          pkts_processed += next1 != SNAT_IN2OUT_NEXT_DROP;

          /* verify speculative enqueues, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, next0, next1);
         }

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0;
          u32 sw_if_index0;
          ip4_header_t * ip0;
          ip_csum_t sum0;
          ip4_address_t new_addr0, old_addr0;
          u16 old_port0, new_port0, lo_port0, i0;
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
          next0 = SNAT_IN2OUT_NEXT_LOOKUP;

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
              next0 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
              goto trace00;
            }

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          if (PREDICT_FALSE(proto0 == SNAT_PROTOCOL_ICMP))
            {
              rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index0);
              icmp0 = (icmp46_header_t *) udp0;

              next0 = icmp_in2out(sm, b0, ip0, icmp0, sw_if_index0,
                                  rx_fib_index0, node, next0, thread_index,
                                  &ses0, &dm0);
              goto trace00;
            }

          dm0 = snat_det_map_by_user(sm, &ip0->src_address);
          if (PREDICT_FALSE(!dm0))
            {
              nat_log_info ("no match for internal host %U",
                            format_ip4_address, &ip0->src_address);
              next0 = SNAT_IN2OUT_NEXT_DROP;
              b0->error = node->errors[SNAT_IN2OUT_ERROR_NO_TRANSLATION];
              goto trace00;
            }

          snat_det_forward(dm0, &ip0->src_address, &new_addr0, &lo_port0);

          key0.ext_host_addr = ip0->dst_address;
          key0.ext_host_port = tcp0->dst;

          ses0 = snat_det_find_ses_by_in(dm0, &ip0->src_address, tcp0->src, key0);
          if (PREDICT_FALSE(!ses0))
            {
              for (i0 = 0; i0 < dm0->ports_per_host; i0++)
                {
                  key0.out_port = clib_host_to_net_u16 (lo_port0 +
                    ((i0 + clib_net_to_host_u16 (tcp0->src)) % dm0->ports_per_host));

                  if (snat_det_get_ses_by_out (dm0, &ip0->src_address, key0.as_u64))
                    continue;

                  ses0 = snat_det_ses_create(dm0, &ip0->src_address, tcp0->src, &key0);
                  break;
                }
              if (PREDICT_FALSE(!ses0))
                {
                  /* too many sessions for user, send ICMP error packet */

                  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
                  icmp4_error_set_vnet_buffer (b0, ICMP4_destination_unreachable,
                                               ICMP4_destination_unreachable_destination_unreachable_host,
                                               0);
                  next0 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
                  goto trace00;
                }
            }

          new_port0 = ses0->out.out_port;

          old_addr0.as_u32 = ip0->src_address.as_u32;
          ip0->src_address.as_u32 = new_addr0.as_u32;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm->outside_fib_index;

          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0.as_u32, new_addr0.as_u32,
                                 ip4_header_t,
                                 src_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
            {
              if (tcp0->flags & TCP_FLAG_SYN)
                ses0->state = SNAT_SESSION_TCP_SYN_SENT;
              else if (tcp0->flags & TCP_FLAG_ACK && ses0->state == SNAT_SESSION_TCP_SYN_SENT)
                ses0->state = SNAT_SESSION_TCP_ESTABLISHED;
              else if (tcp0->flags & TCP_FLAG_FIN && ses0->state == SNAT_SESSION_TCP_ESTABLISHED)
                ses0->state = SNAT_SESSION_TCP_FIN_WAIT;
              else if (tcp0->flags & TCP_FLAG_ACK && ses0->state == SNAT_SESSION_TCP_FIN_WAIT)
                snat_det_ses_close(dm0, ses0);
              else if (tcp0->flags & TCP_FLAG_FIN && ses0->state == SNAT_SESSION_TCP_CLOSE_WAIT)
                ses0->state = SNAT_SESSION_TCP_LAST_ACK;
              else if (tcp0->flags == 0 && ses0->state == SNAT_SESSION_UNKNOWN)
                ses0->state = SNAT_SESSION_TCP_ESTABLISHED;

              old_port0 = tcp0->src;
              tcp0->src = new_port0;

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
              ses0->state = SNAT_SESSION_UDP_ACTIVE;
              old_port0 = udp0->src_port;
              udp0->src_port = new_port0;
              udp0->checksum = 0;
            }

          switch(ses0->state)
            {
            case SNAT_SESSION_UDP_ACTIVE:
                ses0->expire = now + sm->udp_timeout;
                break;
            case SNAT_SESSION_TCP_SYN_SENT:
            case SNAT_SESSION_TCP_FIN_WAIT:
            case SNAT_SESSION_TCP_CLOSE_WAIT:
            case SNAT_SESSION_TCP_LAST_ACK:
                ses0->expire = now + sm->tcp_transitory_timeout;
                break;
            case SNAT_SESSION_TCP_ESTABLISHED:
                ses0->expire = now + sm->tcp_established_timeout;
                break;
            }

        trace00:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_in2out_trace_t *t =
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->is_slow_path = 0;
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
              t->session_index = ~0;
              if (ses0)
                t->session_index = ses0 - dm0->sessions;
            }

          pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, snat_det_in2out_node.index,
                               SNAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (snat_det_in2out_node) = {
  .function = snat_det_in2out_node_fn,
  .name = "nat44-det-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),

  .n_next_nodes = 3,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [SNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (snat_det_in2out_node, snat_det_in2out_node_fn);

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
u32 icmp_match_in2out_det(snat_main_t *sm, vlib_node_runtime_t *node,
                          u32 thread_index, vlib_buffer_t *b0,
                          ip4_header_t *ip0, u8 *p_proto,
                          snat_session_key_t *p_value,
                          u8 *p_dont_translate, void *d, void *e)
{
  icmp46_header_t *icmp0;
  u32 sw_if_index0;
  u32 rx_fib_index0;
  u8 protocol;
  snat_det_out_key_t key0;
  u8 dont_translate = 0;
  u32 next0 = ~0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;
  snat_det_map_t * dm0 = 0;
  ip4_address_t new_addr0;
  u16 lo_port0, i0;
  snat_det_session_t * ses0 = 0;
  ip4_address_t in_addr;
  u16 in_port;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *)(icmp0+1);
  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  if (!icmp_is_error_message (icmp0))
    {
      protocol = SNAT_PROTOCOL_ICMP;
      in_addr = ip0->src_address;
      in_port = echo0->identifier;
    }
  else
    {
      inner_ip0 = (ip4_header_t *)(echo0+1);
      l4_header = ip4_next_header (inner_ip0);
      protocol = ip_proto_to_snat_proto (inner_ip0->protocol);
      in_addr = inner_ip0->dst_address;
      switch (protocol)
        {
        case SNAT_PROTOCOL_ICMP:
          inner_icmp0 = (icmp46_header_t*)l4_header;
          inner_echo0 = (icmp_echo_header_t *)(inner_icmp0+1);
          in_port = inner_echo0->identifier;
          break;
        case SNAT_PROTOCOL_UDP:
        case SNAT_PROTOCOL_TCP:
          in_port = ((tcp_udp_header_t*)l4_header)->dst_port;
          break;
        default:
          b0->error = node->errors[SNAT_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
          next0 = SNAT_IN2OUT_NEXT_DROP;
          goto out;
        }
    }

  dm0 = snat_det_map_by_user(sm, &in_addr);
  if (PREDICT_FALSE(!dm0))
    {
      nat_log_info ("no match for internal host %U",
                    format_ip4_address, &in_addr);
      if (PREDICT_FALSE(snat_not_translate_fast(sm, node, sw_if_index0, ip0,
          IP_PROTOCOL_ICMP, rx_fib_index0)))
        {
          dont_translate = 1;
          goto out;
        }
      next0 = SNAT_IN2OUT_NEXT_DROP;
      b0->error = node->errors[SNAT_IN2OUT_ERROR_NO_TRANSLATION];
      goto out;
    }

  snat_det_forward(dm0, &in_addr, &new_addr0, &lo_port0);

  key0.ext_host_addr = ip0->dst_address;
  key0.ext_host_port = 0;

  ses0 = snat_det_find_ses_by_in(dm0, &in_addr, in_port, key0);
  if (PREDICT_FALSE(!ses0))
    {
      if (PREDICT_FALSE(snat_not_translate_fast(sm, node, sw_if_index0, ip0,
          IP_PROTOCOL_ICMP, rx_fib_index0)))
        {
          dont_translate = 1;
          goto out;
        }
      if (icmp0->type != ICMP4_echo_request)
        {
          b0->error = node->errors[SNAT_IN2OUT_ERROR_BAD_ICMP_TYPE];
          next0 = SNAT_IN2OUT_NEXT_DROP;
          goto out;
        }
      for (i0 = 0; i0 < dm0->ports_per_host; i0++)
        {
          key0.out_port = clib_host_to_net_u16 (lo_port0 +
            ((i0 + clib_net_to_host_u16 (echo0->identifier)) % dm0->ports_per_host));

          if (snat_det_get_ses_by_out (dm0, &in_addr, key0.as_u64))
            continue;

          ses0 = snat_det_ses_create(dm0, &in_addr, echo0->identifier, &key0);
          break;
        }
      if (PREDICT_FALSE(!ses0))
        {
          next0 = SNAT_IN2OUT_NEXT_DROP;
          b0->error = node->errors[SNAT_IN2OUT_ERROR_OUT_OF_PORTS];
          goto out;
        }
    }

  if (PREDICT_FALSE(icmp0->type != ICMP4_echo_request &&
                    !icmp_is_error_message (icmp0)))
    {
      b0->error = node->errors[SNAT_IN2OUT_ERROR_BAD_ICMP_TYPE];
      next0 = SNAT_IN2OUT_NEXT_DROP;
      goto out;
    }

  u32 now = (u32) vlib_time_now (sm->vlib_main);

  ses0->state = SNAT_SESSION_ICMP_ACTIVE;
  ses0->expire = now + sm->icmp_timeout;

out:
  *p_proto = protocol;
  if (ses0)
    {
      p_value->addr = new_addr0;
      p_value->fib_index = sm->outside_fib_index;
      p_value->port = ses0->out.out_port;
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
static inline uword
snat_in2out_worker_handoff_fn_inline (vlib_main_t * vm,
                                      vlib_node_runtime_t * node,
                                      vlib_frame_t * frame,
                                      u8 is_output)
{
  snat_main_t *sm = &snat_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 n_left_from, *from, *to_next = 0, *to_next_drop = 0;
  static __thread vlib_frame_queue_elt_t **handoff_queue_elt_by_worker_index;
  static __thread vlib_frame_queue_t **congested_handoff_queue_by_worker_index
    = 0;
  vlib_frame_queue_elt_t *hf = 0;
  vlib_frame_queue_t *fq;
  vlib_frame_t *f = 0;
  int i;
  u32 n_left_to_next_worker = 0, *to_next_worker = 0;
  u32 next_worker_index = 0;
  u32 current_worker_index = ~0;
  u32 thread_index = vm->thread_index;
  u32 fq_index;
  u32 to_node_index;
  vlib_frame_t *d = 0;

  ASSERT (vec_len (sm->workers));

  if (is_output)
    {
      fq_index = sm->fq_in2out_output_index;
      to_node_index = sm->in2out_output_node_index;
    }
  else
    {
      fq_index = sm->fq_in2out_index;
      to_node_index = sm->in2out_node_index;
    }

  if (PREDICT_FALSE (handoff_queue_elt_by_worker_index == 0))
    {
      vec_validate (handoff_queue_elt_by_worker_index, tm->n_vlib_mains - 1);

      vec_validate_init_empty (congested_handoff_queue_by_worker_index,
			       tm->n_vlib_mains - 1,
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

      next_worker_index = sm->worker_in2out_cb(ip0, rx_fib_index0);

      if (PREDICT_FALSE (next_worker_index != thread_index))
        {
          do_handoff = 1;

          if (next_worker_index != current_worker_index)
            {
              fq = is_vlib_frame_queue_congested (
                fq_index, next_worker_index, NAT_FQ_NELTS - 2,
                congested_handoff_queue_by_worker_index);

              if (fq)
                {
                  /* if this is 1st frame */
                  if (!d)
                    {
                      d = vlib_get_frame_to_node (vm, sm->error_node_index);
                      to_next_drop = vlib_frame_vector_args (d);
                    }

                  to_next_drop[0] = bi0;
                  to_next_drop += 1;
                  d->n_vectors++;
                  b0->error = node->errors[SNAT_IN2OUT_ERROR_FQ_CONGESTED];
                  goto trace0;
                }

              if (hf)
                hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;

              hf = vlib_get_worker_handoff_queue_elt (fq_index,
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
              f = vlib_get_frame_to_node (vm, to_node_index);
              to_next = vlib_frame_vector_args (f);
            }

          to_next[0] = bi0;
          to_next += 1;
          f->n_vectors++;
        }

trace0:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
          snat_in2out_worker_handoff_trace_t *t =
            vlib_add_trace (vm, node, b0, sizeof (*t));
          t->next_worker_index = next_worker_index;
          t->do_handoff = do_handoff;
        }
    }

  if (f)
    vlib_put_frame_to_node (vm, to_node_index, f);

  if (d)
    vlib_put_frame_to_node (vm, sm->error_node_index, d);

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

static uword
snat_in2out_worker_handoff_fn (vlib_main_t * vm,
                               vlib_node_runtime_t * node,
                               vlib_frame_t * frame)
{
  return snat_in2out_worker_handoff_fn_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (snat_in2out_worker_handoff_node) = {
  .function = snat_in2out_worker_handoff_fn,
  .name = "nat44-in2out-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_worker_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_worker_handoff_node,
                              snat_in2out_worker_handoff_fn);

static uword
snat_in2out_output_worker_handoff_fn (vlib_main_t * vm,
                                      vlib_node_runtime_t * node,
                                      vlib_frame_t * frame)
{
  return snat_in2out_worker_handoff_fn_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (snat_in2out_output_worker_handoff_node) = {
  .function = snat_in2out_output_worker_handoff_fn,
  .name = "nat44-in2out-output-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_worker_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_output_worker_handoff_node,
                              snat_in2out_output_worker_handoff_fn);

static_always_inline int
is_hairpinning (snat_main_t *sm, ip4_address_t * dst_addr)
{
  snat_address_t * ap;
  clib_bihash_kv_8_8_t kv, value;
  snat_session_key_t m_key;

  vec_foreach (ap, sm->addresses)
    {
      if (ap->addr.as_u32 == dst_addr->as_u32)
        return 1;
    }

  m_key.addr.as_u32 = dst_addr->as_u32;
  m_key.fib_index = 0;
  m_key.port = 0;
  m_key.protocol = 0;
  kv.key = m_key.as_u64;
  if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    return 1;

  return 0;
}

static inline uword
snat_hairpin_dst_fn_inline (vlib_main_t * vm,
                            vlib_node_runtime_t * node,
                            vlib_frame_t * frame,
                            int is_ed)
{
  u32 n_left_from, * from, * to_next, stats_node_index;
  snat_in2out_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t * sm = &snat_main;

  stats_node_index = is_ed ? nat44_ed_hairpin_dst_node.index :
    snat_hairpin_dst_node.index;

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
          u32 next0;
          ip4_header_t * ip0;
          u32 proto0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          next0 = SNAT_IN2OUT_NEXT_LOOKUP;
          ip0 = vlib_buffer_get_current (b0);

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          vnet_buffer (b0)->snat.flags = 0;
          if (PREDICT_FALSE (is_hairpinning (sm, &ip0->dst_address)))
            {
              if (proto0 == SNAT_PROTOCOL_TCP || proto0 == SNAT_PROTOCOL_UDP)
                {
                  udp_header_t * udp0 = ip4_next_header (ip0);
                  tcp_header_t * tcp0 = (tcp_header_t *) udp0;

                  snat_hairpinning (sm, b0, ip0, udp0, tcp0, proto0, is_ed);
                }
              else if (proto0 == SNAT_PROTOCOL_ICMP)
                {
                  icmp46_header_t * icmp0 = ip4_next_header (ip0);

                  snat_icmp_hairpinning (sm, b0, ip0, icmp0, is_ed);
                }
              else
                {
                  if (is_ed)
                    nat44_ed_hairpinning_unknown_proto (sm, b0, ip0);
                  else
                    nat_hairpinning_sm_unknown_proto (sm, b0, ip0);
                }

              vnet_buffer (b0)->snat.flags = SNAT_FLAG_HAIRPINNING;
            }

          pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
         }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
                               SNAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

static uword
snat_hairpin_dst_fn (vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * frame)
{
  return snat_hairpin_dst_fn_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (snat_hairpin_dst_node) = {
  .function = snat_hairpin_dst_fn,
  .name = "nat44-hairpin-dst",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,
  .n_next_nodes = 2,
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (snat_hairpin_dst_node,
                              snat_hairpin_dst_fn);

static uword
nat44_ed_hairpin_dst_fn (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame)
{
  return snat_hairpin_dst_fn_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (nat44_ed_hairpin_dst_node) = {
  .function = nat44_ed_hairpin_dst_fn,
  .name = "nat44-ed-hairpin-dst",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,
  .n_next_nodes = 2,
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_hairpin_dst_node,
                              nat44_ed_hairpin_dst_fn);

static inline uword
snat_hairpin_src_fn_inline (vlib_main_t * vm,
                            vlib_node_runtime_t * node,
                            vlib_frame_t * frame,
                            int is_ed)
{
  u32 n_left_from, * from, * to_next, stats_node_index;
  snat_in2out_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t *sm = &snat_main;

  stats_node_index = is_ed ? nat44_ed_hairpin_src_node.index :
    snat_hairpin_src_node.index;

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
          u32 next0;
          snat_interface_t *i;
          u32 sw_if_index0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          next0 = SNAT_HAIRPIN_SRC_NEXT_INTERFACE_OUTPUT;

          pool_foreach (i, sm->output_feature_interfaces,
          ({
            /* Only packets from NAT inside interface */
            if ((nat_interface_is_inside(i)) && (sw_if_index0 == i->sw_if_index))
              {
                if (PREDICT_FALSE ((vnet_buffer (b0)->snat.flags) &
                                    SNAT_FLAG_HAIRPINNING))
                  {
                    if (PREDICT_TRUE (sm->num_workers > 1))
                      next0 = SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT_WH;
                    else
                      next0 = SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT;
                  }
                break;
              }
          }));

          pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
         }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
                               SNAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

static uword
snat_hairpin_src_fn (vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * frame)
{
  return snat_hairpin_src_fn_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (snat_hairpin_src_node) = {
  .function = snat_hairpin_src_fn,
  .name = "nat44-hairpin-src",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,
  .n_next_nodes = SNAT_HAIRPIN_SRC_N_NEXT,
  .next_nodes = {
     [SNAT_HAIRPIN_SRC_NEXT_DROP] = "error-drop",
     [SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT] = "nat44-in2out-output",
     [SNAT_HAIRPIN_SRC_NEXT_INTERFACE_OUTPUT] = "interface-output",
     [SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT_WH] = "nat44-in2out-output-worker-handoff",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (snat_hairpin_src_node,
                              snat_hairpin_src_fn);

static uword
nat44_ed_hairpin_src_fn (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * frame)
{
  return snat_hairpin_src_fn_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (nat44_ed_hairpin_src_node) = {
  .function = nat44_ed_hairpin_src_fn,
  .name = "nat44-ed-hairpin-src",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,
  .n_next_nodes = SNAT_HAIRPIN_SRC_N_NEXT,
  .next_nodes = {
     [SNAT_HAIRPIN_SRC_NEXT_DROP] = "error-drop",
     [SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT] = "nat44-ed-in2out-output",
     [SNAT_HAIRPIN_SRC_NEXT_INTERFACE_OUTPUT] = "interface-output",
     [SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT_WH] = "nat44-in2out-output-worker-handoff",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_hairpin_src_node,
                              nat44_ed_hairpin_src_fn);

static uword
snat_in2out_fast_static_map_fn (vlib_main_t * vm,
                                vlib_node_runtime_t * node,
                                vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  snat_in2out_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t * sm = &snat_main;
  u32 stats_node_index;

  stats_node_index = snat_in2out_fast_node.index;

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
          u32 next0;
          u32 sw_if_index0;
          ip4_header_t * ip0;
          ip_csum_t sum0;
          u32 new_addr0, old_addr0;
          u16 old_port0, new_port0;
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
          next0 = SNAT_IN2OUT_NEXT_LOOKUP;

          ip0 = vlib_buffer_get_current (b0);
          udp0 = ip4_next_header (ip0);
          tcp0 = (tcp_header_t *) udp0;
          icmp0 = (icmp46_header_t *) udp0;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index0);

          if (PREDICT_FALSE(ip0->ttl == 1))
            {
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
              icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
                                           ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                           0);
              next0 = SNAT_IN2OUT_NEXT_ICMP_ERROR;
              goto trace0;
            }

          proto0 = ip_proto_to_snat_proto (ip0->protocol);

          if (PREDICT_FALSE (proto0 == ~0))
              goto trace0;

          if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
            {
              next0 = icmp_in2out(sm, b0, ip0, icmp0, sw_if_index0,
                                  rx_fib_index0, node, next0, ~0, 0, 0);
              goto trace0;
            }

          key0.addr = ip0->src_address;
          key0.protocol = proto0;
          key0.port = udp0->src_port;
          key0.fib_index = rx_fib_index0;

          if (snat_static_mapping_match(sm, key0, &sm0, 0, 0, 0, 0))
            {
              b0->error = node->errors[SNAT_IN2OUT_ERROR_NO_TRANSLATION];
              next0= SNAT_IN2OUT_NEXT_DROP;
              goto trace0;
            }

          new_addr0 = sm0.addr.as_u32;
          new_port0 = sm0.port;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm0.fib_index;
          old_addr0 = ip0->src_address.as_u32;
          ip0->src_address.as_u32 = new_addr0;

          sum0 = ip0->checksum;
          sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
                                 ip4_header_t,
                                 src_address /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);

          if (PREDICT_FALSE(new_port0 != udp0->dst_port))
            {
              if (PREDICT_TRUE(proto0 == SNAT_PROTOCOL_TCP))
                {
                  old_port0 = tcp0->src_port;
                  tcp0->src_port = new_port0;

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
                  old_port0 = udp0->src_port;
                  udp0->src_port = new_port0;
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

          /* Hairpinning */
          snat_hairpinning (sm, b0, ip0, udp0, tcp0, proto0, 0);

        trace0:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              snat_in2out_trace_t *t =
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
            }

          pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
                               SNAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}


VLIB_REGISTER_NODE (snat_in2out_fast_node) = {
  .function = snat_in2out_fast_static_map_fn,
  .name = "nat44-in2out-fast",
  .vector_size = sizeof (u32),
  .format_trace = format_snat_in2out_fast_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(snat_in2out_error_strings),
  .error_strings = snat_in2out_error_strings,

  .runtime_data_bytes = sizeof (snat_runtime_t),

  .n_next_nodes = SNAT_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [SNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [SNAT_IN2OUT_NEXT_SLOW_PATH] = "nat44-in2out-slowpath",
    [SNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [SNAT_IN2OUT_NEXT_REASS] = "nat44-in2out-reass",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_fast_node, snat_in2out_fast_static_map_fn);
