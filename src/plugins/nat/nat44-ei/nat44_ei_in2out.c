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
/**
 * @file
 * @brief NAT44 EI inside to outside network translation
 */

#include <vlib/vlib.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/udp/udp_local.h>
#include <vnet/fib/ip4_fib.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#include <nat/lib/log.h>
#include <nat/lib/nat_syslog.h>
#include <nat/lib/ipfix_logging.h>
#include <nat/lib/nat_inlines.h>
#include <nat/nat44-ei/nat44_ei_inlines.h>
#include <nat/nat44-ei/nat44_ei.h>
#include <nat/nat44-ei/nat44_ei_hairpinning.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
  u32 is_slow_path;
  u32 is_hairpinning;
} nat44_ei_in2out_trace_t;

/* packet trace format function */
static u8 *
format_nat44_ei_in2out_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat44_ei_in2out_trace_t *t = va_arg (*args, nat44_ei_in2out_trace_t *);
  char *tag;

  tag = t->is_slow_path ? "NAT44_IN2OUT_SLOW_PATH" : "NAT44_IN2OUT_FAST_PATH";

  s = format (s, "%s: sw_if_index %d, next index %d, session %d", tag,
	      t->sw_if_index, t->next_index, t->session_index);
  if (t->is_hairpinning)
    {
      s = format (s, ", with-hairpinning");
    }

  return s;
}

static u8 *
format_nat44_ei_in2out_fast_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat44_ei_in2out_trace_t *t = va_arg (*args, nat44_ei_in2out_trace_t *);

  s = format (s, "NAT44_IN2OUT_FAST: sw_if_index %d, next index %d",
	      t->sw_if_index, t->next_index);

  return s;
}

#define foreach_nat44_ei_in2out_error                                         \
  _ (UNSUPPORTED_PROTOCOL, "unsupported protocol")                            \
  _ (OUT_OF_PORTS, "out of ports")                                            \
  _ (BAD_OUTSIDE_FIB, "outside VRF ID not found")                             \
  _ (BAD_ICMP_TYPE, "unsupported ICMP type")                                  \
  _ (NO_TRANSLATION, "no translation")                                        \
  _ (MAX_SESSIONS_EXCEEDED, "maximum sessions exceeded")                      \
  _ (CANNOT_CREATE_USER, "cannot create NAT user")

typedef enum
{
#define _(sym, str) NAT44_EI_IN2OUT_ERROR_##sym,
  foreach_nat44_ei_in2out_error
#undef _
    NAT44_EI_IN2OUT_N_ERROR,
} nat44_ei_in2out_error_t;

static char *nat44_ei_in2out_error_strings[] = {
#define _(sym,string) string,
  foreach_nat44_ei_in2out_error
#undef _
};

typedef enum
{
  NAT44_EI_IN2OUT_NEXT_LOOKUP,
  NAT44_EI_IN2OUT_NEXT_DROP,
  NAT44_EI_IN2OUT_NEXT_ICMP_ERROR,
  NAT44_EI_IN2OUT_NEXT_SLOW_PATH,
  NAT44_EI_IN2OUT_NEXT_HAIRPINNING_HANDOFF,
  NAT44_EI_IN2OUT_N_NEXT,
} nat44_ei_in2out_next_t;

typedef enum
{
  NAT44_EI_IN2OUT_HAIRPINNING_FINISH_NEXT_DROP,
  NAT44_EI_IN2OUT_HAIRPINNING_FINISH_NEXT_LOOKUP,
  NAT44_EI_IN2OUT_HAIRPINNING_FINISH_N_NEXT,
} nat44_ei_in2out_hairpinnig_finish_next_t;

static inline int
nat44_ei_not_translate_fast (vlib_node_runtime_t *node, u32 sw_if_index0,
			     ip4_header_t *ip0, u32 proto0, u32 rx_fib_index0)
{
  nat44_ei_main_t *nm = &nat44_ei_main;

  if (nm->out2in_dpo)
    return 0;

  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  nat44_ei_outside_fib_t *outside_fib;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
		.ip4.as_u32 = ip0->dst_address.as_u32,
		}
    ,
  };

  /* Don't NAT packet aimed at the intfc address */
  if (PREDICT_FALSE (nat44_ei_is_interface_addr (
	nm->ip4_main, node, sw_if_index0, ip0->dst_address.as_u32)))
    return 1;

  fei = fib_table_lookup (rx_fib_index0, &pfx);
  if (FIB_NODE_INDEX_INVALID != fei)
    {
      u32 sw_if_index = fib_entry_get_resolving_interface (fei);
      if (sw_if_index == ~0)
	{
	  vec_foreach (outside_fib, nm->outside_fibs)
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

      nat44_ei_interface_t *i;
      pool_foreach (i, nm->interfaces)
	{
	  /* NAT packet aimed at outside interface */
	  if ((nat44_ei_interface_is_outside (i)) &&
	      (sw_if_index == i->sw_if_index))
	    return 0;
	}
    }

  return 1;
}

static inline int
nat44_ei_not_translate (nat44_ei_main_t *nm, vlib_node_runtime_t *node,
			u32 sw_if_index0, ip4_header_t *ip0, u32 proto0,
			u32 rx_fib_index0, u32 thread_index)
{
  udp_header_t *udp0 = ip4_next_header (ip0);
  clib_bihash_kv_8_8_t kv0, value0;

  init_nat_k (&kv0, ip0->dst_address, udp0->dst_port, nm->outside_fib_index,
	      proto0);

  /* NAT packet aimed at external address if */
  /* has active sessions */
  if (clib_bihash_search_8_8 (&nm->out2in, &kv0, &value0))
    {
      /* or is static mappings */
      ip4_address_t placeholder_addr;
      u16 placeholder_port;
      u32 placeholder_fib_index;
      if (!nat44_ei_static_mapping_match (ip0->dst_address, udp0->dst_port,
					  nm->outside_fib_index, proto0,
					  &placeholder_addr, &placeholder_port,
					  &placeholder_fib_index, 1, 0, 0))
	return 0;
    }
  else
    return 0;

  if (nm->forwarding_enabled)
    return 1;

  return nat44_ei_not_translate_fast (node, sw_if_index0, ip0, proto0,
				      rx_fib_index0);
}

static inline int
nat44_ei_not_translate_output_feature (nat44_ei_main_t *nm, ip4_header_t *ip0,
				       u32 proto0, u16 src_port, u16 dst_port,
				       u32 thread_index, u32 sw_if_index)
{
  clib_bihash_kv_8_8_t kv0, value0;
  nat44_ei_interface_t *i;

  /* src NAT check */
  init_nat_k (&kv0, ip0->src_address, src_port,
	      ip4_fib_table_get_index_for_sw_if_index (sw_if_index), proto0);

  if (!clib_bihash_search_8_8 (&nm->out2in, &kv0, &value0))
    return 1;

  /* dst NAT check */
  init_nat_k (&kv0, ip0->dst_address, dst_port,
	      ip4_fib_table_get_index_for_sw_if_index (sw_if_index), proto0);
  if (!clib_bihash_search_8_8 (&nm->in2out, &kv0, &value0))
    {
      /* hairpinning */
      pool_foreach (i, nm->output_feature_interfaces)
	{
	  if ((nat44_ei_interface_is_inside (i)) &&
	      (sw_if_index == i->sw_if_index))
	    return 0;
	}
      return 1;
    }

  return 0;
}

#ifndef CLIB_MARCH_VARIANT
int
nat44_i2o_is_idle_session_cb (clib_bihash_kv_8_8_t * kv, void *arg)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_is_idle_session_ctx_t *ctx = arg;
  nat44_ei_session_t *s;
  u64 sess_timeout_time;
  nat44_ei_main_per_thread_data_t *tnm =
    vec_elt_at_index (nm->per_thread_data, ctx->thread_index);
  clib_bihash_kv_8_8_t s_kv;

  if (ctx->thread_index != nat_value_get_thread_index (kv))
    {
      return 0;
    }

  s = pool_elt_at_index (tnm->sessions, nat_value_get_session_index (kv));
  sess_timeout_time = s->last_heard + (f64) nat_session_get_timeout (
					&nm->timeouts, s->nat_proto, s->state);
  if (ctx->now >= sess_timeout_time)
    {
      init_nat_o2i_k (&s_kv, s);
      if (clib_bihash_add_del_8_8 (&nm->out2in, &s_kv, 0))
	nat_elog_warn (nm, "out2in key del failed");

      nat_ipfix_logging_nat44_ses_delete (
	ctx->thread_index, s->in2out.addr.as_u32, s->out2in.addr.as_u32,
	nat_proto_to_ip_proto (s->nat_proto), s->in2out.port, s->out2in.port,
	s->in2out.fib_index);

      nat_syslog_nat44_apmdel (s->user_index, s->in2out.fib_index,
			       &s->in2out.addr, s->in2out.port,
			       &s->out2in.addr, s->out2in.port, s->nat_proto);

      nat_ha_sdel (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
		   s->ext_host_port, s->nat_proto, s->out2in.fib_index,
		   ctx->thread_index);

      if (!nat44_ei_is_session_static (s))
	nat44_ei_free_outside_address_and_port (
	  nm->addresses, ctx->thread_index, &s->out2in.addr, s->out2in.port,
	  s->nat_proto);

      nat44_ei_delete_session (nm, s, ctx->thread_index);
      return 1;
    }

  return 0;
}
#endif

static u32
slow_path (nat44_ei_main_t *nm, vlib_buffer_t *b0, ip4_header_t *ip0,
	   ip4_address_t i2o_addr, u16 i2o_port, u32 rx_fib_index0,
	   nat_protocol_t nat_proto, nat44_ei_session_t **sessionp,
	   vlib_node_runtime_t *node, u32 next0, u32 thread_index, f64 now)
{
  nat44_ei_user_t *u;
  nat44_ei_session_t *s = 0;
  clib_bihash_kv_8_8_t kv0;
  u8 is_sm = 0;
  nat44_ei_outside_fib_t *outside_fib;
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  u8 identity_nat;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
		.ip4.as_u32 = ip0->dst_address.as_u32,
		},
  };
  nat44_ei_is_idle_session_ctx_t ctx0;
  ip4_address_t sm_addr;
  u16 sm_port;
  u32 sm_fib_index;

  if (PREDICT_FALSE (nat44_ei_maximum_sessions_exceeded (nm, thread_index)))
    {
      b0->error = node->errors[NAT44_EI_IN2OUT_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_ipfix_logging_max_sessions (thread_index,
				      nm->max_translations_per_thread);
      nat_elog_notice (nm, "maximum sessions exceeded");
      return NAT44_EI_IN2OUT_NEXT_DROP;
    }

  /* First try to match static mapping by local address and port */
  if (nat44_ei_static_mapping_match (i2o_addr, i2o_port, rx_fib_index0,
				     nat_proto, &sm_addr, &sm_port,
				     &sm_fib_index, 0, 0, &identity_nat))
    {
      /* Try to create dynamic translation */
      if (nm->alloc_addr_and_port (
	    nm->addresses, rx_fib_index0, thread_index, nat_proto,
	    ip0->src_address, &sm_addr, &sm_port, nm->port_per_thread,
	    nm->per_thread_data[thread_index].snat_thread_index))
	{
	  b0->error = node->errors[NAT44_EI_IN2OUT_ERROR_OUT_OF_PORTS];
	  return NAT44_EI_IN2OUT_NEXT_DROP;
	}
    }
  else
    {
      if (PREDICT_FALSE (identity_nat))
	{
	  *sessionp = s;
	  return next0;
	}

      is_sm = 1;
    }

  u = nat44_ei_user_get_or_create (nm, &ip0->src_address, rx_fib_index0,
				   thread_index);
  if (!u)
    {
      b0->error = node->errors[NAT44_EI_IN2OUT_ERROR_CANNOT_CREATE_USER];
      return NAT44_EI_IN2OUT_NEXT_DROP;
    }

  s = nat44_ei_session_alloc_or_recycle (nm, u, thread_index, now);
  if (!s)
    {
      nat44_ei_delete_user_with_no_session (nm, u, thread_index);
      nat_elog_warn (nm, "create NAT session failed");
      return NAT44_EI_IN2OUT_NEXT_DROP;
    }

  if (is_sm)
    s->flags |= NAT44_EI_SESSION_FLAG_STATIC_MAPPING;
  nat44_ei_user_session_increment (nm, u, is_sm);
  s->in2out.addr = i2o_addr;
  s->in2out.port = i2o_port;
  s->in2out.fib_index = rx_fib_index0;
  s->nat_proto = nat_proto;
  s->out2in.addr = sm_addr;
  s->out2in.port = sm_port;
  s->out2in.fib_index = nm->outside_fib_index;
  switch (vec_len (nm->outside_fibs))
    {
    case 0:
      s->out2in.fib_index = nm->outside_fib_index;
      break;
    case 1:
      s->out2in.fib_index = nm->outside_fibs[0].fib_index;
      break;
    default:
      vec_foreach (outside_fib, nm->outside_fibs)
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
  s->ext_host_port = vnet_buffer (b0)->ip.reass.l4_dst_port;
  *sessionp = s;

  /* Add to translation hashes */
  ctx0.now = now;
  ctx0.thread_index = thread_index;
  init_nat_i2o_kv (&kv0, s, thread_index,
		   s - nm->per_thread_data[thread_index].sessions);
  if (clib_bihash_add_or_overwrite_stale_8_8 (
	&nm->in2out, &kv0, nat44_i2o_is_idle_session_cb, &ctx0))
    nat_elog_notice (nm, "in2out key add failed");

  init_nat_o2i_kv (&kv0, s, thread_index,
		   s - nm->per_thread_data[thread_index].sessions);
  if (clib_bihash_add_or_overwrite_stale_8_8 (
	&nm->out2in, &kv0, nat44_o2i_is_idle_session_cb, &ctx0))
    nat_elog_notice (nm, "out2in key add failed");

  /* log NAT event */
  nat_ipfix_logging_nat44_ses_create (
    thread_index, s->in2out.addr.as_u32, s->out2in.addr.as_u32,
    nat_proto_to_ip_proto (s->nat_proto), s->in2out.port, s->out2in.port,
    s->in2out.fib_index);

  nat_syslog_nat44_apmadd (s->user_index, s->in2out.fib_index, &s->in2out.addr,
			   s->in2out.port, &s->out2in.addr, s->out2in.port,
			   s->nat_proto);

  nat_ha_sadd (&s->in2out.addr, s->in2out.port, &s->out2in.addr,
	       s->out2in.port, &s->ext_host_addr, s->ext_host_port,
	       &s->ext_host_nat_addr, s->ext_host_nat_port, s->nat_proto,
	       s->in2out.fib_index, s->flags, thread_index, 0);

  return next0;
}

#ifndef CLIB_MARCH_VARIANT
static_always_inline nat44_ei_in2out_error_t
icmp_get_key (vlib_buffer_t *b, ip4_header_t *ip0, ip4_address_t *addr,
	      u16 *port, nat_protocol_t *nat_proto)
{
  icmp46_header_t *icmp0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0 = 0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *) (icmp0 + 1);

  if (!icmp_type_is_error_message
      (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
    {
      *nat_proto = NAT_PROTOCOL_ICMP;
      *addr = ip0->src_address;
      *port = vnet_buffer (b)->ip.reass.l4_src_port;
    }
  else
    {
      inner_ip0 = (ip4_header_t *) (echo0 + 1);
      l4_header = ip4_next_header (inner_ip0);
      *nat_proto = ip_proto_to_nat_proto (inner_ip0->protocol);
      *addr = inner_ip0->dst_address;
      switch (*nat_proto)
	{
	case NAT_PROTOCOL_ICMP:
	  inner_icmp0 = (icmp46_header_t *) l4_header;
	  inner_echo0 = (icmp_echo_header_t *) (inner_icmp0 + 1);
	  *port = inner_echo0->identifier;
	  break;
	case NAT_PROTOCOL_UDP:
	case NAT_PROTOCOL_TCP:
	  *port = ((tcp_udp_header_t *) l4_header)->dst_port;
	  break;
	default:
	  return NAT44_EI_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL;
	}
    }
  return -1;			/* success */
}

/**
 * Get address and port values to be used for ICMP packet translation
 * and create session if needed
 *
 * @param[in,out] nm             NAT main
 * @param[in,out] node           NAT node runtime
 * @param[in] thread_index       thread index
 * @param[in,out] b0             buffer containing packet to be translated
 * @param[in,out] ip0            ip header
 * @param[out] p_proto           protocol used for matching
 * @param[out] p_value           address and port after NAT translation
 * @param[out] p_dont_translate  if packet should not be translated
 * @param d                      optional parameter
 * @param e                      optional parameter
 */
u32
nat44_ei_icmp_match_in2out_slow (vlib_node_runtime_t *node, u32 thread_index,
				 vlib_buffer_t *b0, ip4_header_t *ip0,
				 ip4_address_t *addr, u16 *port,
				 u32 *fib_index, nat_protocol_t *proto,
				 nat44_ei_session_t **p_s0, u8 *dont_translate)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_main_per_thread_data_t *tnm = &nm->per_thread_data[thread_index];
  u32 sw_if_index0;
  nat44_ei_session_t *s0 = 0;
  clib_bihash_kv_8_8_t kv0, value0;
  u32 next0 = ~0;
  int err;
  vlib_main_t *vm = vlib_get_main ();
  *dont_translate = 0;

  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  *fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  err = icmp_get_key (b0, ip0, addr, port, proto);
  if (err != -1)
    {
      b0->error = node->errors[err];
      next0 = NAT44_EI_IN2OUT_NEXT_DROP;
      goto out;
    }

  init_nat_k (&kv0, *addr, *port, *fib_index, *proto);
  if (clib_bihash_search_8_8 (&nm->in2out, &kv0, &value0))
    {
      if (vnet_buffer (b0)->sw_if_index[VLIB_TX] != ~0)
	{
	  if (PREDICT_FALSE (nat44_ei_not_translate_output_feature (
		nm, ip0, *proto, *port, *port, thread_index, sw_if_index0)))
	    {
	      *dont_translate = 1;
	      goto out;
	    }
	}
      else
	{
	  if (PREDICT_FALSE (nat44_ei_not_translate (
		nm, node, sw_if_index0, ip0, NAT_PROTOCOL_ICMP, *fib_index,
		thread_index)))
	    {
	      *dont_translate = 1;
	      goto out;
	    }
	}

      if (PREDICT_FALSE
	  (icmp_type_is_error_message
	   (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags)))
	{
	  b0->error = node->errors[NAT44_EI_IN2OUT_ERROR_BAD_ICMP_TYPE];
	  next0 = NAT44_EI_IN2OUT_NEXT_DROP;
	  goto out;
	}

      next0 = slow_path (nm, b0, ip0, *addr, *port, *fib_index, *proto, &s0,
			 node, next0, thread_index, vlib_time_now (vm));

      if (PREDICT_FALSE (next0 == NAT44_EI_IN2OUT_NEXT_DROP))
	goto out;

      if (!s0)
	{
	  *dont_translate = 1;
	  goto out;
	}
    }
  else
    {
      if (PREDICT_FALSE
	  (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_request
	   && vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_reply
	   && !icmp_type_is_error_message (vnet_buffer (b0)->ip.
					   reass.icmp_type_or_tcp_flags)))
	{
	  b0->error = node->errors[NAT44_EI_IN2OUT_ERROR_BAD_ICMP_TYPE];
	  next0 = NAT44_EI_IN2OUT_NEXT_DROP;
	  goto out;
	}

      s0 = pool_elt_at_index (tnm->sessions,
			      nat_value_get_session_index (&value0));
    }

out:
  if (s0)
    {
      *addr = s0->out2in.addr;
      *port = s0->out2in.port;
      *fib_index = s0->out2in.fib_index;
    }
  if (p_s0)
    *p_s0 = s0;
  return next0;
}
#endif

#ifndef CLIB_MARCH_VARIANT
u32
nat44_ei_icmp_match_in2out_fast (vlib_node_runtime_t *node, u32 thread_index,
				 vlib_buffer_t *b0, ip4_header_t *ip0,
				 ip4_address_t *addr, u16 *port,
				 u32 *fib_index, nat_protocol_t *proto,
				 nat44_ei_session_t **s0, u8 *dont_translate)
{
  u32 sw_if_index0;
  u8 is_addr_only;
  u32 next0 = ~0;
  int err;
  *dont_translate = 0;

  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  *fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  err = icmp_get_key (b0, ip0, addr, port, proto);
  if (err != -1)
    {
      b0->error = node->errors[err];
      next0 = NAT44_EI_IN2OUT_NEXT_DROP;
      goto out;
    }

  ip4_address_t sm_addr;
  u16 sm_port;
  u32 sm_fib_index;

  if (nat44_ei_static_mapping_match (*addr, *port, *fib_index, *proto,
				     &sm_addr, &sm_port, &sm_fib_index, 0,
				     &is_addr_only, 0))
    {
      if (PREDICT_FALSE (nat44_ei_not_translate_fast (
	    node, sw_if_index0, ip0, IP_PROTOCOL_ICMP, *fib_index)))
	{
	  *dont_translate = 1;
	  goto out;
	}

      if (icmp_type_is_error_message
	  (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags))
	{
	  next0 = NAT44_EI_IN2OUT_NEXT_DROP;
	  goto out;
	}

      b0->error = node->errors[NAT44_EI_IN2OUT_ERROR_NO_TRANSLATION];
      next0 = NAT44_EI_IN2OUT_NEXT_DROP;
      goto out;
    }

  if (PREDICT_FALSE
      (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags != ICMP4_echo_request
       && (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_reply || !is_addr_only)
       && !icmp_type_is_error_message (vnet_buffer (b0)->ip.
				       reass.icmp_type_or_tcp_flags)))
    {
      b0->error = node->errors[NAT44_EI_IN2OUT_ERROR_BAD_ICMP_TYPE];
      next0 = NAT44_EI_IN2OUT_NEXT_DROP;
      goto out;
    }

out:
  return next0;
}
#endif

u32 nat44_ei_icmp_in2out (vlib_buffer_t *b0, ip4_header_t *ip0,
			  icmp46_header_t *icmp0, u32 sw_if_index0,
			  u32 rx_fib_index0, vlib_node_runtime_t *node,
			  u32 next0, u32 thread_index,
			  nat44_ei_session_t **p_s0);

#ifndef CLIB_MARCH_VARIANT
u32
nat44_ei_icmp_in2out (vlib_buffer_t *b0, ip4_header_t *ip0,
		      icmp46_header_t *icmp0, u32 sw_if_index0,
		      u32 rx_fib_index0, vlib_node_runtime_t *node, u32 next0,
		      u32 thread_index, nat44_ei_session_t **p_s0)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vlib_main_t *vm = vlib_get_main ();
  ip4_address_t addr;
  u16 port;
  u32 fib_index;
  nat_protocol_t proto;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;
  u8 dont_translate;
  u32 new_addr0, old_addr0;
  u16 old_id0, new_id0;
  u16 old_checksum0, new_checksum0;
  ip_csum_t sum0;
  u16 checksum0;
  u32 next0_tmp;
  u32 required_thread_index = thread_index;

  echo0 = (icmp_echo_header_t *) (icmp0 + 1);

  if (PREDICT_TRUE (nm->pat))
    {
      next0_tmp = nat44_ei_icmp_match_in2out_slow (
	node, thread_index, b0, ip0, &addr, &port, &fib_index, &proto, p_s0,
	&dont_translate);
    }
  else
    {
      next0_tmp = nat44_ei_icmp_match_in2out_fast (
	node, thread_index, b0, ip0, &addr, &port, &fib_index, &proto, p_s0,
	&dont_translate);
    }

  if (next0_tmp != ~0)
    next0 = next0_tmp;
  if (next0 == NAT44_EI_IN2OUT_NEXT_DROP || dont_translate)
    goto out;

  if (PREDICT_TRUE (!ip4_is_fragment (ip0)))
    {
      sum0 =
	ip_incremental_checksum_buffer (vm, b0,
					(u8 *) icmp0 -
					(u8 *) vlib_buffer_get_current (b0),
					ntohs (ip0->length) -
					ip4_header_bytes (ip0), 0);
      checksum0 = ~ip_csum_fold (sum0);
      if (PREDICT_FALSE (checksum0 != 0 && checksum0 != 0xffff))
	{
	  next0 = NAT44_EI_IN2OUT_NEXT_DROP;
	  goto out;
	}
    }

  old_addr0 = ip0->src_address.as_u32;
  new_addr0 = ip0->src_address.as_u32 = addr.as_u32;

  sum0 = ip0->checksum;
  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			 src_address /* changed member */ );
  ip0->checksum = ip_csum_fold (sum0);

  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
    {
      if (icmp0->checksum == 0)
	icmp0->checksum = 0xffff;

      if (!icmp_type_is_error_message (icmp0->type))
	{
	  new_id0 = port;
	  if (PREDICT_FALSE (new_id0 != echo0->identifier))
	    {
	      old_id0 = echo0->identifier;
	      new_id0 = port;
	      echo0->identifier = new_id0;

	      sum0 = icmp0->checksum;
	      sum0 =
		ip_csum_update (sum0, old_id0, new_id0, icmp_echo_header_t,
				identifier);
	      icmp0->checksum = ip_csum_fold (sum0);
	    }
	}
      else
	{
	  inner_ip0 = (ip4_header_t *) (echo0 + 1);
	  l4_header = ip4_next_header (inner_ip0);

	  if (!ip4_header_checksum_is_valid (inner_ip0))
	    {
	      next0 = NAT44_EI_IN2OUT_NEXT_DROP;
	      goto out;
	    }

	  /* update inner destination IP address */
	  old_addr0 = inner_ip0->dst_address.as_u32;
	  inner_ip0->dst_address = addr;
	  new_addr0 = inner_ip0->dst_address.as_u32;
	  sum0 = icmp0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				 dst_address /* changed member */ );
	  icmp0->checksum = ip_csum_fold (sum0);

	  /* update inner IP header checksum */
	  old_checksum0 = inner_ip0->checksum;
	  sum0 = inner_ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				 dst_address /* changed member */ );
	  inner_ip0->checksum = ip_csum_fold (sum0);
	  new_checksum0 = inner_ip0->checksum;
	  sum0 = icmp0->checksum;
	  sum0 =
	    ip_csum_update (sum0, old_checksum0, new_checksum0, ip4_header_t,
			    checksum);
	  icmp0->checksum = ip_csum_fold (sum0);

	  switch (proto)
	    {
	    case NAT_PROTOCOL_ICMP:
	      inner_icmp0 = (icmp46_header_t *) l4_header;
	      inner_echo0 = (icmp_echo_header_t *) (inner_icmp0 + 1);

	      old_id0 = inner_echo0->identifier;
	      new_id0 = port;
	      inner_echo0->identifier = new_id0;

	      sum0 = icmp0->checksum;
	      sum0 =
		ip_csum_update (sum0, old_id0, new_id0, icmp_echo_header_t,
				identifier);
	      icmp0->checksum = ip_csum_fold (sum0);
	      break;
	    case NAT_PROTOCOL_UDP:
	    case NAT_PROTOCOL_TCP:
	      old_id0 = ((tcp_udp_header_t *) l4_header)->dst_port;
	      new_id0 = port;
	      ((tcp_udp_header_t *) l4_header)->dst_port = new_id0;

	      sum0 = icmp0->checksum;
	      sum0 = ip_csum_update (sum0, old_id0, new_id0, tcp_udp_header_t,
				     dst_port);
	      icmp0->checksum = ip_csum_fold (sum0);
	      break;
	    default:
	      ASSERT (0);
	    }
	}
    }

  if (vnet_buffer (b0)->sw_if_index[VLIB_TX] == ~0)
    {
      if (0 != nat44_ei_icmp_hairpinning (nm, b0, thread_index, ip0, icmp0,
					  &required_thread_index))
	vnet_buffer (b0)->sw_if_index[VLIB_TX] = fib_index;
      if (thread_index != required_thread_index)
	{
	  vnet_buffer (b0)->snat.required_thread_index = required_thread_index;
	  next0 = NAT44_EI_IN2OUT_NEXT_HAIRPINNING_HANDOFF;
	}
    }

out:
  return next0;
}
#endif

static_always_inline u32
nat44_ei_icmp_in2out_slow_path (nat44_ei_main_t *nm, vlib_buffer_t *b0,
				ip4_header_t *ip0, icmp46_header_t *icmp0,
				u32 sw_if_index0, u32 rx_fib_index0,
				vlib_node_runtime_t *node, u32 next0, f64 now,
				u32 thread_index, nat44_ei_session_t **p_s0)
{
  vlib_main_t *vm = vlib_get_main ();

  next0 = nat44_ei_icmp_in2out (b0, ip0, icmp0, sw_if_index0, rx_fib_index0,
				node, next0, thread_index, p_s0);
  nat44_ei_session_t *s0 = *p_s0;
  if (PREDICT_TRUE (next0 != NAT44_EI_IN2OUT_NEXT_DROP && s0))
    {
      /* Accounting */
      nat44_ei_session_update_counters (
	s0, now, vlib_buffer_length_in_chain (vm, b0), thread_index);
      /* Per-user LRU list maintenance */
      nat44_ei_session_update_lru (nm, s0, thread_index);
    }
  return next0;
}

static int
nat_in2out_sm_unknown_proto (nat44_ei_main_t *nm, vlib_buffer_t *b,
			     ip4_header_t *ip, u32 rx_fib_index)
{
  clib_bihash_kv_8_8_t kv, value;
  nat44_ei_static_mapping_t *m;
  u32 old_addr, new_addr;
  ip_csum_t sum;

  init_nat_k (&kv, ip->src_address, 0, rx_fib_index, 0);
  if (clib_bihash_search_8_8 (&nm->static_mapping_by_local, &kv, &value))
    return 1;

  m = pool_elt_at_index (nm->static_mappings, value.value);

  old_addr = ip->src_address.as_u32;
  new_addr = ip->src_address.as_u32 = m->external_addr.as_u32;
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, src_address);
  ip->checksum = ip_csum_fold (sum);


  /* Hairpinning */
  if (vnet_buffer (b)->sw_if_index[VLIB_TX] == ~0)
    {
      vnet_buffer (b)->sw_if_index[VLIB_TX] = m->fib_index;
      nat44_ei_hairpinning_sm_unknown_proto (nm, b, ip);
    }

  return 0;
}

static inline uword
nat44_ei_in2out_node_fn_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				vlib_frame_t *frame, int is_slow_path,
				int is_output_feature)
{
  u32 n_left_from, *from;
  nat44_ei_main_t *nm = &nat44_ei_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from >= 2)
    {
      vlib_buffer_t *b0, *b1;
      u32 next0, next1;
      u32 rx_sw_if_index0, rx_sw_if_index1;
      u32 tx_sw_if_index0, tx_sw_if_index1;
      u32 cntr_sw_if_index0, cntr_sw_if_index1;
      ip4_header_t *ip0, *ip1;
      ip_csum_t sum0, sum1;
      u32 new_addr0, old_addr0, new_addr1, old_addr1;
      u16 old_port0, new_port0, old_port1, new_port1;
      udp_header_t *udp0, *udp1;
      tcp_header_t *tcp0, *tcp1;
      icmp46_header_t *icmp0, *icmp1;
      u32 rx_fib_index0, rx_fib_index1;
      u32 proto0, proto1;
      nat44_ei_session_t *s0 = 0, *s1 = 0;
      clib_bihash_kv_8_8_t kv0, value0, kv1, value1;
      u32 iph_offset0 = 0, iph_offset1 = 0;

      b0 = *b;
      b++;
      b1 = *b;
      b++;

      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 4))
	{
	  vlib_buffer_t *p2, *p3;

	  p2 = *b;
	  p3 = *(b + 1);

	  vlib_prefetch_buffer_header (p2, LOAD);
	  vlib_prefetch_buffer_header (p3, LOAD);

	  clib_prefetch_load (p2->data);
	  clib_prefetch_load (p3->data);
	}

      if (is_output_feature)
	iph_offset0 = vnet_buffer (b0)->ip.reass.save_rewrite_length;

      ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
			      iph_offset0);

      udp0 = ip4_next_header (ip0);
      tcp0 = (tcp_header_t *) udp0;
      icmp0 = (icmp46_header_t *) udp0;

      rx_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      tx_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      cntr_sw_if_index0 =
	is_output_feature ? tx_sw_if_index0 : rx_sw_if_index0;
      rx_fib_index0 =
	vec_elt (nm->ip4_main->fib_index_by_sw_if_index, rx_sw_if_index0);

      next0 = next1 = NAT44_EI_IN2OUT_NEXT_LOOKUP;

      if (PREDICT_FALSE (ip0->ttl == 1))
	{
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next0 = NAT44_EI_IN2OUT_NEXT_ICMP_ERROR;
	  goto trace00;
	}

      proto0 = ip_proto_to_nat_proto (ip0->protocol);

      /* Next configured feature, probably ip4-lookup */
      if (is_slow_path)
	{
	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	    {
	      if (nat_in2out_sm_unknown_proto (nm, b0, ip0, rx_fib_index0))
		{
		  next0 = NAT44_EI_IN2OUT_NEXT_DROP;
		  b0->error =
		    node->errors[NAT44_EI_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
		}
	      vlib_increment_simple_counter (
		is_slow_path ? &nm->counters.slowpath.in2out.other :
			       &nm->counters.fastpath.in2out.other,
		thread_index, cntr_sw_if_index0, 1);
	      goto trace00;
	    }

	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	    {
	      next0 = nat44_ei_icmp_in2out_slow_path (
		nm, b0, ip0, icmp0, rx_sw_if_index0, rx_fib_index0, node,
		next0, now, thread_index, &s0);
	      vlib_increment_simple_counter (
		is_slow_path ? &nm->counters.slowpath.in2out.icmp :
			       &nm->counters.fastpath.in2out.icmp,
		thread_index, cntr_sw_if_index0, 1);
	      goto trace00;
	    }
	}
      else
	{
	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	    {
	      next0 = NAT44_EI_IN2OUT_NEXT_SLOW_PATH;
	      goto trace00;
	    }

	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	    {
	      next0 = NAT44_EI_IN2OUT_NEXT_SLOW_PATH;
	      goto trace00;
	    }
	}

      init_nat_k (&kv0, ip0->src_address,
		  vnet_buffer (b0)->ip.reass.l4_src_port, rx_fib_index0,
		  proto0);
      if (PREDICT_FALSE (clib_bihash_search_8_8 (&nm->in2out, &kv0, &value0) !=
			 0))
	{
	  if (is_slow_path)
	    {
	      if (is_output_feature)
		{
		  if (PREDICT_FALSE (nat44_ei_not_translate_output_feature (
			nm, ip0, proto0,
			vnet_buffer (b0)->ip.reass.l4_src_port,
			vnet_buffer (b0)->ip.reass.l4_dst_port, thread_index,
			rx_sw_if_index0)))
		    goto trace00;

		  /*
		   * Send DHCP packets to the ipv4 stack, or we won't
		   * be able to use dhcp client on the outside interface
		   */
		  if (PREDICT_FALSE
		      (proto0 == NAT_PROTOCOL_UDP
		       && (vnet_buffer (b0)->ip.reass.l4_dst_port ==
			   clib_host_to_net_u16
			   (UDP_DST_PORT_dhcp_to_server))
		       && ip0->dst_address.as_u32 == 0xffffffff))
		    goto trace00;
		}
	      else
		{
		  if (PREDICT_FALSE (nat44_ei_not_translate (
			nm, node, rx_sw_if_index0, ip0, proto0, rx_fib_index0,
			thread_index)))
		    goto trace00;
		}

	      next0 = slow_path (nm, b0, ip0, ip0->src_address,
				 vnet_buffer (b0)->ip.reass.l4_src_port,
				 rx_fib_index0, proto0, &s0, node, next0,
				 thread_index, now);
	      if (PREDICT_FALSE (next0 == NAT44_EI_IN2OUT_NEXT_DROP))
		goto trace00;

	      if (PREDICT_FALSE (!s0))
		goto trace00;
	    }
	  else
	    {
	      next0 = NAT44_EI_IN2OUT_NEXT_SLOW_PATH;
	      goto trace00;
	    }
	}
      else
	s0 = pool_elt_at_index (nm->per_thread_data[thread_index].sessions,
				nat_value_get_session_index (&value0));

      b0->flags |= VNET_BUFFER_F_IS_NATED;

      old_addr0 = ip0->src_address.as_u32;
      ip0->src_address = s0->out2in.addr;
      new_addr0 = ip0->src_address.as_u32;
      if (!is_output_feature)
	vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
			     ip4_header_t, src_address /* changed member */ );
      ip0->checksum = ip_csum_fold (sum0);


      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      old_port0 = vnet_buffer (b0)->ip.reass.l4_src_port;
	      new_port0 = udp0->src_port = s0->out2in.port;
	      sum0 = tcp0->checksum;
	      sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
				     ip4_header_t,
				     dst_address /* changed member */ );
	      sum0 = ip_csum_update (sum0, old_port0, new_port0,
				     ip4_header_t /* cheat */ ,
				     length /* changed member */ );
	      mss_clamping (nm->mss_clamping, tcp0, &sum0);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  vlib_increment_simple_counter (is_slow_path ?
					   &nm->counters.slowpath.in2out.tcp :
					   &nm->counters.fastpath.in2out.tcp,
					 thread_index, cntr_sw_if_index0, 1);
	}
      else
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      udp0->src_port = s0->out2in.port;
	      if (PREDICT_FALSE (udp0->checksum))
		{
		  old_port0 = vnet_buffer (b0)->ip.reass.l4_src_port;
		  new_port0 = udp0->src_port;
		  sum0 = udp0->checksum;
		  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t, dst_address	/* changed member */
		    );
		  sum0 =
		    ip_csum_update (sum0, old_port0, new_port0,
				    ip4_header_t /* cheat */ ,
				    length /* changed member */ );
		  udp0->checksum = ip_csum_fold (sum0);
		}
	    }
	  vlib_increment_simple_counter (is_slow_path ?
					   &nm->counters.slowpath.in2out.udp :
					   &nm->counters.fastpath.in2out.udp,
					 thread_index, cntr_sw_if_index0, 1);
	}

      /* Accounting */
      nat44_ei_session_update_counters (
	s0, now, vlib_buffer_length_in_chain (vm, b0), thread_index);
      /* Per-user LRU list maintenance */
      nat44_ei_session_update_lru (nm, s0, thread_index);
    trace00:

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat44_ei_in2out_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->is_slow_path = is_slow_path;
	  t->sw_if_index = rx_sw_if_index0;
	  t->next_index = next0;
	  t->session_index = ~0;
	  if (s0)
	    t->session_index = s0 - nm->per_thread_data[thread_index].sessions;
	}

      if (next0 == NAT44_EI_IN2OUT_NEXT_DROP)
	{
	  vlib_increment_simple_counter (
	    is_slow_path ? &nm->counters.slowpath.in2out.drops :
			   &nm->counters.fastpath.in2out.drops,
	    thread_index, cntr_sw_if_index0, 1);
	}

      if (is_output_feature)
	iph_offset1 = vnet_buffer (b1)->ip.reass.save_rewrite_length;

      ip1 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b1) +
			      iph_offset1);

      udp1 = ip4_next_header (ip1);
      tcp1 = (tcp_header_t *) udp1;
      icmp1 = (icmp46_header_t *) udp1;

      rx_sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
      tx_sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];
      cntr_sw_if_index1 =
	is_output_feature ? tx_sw_if_index1 : rx_sw_if_index1;
      rx_fib_index1 =
	vec_elt (nm->ip4_main->fib_index_by_sw_if_index, rx_sw_if_index1);

      if (PREDICT_FALSE (ip1->ttl == 1))
	{
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  icmp4_error_set_vnet_buffer (b1, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next1 = NAT44_EI_IN2OUT_NEXT_ICMP_ERROR;
	  goto trace01;
	}

      proto1 = ip_proto_to_nat_proto (ip1->protocol);

      /* Next configured feature, probably ip4-lookup */
      if (is_slow_path)
	{
	  if (PREDICT_FALSE (proto1 == NAT_PROTOCOL_OTHER))
	    {
	      if (nat_in2out_sm_unknown_proto (nm, b1, ip1, rx_fib_index1))
		{
		  next1 = NAT44_EI_IN2OUT_NEXT_DROP;
		  b1->error =
		    node->errors[NAT44_EI_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
		}
	      vlib_increment_simple_counter (
		is_slow_path ? &nm->counters.slowpath.in2out.other :
			       &nm->counters.fastpath.in2out.other,
		thread_index, cntr_sw_if_index1, 1);
	      goto trace01;
	    }

	  if (PREDICT_FALSE (proto1 == NAT_PROTOCOL_ICMP))
	    {
	      next1 = nat44_ei_icmp_in2out_slow_path (
		nm, b1, ip1, icmp1, rx_sw_if_index1, rx_fib_index1, node,
		next1, now, thread_index, &s1);
	      vlib_increment_simple_counter (
		is_slow_path ? &nm->counters.slowpath.in2out.icmp :
			       &nm->counters.fastpath.in2out.icmp,
		thread_index, cntr_sw_if_index1, 1);
	      goto trace01;
	    }
	}
      else
	{
	  if (PREDICT_FALSE (proto1 == NAT_PROTOCOL_OTHER))
	    {
	      next1 = NAT44_EI_IN2OUT_NEXT_SLOW_PATH;
	      goto trace01;
	    }

	  if (PREDICT_FALSE (proto1 == NAT_PROTOCOL_ICMP))
	    {
	      next1 = NAT44_EI_IN2OUT_NEXT_SLOW_PATH;
	      goto trace01;
	    }
	}

      init_nat_k (&kv1, ip1->src_address,
		  vnet_buffer (b1)->ip.reass.l4_src_port, rx_fib_index1,
		  proto1);
      if (PREDICT_FALSE (clib_bihash_search_8_8 (&nm->in2out, &kv1, &value1) !=
			 0))
	{
	  if (is_slow_path)
	    {
	      if (is_output_feature)
		{
		  if (PREDICT_FALSE (nat44_ei_not_translate_output_feature (
			nm, ip1, proto1,
			vnet_buffer (b1)->ip.reass.l4_src_port,
			vnet_buffer (b1)->ip.reass.l4_dst_port, thread_index,
			rx_sw_if_index1)))
		    goto trace01;

		  /*
		   * Send DHCP packets to the ipv4 stack, or we won't
		   * be able to use dhcp client on the outside interface
		   */
		  if (PREDICT_FALSE
		      (proto1 == NAT_PROTOCOL_UDP
		       && (vnet_buffer (b1)->ip.reass.l4_dst_port ==
			   clib_host_to_net_u16
			   (UDP_DST_PORT_dhcp_to_server))
		       && ip1->dst_address.as_u32 == 0xffffffff))
		    goto trace01;
		}
	      else
		{
		  if (PREDICT_FALSE (nat44_ei_not_translate (
			nm, node, rx_sw_if_index1, ip1, proto1, rx_fib_index1,
			thread_index)))
		    goto trace01;
		}

	      next1 = slow_path (nm, b1, ip1, ip1->src_address,
				 vnet_buffer (b1)->ip.reass.l4_src_port,
				 rx_fib_index1, proto1, &s1, node, next1,
				 thread_index, now);
	      if (PREDICT_FALSE (next1 == NAT44_EI_IN2OUT_NEXT_DROP))
		goto trace01;

	      if (PREDICT_FALSE (!s1))
		goto trace01;
	    }
	  else
	    {
	      next1 = NAT44_EI_IN2OUT_NEXT_SLOW_PATH;
	      goto trace01;
	    }
	}
      else
	s1 = pool_elt_at_index (nm->per_thread_data[thread_index].sessions,
				nat_value_get_session_index (&value1));

      b1->flags |= VNET_BUFFER_F_IS_NATED;

      old_addr1 = ip1->src_address.as_u32;
      ip1->src_address = s1->out2in.addr;
      new_addr1 = ip1->src_address.as_u32;
      if (!is_output_feature)
	vnet_buffer (b1)->sw_if_index[VLIB_TX] = s1->out2in.fib_index;

      sum1 = ip1->checksum;
      sum1 = ip_csum_update (sum1, old_addr1, new_addr1,
			     ip4_header_t, src_address /* changed member */ );
      ip1->checksum = ip_csum_fold (sum1);

      if (PREDICT_TRUE (proto1 == NAT_PROTOCOL_TCP))
	{
	  if (!vnet_buffer (b1)->ip.reass.is_non_first_fragment)
	    {
	      old_port1 = vnet_buffer (b1)->ip.reass.l4_src_port;
	      new_port1 = udp1->src_port = s1->out2in.port;
	      sum1 = tcp1->checksum;
	      sum1 = ip_csum_update (sum1, old_addr1, new_addr1,
				     ip4_header_t,
				     dst_address /* changed member */ );
	      sum1 = ip_csum_update (sum1, old_port1, new_port1,
				     ip4_header_t /* cheat */ ,
				     length /* changed member */ );
	      mss_clamping (nm->mss_clamping, tcp1, &sum1);
	      tcp1->checksum = ip_csum_fold (sum1);
	    }
	  vlib_increment_simple_counter (is_slow_path ?
					   &nm->counters.slowpath.in2out.tcp :
					   &nm->counters.fastpath.in2out.tcp,
					 thread_index, cntr_sw_if_index1, 1);
	}
      else
	{
	  if (!vnet_buffer (b1)->ip.reass.is_non_first_fragment)
	    {
	      udp1->src_port = s1->out2in.port;
	      if (PREDICT_FALSE (udp1->checksum))
		{
		  old_port1 = vnet_buffer (b1)->ip.reass.l4_src_port;
		  new_port1 = udp1->src_port;
		  sum1 = udp1->checksum;
		  sum1 = ip_csum_update (sum1, old_addr1, new_addr1, ip4_header_t, dst_address	/* changed member */
		    );
		  sum1 =
		    ip_csum_update (sum1, old_port1, new_port1,
				    ip4_header_t /* cheat */ ,
				    length /* changed member */ );
		  udp1->checksum = ip_csum_fold (sum1);
		}
	    }
	  vlib_increment_simple_counter (is_slow_path ?
					   &nm->counters.slowpath.in2out.udp :
					   &nm->counters.fastpath.in2out.udp,
					 thread_index, cntr_sw_if_index1, 1);
	}

      /* Accounting */
      nat44_ei_session_update_counters (
	s1, now, vlib_buffer_length_in_chain (vm, b1), thread_index);
      /* Per-user LRU list maintenance */
      nat44_ei_session_update_lru (nm, s1, thread_index);
    trace01:

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b1->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat44_ei_in2out_trace_t *t =
	    vlib_add_trace (vm, node, b1, sizeof (*t));
	  t->sw_if_index = rx_sw_if_index1;
	  t->next_index = next1;
	  t->session_index = ~0;
	  if (s1)
	    t->session_index = s1 - nm->per_thread_data[thread_index].sessions;
	}

      if (next1 == NAT44_EI_IN2OUT_NEXT_DROP)
	{
	  vlib_increment_simple_counter (
	    is_slow_path ? &nm->counters.slowpath.in2out.drops :
			   &nm->counters.fastpath.in2out.drops,
	    thread_index, cntr_sw_if_index1, 1);
	}

      n_left_from -= 2;
      next[0] = next0;
      next[1] = next1;
      next += 2;
    }

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0;
      u32 next0;
      u32 rx_sw_if_index0;
      u32 tx_sw_if_index0;
      u32 cntr_sw_if_index0;
      ip4_header_t *ip0;
      ip_csum_t sum0;
      u32 new_addr0, old_addr0;
      u16 old_port0, new_port0;
      udp_header_t *udp0;
      tcp_header_t *tcp0;
      icmp46_header_t *icmp0;
      u32 rx_fib_index0;
      u32 proto0;
      nat44_ei_session_t *s0 = 0;
      clib_bihash_kv_8_8_t kv0, value0;
      u32 iph_offset0 = 0;

      b0 = *b;
      b++;
      next0 = NAT44_EI_IN2OUT_NEXT_LOOKUP;

      if (is_output_feature)
	iph_offset0 = vnet_buffer (b0)->ip.reass.save_rewrite_length;

      ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
			      iph_offset0);

      udp0 = ip4_next_header (ip0);
      tcp0 = (tcp_header_t *) udp0;
      icmp0 = (icmp46_header_t *) udp0;

      rx_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      tx_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      cntr_sw_if_index0 =
	is_output_feature ? tx_sw_if_index0 : rx_sw_if_index0;
      rx_fib_index0 =
	vec_elt (nm->ip4_main->fib_index_by_sw_if_index, rx_sw_if_index0);

      if (PREDICT_FALSE (ip0->ttl == 1))
	{
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next0 = NAT44_EI_IN2OUT_NEXT_ICMP_ERROR;
	  goto trace0;
	}

      proto0 = ip_proto_to_nat_proto (ip0->protocol);

      /* Next configured feature, probably ip4-lookup */
      if (is_slow_path)
	{
	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	    {
	      if (nat_in2out_sm_unknown_proto (nm, b0, ip0, rx_fib_index0))
		{
		  next0 = NAT44_EI_IN2OUT_NEXT_DROP;
		  b0->error =
		    node->errors[NAT44_EI_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
		}
	      vlib_increment_simple_counter (
		is_slow_path ? &nm->counters.slowpath.in2out.other :
			       &nm->counters.fastpath.in2out.other,
		thread_index, cntr_sw_if_index0, 1);
	      goto trace0;
	    }

	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	    {
	      next0 = nat44_ei_icmp_in2out_slow_path (
		nm, b0, ip0, icmp0, rx_sw_if_index0, rx_fib_index0, node,
		next0, now, thread_index, &s0);
	      vlib_increment_simple_counter (
		is_slow_path ? &nm->counters.slowpath.in2out.icmp :
			       &nm->counters.fastpath.in2out.icmp,
		thread_index, cntr_sw_if_index0, 1);
	      goto trace0;
	    }
	}
      else
	{
	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	    {
	      next0 = NAT44_EI_IN2OUT_NEXT_SLOW_PATH;
	      goto trace0;
	    }

	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	    {
	      next0 = NAT44_EI_IN2OUT_NEXT_SLOW_PATH;
	      goto trace0;
	    }
	}

      init_nat_k (&kv0, ip0->src_address,
		  vnet_buffer (b0)->ip.reass.l4_src_port, rx_fib_index0,
		  proto0);

      if (clib_bihash_search_8_8 (&nm->in2out, &kv0, &value0))
	{
	  if (is_slow_path)
	    {
	      if (is_output_feature)
		{
		  if (PREDICT_FALSE (nat44_ei_not_translate_output_feature (
			nm, ip0, proto0,
			vnet_buffer (b0)->ip.reass.l4_src_port,
			vnet_buffer (b0)->ip.reass.l4_dst_port, thread_index,
			rx_sw_if_index0)))
		    goto trace0;

		  /*
		   * Send DHCP packets to the ipv4 stack, or we won't
		   * be able to use dhcp client on the outside interface
		   */
		  if (PREDICT_FALSE
		      (proto0 == NAT_PROTOCOL_UDP
		       && (vnet_buffer (b0)->ip.reass.l4_dst_port ==
			   clib_host_to_net_u16
			   (UDP_DST_PORT_dhcp_to_server))
		       && ip0->dst_address.as_u32 == 0xffffffff))
		    goto trace0;
		}
	      else
		{
		  if (PREDICT_FALSE (nat44_ei_not_translate (
			nm, node, rx_sw_if_index0, ip0, proto0, rx_fib_index0,
			thread_index)))
		    goto trace0;
		}

	      next0 = slow_path (nm, b0, ip0, ip0->src_address,
				 vnet_buffer (b0)->ip.reass.l4_src_port,
				 rx_fib_index0, proto0, &s0, node, next0,
				 thread_index, now);

	      if (PREDICT_FALSE (next0 == NAT44_EI_IN2OUT_NEXT_DROP))
		goto trace0;

	      if (PREDICT_FALSE (!s0))
		goto trace0;
	    }
	  else
	    {
	      next0 = NAT44_EI_IN2OUT_NEXT_SLOW_PATH;
	      goto trace0;
	    }
	}
      else
	s0 = pool_elt_at_index (nm->per_thread_data[thread_index].sessions,
				nat_value_get_session_index (&value0));

      b0->flags |= VNET_BUFFER_F_IS_NATED;

      old_addr0 = ip0->src_address.as_u32;
      ip0->src_address = s0->out2in.addr;
      new_addr0 = ip0->src_address.as_u32;
      if (!is_output_feature)
	vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
			     ip4_header_t, src_address /* changed member */ );
      ip0->checksum = ip_csum_fold (sum0);

      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      old_port0 = vnet_buffer (b0)->ip.reass.l4_src_port;
	      new_port0 = udp0->src_port = s0->out2in.port;
	      sum0 = tcp0->checksum;
	      sum0 =
		ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				dst_address /* changed member */ );
	      sum0 =
		ip_csum_update (sum0, old_port0, new_port0,
				ip4_header_t /* cheat */ ,
				length /* changed member */ );
	      mss_clamping (nm->mss_clamping, tcp0, &sum0);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  vlib_increment_simple_counter (is_slow_path ?
					   &nm->counters.slowpath.in2out.tcp :
					   &nm->counters.fastpath.in2out.tcp,
					 thread_index, cntr_sw_if_index0, 1);
	}
      else
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      udp0->src_port = s0->out2in.port;
	      if (PREDICT_FALSE (udp0->checksum))
		{
		  old_port0 = vnet_buffer (b0)->ip.reass.l4_src_port;
		  new_port0 = udp0->src_port;
		  sum0 = udp0->checksum;
		  sum0 =
		    ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				    dst_address /* changed member */ );
		  sum0 =
		    ip_csum_update (sum0, old_port0, new_port0,
				    ip4_header_t /* cheat */ ,
				    length /* changed member */ );
		  udp0->checksum = ip_csum_fold (sum0);
		}
	    }
	  vlib_increment_simple_counter (is_slow_path ?
					   &nm->counters.slowpath.in2out.udp :
					   &nm->counters.fastpath.in2out.udp,
					 thread_index, cntr_sw_if_index0, 1);
	}

      /* Accounting */
      nat44_ei_session_update_counters (
	s0, now, vlib_buffer_length_in_chain (vm, b0), thread_index);
      /* Per-user LRU list maintenance */
      nat44_ei_session_update_lru (nm, s0, thread_index);

    trace0:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat44_ei_in2out_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->is_slow_path = is_slow_path;
	  t->sw_if_index = rx_sw_if_index0;
	  t->next_index = next0;
	  t->session_index = ~0;
	  if (s0)
	    t->session_index = s0 - nm->per_thread_data[thread_index].sessions;
	}

      if (next0 == NAT44_EI_IN2OUT_NEXT_DROP)
	{
	  vlib_increment_simple_counter (
	    is_slow_path ? &nm->counters.slowpath.in2out.drops :
			   &nm->counters.fastpath.in2out.drops,
	    thread_index, cntr_sw_if_index0, 1);
	}

      n_left_from--;
      next[0] = next0;
      next++;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
			       frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (nat44_ei_in2out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return nat44_ei_in2out_node_fn_inline (vm, node, frame, 0 /* is_slow_path */,
					 0);
}

VLIB_REGISTER_NODE (nat44_ei_in2out_node) = {
  .name = "nat44-ei-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nat44_ei_in2out_error_strings),
  .error_strings = nat44_ei_in2out_error_strings,

  .runtime_data_bytes = sizeof (nat44_ei_runtime_t),

  .n_next_nodes = NAT44_EI_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [NAT44_EI_IN2OUT_NEXT_DROP] = "error-drop",
    [NAT44_EI_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [NAT44_EI_IN2OUT_NEXT_SLOW_PATH] = "nat44-ei-in2out-slowpath",
    [NAT44_EI_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT44_EI_IN2OUT_NEXT_HAIRPINNING_HANDOFF] = "nat44-ei-in2out-hairpinning-handoff-ip4-lookup",
  },
};

VLIB_NODE_FN (nat44_ei_in2out_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return nat44_ei_in2out_node_fn_inline (vm, node, frame, 0 /* is_slow_path */,
					 1);
}

VLIB_REGISTER_NODE (nat44_ei_in2out_output_node) = {
  .name = "nat44-ei-in2out-output",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nat44_ei_in2out_error_strings),
  .error_strings = nat44_ei_in2out_error_strings,

  .runtime_data_bytes = sizeof (nat44_ei_runtime_t),

  .n_next_nodes = NAT44_EI_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [NAT44_EI_IN2OUT_NEXT_DROP] = "error-drop",
    [NAT44_EI_IN2OUT_NEXT_LOOKUP] = "interface-output",
    [NAT44_EI_IN2OUT_NEXT_SLOW_PATH] = "nat44-ei-in2out-output-slowpath",
    [NAT44_EI_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT44_EI_IN2OUT_NEXT_HAIRPINNING_HANDOFF] = "nat44-ei-in2out-hairpinning-handoff-interface-output",
  },
};

VLIB_NODE_FN (nat44_ei_in2out_slowpath_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return nat44_ei_in2out_node_fn_inline (vm, node, frame, 1 /* is_slow_path */,
					 0);
}

VLIB_REGISTER_NODE (nat44_ei_in2out_slowpath_node) = {
  .name = "nat44-ei-in2out-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nat44_ei_in2out_error_strings),
  .error_strings = nat44_ei_in2out_error_strings,

  .runtime_data_bytes = sizeof (nat44_ei_runtime_t),

  .n_next_nodes = NAT44_EI_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [NAT44_EI_IN2OUT_NEXT_DROP] = "error-drop",
    [NAT44_EI_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [NAT44_EI_IN2OUT_NEXT_SLOW_PATH] = "nat44-ei-in2out-slowpath",
    [NAT44_EI_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT44_EI_IN2OUT_NEXT_HAIRPINNING_HANDOFF] = "nat44-ei-in2out-hairpinning-handoff-ip4-lookup",
  },
};

VLIB_NODE_FN (nat44_ei_in2out_output_slowpath_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return nat44_ei_in2out_node_fn_inline (vm, node, frame, 1 /* is_slow_path */,
					 1);
}

VLIB_REGISTER_NODE (nat44_ei_in2out_output_slowpath_node) = {
  .name = "nat44-ei-in2out-output-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nat44_ei_in2out_error_strings),
  .error_strings = nat44_ei_in2out_error_strings,

  .runtime_data_bytes = sizeof (nat44_ei_runtime_t),

  .n_next_nodes = NAT44_EI_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [NAT44_EI_IN2OUT_NEXT_DROP] = "error-drop",
    [NAT44_EI_IN2OUT_NEXT_LOOKUP] = "interface-output",
    [NAT44_EI_IN2OUT_NEXT_SLOW_PATH] = "nat44-ei-in2out-output-slowpath",
    [NAT44_EI_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT44_EI_IN2OUT_NEXT_HAIRPINNING_HANDOFF] = "nat44-ei-in2out-hairpinning-handoff-interface-output",
  },
};

VLIB_NODE_FN (nat44_ei_in2out_fast_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  u32 thread_index = vm->thread_index;
  nat44_ei_in2out_next_t next_index;
  nat44_ei_main_t *nm = &nat44_ei_main;
  int is_hairpinning = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 sw_if_index0;
	  ip4_header_t *ip0;
	  ip_csum_t sum0;
	  u32 new_addr0, old_addr0;
	  u16 old_port0, new_port0;
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;
	  icmp46_header_t *icmp0;
	  u32 proto0;
	  u32 rx_fib_index0;
	  ip4_address_t sm0_addr;
	  u16 sm0_port;
	  u32 sm0_fib_index;
	  u32 required_thread_index = thread_index;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  next0 = NAT44_EI_IN2OUT_NEXT_LOOKUP;

	  ip0 = vlib_buffer_get_current (b0);
	  udp0 = ip4_next_header (ip0);
	  tcp0 = (tcp_header_t *) udp0;
	  icmp0 = (icmp46_header_t *) udp0;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 =
	    ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

	  if (PREDICT_FALSE (ip0->ttl == 1))
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next0 = NAT44_EI_IN2OUT_NEXT_ICMP_ERROR;
	      goto trace0;
	    }

	  proto0 = ip_proto_to_nat_proto (ip0->protocol);

	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	    goto trace0;

	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	    {
	      next0 = nat44_ei_icmp_in2out (b0, ip0, icmp0, sw_if_index0,
					    rx_fib_index0, node, next0, ~0, 0);
	      goto trace0;
	    }

	  if (nat44_ei_static_mapping_match (
		ip0->src_address, udp0->src_port, rx_fib_index0, proto0,
		&sm0_addr, &sm0_port, &sm0_fib_index, 0, 0, 0))
	    {
	      b0->error = node->errors[NAT44_EI_IN2OUT_ERROR_NO_TRANSLATION];
	      next0 = NAT44_EI_IN2OUT_NEXT_DROP;
	      goto trace0;
	    }

	  new_addr0 = sm0_addr.as_u32;
	  new_port0 = sm0_port;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sm0_fib_index;
	  old_addr0 = ip0->src_address.as_u32;
	  ip0->src_address.as_u32 = new_addr0;

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
				 ip4_header_t,
				 src_address /* changed member */ );
	  ip0->checksum = ip_csum_fold (sum0);

	  if (PREDICT_FALSE (new_port0 != udp0->dst_port))
	    {
	      old_port0 = udp0->src_port;
	      udp0->src_port = new_port0;

	      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
		{
		  sum0 = tcp0->checksum;
		  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
					 ip4_header_t,
					 dst_address /* changed member */ );
		  sum0 = ip_csum_update (sum0, old_port0, new_port0,
					 ip4_header_t /* cheat */ ,
					 length /* changed member */ );
		  mss_clamping (nm->mss_clamping, tcp0, &sum0);
		  tcp0->checksum = ip_csum_fold (sum0);
		}
	      else if (udp0->checksum)
		{
		  sum0 = udp0->checksum;
		  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
					 ip4_header_t,
					 dst_address /* changed member */ );
		  sum0 = ip_csum_update (sum0, old_port0, new_port0,
					 ip4_header_t /* cheat */ ,
					 length /* changed member */ );
		  udp0->checksum = ip_csum_fold (sum0);
		}
	    }
	  else
	    {
	      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
		{
		  sum0 = tcp0->checksum;
		  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
					 ip4_header_t,
					 dst_address /* changed member */ );
		  mss_clamping (nm->mss_clamping, tcp0, &sum0);
		  tcp0->checksum = ip_csum_fold (sum0);
		}
	      else if (udp0->checksum)
		{
		  sum0 = udp0->checksum;
		  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
					 ip4_header_t,
					 dst_address /* changed member */ );
		  udp0->checksum = ip_csum_fold (sum0);
		}
	    }

	  /* Hairpinning */
	  is_hairpinning = nat44_ei_hairpinning (
	    vm, node, nm, thread_index, b0, ip0, udp0, tcp0, proto0,
	    0 /* do_trace */, &required_thread_index);

	  if (thread_index != required_thread_index)
	    {
	      vnet_buffer (b0)->snat.required_thread_index =
		required_thread_index;
	      next0 = NAT44_EI_IN2OUT_NEXT_HAIRPINNING_HANDOFF;
	    }

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat44_ei_in2out_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->is_hairpinning = is_hairpinning;
	    }

	  if (next0 != NAT44_EI_IN2OUT_NEXT_DROP)
	    {

	      vlib_increment_simple_counter (
		&nm->counters.fastpath.in2out.other, sw_if_index0,
		vm->thread_index, 1);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (nat44_ei_in2out_fast_node) = {
  .name = "nat44-ei-in2out-fast",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_in2out_fast_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nat44_ei_in2out_error_strings),
  .error_strings = nat44_ei_in2out_error_strings,

  .runtime_data_bytes = sizeof (nat44_ei_runtime_t),

  .n_next_nodes = NAT44_EI_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [NAT44_EI_IN2OUT_NEXT_DROP] = "error-drop",
    [NAT44_EI_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [NAT44_EI_IN2OUT_NEXT_SLOW_PATH] = "nat44-ei-in2out-slowpath",
    [NAT44_EI_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT44_EI_IN2OUT_NEXT_HAIRPINNING_HANDOFF] = "nat44-ei-in2out-hairpinning-handoff-ip4-lookup",
  },
};

VLIB_NODE_FN (nat44_ei_in2out_hairpinning_handoff_ip4_lookup_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return nat44_ei_hairpinning_handoff_fn_inline (
    vm, node, frame,
    nat44_ei_main.in2out_hairpinning_finish_ip4_lookup_node_fq_index);
}

VLIB_REGISTER_NODE (nat44_ei_in2out_hairpinning_handoff_ip4_lookup_node) = {
  .name = "nat44-ei-in2out-hairpinning-handoff-ip4-lookup",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(nat44_ei_hairpinning_handoff_error_strings),
  .error_strings = nat44_ei_hairpinning_handoff_error_strings,
  .format_trace = format_nat44_ei_hairpinning_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FN (nat44_ei_in2out_hairpinning_handoff_interface_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return nat44_ei_hairpinning_handoff_fn_inline (
    vm, node, frame,
    nat44_ei_main.in2out_hairpinning_finish_interface_output_node_fq_index);
}

VLIB_REGISTER_NODE (nat44_ei_in2out_hairpinning_handoff_interface_output_node) = {
  .name = "nat44-ei-in2out-hairpinning-handoff-interface-output",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(nat44_ei_hairpinning_handoff_error_strings),
  .error_strings = nat44_ei_hairpinning_handoff_error_strings,
  .format_trace = format_nat44_ei_hairpinning_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

static_always_inline int
nat44_ei_in2out_hairpinning_finish_inline (vlib_main_t *vm,
					   vlib_node_runtime_t *node,
					   vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  u32 thread_index = vm->thread_index;
  nat44_ei_in2out_next_t next_index;
  nat44_ei_main_t *nm = &nat44_ei_main;
  int is_hairpinning = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 sw_if_index0;
	  ip4_header_t *ip0;
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;
	  icmp46_header_t *icmp0;
	  u32 proto0;
	  u32 required_thread_index = thread_index;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  next0 = NAT44_EI_IN2OUT_HAIRPINNING_FINISH_NEXT_LOOKUP;

	  ip0 = vlib_buffer_get_current (b0);
	  udp0 = ip4_next_header (ip0);
	  tcp0 = (tcp_header_t *) udp0;
	  icmp0 = (icmp46_header_t *) udp0;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  proto0 = ip_proto_to_nat_proto (ip0->protocol);

	  switch (proto0)
	    {
	    case NAT_PROTOCOL_TCP:
	      // fallthrough
	    case NAT_PROTOCOL_UDP:
	      is_hairpinning = nat44_ei_hairpinning (
		vm, node, nm, thread_index, b0, ip0, udp0, tcp0, proto0,
		0 /* do_trace */, &required_thread_index);
	      break;
	    case NAT_PROTOCOL_ICMP:
	      is_hairpinning = (0 == nat44_ei_icmp_hairpinning (
				       nm, b0, thread_index, ip0, icmp0,
				       &required_thread_index));
	      break;
	    case NAT_PROTOCOL_OTHER:
	      // this should never happen
	      next0 = NAT44_EI_IN2OUT_HAIRPINNING_FINISH_NEXT_DROP;
	      break;
	    }

	  if (thread_index != required_thread_index)
	    {
	      // but we already did a handoff ...
	      next0 = NAT44_EI_IN2OUT_HAIRPINNING_FINISH_NEXT_DROP;
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat44_ei_in2out_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->is_hairpinning = is_hairpinning;
	    }

	  if (next0 != NAT44_EI_IN2OUT_HAIRPINNING_FINISH_NEXT_DROP)
	    {
	      vlib_increment_simple_counter (
		&nm->counters.fastpath.in2out.other, sw_if_index0,
		vm->thread_index, 1);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (nat44_ei_in2out_hairpinning_finish_ip4_lookup_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return nat44_ei_in2out_hairpinning_finish_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (nat44_ei_in2out_hairpinning_finish_ip4_lookup_node) = {
  .name = "nat44-ei-in2out-hairpinning-finish-ip4-lookup",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_in2out_fast_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nat44_ei_in2out_error_strings),
  .error_strings = nat44_ei_in2out_error_strings,

  .runtime_data_bytes = sizeof (nat44_ei_runtime_t),

  .n_next_nodes = NAT44_EI_IN2OUT_HAIRPINNING_FINISH_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [NAT44_EI_IN2OUT_HAIRPINNING_FINISH_NEXT_DROP] = "error-drop",
    [NAT44_EI_IN2OUT_HAIRPINNING_FINISH_NEXT_LOOKUP] = "ip4-lookup",
  },
};

VLIB_NODE_FN (nat44_ei_in2out_hairpinning_finish_interface_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return nat44_ei_in2out_hairpinning_finish_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (nat44_ei_in2out_hairpinning_finish_interface_output_node) = {
  .name = "nat44-ei-in2out-hairpinning-finish-interface-output",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_in2out_fast_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nat44_ei_in2out_error_strings),
  .error_strings = nat44_ei_in2out_error_strings,

  .runtime_data_bytes = sizeof (nat44_ei_runtime_t),

  .n_next_nodes = NAT44_EI_IN2OUT_HAIRPINNING_FINISH_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [NAT44_EI_IN2OUT_HAIRPINNING_FINISH_NEXT_DROP] = "error-drop",
    [NAT44_EI_IN2OUT_HAIRPINNING_FINISH_NEXT_LOOKUP] = "interface-output",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
