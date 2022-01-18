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
 * @brief NAT44 EI outside to inside network translation
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
#include <nat/nat44-ei/nat44_ei_inlines.h>
#include <nat/nat44-ei/nat44_ei.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
} nat44_ei_out2in_trace_t;

/* packet trace format function */
static u8 *
format_nat44_ei_out2in_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat44_ei_out2in_trace_t *t = va_arg (*args, nat44_ei_out2in_trace_t *);

  s =
    format (s,
	    "NAT44_OUT2IN: sw_if_index %d, next index %d, session index %d",
	    t->sw_if_index, t->next_index, t->session_index);
  return s;
}

#define foreach_nat44_ei_out2in_error                                         \
  _ (UNSUPPORTED_PROTOCOL, "unsupported protocol")                            \
  _ (OUT_OF_PORTS, "out of ports")                                            \
  _ (BAD_ICMP_TYPE, "unsupported ICMP type")                                  \
  _ (NO_TRANSLATION, "no translation")                                        \
  _ (MAX_SESSIONS_EXCEEDED, "maximum sessions exceeded")                      \
  _ (CANNOT_CREATE_USER, "cannot create NAT user")

typedef enum
{
#define _(sym, str) NAT44_EI_OUT2IN_ERROR_##sym,
  foreach_nat44_ei_out2in_error
#undef _
    NAT44_EI_OUT2IN_N_ERROR,
} nat44_ei_out2in_error_t;

static char *nat44_ei_out2in_error_strings[] = {
#define _(sym,string) string,
  foreach_nat44_ei_out2in_error
#undef _
};

typedef enum
{
  NAT44_EI_OUT2IN_NEXT_DROP,
  NAT44_EI_OUT2IN_NEXT_LOOKUP,
  NAT44_EI_OUT2IN_NEXT_ICMP_ERROR,
  NAT44_EI_OUT2IN_N_NEXT,
} nat44_ei_out2in_next_t;

#ifndef CLIB_MARCH_VARIANT
int
nat44_o2i_is_idle_session_cb (clib_bihash_kv_8_8_t * kv, void *arg)
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
      init_nat_i2o_k (&s_kv, s);
      if (clib_bihash_add_del_8_8 (&nm->in2out, &s_kv, 0))
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

/**
 * @brief Create session for static mapping.
 *
 * Create NAT session initiated by host from external network with static
 * mapping.
 *
 * @param nm     NAT main.
 * @param b0     Vlib buffer.
 * @param in2out In2out NAT44 session key.
 * @param out2in Out2in NAT44 session key.
 * @param node   Vlib node.
 *
 * @returns NAT44_EI session if successfully created otherwise 0.
 */
static inline nat44_ei_session_t *
create_session_for_static_mapping (
  nat44_ei_main_t *nm, vlib_buffer_t *b0, ip4_address_t i2o_addr, u16 i2o_port,
  u32 i2o_fib_index, ip4_address_t o2i_addr, u16 o2i_port, u32 o2i_fib_index,
  nat_protocol_t proto, vlib_node_runtime_t *node, u32 thread_index, f64 now)
{
  nat44_ei_user_t *u;
  nat44_ei_session_t *s;
  clib_bihash_kv_8_8_t kv0;
  ip4_header_t *ip0;
  udp_header_t *udp0;
  nat44_ei_is_idle_session_ctx_t ctx0;

  if (PREDICT_FALSE (nat44_ei_maximum_sessions_exceeded (nm, thread_index)))
    {
      b0->error = node->errors[NAT44_EI_OUT2IN_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_elog_notice (nm, "maximum sessions exceeded");
      return 0;
    }

  ip0 = vlib_buffer_get_current (b0);
  udp0 = ip4_next_header (ip0);

  u = nat44_ei_user_get_or_create (nm, &i2o_addr, i2o_fib_index, thread_index);
  if (!u)
    {
      b0->error = node->errors[NAT44_EI_OUT2IN_ERROR_CANNOT_CREATE_USER];
      return 0;
    }

  s = nat44_ei_session_alloc_or_recycle (nm, u, thread_index, now);
  if (!s)
    {
      nat44_ei_delete_user_with_no_session (nm, u, thread_index);
      nat_elog_warn (nm, "create NAT session failed");
      return 0;
    }

  s->flags |= NAT44_EI_SESSION_FLAG_STATIC_MAPPING;
  s->ext_host_addr.as_u32 = ip0->src_address.as_u32;
  s->ext_host_port = udp0->src_port;
  nat44_ei_user_session_increment (nm, u, 1 /* static */);
  s->in2out.addr = i2o_addr;
  s->in2out.port = i2o_port;
  s->in2out.fib_index = i2o_fib_index;
  s->out2in.addr = o2i_addr;
  s->out2in.port = o2i_port;
  s->out2in.fib_index = o2i_fib_index;
  s->nat_proto = proto;

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

  nat_syslog_nat44_apmadd (s->user_index, s->in2out.fib_index,
			   &s->in2out.addr, s->in2out.port, &s->out2in.addr,
			   s->out2in.port, s->nat_proto);

  nat_ha_sadd (&s->in2out.addr, s->in2out.port, &s->out2in.addr,
	       s->out2in.port, &s->ext_host_addr, s->ext_host_port,
	       &s->ext_host_nat_addr, s->ext_host_nat_port,
	       s->nat_proto, s->in2out.fib_index, s->flags, thread_index, 0);

  return s;
}

#ifndef CLIB_MARCH_VARIANT
static_always_inline nat44_ei_out2in_error_t
icmp_get_key (vlib_buffer_t *b, ip4_header_t *ip0, ip4_address_t *addr,
	      u16 *port, nat_protocol_t *nat_proto)
{
  icmp46_header_t *icmp0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *) (icmp0 + 1);

  if (!icmp_type_is_error_message
      (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
    {
      *nat_proto = NAT_PROTOCOL_ICMP;
      *addr = ip0->dst_address;
      *port = vnet_buffer (b)->ip.reass.l4_src_port;
    }
  else
    {
      inner_ip0 = (ip4_header_t *) (echo0 + 1);
      l4_header = ip4_next_header (inner_ip0);
      *nat_proto = ip_proto_to_nat_proto (inner_ip0->protocol);
      *addr = inner_ip0->src_address;
      switch (*nat_proto)
	{
	case NAT_PROTOCOL_ICMP:
	  inner_icmp0 = (icmp46_header_t *) l4_header;
	  inner_echo0 = (icmp_echo_header_t *) (inner_icmp0 + 1);
	  *port = inner_echo0->identifier;
	  break;
	case NAT_PROTOCOL_UDP:
	case NAT_PROTOCOL_TCP:
	  *port = ((tcp_udp_header_t *) l4_header)->src_port;
	  break;
	default:
	  return NAT44_EI_OUT2IN_ERROR_UNSUPPORTED_PROTOCOL;
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
nat44_ei_icmp_match_out2in_slow (vlib_node_runtime_t *node, u32 thread_index,
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
  u8 is_addr_only;
  u32 next0 = ~0;
  int err;
  u8 identity_nat;
  vlib_main_t *vm = vlib_get_main ();
  *dont_translate = 0;

  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  *fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  *proto = 0;

  err = icmp_get_key (b0, ip0, addr, port, proto);
  if (err != -1)
    {
      b0->error = node->errors[NAT44_EI_OUT2IN_ERROR_UNSUPPORTED_PROTOCOL];
      next0 = NAT44_EI_OUT2IN_NEXT_DROP;
      goto out;
    }

  ip4_address_t mapping_addr;
  u16 mapping_port;
  u32 mapping_fib_index;

  init_nat_k (&kv0, *addr, *port, *fib_index, *proto);
  if (clib_bihash_search_8_8 (&nm->out2in, &kv0, &value0))
    {
      /* Try to match static mapping by external address and port,
         destination address and port in packet */
      if (nat44_ei_static_mapping_match (
	    *addr, *port, *fib_index, *proto, &mapping_addr, &mapping_port,
	    &mapping_fib_index, 1, &is_addr_only, &identity_nat))
	{
	  if (!nm->forwarding_enabled)
	    {
	      /* Don't NAT packet aimed at the intfc address */
	      if (PREDICT_FALSE (nat44_ei_is_interface_addr (
		    nm->ip4_main, node, sw_if_index0,
		    ip0->dst_address.as_u32)))
		{
		  *dont_translate = 1;
		  goto out;
		}
	      b0->error = node->errors[NAT44_EI_OUT2IN_ERROR_NO_TRANSLATION];
	      next0 = NAT44_EI_OUT2IN_NEXT_DROP;
	      goto out;
	    }
	  else
	    {
	      *dont_translate = 1;
	      goto out;
	    }
	}

      if (PREDICT_FALSE
	  (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_reply
	   && (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
	       ICMP4_echo_request || !is_addr_only)))
	{
	  b0->error = node->errors[NAT44_EI_OUT2IN_ERROR_BAD_ICMP_TYPE];
	  next0 = NAT44_EI_OUT2IN_NEXT_DROP;
	  goto out;
	}

      if (PREDICT_FALSE (identity_nat))
	{
	  *dont_translate = 1;
	  goto out;
	}
      /* Create session initiated by host from external network */
      s0 = create_session_for_static_mapping (
	nm, b0, mapping_addr, mapping_port, mapping_fib_index, *addr, *port,
	*fib_index, *proto, node, thread_index, vlib_time_now (vm));

      if (!s0)
	{
	  next0 = NAT44_EI_OUT2IN_NEXT_DROP;
	  goto out;
	}
    }
  else
    {
      if (PREDICT_FALSE
	  (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_reply
	   && vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_request
	   && !icmp_type_is_error_message (vnet_buffer (b0)->ip.
					   reass.icmp_type_or_tcp_flags)))
	{
	  b0->error = node->errors[NAT44_EI_OUT2IN_ERROR_BAD_ICMP_TYPE];
	  next0 = NAT44_EI_OUT2IN_NEXT_DROP;
	  goto out;
	}

      s0 = pool_elt_at_index (tnm->sessions,
			      nat_value_get_session_index (&value0));
    }

out:
  if (s0)
    {
      *addr = s0->in2out.addr;
      *port = s0->in2out.port;
      *fib_index = s0->in2out.fib_index;
    }
  if (p_s0)
    *p_s0 = s0;
  return next0;
}
#endif

#ifndef CLIB_MARCH_VARIANT
u32
nat44_ei_icmp_match_out2in_fast (vlib_node_runtime_t *node, u32 thread_index,
				 vlib_buffer_t *b0, ip4_header_t *ip0,
				 ip4_address_t *mapping_addr,
				 u16 *mapping_port, u32 *mapping_fib_index,
				 nat_protocol_t *proto,
				 nat44_ei_session_t **p_s0, u8 *dont_translate)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  u32 sw_if_index0;
  u32 rx_fib_index0;
  u8 is_addr_only;
  u32 next0 = ~0;
  int err;
  ip4_address_t addr;
  u16 port;
  *dont_translate = 0;

  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  err = icmp_get_key (b0, ip0, &addr, &port, proto);
  if (err != -1)
    {
      b0->error = node->errors[err];
      next0 = NAT44_EI_OUT2IN_NEXT_DROP;
      goto out;
    }
  if (nat44_ei_static_mapping_match (addr, port, rx_fib_index0, *proto,
				     mapping_addr, mapping_port,
				     mapping_fib_index, 1, &is_addr_only, 0))
    {
      /* Don't NAT packet aimed at the intfc address */
      if (nat44_ei_is_interface_addr (nm->ip4_main, node, sw_if_index0,
				      ip0->dst_address.as_u32))
	{
	  *dont_translate = 1;
	  goto out;
	}
      b0->error = node->errors[NAT44_EI_OUT2IN_ERROR_NO_TRANSLATION];
      next0 = NAT44_EI_OUT2IN_NEXT_DROP;
      goto out;
    }

  if (PREDICT_FALSE
      (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags != ICMP4_echo_reply
       && (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_request || !is_addr_only)
       && !icmp_type_is_error_message (vnet_buffer (b0)->ip.
				       reass.icmp_type_or_tcp_flags)))
    {
      b0->error = node->errors[NAT44_EI_OUT2IN_ERROR_BAD_ICMP_TYPE];
      next0 = NAT44_EI_OUT2IN_NEXT_DROP;
      goto out;
    }

out:
  return next0;
}
#endif

u32 nat44_ei_icmp_out2in (vlib_buffer_t *b0, ip4_header_t *ip0,
			  icmp46_header_t *icmp0, u32 sw_if_index0,
			  u32 rx_fib_index0, vlib_node_runtime_t *node,
			  u32 next0, u32 thread_index,
			  nat44_ei_session_t **p_s0);

#ifndef CLIB_MARCH_VARIANT
u32
nat44_ei_icmp_out2in (vlib_buffer_t *b0, ip4_header_t *ip0,
		      icmp46_header_t *icmp0, u32 sw_if_index0,
		      u32 rx_fib_index0, vlib_node_runtime_t *node, u32 next0,
		      u32 thread_index, nat44_ei_session_t **p_s0)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
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
  vlib_main_t *vm = vlib_get_main ();
  ip4_address_t addr;
  u16 port;
  u32 fib_index;
  nat_protocol_t proto;

  echo0 = (icmp_echo_header_t *) (icmp0 + 1);

  if (PREDICT_TRUE (nm->pat))
    {
      next0_tmp = nat44_ei_icmp_match_out2in_slow (
	node, thread_index, b0, ip0, &addr, &port, &fib_index, &proto, p_s0,
	&dont_translate);
    }
  else
    {
      next0_tmp = nat44_ei_icmp_match_out2in_fast (
	node, thread_index, b0, ip0, &addr, &port, &fib_index, &proto, p_s0,
	&dont_translate);
    }

  if (next0_tmp != ~0)
    next0 = next0_tmp;
  if (next0 == NAT44_EI_OUT2IN_NEXT_DROP || dont_translate)
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
      if (checksum0 != 0 && checksum0 != 0xffff)
	{
	  next0 = NAT44_EI_OUT2IN_NEXT_DROP;
	  goto out;
	}
    }

  old_addr0 = ip0->dst_address.as_u32;
  new_addr0 = ip0->dst_address.as_u32 = addr.as_u32;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = fib_index;

  sum0 = ip0->checksum;
  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			 dst_address /* changed member */ );
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
				identifier /* changed member */ );
	      icmp0->checksum = ip_csum_fold (sum0);
	    }
	}
      else
	{
	  inner_ip0 = (ip4_header_t *) (echo0 + 1);
	  l4_header = ip4_next_header (inner_ip0);

	  if (!ip4_header_checksum_is_valid (inner_ip0))
	    {
	      next0 = NAT44_EI_OUT2IN_NEXT_DROP;
	      goto out;
	    }

	  old_addr0 = inner_ip0->src_address.as_u32;
	  inner_ip0->src_address = addr;
	  new_addr0 = inner_ip0->src_address.as_u32;

	  sum0 = icmp0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				 src_address /* changed member */ );
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
	      old_id0 = ((tcp_udp_header_t *) l4_header)->src_port;
	      new_id0 = port;
	      ((tcp_udp_header_t *) l4_header)->src_port = new_id0;

	      sum0 = icmp0->checksum;
	      sum0 = ip_csum_update (sum0, old_id0, new_id0, tcp_udp_header_t,
				     src_port);
	      icmp0->checksum = ip_csum_fold (sum0);
	      break;
	    default:
	      ASSERT (0);
	    }
	}
    }

out:
  return next0;
}
#endif

static inline u32
nat44_ei_icmp_out2in_slow_path (nat44_ei_main_t *nm, vlib_buffer_t *b0,
				ip4_header_t *ip0, icmp46_header_t *icmp0,
				u32 sw_if_index0, u32 rx_fib_index0,
				vlib_node_runtime_t *node, u32 next0, f64 now,
				u32 thread_index, nat44_ei_session_t **p_s0)
{
  vlib_main_t *vm = vlib_get_main ();

  next0 = nat44_ei_icmp_out2in (b0, ip0, icmp0, sw_if_index0, rx_fib_index0,
				node, next0, thread_index, p_s0);
  nat44_ei_session_t *s0 = *p_s0;
  if (PREDICT_TRUE (next0 != NAT44_EI_OUT2IN_NEXT_DROP && s0))
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
nat_out2in_sm_unknown_proto (nat44_ei_main_t *nm, vlib_buffer_t *b,
			     ip4_header_t *ip, u32 rx_fib_index)
{
  clib_bihash_kv_8_8_t kv, value;
  nat44_ei_static_mapping_t *m;
  u32 old_addr, new_addr;
  ip_csum_t sum;

  init_nat_k (&kv, ip->dst_address, 0, 0, 0);
  if (clib_bihash_search_8_8 (&nm->static_mapping_by_external, &kv, &value))
    return 1;

  m = pool_elt_at_index (nm->static_mappings, value.value);

  old_addr = ip->dst_address.as_u32;
  new_addr = ip->dst_address.as_u32 = m->local_addr.as_u32;
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
  ip->checksum = ip_csum_fold (sum);

  vnet_buffer (b)->sw_if_index[VLIB_TX] = m->fib_index;
  return 0;
}

VLIB_NODE_FN (nat44_ei_out2in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from;
  nat44_ei_main_t *nm = &nat44_ei_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  nat44_ei_main_per_thread_data_t *tnm = &nm->per_thread_data[thread_index];

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from >= 2)
    {
      vlib_buffer_t *b0, *b1;
      u32 next0 = NAT44_EI_OUT2IN_NEXT_LOOKUP;
      u32 next1 = NAT44_EI_OUT2IN_NEXT_LOOKUP;
      u32 sw_if_index0, sw_if_index1;
      ip4_header_t *ip0, *ip1;
      ip_csum_t sum0, sum1;
      u32 new_addr0, old_addr0;
      u16 new_port0, old_port0;
      u32 new_addr1, old_addr1;
      u16 new_port1, old_port1;
      udp_header_t *udp0, *udp1;
      tcp_header_t *tcp0, *tcp1;
      icmp46_header_t *icmp0, *icmp1;
      u32 rx_fib_index0, rx_fib_index1;
      u32 proto0, proto1;
      nat44_ei_session_t *s0 = 0, *s1 = 0;
      clib_bihash_kv_8_8_t kv0, kv1, value0, value1;
      u8 identity_nat0, identity_nat1;
      ip4_address_t sm_addr0, sm_addr1;
      u16 sm_port0, sm_port1;
      u32 sm_fib_index0, sm_fib_index1;

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

      vnet_buffer (b0)->snat.flags = 0;
      vnet_buffer (b1)->snat.flags = 0;

      ip0 = vlib_buffer_get_current (b0);
      udp0 = ip4_next_header (ip0);
      tcp0 = (tcp_header_t *) udp0;
      icmp0 = (icmp46_header_t *) udp0;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      rx_fib_index0 =
	vec_elt (nm->ip4_main->fib_index_by_sw_if_index, sw_if_index0);

      if (PREDICT_FALSE (ip0->ttl == 1))
	{
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next0 = NAT44_EI_OUT2IN_NEXT_ICMP_ERROR;
	  goto trace0;
	}

      proto0 = ip_proto_to_nat_proto (ip0->protocol);

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	{
	  if (nat_out2in_sm_unknown_proto (nm, b0, ip0, rx_fib_index0))
	    {
	      if (!nm->forwarding_enabled)
		{
		  b0->error =
		    node->errors[NAT44_EI_OUT2IN_ERROR_UNSUPPORTED_PROTOCOL];
		  next0 = NAT44_EI_OUT2IN_NEXT_DROP;
		}
	    }
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.other,
					 thread_index, sw_if_index0, 1);

	  goto trace0;
	}

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	{
	  next0 = nat44_ei_icmp_out2in_slow_path (
	    nm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node, next0, now,
	    thread_index, &s0);
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.icmp,
					 thread_index, sw_if_index0, 1);
	  goto trace0;
	}

      init_nat_k (&kv0, ip0->dst_address,
		  vnet_buffer (b0)->ip.reass.l4_dst_port, rx_fib_index0,
		  proto0);
      if (clib_bihash_search_8_8 (&nm->out2in, &kv0, &value0))
	{
	  /* Try to match static mapping by external address and port,
	     destination address and port in packet */
	  if (nat44_ei_static_mapping_match (
		ip0->dst_address, vnet_buffer (b0)->ip.reass.l4_dst_port,
		rx_fib_index0, proto0, &sm_addr0, &sm_port0, &sm_fib_index0, 1,
		0, &identity_nat0))
	    {
	      /*
	       * Send DHCP packets to the ipv4 stack, or we won't
	       * be able to use dhcp client on the outside interface
	       */
	      if (PREDICT_FALSE
		  (proto0 == NAT_PROTOCOL_UDP
		   && (vnet_buffer (b0)->ip.reass.l4_dst_port ==
		       clib_host_to_net_u16 (UDP_DST_PORT_dhcp_to_client))))
		{
		  vnet_feature_next (&next0, b0);
		  goto trace0;
		}

	      if (!nm->forwarding_enabled)
		{
		  b0->error =
		    node->errors[NAT44_EI_OUT2IN_ERROR_NO_TRANSLATION];
		  next0 = NAT44_EI_OUT2IN_NEXT_DROP;
		}
	      goto trace0;
	    }

	  if (PREDICT_FALSE (identity_nat0))
	    goto trace0;

	  /* Create session initiated by host from external network */
	  s0 = create_session_for_static_mapping (
	    nm, b0, sm_addr0, sm_port0, sm_fib_index0, ip0->dst_address,
	    vnet_buffer (b0)->ip.reass.l4_dst_port, rx_fib_index0, proto0,
	    node, thread_index, now);
	  if (!s0)
	    {
	      next0 = NAT44_EI_OUT2IN_NEXT_DROP;
	      goto trace0;
	    }
	}
      else
	s0 = pool_elt_at_index (tnm->sessions,
				nat_value_get_session_index (&value0));

      old_addr0 = ip0->dst_address.as_u32;
      ip0->dst_address = s0->in2out.addr;
      new_addr0 = ip0->dst_address.as_u32;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;

      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
			     ip4_header_t, dst_address /* changed member */ );
      ip0->checksum = ip_csum_fold (sum0);

      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      old_port0 = vnet_buffer (b0)->ip.reass.l4_dst_port;
	      new_port0 = udp0->dst_port = s0->in2out.port;
	      sum0 = tcp0->checksum;
	      sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
				     ip4_header_t,
				     dst_address /* changed member */ );

	      sum0 = ip_csum_update (sum0, old_port0, new_port0,
				     ip4_header_t /* cheat */ ,
				     length /* changed member */ );
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.tcp,
					 thread_index, sw_if_index0, 1);
	}
      else
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      old_port0 = vnet_buffer (b0)->ip.reass.l4_dst_port;
	      new_port0 = udp0->dst_port = s0->in2out.port;
	      if (PREDICT_FALSE (udp0->checksum))
		{
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
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.udp,
					 thread_index, sw_if_index0, 1);
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
	  nat44_ei_out2in_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_index = next0;
	  t->session_index = ~0;
	  if (s0)
	    t->session_index = s0 - nm->per_thread_data[thread_index].sessions;
	}

      if (next0 == NAT44_EI_OUT2IN_NEXT_DROP)
	{
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.drops,
					 thread_index, sw_if_index0, 1);
	}


      ip1 = vlib_buffer_get_current (b1);
      udp1 = ip4_next_header (ip1);
      tcp1 = (tcp_header_t *) udp1;
      icmp1 = (icmp46_header_t *) udp1;

      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
      rx_fib_index1 =
	vec_elt (nm->ip4_main->fib_index_by_sw_if_index, sw_if_index1);

      if (PREDICT_FALSE (ip1->ttl == 1))
	{
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  icmp4_error_set_vnet_buffer (b1, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next1 = NAT44_EI_OUT2IN_NEXT_ICMP_ERROR;
	  goto trace1;
	}

      proto1 = ip_proto_to_nat_proto (ip1->protocol);

      if (PREDICT_FALSE (proto1 == NAT_PROTOCOL_OTHER))
	{
	  if (nat_out2in_sm_unknown_proto (nm, b1, ip1, rx_fib_index1))
	    {
	      if (!nm->forwarding_enabled)
		{
		  b1->error =
		    node->errors[NAT44_EI_OUT2IN_ERROR_UNSUPPORTED_PROTOCOL];
		  next1 = NAT44_EI_OUT2IN_NEXT_DROP;
		}
	    }
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.other,
					 thread_index, sw_if_index1, 1);
	  goto trace1;
	}

      if (PREDICT_FALSE (proto1 == NAT_PROTOCOL_ICMP))
	{
	  next1 = nat44_ei_icmp_out2in_slow_path (
	    nm, b1, ip1, icmp1, sw_if_index1, rx_fib_index1, node, next1, now,
	    thread_index, &s1);
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.icmp,
					 thread_index, sw_if_index1, 1);
	  goto trace1;
	}

      init_nat_k (&kv1, ip1->dst_address,
		  vnet_buffer (b1)->ip.reass.l4_dst_port, rx_fib_index1,
		  proto1);
      if (clib_bihash_search_8_8 (&nm->out2in, &kv1, &value1))
	{
	  /* Try to match static mapping by external address and port,
	     destination address and port in packet */
	  if (nat44_ei_static_mapping_match (
		ip1->dst_address, vnet_buffer (b1)->ip.reass.l4_dst_port,
		rx_fib_index1, proto1, &sm_addr1, &sm_port1, &sm_fib_index1, 1,
		0, &identity_nat1))
	    {
	      /*
	       * Send DHCP packets to the ipv4 stack, or we won't
	       * be able to use dhcp client on the outside interface
	       */
	      if (PREDICT_FALSE
		  (proto1 == NAT_PROTOCOL_UDP
		   && (vnet_buffer (b1)->ip.reass.l4_dst_port ==
		       clib_host_to_net_u16 (UDP_DST_PORT_dhcp_to_client))))
		{
		  vnet_feature_next (&next1, b1);
		  goto trace1;
		}

	      if (!nm->forwarding_enabled)
		{
		  b1->error =
		    node->errors[NAT44_EI_OUT2IN_ERROR_NO_TRANSLATION];
		  next1 = NAT44_EI_OUT2IN_NEXT_DROP;
		}
	      goto trace1;
	    }

	  if (PREDICT_FALSE (identity_nat1))
	    goto trace1;

	  /* Create session initiated by host from external network */
	  s1 = create_session_for_static_mapping (
	    nm, b1, sm_addr1, sm_port1, sm_fib_index1, ip1->dst_address,
	    vnet_buffer (b1)->ip.reass.l4_dst_port, rx_fib_index1, proto1,
	    node, thread_index, now);
	  if (!s1)
	    {
	      next1 = NAT44_EI_OUT2IN_NEXT_DROP;
	      goto trace1;
	    }
	}
      else
	s1 = pool_elt_at_index (nm->per_thread_data[thread_index].sessions,
				nat_value_get_session_index (&value1));

      old_addr1 = ip1->dst_address.as_u32;
      ip1->dst_address = s1->in2out.addr;
      new_addr1 = ip1->dst_address.as_u32;
      vnet_buffer (b1)->sw_if_index[VLIB_TX] = s1->in2out.fib_index;

      sum1 = ip1->checksum;
      sum1 = ip_csum_update (sum1, old_addr1, new_addr1,
			     ip4_header_t, dst_address /* changed member */ );
      ip1->checksum = ip_csum_fold (sum1);

      if (PREDICT_TRUE (proto1 == NAT_PROTOCOL_TCP))
	{
	  if (!vnet_buffer (b1)->ip.reass.is_non_first_fragment)
	    {
	      old_port1 = vnet_buffer (b1)->ip.reass.l4_dst_port;
	      new_port1 = udp1->dst_port = s1->in2out.port;

	      sum1 = tcp1->checksum;
	      sum1 = ip_csum_update (sum1, old_addr1, new_addr1,
				     ip4_header_t,
				     dst_address /* changed member */ );

	      sum1 = ip_csum_update (sum1, old_port1, new_port1,
				     ip4_header_t /* cheat */ ,
				     length /* changed member */ );
	      tcp1->checksum = ip_csum_fold (sum1);
	    }
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.tcp,
					 thread_index, sw_if_index1, 1);
	}
      else
	{
	  if (!vnet_buffer (b1)->ip.reass.is_non_first_fragment)
	    {
	      old_port1 = vnet_buffer (b1)->ip.reass.l4_dst_port;
	      new_port1 = udp1->dst_port = s1->in2out.port;
	      if (PREDICT_FALSE (udp1->checksum))
		{

		  sum1 = udp1->checksum;
		  sum1 =
		    ip_csum_update (sum1, old_addr1, new_addr1,
				    ip4_header_t,
				    dst_address /* changed member */ );
		  sum1 =
		    ip_csum_update (sum1, old_port1, new_port1,
				    ip4_header_t /* cheat */ ,
				    length /* changed member */ );
		  udp1->checksum = ip_csum_fold (sum1);
		}
	    }
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.udp,
					 thread_index, sw_if_index1, 1);
	}

      /* Accounting */
      nat44_ei_session_update_counters (
	s1, now, vlib_buffer_length_in_chain (vm, b1), thread_index);
      /* Per-user LRU list maintenance */
      nat44_ei_session_update_lru (nm, s1, thread_index);
    trace1:

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b1->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat44_ei_out2in_trace_t *t =
	    vlib_add_trace (vm, node, b1, sizeof (*t));
	  t->sw_if_index = sw_if_index1;
	  t->next_index = next1;
	  t->session_index = ~0;
	  if (s1)
	    t->session_index = s1 - nm->per_thread_data[thread_index].sessions;
	}

      if (next1 == NAT44_EI_OUT2IN_NEXT_DROP)
	{
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.drops,
					 thread_index, sw_if_index1, 1);
	}

      n_left_from -= 2;
      next[0] = next0;
      next[1] = next1;
      next += 2;
    }

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0;
      u32 next0 = NAT44_EI_OUT2IN_NEXT_LOOKUP;
      u32 sw_if_index0;
      ip4_header_t *ip0;
      ip_csum_t sum0;
      u32 new_addr0, old_addr0;
      u16 new_port0, old_port0;
      udp_header_t *udp0;
      tcp_header_t *tcp0;
      icmp46_header_t *icmp0;
      u32 rx_fib_index0;
      u32 proto0;
      nat44_ei_session_t *s0 = 0;
      clib_bihash_kv_8_8_t kv0, value0;
      u8 identity_nat0;
      ip4_address_t sm_addr0;
      u16 sm_port0;
      u32 sm_fib_index0;

      b0 = *b;
      ++b;

      vnet_buffer (b0)->snat.flags = 0;

      ip0 = vlib_buffer_get_current (b0);
      udp0 = ip4_next_header (ip0);
      tcp0 = (tcp_header_t *) udp0;
      icmp0 = (icmp46_header_t *) udp0;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      rx_fib_index0 =
	vec_elt (nm->ip4_main->fib_index_by_sw_if_index, sw_if_index0);

      proto0 = ip_proto_to_nat_proto (ip0->protocol);

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	{
	  if (nat_out2in_sm_unknown_proto (nm, b0, ip0, rx_fib_index0))
	    {
	      if (!nm->forwarding_enabled)
		{
		  b0->error =
		    node->errors[NAT44_EI_OUT2IN_ERROR_UNSUPPORTED_PROTOCOL];
		  next0 = NAT44_EI_OUT2IN_NEXT_DROP;
		}
	    }
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.other,
					 thread_index, sw_if_index0, 1);
	  goto trace00;
	}

      if (PREDICT_FALSE (ip0->ttl == 1))
	{
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next0 = NAT44_EI_OUT2IN_NEXT_ICMP_ERROR;
	  goto trace00;
	}

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	{
	  next0 = nat44_ei_icmp_out2in_slow_path (
	    nm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node, next0, now,
	    thread_index, &s0);
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.icmp,
					 thread_index, sw_if_index0, 1);
	  goto trace00;
	}

      init_nat_k (&kv0, ip0->dst_address,
		  vnet_buffer (b0)->ip.reass.l4_dst_port, rx_fib_index0,
		  proto0);

      if (clib_bihash_search_8_8 (&nm->out2in, &kv0, &value0))
	{
	  /* Try to match static mapping by external address and port,
	     destination address and port in packet */
	  if (nat44_ei_static_mapping_match (
		ip0->dst_address, vnet_buffer (b0)->ip.reass.l4_dst_port,
		rx_fib_index0, proto0, &sm_addr0, &sm_port0, &sm_fib_index0, 1,
		0, &identity_nat0))
	    {
	      /*
	       * Send DHCP packets to the ipv4 stack, or we won't
	       * be able to use dhcp client on the outside interface
	       */
	      if (PREDICT_FALSE
		  (proto0 == NAT_PROTOCOL_UDP
		   && (vnet_buffer (b0)->ip.reass.l4_dst_port ==
		       clib_host_to_net_u16 (UDP_DST_PORT_dhcp_to_client))))
		{
		  vnet_feature_next (&next0, b0);
		  goto trace00;
		}

	      if (!nm->forwarding_enabled)
		{
		  b0->error =
		    node->errors[NAT44_EI_OUT2IN_ERROR_NO_TRANSLATION];
		  next0 = NAT44_EI_OUT2IN_NEXT_DROP;
		}
	      goto trace00;
	    }

	  if (PREDICT_FALSE (identity_nat0))
	    goto trace00;

	  /* Create session initiated by host from external network */
	  s0 = create_session_for_static_mapping (
	    nm, b0, sm_addr0, sm_port0, sm_fib_index0, ip0->dst_address,
	    vnet_buffer (b0)->ip.reass.l4_dst_port, rx_fib_index0, proto0,
	    node, thread_index, now);
	  if (!s0)
	    {
	      next0 = NAT44_EI_OUT2IN_NEXT_DROP;
	      goto trace00;
	    }
	}
      else
	s0 = pool_elt_at_index (nm->per_thread_data[thread_index].sessions,
				nat_value_get_session_index (&value0));

      old_addr0 = ip0->dst_address.as_u32;
      ip0->dst_address = s0->in2out.addr;
      new_addr0 = ip0->dst_address.as_u32;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;

      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
			     ip4_header_t, dst_address /* changed member */ );
      ip0->checksum = ip_csum_fold (sum0);

      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      old_port0 = vnet_buffer (b0)->ip.reass.l4_dst_port;
	      new_port0 = udp0->dst_port = s0->in2out.port;

	      sum0 = tcp0->checksum;
	      sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
				     ip4_header_t,
				     dst_address /* changed member */ );

	      sum0 = ip_csum_update (sum0, old_port0, new_port0,
				     ip4_header_t /* cheat */ ,
				     length /* changed member */ );
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.tcp,
					 thread_index, sw_if_index0, 1);
	}
      else
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      old_port0 = vnet_buffer (b0)->ip.reass.l4_dst_port;
	      new_port0 = udp0->dst_port = s0->in2out.port;
	      if (PREDICT_FALSE (udp0->checksum))
		{
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
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.udp,
					 thread_index, sw_if_index0, 1);
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
	  nat44_ei_out2in_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_index = next0;
	  t->session_index = ~0;
	  if (s0)
	    t->session_index = s0 - nm->per_thread_data[thread_index].sessions;
	}

      if (next0 == NAT44_EI_OUT2IN_NEXT_DROP)
	{
	  vlib_increment_simple_counter (&nm->counters.slowpath.out2in.drops,
					 thread_index, sw_if_index0, 1);
	}

      n_left_from--;
      next[0] = next0;
      next++;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
			       frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (nat44_ei_out2in_node) = {
  .name = "nat44-ei-out2in",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_out2in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nat44_ei_out2in_error_strings),
  .error_strings = nat44_ei_out2in_error_strings,

  .runtime_data_bytes = sizeof (nat44_ei_runtime_t),

  .n_next_nodes = NAT44_EI_OUT2IN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [NAT44_EI_OUT2IN_NEXT_DROP] = "error-drop",
    [NAT44_EI_OUT2IN_NEXT_LOOKUP] = "ip4-lookup",
    [NAT44_EI_OUT2IN_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
