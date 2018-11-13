/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 * @brief NAT44 endpoint-dependent inside to outside network translation
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/ip4_fib.h>
#include <vppinfra/error.h>
#include <nat/nat.h>
#include <nat/nat_ipfix_logging.h>
#include <nat/nat_reass.h>
#include <nat/nat_inlines.h>

#define foreach_nat_in2out_ed_error                       \
_(UNSUPPORTED_PROTOCOL, "Unsupported protocol")         \
_(IN2OUT_PACKETS, "Good in2out packets processed")      \
_(OUT_OF_PORTS, "Out of ports")                         \
_(BAD_ICMP_TYPE, "unsupported ICMP type")               \
_(MAX_SESSIONS_EXCEEDED, "Maximum sessions exceeded")   \
_(DROP_FRAGMENT, "Drop fragment")                       \
_(MAX_REASS, "Maximum reassemblies exceeded")           \
_(MAX_FRAG, "Maximum fragments per reassembly exceeded")

typedef enum
{
#define _(sym,str) NAT_IN2OUT_ED_ERROR_##sym,
  foreach_nat_in2out_ed_error
#undef _
    NAT_IN2OUT_ED_N_ERROR,
} nat_in2out_ed_error_t;

static char *nat_in2out_ed_error_strings[] = {
#define _(sym,string) string,
  foreach_nat_in2out_ed_error
#undef _
};

typedef enum
{
  NAT_IN2OUT_ED_NEXT_LOOKUP,
  NAT_IN2OUT_ED_NEXT_DROP,
  NAT_IN2OUT_ED_NEXT_ICMP_ERROR,
  NAT_IN2OUT_ED_NEXT_SLOW_PATH,
  NAT_IN2OUT_ED_NEXT_REASS,
  NAT_IN2OUT_ED_N_NEXT,
} nat_in2out_ed_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
  u32 is_slow_path;
} nat_in2out_ed_trace_t;

vlib_node_registration_t nat44_ed_in2out_node;
vlib_node_registration_t nat44_ed_in2out_slowpath_node;
vlib_node_registration_t nat44_ed_in2out_output_node;
vlib_node_registration_t nat44_ed_in2out_output_slowpath_node;
vlib_node_registration_t nat44_ed_in2out_reass_node;

static u8 *
format_nat_in2out_ed_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat_in2out_ed_trace_t *t = va_arg (*args, nat_in2out_ed_trace_t *);
  char *tag;

  tag =
    t->is_slow_path ? "NAT44_IN2OUT_ED_SLOW_PATH" :
    "NAT44_IN2OUT_ED_FAST_PATH";

  s = format (s, "%s: sw_if_index %d, next index %d, session %d", tag,
	      t->sw_if_index, t->next_index, t->session_index);

  return s;
}

static_always_inline int
icmp_get_ed_key (ip4_header_t * ip0, nat_ed_ses_key_t * p_key0)
{
  icmp46_header_t *icmp0;
  nat_ed_ses_key_t key0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0 = 0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *) (icmp0 + 1);

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
      inner_ip0 = (ip4_header_t *) (echo0 + 1);
      l4_header = ip4_next_header (inner_ip0);
      key0.proto = inner_ip0->protocol;
      key0.r_addr = inner_ip0->src_address;
      key0.l_addr = inner_ip0->dst_address;
      switch (ip_proto_to_snat_proto (inner_ip0->protocol))
	{
	case SNAT_PROTOCOL_ICMP:
	  inner_icmp0 = (icmp46_header_t *) l4_header;
	  inner_echo0 = (icmp_echo_header_t *) (inner_icmp0 + 1);
	  key0.r_port = 0;
	  key0.l_port = inner_echo0->identifier;
	  break;
	case SNAT_PROTOCOL_UDP:
	case SNAT_PROTOCOL_TCP:
	  key0.l_port = ((tcp_udp_header_t *) l4_header)->dst_port;
	  key0.r_port = ((tcp_udp_header_t *) l4_header)->src_port;
	  break;
	default:
	  return NAT_IN2OUT_ED_ERROR_UNSUPPORTED_PROTOCOL;
	}
    }
  *p_key0 = key0;
  return 0;
}

int
nat44_i2o_ed_is_idle_session_cb (clib_bihash_kv_16_8_t * kv, void *arg)
{
  snat_main_t *sm = &snat_main;
  nat44_is_idle_session_ctx_t *ctx = arg;
  snat_session_t *s;
  u64 sess_timeout_time;
  nat_ed_ses_key_t ed_key;
  clib_bihash_kv_16_8_t ed_kv;
  int i;
  snat_address_t *a;
  snat_session_key_t key;
  snat_main_per_thread_data_t *tsm = vec_elt_at_index (sm->per_thread_data,
						       ctx->thread_index);

  s = pool_elt_at_index (tsm->sessions, kv->value);
  sess_timeout_time = s->last_heard + (f64) nat44_session_get_timeout (sm, s);
  if (ctx->now >= sess_timeout_time)
    {
      if (is_fwd_bypass_session (s))
	goto delete;

      ed_key.l_addr = s->out2in.addr;
      ed_key.r_addr = s->ext_host_addr;
      ed_key.fib_index = s->out2in.fib_index;
      if (snat_is_unk_proto_session (s))
	{
	  ed_key.proto = s->in2out.port;
	  ed_key.r_port = 0;
	  ed_key.l_port = 0;
	}
      else
	{
	  ed_key.proto = snat_proto_to_ip_proto (s->in2out.protocol);
	  ed_key.l_port = s->out2in.port;
	  ed_key.r_port = s->ext_host_port;
	}
      ed_kv.key[0] = ed_key.as_u64[0];
      ed_kv.key[1] = ed_key.as_u64[1];
      if (clib_bihash_add_del_16_8 (&tsm->out2in_ed, &ed_kv, 0))
	nat_log_warn ("out2in_ed key del failed");

      if (snat_is_unk_proto_session (s))
	goto delete;

      snat_ipfix_logging_nat44_ses_delete (s->in2out.addr.as_u32,
					   s->out2in.addr.as_u32,
					   s->in2out.protocol,
					   s->in2out.port,
					   s->out2in.port,
					   s->in2out.fib_index);

      if (is_twice_nat_session (s))
	{
	  for (i = 0; i < vec_len (sm->twice_nat_addresses); i++)
	    {
	      key.protocol = s->in2out.protocol;
	      key.port = s->ext_host_nat_port;
	      a = sm->twice_nat_addresses + i;
	      if (a->addr.as_u32 == s->ext_host_nat_addr.as_u32)
		{
		  snat_free_outside_address_and_port (sm->twice_nat_addresses,
						      ctx->thread_index,
						      &key);
		  break;
		}
	    }
	}

      if (snat_is_session_static (s))
	goto delete;

      snat_free_outside_address_and_port (sm->addresses, ctx->thread_index,
					  &s->out2in);
    delete:
      nat44_delete_session (sm, s, ctx->thread_index);
      return 1;
    }

  return 0;
}

static inline u32
icmp_in2out_ed_slow_path (snat_main_t * sm, vlib_buffer_t * b0,
			  ip4_header_t * ip0, icmp46_header_t * icmp0,
			  u32 sw_if_index0, u32 rx_fib_index0,
			  vlib_node_runtime_t * node, u32 next0, f64 now,
			  u32 thread_index, snat_session_t ** p_s0)
{
  next0 = icmp_in2out (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
		       next0, thread_index, p_s0, 0);
  snat_session_t *s0 = *p_s0;
  if (PREDICT_TRUE (next0 != NAT_IN2OUT_ED_NEXT_DROP && s0))
    {
      /* Accounting */
      nat44_session_update_counters (s0, now,
				     vlib_buffer_length_in_chain
				     (sm->vlib_main, b0));
      /* Per-user LRU list maintenance */
      nat44_session_update_lru (sm, s0, thread_index);
    }
  return next0;
}

static u32
slow_path_ed (snat_main_t * sm,
	      vlib_buffer_t * b,
	      u32 rx_fib_index,
	      clib_bihash_kv_16_8_t * kv,
	      snat_session_t ** sessionp,
	      vlib_node_runtime_t * node, u32 next, u32 thread_index, f64 now)
{
  snat_session_t *s = 0;
  snat_user_t *u;
  snat_session_key_t key0, key1;
  lb_nat_type_t lb = 0, is_sm = 0;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  nat_ed_ses_key_t *key = (nat_ed_ses_key_t *) kv->key;
  u32 proto = ip_proto_to_snat_proto (key->proto);
  nat_outside_fib_t *outside_fib;
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  u8 identity_nat;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
		.ip4.as_u32 = key->r_addr.as_u32,
		},
  };
  nat44_is_idle_session_ctx_t ctx;

  if (PREDICT_FALSE (maximum_sessions_exceeded (sm, thread_index)))
    {
      b->error = node->errors[NAT_IN2OUT_ED_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_ipfix_logging_max_sessions (sm->max_translations);
      nat_log_notice ("maximum sessions exceeded");
      return NAT_IN2OUT_ED_NEXT_DROP;
    }

  key0.addr = key->l_addr;
  key0.port = key->l_port;
  key1.protocol = key0.protocol = proto;
  key0.fib_index = rx_fib_index;
  key1.fib_index = sm->outside_fib_index;
  /* First try to match static mapping by local address and port */
  if (snat_static_mapping_match
      (sm, key0, &key1, 0, 0, 0, &lb, 0, &identity_nat))
    {
      /* Try to create dynamic translation */
      if (snat_alloc_outside_address_and_port (sm->addresses, rx_fib_index,
					       thread_index, &key1,
					       sm->port_per_thread,
					       tsm->snat_thread_index))
	{
	  nat_log_notice ("addresses exhausted");
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_OUT_OF_PORTS];
	  return NAT_IN2OUT_ED_NEXT_DROP;
	}
    }
  else
    {
      if (PREDICT_FALSE (identity_nat))
	{
	  *sessionp = s;
	  return next;
	}

      is_sm = 1;
    }

  u = nat_user_get_or_create (sm, &key->l_addr, rx_fib_index, thread_index);
  if (!u)
    {
      nat_log_warn ("create NAT user failed");
      if (!is_sm)
	snat_free_outside_address_and_port (sm->addresses,
					    thread_index, &key1);
      return NAT_IN2OUT_ED_NEXT_DROP;
    }

  s = nat_ed_session_alloc (sm, u, thread_index, now);
  if (!s)
    {
      nat44_delete_user_with_no_session (sm, u, thread_index);
      nat_log_warn ("create NAT session failed");
      if (!is_sm)
	snat_free_outside_address_and_port (sm->addresses,
					    thread_index, &key1);
      return NAT_IN2OUT_ED_NEXT_DROP;
    }

  user_session_increment (sm, u, is_sm);
  if (is_sm)
    s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
  if (lb)
    s->flags |= SNAT_SESSION_FLAG_LOAD_BALANCING;
  s->flags |= SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT;
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
      /* *INDENT-OFF* */
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
      /* *INDENT-ON* */
      break;
    }

  /* Add to lookup tables */
  kv->value = s - tsm->sessions;
  ctx.now = now;
  ctx.thread_index = thread_index;
  if (clib_bihash_add_or_overwrite_stale_16_8 (&tsm->in2out_ed, kv,
					       nat44_i2o_ed_is_idle_session_cb,
					       &ctx))
    nat_log_notice ("in2out-ed key add failed");

  make_ed_kv (kv, &key1.addr, &key->r_addr, key->proto, s->out2in.fib_index,
	      key1.port, key->r_port);
  kv->value = s - tsm->sessions;
  if (clib_bihash_add_or_overwrite_stale_16_8 (&tsm->out2in_ed, kv,
					       nat44_o2i_ed_is_idle_session_cb,
					       &ctx))
    nat_log_notice ("out2in-ed key add failed");

  *sessionp = s;

  /* log NAT event */
  snat_ipfix_logging_nat44_ses_create (s->in2out.addr.as_u32,
				       s->out2in.addr.as_u32,
				       s->in2out.protocol,
				       s->in2out.port,
				       s->out2in.port, s->in2out.fib_index);
  return next;
}

static_always_inline int
nat44_ed_not_translate (snat_main_t * sm, vlib_node_runtime_t * node,
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
      if (!snat_static_mapping_match (sm, key0, &key1, 1, 0, 0, 0, 0, 0))
	return 0;
    }
  else
    return 0;

  if (sm->forwarding_enabled)
    return 1;

  return snat_not_translate_fast (sm, node, sw_if_index, ip, proto,
				  rx_fib_index);
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
      udp = ip4_next_header (ip);
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
	      tcp_header_t *tcp = ip4_next_header (ip);
	      if (nat44_set_tcp_session_state_i2o (sm, s, tcp, thread_index))
		return 1;
	    }
	  /* Accounting */
	  nat44_session_update_counters (s, now,
					 vlib_buffer_length_in_chain (vm, b));
	  /* Per-user LRU list maintenance */
	  nat44_session_update_lru (sm, s, thread_index);
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
      /* *INDENT-OFF* */
      pool_foreach (i, sm->output_feature_interfaces,
      ({
        if ((nat_interface_is_inside (i)) && (rx_sw_if_index == i->sw_if_index))
           return 0;
      }));
      /* *INDENT-ON* */
      return 1;
    }

  return 0;
}

u32
icmp_match_in2out_ed (snat_main_t * sm, vlib_node_runtime_t * node,
		      u32 thread_index, vlib_buffer_t * b, ip4_header_t * ip,
		      u8 * p_proto, snat_session_key_t * p_value,
		      u8 * p_dont_translate, void *d, void *e)
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
  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  rx_fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  key.as_u64[0] = key.as_u64[1] = 0;
  err = icmp_get_ed_key (ip, &key);
  if (err != 0)
    {
      b->error = node->errors[err];
      next = NAT_IN2OUT_ED_NEXT_DROP;
      goto out;
    }
  key.fib_index = rx_fib_index;

  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];

  if (clib_bihash_search_16_8 (&tsm->in2out_ed, &kv, &value))
    {
      if (vnet_buffer (b)->sw_if_index[VLIB_TX] != ~0)
	{
	  if (PREDICT_FALSE (nat44_ed_not_translate_output_feature (sm, ip,
								    key.proto,
								    key.
								    l_port,
								    key.
								    r_port,
								    thread_index,
								    sw_if_index,
								    vnet_buffer
								    (b)->
								    sw_if_index
								    [VLIB_TX])))
	    {
	      dont_translate = 1;
	      goto out;
	    }
	}
      else
	{
	  if (PREDICT_FALSE (nat44_ed_not_translate (sm, node, sw_if_index,
						     ip, SNAT_PROTOCOL_ICMP,
						     rx_fib_index,
						     thread_index)))
	    {
	      dont_translate = 1;
	      goto out;
	    }
	}

      if (PREDICT_FALSE (icmp_is_error_message (icmp)))
	{
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_BAD_ICMP_TYPE];
	  next = NAT_IN2OUT_ED_NEXT_DROP;
	  goto out;
	}

      next = slow_path_ed (sm, b, rx_fib_index, &kv, &s, node, next,
			   thread_index, vlib_time_now (sm->vlib_main));

      if (PREDICT_FALSE (next == NAT_IN2OUT_ED_NEXT_DROP))
	goto out;

      if (!s)
	{
	  dont_translate = 1;
	  goto out;
	}
    }
  else
    {
      if (PREDICT_FALSE (icmp->type != ICMP4_echo_request &&
			 icmp->type != ICMP4_echo_reply &&
			 !icmp_is_error_message (icmp)))
	{
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_BAD_ICMP_TYPE];
	  next = NAT_IN2OUT_ED_NEXT_DROP;
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
    *(snat_session_t **) d = s;
  return next;
}

static snat_session_t *
nat44_ed_in2out_unknown_proto (snat_main_t * sm,
			       vlib_buffer_t * b,
			       ip4_header_t * ip,
			       u32 rx_fib_index,
			       u32 thread_index,
			       f64 now,
			       vlib_main_t * vm, vlib_node_runtime_t * node)
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
  snat_session_t *s;
  u32 outside_fib_index = sm->outside_fib_index;
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
      /* *INDENT-OFF* */
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
      /* *INDENT-ON* */
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
      if (PREDICT_FALSE (maximum_sessions_exceeded (sm, thread_index)))
	{
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_MAX_SESSIONS_EXCEEDED];
	  nat_ipfix_logging_max_sessions (sm->max_translations);
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
	      s = pool_elt_at_index (tsm->sessions, ses_index);
	      elt_index = elt->next;
	      elt = pool_elt_at_index (tsm->list_pool, elt_index);
	      ses_index = elt->value;

	      if (s->ext_host_addr.as_u32 == ip->dst_address.as_u32)
		{
		  new_addr = ip->src_address.as_u32 = s->out2in.addr.as_u32;

		  make_ed_kv (&s_kv, &s->out2in.addr, &ip->dst_address,
			      ip->protocol, outside_fib_index, 0, 0);
		  if (clib_bihash_search_16_8
		      (&tsm->out2in_ed, &s_kv, &s_value))
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
		  goto create_ses;
		}
	    }
	  return 0;
	}

    create_ses:
      s = nat_ed_session_alloc (sm, u, thread_index, now);
      if (!s)
	{
	  nat44_delete_user_with_no_session (sm, u, thread_index);
	  nat_log_warn ("create NAT session failed");
	  return 0;
	}

      s->ext_host_addr.as_u32 = ip->dst_address.as_u32;
      s->flags |= SNAT_SESSION_FLAG_UNKNOWN_PROTO;
      s->flags |= SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT;
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
  if (vnet_buffer (b)->sw_if_index[VLIB_TX] == ~0)
    nat44_ed_hairpinning_unknown_proto (sm, b, ip);

  if (vnet_buffer (b)->sw_if_index[VLIB_TX] == ~0)
    vnet_buffer (b)->sw_if_index[VLIB_TX] = outside_fib_index;

  return s;
}

static inline uword
nat44_ed_in2out_node_fn_inline (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame, int is_slow_path,
				int is_output_feature)
{
  u32 n_left_from, *from, *to_next, pkts_processed = 0, stats_node_index;
  nat_in2out_ed_next_t next_index;
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
	    vlib_buffer_t *p2, *p3;

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

	  next0 = NAT_IN2OUT_ED_NEXT_LOOKUP;

	  if (is_output_feature)
	    iph_offset0 = vnet_buffer (b0)->ip.save_rewrite_length;

	  ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
				  iph_offset0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 =
	    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						 sw_if_index0);

	  if (PREDICT_FALSE (ip0->ttl == 1))
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next0 = NAT_IN2OUT_ED_NEXT_ICMP_ERROR;
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
		    next0 = NAT_IN2OUT_ED_NEXT_DROP;
		  goto trace00;
		}

	      if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
		{
		  next0 = icmp_in2out_ed_slow_path
		    (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
		     next0, now, thread_index, &s0);
		  goto trace00;
		}
	    }
	  else
	    {
	      if (PREDICT_FALSE (proto0 == ~0))
		{
		  next0 = NAT_IN2OUT_ED_NEXT_SLOW_PATH;
		  goto trace00;
		}

	      if (ip4_is_fragment (ip0))
		{
		  next0 = NAT_IN2OUT_ED_NEXT_REASS;
		  goto trace00;
		}

	      if (is_output_feature)
		{
		  if (PREDICT_FALSE
		      (nat_not_translate_output_feature_fwd
		       (sm, ip0, thread_index, now, vm, b0)))
		    goto trace00;
		}

	      if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
		{
		  next0 = NAT_IN2OUT_ED_NEXT_SLOW_PATH;
		  goto trace00;
		}
	    }

	  make_ed_kv (&kv0, &ip0->src_address, &ip0->dst_address,
		      ip0->protocol, rx_fib_index0, udp0->src_port,
		      udp0->dst_port);

	  if (clib_bihash_search_16_8 (&tsm->in2out_ed, &kv0, &value0))
	    {
	      if (is_slow_path)
		{
		  if (is_output_feature)
		    {
		      if (PREDICT_FALSE
			  (nat44_ed_not_translate_output_feature
			   (sm, ip0, ip0->protocol, udp0->src_port,
			    udp0->dst_port, thread_index, sw_if_index0,
			    vnet_buffer (b0)->sw_if_index[VLIB_TX])))
			goto trace00;
		    }
		  else
		    {
		      if (PREDICT_FALSE (nat44_ed_not_translate (sm, node,
								 sw_if_index0,
								 ip0, proto0,
								 rx_fib_index0,
								 thread_index)))
			goto trace00;
		    }

		  next0 =
		    slow_path_ed (sm, b0, rx_fib_index0, &kv0, &s0, node,
				  next0, thread_index, now);

		  if (PREDICT_FALSE (next0 == NAT_IN2OUT_ED_NEXT_DROP))
		    goto trace00;

		  if (PREDICT_FALSE (!s0))
		    goto trace00;
		}
	      else
		{
		  next0 = NAT_IN2OUT_ED_NEXT_SLOW_PATH;
		  goto trace00;
		}
	    }
	  else
	    {
	      s0 = pool_elt_at_index (tsm->sessions, value0.value);
	    }

	  b0->flags |= VNET_BUFFER_F_IS_NATED;

	  if (!is_output_feature)
	    vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

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
	      mss_clamping (sm, tcp0, &sum0);
	      tcp0->checksum = ip_csum_fold (sum0);
	      if (nat44_set_tcp_session_state_i2o
		  (sm, s0, tcp0, thread_index))
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
					 vlib_buffer_length_in_chain (vm,
								      b0));
	  /* Per-user LRU list maintenance */
	  nat44_session_update_lru (sm, s0, thread_index);

	trace00:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat_in2out_ed_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->is_slow_path = is_slow_path;
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->session_index = ~0;
	      if (s0)
		t->session_index = s0 - tsm->sessions;
	    }

	  pkts_processed += next0 != NAT_IN2OUT_ED_NEXT_DROP;


	  next1 = NAT_IN2OUT_ED_NEXT_LOOKUP;

	  if (is_output_feature)
	    iph_offset1 = vnet_buffer (b1)->ip.save_rewrite_length;

	  ip1 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b1) +
				  iph_offset1);

	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	  rx_fib_index1 =
	    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						 sw_if_index1);

	  if (PREDICT_FALSE (ip1->ttl == 1))
	    {
	      vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      icmp4_error_set_vnet_buffer (b1, ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next1 = NAT_IN2OUT_ED_NEXT_ICMP_ERROR;
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
		    next1 = NAT_IN2OUT_ED_NEXT_DROP;
		  goto trace01;
		}

	      if (PREDICT_FALSE (proto1 == SNAT_PROTOCOL_ICMP))
		{
		  next1 = icmp_in2out_ed_slow_path
		    (sm, b1, ip1, icmp1, sw_if_index1, rx_fib_index1, node,
		     next1, now, thread_index, &s1);
		  goto trace01;
		}
	    }
	  else
	    {
	      if (PREDICT_FALSE (proto1 == ~0))
		{
		  next1 = NAT_IN2OUT_ED_NEXT_SLOW_PATH;
		  goto trace01;
		}

	      if (ip4_is_fragment (ip1))
		{
		  next1 = NAT_IN2OUT_ED_NEXT_REASS;
		  goto trace01;
		}

	      if (is_output_feature)
		{
		  if (PREDICT_FALSE
		      (nat_not_translate_output_feature_fwd
		       (sm, ip1, thread_index, now, vm, b1)))
		    goto trace01;
		}

	      if (PREDICT_FALSE (proto1 == SNAT_PROTOCOL_ICMP))
		{
		  next1 = NAT_IN2OUT_ED_NEXT_SLOW_PATH;
		  goto trace01;
		}
	    }

	  make_ed_kv (&kv1, &ip1->src_address, &ip1->dst_address,
		      ip1->protocol, rx_fib_index1, udp1->src_port,
		      udp1->dst_port);

	  if (clib_bihash_search_16_8 (&tsm->in2out_ed, &kv1, &value1))
	    {
	      if (is_slow_path)
		{
		  if (is_output_feature)
		    {
		      if (PREDICT_FALSE
			  (nat44_ed_not_translate_output_feature
			   (sm, ip1, ip1->protocol, udp1->src_port,
			    udp1->dst_port, thread_index, sw_if_index1,
			    vnet_buffer (b1)->sw_if_index[VLIB_TX])))
			goto trace01;
		    }
		  else
		    {
		      if (PREDICT_FALSE (nat44_ed_not_translate (sm, node,
								 sw_if_index1,
								 ip1, proto1,
								 rx_fib_index1,
								 thread_index)))
			goto trace01;
		    }

		  next1 =
		    slow_path_ed (sm, b1, rx_fib_index1, &kv1, &s1, node,
				  next1, thread_index, now);

		  if (PREDICT_FALSE (next1 == NAT_IN2OUT_ED_NEXT_DROP))
		    goto trace01;

		  if (PREDICT_FALSE (!s1))
		    goto trace01;
		}
	      else
		{
		  next1 = NAT_IN2OUT_ED_NEXT_SLOW_PATH;
		  goto trace01;
		}
	    }
	  else
	    {
	      s1 = pool_elt_at_index (tsm->sessions, value1.value);
	    }

	  b1->flags |= VNET_BUFFER_F_IS_NATED;

	  if (!is_output_feature)
	    vnet_buffer (b1)->sw_if_index[VLIB_TX] = s1->out2in.fib_index;

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
	      tcp1->checksum = ip_csum_fold (sum1);
	      mss_clamping (sm, tcp1, &sum1);
	      if (nat44_set_tcp_session_state_i2o
		  (sm, s1, tcp1, thread_index))
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
					 vlib_buffer_length_in_chain (vm,
								      b1));
	  /* Per-user LRU list maintenance */
	  nat44_session_update_lru (sm, s1, thread_index);

	trace01:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat_in2out_ed_trace_t *t =
		vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->is_slow_path = is_slow_path;
	      t->sw_if_index = sw_if_index1;
	      t->next_index = next1;
	      t->session_index = ~0;
	      if (s1)
		t->session_index = s1 - tsm->sessions;
	    }

	  pkts_processed += next1 != NAT_IN2OUT_ED_NEXT_DROP;

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
	  icmp46_header_t *icmp0;
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
	  next0 = NAT_IN2OUT_ED_NEXT_LOOKUP;

	  if (is_output_feature)
	    iph_offset0 = vnet_buffer (b0)->ip.save_rewrite_length;

	  ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
				  iph_offset0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 =
	    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						 sw_if_index0);

	  if (PREDICT_FALSE (ip0->ttl == 1))
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next0 = NAT_IN2OUT_ED_NEXT_ICMP_ERROR;
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
		    next0 = NAT_IN2OUT_ED_NEXT_DROP;
		  goto trace0;
		}

	      if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
		{
		  next0 = icmp_in2out_ed_slow_path
		    (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
		     next0, now, thread_index, &s0);
		  goto trace0;
		}
	    }
	  else
	    {
	      if (PREDICT_FALSE (proto0 == ~0))
		{
		  next0 = NAT_IN2OUT_ED_NEXT_SLOW_PATH;
		  goto trace0;
		}

	      if (ip4_is_fragment (ip0))
		{
		  next0 = NAT_IN2OUT_ED_NEXT_REASS;
		  goto trace0;
		}

	      if (is_output_feature)
		{
		  if (PREDICT_FALSE
		      (nat_not_translate_output_feature_fwd
		       (sm, ip0, thread_index, now, vm, b0)))
		    goto trace0;
		}

	      if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
		{
		  next0 = NAT_IN2OUT_ED_NEXT_SLOW_PATH;
		  goto trace0;
		}
	    }

	  make_ed_kv (&kv0, &ip0->src_address, &ip0->dst_address,
		      ip0->protocol, rx_fib_index0, udp0->src_port,
		      udp0->dst_port);

	  if (clib_bihash_search_16_8 (&tsm->in2out_ed, &kv0, &value0))
	    {
	      if (is_slow_path)
		{
		  if (is_output_feature)
		    {
		      if (PREDICT_FALSE
			  (nat44_ed_not_translate_output_feature
			   (sm, ip0, ip0->protocol, udp0->src_port,
			    udp0->dst_port, thread_index, sw_if_index0,
			    vnet_buffer (b0)->sw_if_index[VLIB_TX])))
			goto trace0;
		    }
		  else
		    {
		      if (PREDICT_FALSE (nat44_ed_not_translate (sm, node,
								 sw_if_index0,
								 ip0, proto0,
								 rx_fib_index0,
								 thread_index)))
			goto trace0;
		    }

		  next0 =
		    slow_path_ed (sm, b0, rx_fib_index0, &kv0, &s0, node,
				  next0, thread_index, now);

		  if (PREDICT_FALSE (next0 == NAT_IN2OUT_ED_NEXT_DROP))
		    goto trace0;

		  if (PREDICT_FALSE (!s0))
		    goto trace0;
		}
	      else
		{
		  next0 = NAT_IN2OUT_ED_NEXT_SLOW_PATH;
		  goto trace0;
		}
	    }
	  else
	    {
	      s0 = pool_elt_at_index (tsm->sessions, value0.value);
	    }

	  b0->flags |= VNET_BUFFER_F_IS_NATED;

	  if (!is_output_feature)
	    vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

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
	      mss_clamping (sm, tcp0, &sum0);
	      tcp0->checksum = ip_csum_fold (sum0);
	      if (nat44_set_tcp_session_state_i2o
		  (sm, s0, tcp0, thread_index))
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
					 vlib_buffer_length_in_chain (vm,
								      b0));
	  /* Per-user LRU list maintenance */
	  nat44_session_update_lru (sm, s0, thread_index);

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat_in2out_ed_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->is_slow_path = is_slow_path;
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->session_index = ~0;
	      if (s0)
		t->session_index = s0 - tsm->sessions;
	    }

	  pkts_processed += next0 != NAT_IN2OUT_ED_NEXT_DROP;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_IN2OUT_ED_ERROR_IN2OUT_PACKETS,
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_in2out_node) = {
  .function = nat44_ed_in2out_fast_path_fn,
  .name = "nat44-ed-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_nat_in2out_ed_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_in2out_ed_error_strings),
  .error_strings = nat_in2out_ed_error_strings,
  .runtime_data_bytes = sizeof (snat_runtime_t),
  .n_next_nodes = NAT_IN2OUT_ED_N_NEXT,
  .next_nodes = {
    [NAT_IN2OUT_ED_NEXT_DROP] = "error-drop",
    [NAT_IN2OUT_ED_NEXT_LOOKUP] = "ip4-lookup",
    [NAT_IN2OUT_ED_NEXT_SLOW_PATH] = "nat44-ed-in2out-slowpath",
    [NAT_IN2OUT_ED_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT_IN2OUT_ED_NEXT_REASS] = "nat44-ed-in2out-reass",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_in2out_node,
			      nat44_ed_in2out_fast_path_fn);

static uword
nat44_ed_in2out_output_fast_path_fn (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return nat44_ed_in2out_node_fn_inline (vm, node, frame, 0, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_in2out_output_node) = {
  .function = nat44_ed_in2out_output_fast_path_fn,
  .name = "nat44-ed-in2out-output",
  .vector_size = sizeof (u32),
  .format_trace = format_nat_in2out_ed_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_in2out_ed_error_strings),
  .error_strings = nat_in2out_ed_error_strings,
  .runtime_data_bytes = sizeof (snat_runtime_t),
  .n_next_nodes = NAT_IN2OUT_ED_N_NEXT,
  .next_nodes = {
    [NAT_IN2OUT_ED_NEXT_DROP] = "error-drop",
    [NAT_IN2OUT_ED_NEXT_LOOKUP] = "interface-output",
    [NAT_IN2OUT_ED_NEXT_SLOW_PATH] = "nat44-ed-in2out-output-slowpath",
    [NAT_IN2OUT_ED_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT_IN2OUT_ED_NEXT_REASS] = "nat44-ed-in2out-reass-output",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_in2out_output_node,
			      nat44_ed_in2out_output_fast_path_fn);

static uword
nat44_ed_in2out_slow_path_fn (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  return nat44_ed_in2out_node_fn_inline (vm, node, frame, 1, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_in2out_slowpath_node) = {
  .function = nat44_ed_in2out_slow_path_fn,
  .name = "nat44-ed-in2out-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_nat_in2out_ed_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_in2out_ed_error_strings),
  .error_strings = nat_in2out_ed_error_strings,
  .runtime_data_bytes = sizeof (snat_runtime_t),
  .n_next_nodes = NAT_IN2OUT_ED_N_NEXT,
  .next_nodes = {
    [NAT_IN2OUT_ED_NEXT_DROP] = "error-drop",
    [NAT_IN2OUT_ED_NEXT_LOOKUP] = "ip4-lookup",
    [NAT_IN2OUT_ED_NEXT_SLOW_PATH] = "nat44-ed-in2out-slowpath",
    [NAT_IN2OUT_ED_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT_IN2OUT_ED_NEXT_REASS] = "nat44-ed-in2out-reass",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_in2out_slowpath_node,
			      nat44_ed_in2out_slow_path_fn);

static uword
nat44_ed_in2out_output_slow_path_fn (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return nat44_ed_in2out_node_fn_inline (vm, node, frame, 1, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_in2out_output_slowpath_node) = {
  .function = nat44_ed_in2out_output_slow_path_fn,
  .name = "nat44-ed-in2out-output-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_nat_in2out_ed_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_in2out_ed_error_strings),
  .error_strings = nat_in2out_ed_error_strings,
  .runtime_data_bytes = sizeof (snat_runtime_t),
  .n_next_nodes = NAT_IN2OUT_ED_N_NEXT,
  .next_nodes = {
    [NAT_IN2OUT_ED_NEXT_DROP] = "error-drop",
    [NAT_IN2OUT_ED_NEXT_LOOKUP] = "interface-output",
    [NAT_IN2OUT_ED_NEXT_SLOW_PATH] = "nat44-ed-in2out-output-slowpath",
    [NAT_IN2OUT_ED_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT_IN2OUT_ED_NEXT_REASS] = "nat44-ed-in2out-reass",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_in2out_output_slowpath_node,
			      nat44_ed_in2out_output_slow_path_fn);

static inline uword
nat44_ed_in2out_reass_node_fn_inline (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame,
				      int is_output_feature)
{
  u32 n_left_from, *from, *to_next;
  nat_in2out_ed_next_t next_index;
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
	  u32 iph_offset0 = 0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u8 cached0 = 0;
	  ip4_header_t *ip0 = 0;
	  nat_reass_ip4_t *reass0;
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;
	  icmp46_header_t *icmp0;
	  clib_bihash_kv_16_8_t kv0, value0;
	  snat_session_t *s0 = 0;
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

	  next0 = NAT_IN2OUT_ED_NEXT_LOOKUP;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 =
	    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						 sw_if_index0);

	  if (PREDICT_FALSE (nat_reass_is_drop_frag (0)))
	    {
	      next0 = NAT_IN2OUT_ED_NEXT_DROP;
	      b0->error = node->errors[NAT_IN2OUT_ED_ERROR_DROP_FRAGMENT];
	      goto trace0;
	    }

	  if (is_output_feature)
	    iph_offset0 = vnet_buffer (b0)->ip.save_rewrite_length;

	  ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
				  iph_offset0);

	  udp0 = ip4_next_header (ip0);
	  tcp0 = (tcp_header_t *) udp0;
	  icmp0 = (icmp46_header_t *) udp0;
	  proto0 = ip_proto_to_snat_proto (ip0->protocol);

	  reass0 = nat_ip4_reass_find_or_create (ip0->src_address,
						 ip0->dst_address,
						 ip0->fragment_id,
						 ip0->protocol,
						 1, &fragments_to_drop);

	  if (PREDICT_FALSE (!reass0))
	    {
	      next0 = NAT_IN2OUT_ED_NEXT_DROP;
	      b0->error = node->errors[NAT_IN2OUT_ED_ERROR_MAX_REASS];
	      nat_log_notice ("maximum reassemblies exceeded");
	      goto trace0;
	    }

	  if (PREDICT_FALSE (ip4_is_first_fragment (ip0)))
	    {
	      if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
		{
		  if (is_output_feature)
		    {
		      if (PREDICT_FALSE
			  (nat_not_translate_output_feature_fwd
			   (sm, ip0, thread_index, now, vm, b0)))
			reass0->flags |= NAT_REASS_FLAG_ED_DONT_TRANSLATE;
		      goto trace0;
		    }

		  next0 = icmp_in2out_ed_slow_path
		    (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
		     next0, now, thread_index, &s0);

		  if (PREDICT_TRUE (next0 != NAT_IN2OUT_ED_NEXT_DROP))
		    {
		      if (s0)
			reass0->sess_index = s0 - per_thread_data->sessions;
		      else
			reass0->flags |= NAT_REASS_FLAG_ED_DONT_TRANSLATE;
		      nat_ip4_reass_get_frags (reass0,
					       &fragments_to_loopback);
		    }

		  goto trace0;
		}

	      make_ed_kv (&kv0, &ip0->src_address, &ip0->dst_address,
			  ip0->protocol, rx_fib_index0, udp0->src_port,
			  udp0->dst_port);

	      if (clib_bihash_search_16_8
		  (&per_thread_data->in2out_ed, &kv0, &value0))
		{
		  if (is_output_feature)
		    {
		      if (PREDICT_FALSE
			  (nat44_ed_not_translate_output_feature
			   (sm, ip0, ip0->protocol, udp0->src_port,
			    udp0->dst_port, thread_index, sw_if_index0,
			    vnet_buffer (b0)->sw_if_index[VLIB_TX])))
			{
			  reass0->flags |= NAT_REASS_FLAG_ED_DONT_TRANSLATE;
			  nat_ip4_reass_get_frags (reass0,
						   &fragments_to_loopback);
			  goto trace0;
			}
		    }
		  else
		    {
		      if (PREDICT_FALSE (nat44_ed_not_translate (sm, node,
								 sw_if_index0,
								 ip0, proto0,
								 rx_fib_index0,
								 thread_index)))
			{
			  reass0->flags |= NAT_REASS_FLAG_ED_DONT_TRANSLATE;
			  nat_ip4_reass_get_frags (reass0,
						   &fragments_to_loopback);
			  goto trace0;
			}
		    }

		  next0 = slow_path_ed (sm, b0, rx_fib_index0, &kv0,
					&s0, node, next0, thread_index, now);

		  if (PREDICT_FALSE (next0 == NAT_IN2OUT_ED_NEXT_DROP))
		    goto trace0;

		  if (PREDICT_FALSE (!s0))
		    {
		      reass0->flags |= NAT_REASS_FLAG_ED_DONT_TRANSLATE;
		      goto trace0;
		    }

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
	      if (reass0->flags & NAT_REASS_FLAG_ED_DONT_TRANSLATE)
		goto trace0;
	      if (PREDICT_FALSE (reass0->sess_index == (u32) ~ 0))
		{
		  if (nat_ip4_reass_add_fragment
		      (reass0, bi0, &fragments_to_drop))
		    {
		      b0->error = node->errors[NAT_IN2OUT_ED_ERROR_MAX_FRAG];
		      nat_log_notice
			("maximum fragments per reassembly exceeded");
		      next0 = NAT_IN2OUT_ED_NEXT_DROP;
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
	  if (!is_output_feature)
	    vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
				 ip4_header_t,
				 src_address /* changed member */ );
	  if (PREDICT_FALSE (is_twice_nat_session (s0)))
	    sum0 = ip_csum_update (sum0, ip0->dst_address.as_u32,
				   s0->ext_host_addr.as_u32, ip4_header_t,
				   dst_address);
	  ip0->checksum = ip_csum_fold (sum0);

	  if (PREDICT_FALSE (ip4_is_first_fragment (ip0)))
	    {
	      if (PREDICT_TRUE (proto0 == SNAT_PROTOCOL_TCP))
		{
		  old_port0 = tcp0->src_port;
		  tcp0->src_port = s0->out2in.port;
		  new_port0 = tcp0->src_port;

		  sum0 = tcp0->checksum;
		  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
					 ip4_header_t,
					 dst_address /* changed member */ );
		  sum0 = ip_csum_update (sum0, old_port0, new_port0,
					 ip4_header_t /* cheat */ ,
					 length /* changed member */ );
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
		  tcp0->checksum = ip_csum_fold (sum0);
		}
	      else
		{
		  old_port0 = udp0->src_port;
		  udp0->src_port = s0->out2in.port;
		  udp0->checksum = 0;
		  if (PREDICT_FALSE (is_twice_nat_session (s0)))
		    {
		      udp0->dst_port = s0->ext_host_port;
		      ip0->dst_address.as_u32 = s0->ext_host_addr.as_u32;
		    }
		}
	    }

	  /* Hairpinning */
	  nat44_reass_hairpinning (sm, b0, ip0, s0->out2in.port,
				   s0->ext_host_port, proto0, 1);

	  /* Accounting */
	  nat44_session_update_counters (s0, now,
					 vlib_buffer_length_in_chain (vm,
								      b0));
	  /* Per-user LRU list maintenance */
	  nat44_session_update_lru (sm, s0, thread_index);

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat44_reass_trace_t *t =
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
	      pkts_processed += next0 != NAT_IN2OUT_ED_NEXT_DROP;

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
		  clib_memcpy_fast (from, fragments_to_loopback,
				    sizeof (u32) * len);
		  n_left_from = len;
		  vec_reset_length (fragments_to_loopback);
		}
	      else
		{
		  clib_memcpy_fast (from, fragments_to_loopback +
				    (len - VLIB_FRAME_SIZE),
				    sizeof (u32) * VLIB_FRAME_SIZE);
		  n_left_from = VLIB_FRAME_SIZE;
		  _vec_len (fragments_to_loopback) = len - VLIB_FRAME_SIZE;
		}
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, nat44_ed_in2out_reass_node.index,
			       NAT_IN2OUT_ED_ERROR_IN2OUT_PACKETS,
			       pkts_processed);

  nat_send_all_to_node (vm, fragments_to_drop, node,
			&node->errors[NAT_IN2OUT_ED_ERROR_DROP_FRAGMENT],
			NAT_IN2OUT_ED_NEXT_DROP);

  vec_free (fragments_to_drop);
  vec_free (fragments_to_loopback);
  return frame->n_vectors;
}

static uword
nat44_ed_in2out_reass_node_fn (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return nat44_ed_in2out_reass_node_fn_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_in2out_reass_node) = {
  .function = nat44_ed_in2out_reass_node_fn,
  .name = "nat44-ed-in2out-reass",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_in2out_ed_error_strings),
  .error_strings = nat_in2out_ed_error_strings,
  .n_next_nodes = NAT_IN2OUT_ED_N_NEXT,
  .next_nodes = {
    [NAT_IN2OUT_ED_NEXT_DROP] = "error-drop",
    [NAT_IN2OUT_ED_NEXT_LOOKUP] = "ip4-lookup",
    [NAT_IN2OUT_ED_NEXT_SLOW_PATH] = "nat44-in2out-slowpath",
    [NAT_IN2OUT_ED_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT_IN2OUT_ED_NEXT_REASS] = "nat44-ed-in2out-reass",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_in2out_reass_node,
			      nat44_ed_in2out_reass_node_fn);

static uword
nat44_ed_in2out_reass_output_node_fn (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return nat44_ed_in2out_reass_node_fn_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_in2out_reass_output_node) = {
  .function = nat44_ed_in2out_reass_output_node_fn,
  .name = "nat44-ed-in2out-reass-output",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_in2out_ed_error_strings),
  .error_strings = nat_in2out_ed_error_strings,
  .n_next_nodes = NAT_IN2OUT_ED_N_NEXT,
  .next_nodes = {
    [NAT_IN2OUT_ED_NEXT_DROP] = "error-drop",
    [NAT_IN2OUT_ED_NEXT_LOOKUP] = "interface-output",
    [NAT_IN2OUT_ED_NEXT_SLOW_PATH] = "nat44-in2out-slowpath",
    [NAT_IN2OUT_ED_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT_IN2OUT_ED_NEXT_REASS] = "nat44-ed-in2out-reass",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_in2out_reass_output_node,
			      nat44_ed_in2out_reass_output_node_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
