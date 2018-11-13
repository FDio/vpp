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
 * @brief NAT44 inside to outside network translation
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/ip4_fib.h>
#include <nat/nat.h>
#include <nat/nat_ipfix_logging.h>
#include <nat/nat_reass.h>
#include <nat/nat_inlines.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
  u32 is_slow_path;
} snat_in2out_trace_t;

/* packet trace format function */
static u8 *
format_snat_in2out_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snat_in2out_trace_t *t = va_arg (*args, snat_in2out_trace_t *);
  char *tag;

  tag = t->is_slow_path ? "NAT44_IN2OUT_SLOW_PATH" : "NAT44_IN2OUT_FAST_PATH";

  s = format (s, "%s: sw_if_index %d, next index %d, session %d", tag,
	      t->sw_if_index, t->next_index, t->session_index);

  return s;
}

static u8 *
format_snat_in2out_fast_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snat_in2out_trace_t *t = va_arg (*args, snat_in2out_trace_t *);

  s = format (s, "NAT44_IN2OUT_FAST: sw_if_index %d, next index %d",
	      t->sw_if_index, t->next_index);

  return s;
}

vlib_node_registration_t snat_in2out_node;
vlib_node_registration_t snat_in2out_slowpath_node;
vlib_node_registration_t snat_in2out_fast_node;
vlib_node_registration_t snat_in2out_output_node;
vlib_node_registration_t snat_in2out_output_slowpath_node;
vlib_node_registration_t nat44_in2out_reass_node;

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
_(MAX_FRAG, "Maximum fragments per reassembly exceeded")

typedef enum
{
#define _(sym,str) SNAT_IN2OUT_ERROR_##sym,
  foreach_snat_in2out_error
#undef _
    SNAT_IN2OUT_N_ERROR,
} snat_in2out_error_t;

static char *snat_in2out_error_strings[] = {
#define _(sym,string) string,
  foreach_snat_in2out_error
#undef _
};

typedef enum
{
  SNAT_IN2OUT_NEXT_LOOKUP,
  SNAT_IN2OUT_NEXT_DROP,
  SNAT_IN2OUT_NEXT_ICMP_ERROR,
  SNAT_IN2OUT_NEXT_SLOW_PATH,
  SNAT_IN2OUT_NEXT_REASS,
  SNAT_IN2OUT_N_NEXT,
} snat_in2out_next_t;

static inline int
snat_not_translate (snat_main_t * sm, vlib_node_runtime_t * node,
		    u32 sw_if_index0, ip4_header_t * ip0, u32 proto0,
		    u32 rx_fib_index0, u32 thread_index)
{
  udp_header_t *udp0 = ip4_next_header (ip0);
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
      if (!snat_static_mapping_match (sm, key0, &sm0, 1, 0, 0, 0, 0, 0))
	return 0;
    }
  else
    return 0;

  if (sm->forwarding_enabled)
    return 1;

  return snat_not_translate_fast (sm, node, sw_if_index0, ip0, proto0,
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

  if (!clib_bihash_search_8_8
      (&sm->per_thread_data[thread_index].out2in, &kv0, &value0))
    return 1;

  /* dst NAT check */
  key0.addr = ip0->dst_address;
  key0.port = dst_port;
  key0.protocol = proto0;
  kv0.key = key0.as_u64;
  if (!clib_bihash_search_8_8
      (&sm->per_thread_data[thread_index].in2out, &kv0, &value0))
    {
      /* hairpinning */
    /* *INDENT-OFF* */
    pool_foreach (i, sm->output_feature_interfaces,
    ({
      if ((nat_interface_is_inside(i)) && (sw_if_index == i->sw_if_index))
        return 0;
    }));
    /* *INDENT-ON* */
      return 1;
    }

  return 0;
}

int
nat44_i2o_is_idle_session_cb (clib_bihash_kv_8_8_t * kv, void *arg)
{
  snat_main_t *sm = &snat_main;
  nat44_is_idle_session_ctx_t *ctx = arg;
  snat_session_t *s;
  u64 sess_timeout_time;
  snat_main_per_thread_data_t *tsm = vec_elt_at_index (sm->per_thread_data,
						       ctx->thread_index);
  clib_bihash_kv_8_8_t s_kv;

  s = pool_elt_at_index (tsm->sessions, kv->value);
  sess_timeout_time = s->last_heard + (f64) nat44_session_get_timeout (sm, s);
  if (ctx->now >= sess_timeout_time)
    {
      s_kv.key = s->out2in.as_u64;
      if (clib_bihash_add_del_8_8 (&tsm->out2in, &s_kv, 0))
	nat_log_warn ("out2in key del failed");

      snat_ipfix_logging_nat44_ses_delete (s->in2out.addr.as_u32,
					   s->out2in.addr.as_u32,
					   s->in2out.protocol,
					   s->in2out.port,
					   s->out2in.port,
					   s->in2out.fib_index);

      if (!snat_is_session_static (s))
	snat_free_outside_address_and_port (sm->addresses, ctx->thread_index,
					    &s->out2in);

      nat44_delete_session (sm, s, ctx->thread_index);
      return 1;
    }

  return 0;
}

static u32
slow_path (snat_main_t * sm, vlib_buffer_t * b0,
	   ip4_header_t * ip0,
	   u32 rx_fib_index0,
	   snat_session_key_t * key0,
	   snat_session_t ** sessionp,
	   vlib_node_runtime_t * node, u32 next0, u32 thread_index, f64 now)
{
  snat_user_t *u;
  snat_session_t *s = 0;
  clib_bihash_kv_8_8_t kv0;
  snat_session_key_t key1;
  udp_header_t *udp0 = ip4_next_header (ip0);
  u8 is_sm = 0;
  nat_outside_fib_t *outside_fib;
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  u8 identity_nat;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
		.ip4.as_u32 = ip0->dst_address.as_u32,
		},
  };
  nat44_is_idle_session_ctx_t ctx0;

  if (PREDICT_FALSE (maximum_sessions_exceeded (sm, thread_index)))
    {
      b0->error = node->errors[SNAT_IN2OUT_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_ipfix_logging_max_sessions (sm->max_translations);
      nat_log_notice ("maximum sessions exceeded");
      return SNAT_IN2OUT_NEXT_DROP;
    }

  key1.protocol = key0->protocol;

  /* First try to match static mapping by local address and port */
  if (snat_static_mapping_match
      (sm, *key0, &key1, 0, 0, 0, 0, 0, &identity_nat))
    {
      /* Try to create dynamic translation */
      if (snat_alloc_outside_address_and_port (sm->addresses, rx_fib_index0,
					       thread_index, &key1,
					       sm->port_per_thread,
					       sm->per_thread_data
					       [thread_index].snat_thread_index))
	{
	  b0->error = node->errors[SNAT_IN2OUT_ERROR_OUT_OF_PORTS];
	  return SNAT_IN2OUT_NEXT_DROP;
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

  u = nat_user_get_or_create (sm, &ip0->src_address, rx_fib_index0,
			      thread_index);
  if (!u)
    {
      nat_log_warn ("create NAT user failed");
      return SNAT_IN2OUT_NEXT_DROP;
    }

  s = nat_session_alloc_or_recycle (sm, u, thread_index);
  if (!s)
    {
      nat44_delete_user_with_no_session (sm, u, thread_index);
      nat_log_warn ("create NAT session failed");
      return SNAT_IN2OUT_NEXT_DROP;
    }

  if (is_sm)
    s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
  user_session_increment (sm, u, is_sm);
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
  s->ext_host_addr.as_u32 = ip0->dst_address.as_u32;
  s->ext_host_port = udp0->dst_port;
  *sessionp = s;

  /* Add to translation hashes */
  ctx0.now = now;
  ctx0.thread_index = thread_index;
  kv0.key = s->in2out.as_u64;
  kv0.value = s - sm->per_thread_data[thread_index].sessions;
  if (clib_bihash_add_or_overwrite_stale_8_8
      (&sm->per_thread_data[thread_index].in2out, &kv0,
       nat44_i2o_is_idle_session_cb, &ctx0))
    nat_log_notice ("in2out key add failed");

  kv0.key = s->out2in.as_u64;
  kv0.value = s - sm->per_thread_data[thread_index].sessions;

  if (clib_bihash_add_or_overwrite_stale_8_8
      (&sm->per_thread_data[thread_index].out2in, &kv0,
       nat44_o2i_is_idle_session_cb, &ctx0))
    nat_log_notice ("out2in key add failed");

  /* log NAT event */
  snat_ipfix_logging_nat44_ses_create (s->in2out.addr.as_u32,
				       s->out2in.addr.as_u32,
				       s->in2out.protocol,
				       s->in2out.port,
				       s->out2in.port, s->in2out.fib_index);
  return next0;
}

static_always_inline
  snat_in2out_error_t icmp_get_key (ip4_header_t * ip0,
				    snat_session_key_t * p_key0)
{
  icmp46_header_t *icmp0;
  snat_session_key_t key0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0 = 0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *) (icmp0 + 1);

  if (!icmp_is_error_message (icmp0))
    {
      key0.protocol = SNAT_PROTOCOL_ICMP;
      key0.addr = ip0->src_address;
      key0.port = echo0->identifier;
    }
  else
    {
      inner_ip0 = (ip4_header_t *) (echo0 + 1);
      l4_header = ip4_next_header (inner_ip0);
      key0.protocol = ip_proto_to_snat_proto (inner_ip0->protocol);
      key0.addr = inner_ip0->dst_address;
      switch (key0.protocol)
	{
	case SNAT_PROTOCOL_ICMP:
	  inner_icmp0 = (icmp46_header_t *) l4_header;
	  inner_echo0 = (icmp_echo_header_t *) (inner_icmp0 + 1);
	  key0.port = inner_echo0->identifier;
	  break;
	case SNAT_PROTOCOL_UDP:
	case SNAT_PROTOCOL_TCP:
	  key0.port = ((tcp_udp_header_t *) l4_header)->dst_port;
	  break;
	default:
	  return SNAT_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL;
	}
    }
  *p_key0 = key0;
  return -1;			/* success */
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
u32
icmp_match_in2out_slow (snat_main_t * sm, vlib_node_runtime_t * node,
			u32 thread_index, vlib_buffer_t * b0,
			ip4_header_t * ip0, u8 * p_proto,
			snat_session_key_t * p_value,
			u8 * p_dont_translate, void *d, void *e)
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
  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
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
      if (vnet_buffer (b0)->sw_if_index[VLIB_TX] != ~0)
	{
	  if (PREDICT_FALSE (nat_not_translate_output_feature (sm, ip0,
							       key0.protocol,
							       key0.port,
							       key0.port,
							       thread_index,
							       sw_if_index0)))
	    {
	      dont_translate = 1;
	      goto out;
	    }
	}
      else
	{
	  if (PREDICT_FALSE (snat_not_translate (sm, node, sw_if_index0,
						 ip0, SNAT_PROTOCOL_ICMP,
						 rx_fib_index0,
						 thread_index)))
	    {
	      dont_translate = 1;
	      goto out;
	    }
	}

      if (PREDICT_FALSE (icmp_is_error_message (icmp0)))
	{
	  b0->error = node->errors[SNAT_IN2OUT_ERROR_BAD_ICMP_TYPE];
	  next0 = SNAT_IN2OUT_NEXT_DROP;
	  goto out;
	}

      next0 = slow_path (sm, b0, ip0, rx_fib_index0, &key0, &s0, node, next0,
			 thread_index, vlib_time_now (sm->vlib_main));

      if (PREDICT_FALSE (next0 == SNAT_IN2OUT_NEXT_DROP))
	goto out;

      if (!s0)
	{
	  dont_translate = 1;
	  goto out;
	}
    }
  else
    {
      if (PREDICT_FALSE (icmp0->type != ICMP4_echo_request &&
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
    *(snat_session_t **) d = s0;
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
u32
icmp_match_in2out_fast (snat_main_t * sm, vlib_node_runtime_t * node,
			u32 thread_index, vlib_buffer_t * b0,
			ip4_header_t * ip0, u8 * p_proto,
			snat_session_key_t * p_value,
			u8 * p_dont_translate, void *d, void *e)
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
  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

  err = icmp_get_key (ip0, &key0);
  if (err != -1)
    {
      b0->error = node->errors[err];
      next0 = SNAT_IN2OUT_NEXT_DROP;
      goto out2;
    }
  key0.fib_index = rx_fib_index0;

  if (snat_static_mapping_match
      (sm, key0, &sm0, 0, &is_addr_only, 0, 0, 0, 0))
    {
      if (PREDICT_FALSE (snat_not_translate_fast (sm, node, sw_if_index0, ip0,
						  IP_PROTOCOL_ICMP,
						  rx_fib_index0)))
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

  if (PREDICT_FALSE (icmp0->type != ICMP4_echo_request &&
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

u32
icmp_in2out (snat_main_t * sm,
	     vlib_buffer_t * b0,
	     ip4_header_t * ip0,
	     icmp46_header_t * icmp0,
	     u32 sw_if_index0,
	     u32 rx_fib_index0,
	     vlib_node_runtime_t * node,
	     u32 next0, u32 thread_index, void *d, void *e)
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
  u16 old_checksum0, new_checksum0;
  ip_csum_t sum0;
  u16 checksum0;
  u32 next0_tmp;

  echo0 = (icmp_echo_header_t *) (icmp0 + 1);

  next0_tmp = sm->icmp_match_in2out_cb (sm, node, thread_index, b0, ip0,
					&protocol, &sm0, &dont_translate, d,
					e);
  if (next0_tmp != ~0)
    next0 = next0_tmp;
  if (next0 == SNAT_IN2OUT_NEXT_DROP || dont_translate)
    goto out;

  if (PREDICT_TRUE (!ip4_is_fragment (ip0)))
    {
      sum0 = ip_incremental_checksum_buffer (sm->vlib_main, b0, (u8 *) icmp0 -
					     (u8 *)
					     vlib_buffer_get_current (b0),
					     ntohs (ip0->length) -
					     ip4_header_bytes (ip0), 0);
      checksum0 = ~ip_csum_fold (sum0);
      if (PREDICT_FALSE (checksum0 != 0 && checksum0 != 0xffff))
	{
	  next0 = SNAT_IN2OUT_NEXT_DROP;
	  goto out;
	}
    }

  old_addr0 = ip0->src_address.as_u32;
  new_addr0 = ip0->src_address.as_u32 = sm0.addr.as_u32;

  sum0 = ip0->checksum;
  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			 src_address /* changed member */ );
  ip0->checksum = ip_csum_fold (sum0);

  if (icmp0->checksum == 0)
    icmp0->checksum = 0xffff;

  if (!icmp_is_error_message (icmp0))
    {
      new_id0 = sm0.port;
      if (PREDICT_FALSE (new_id0 != echo0->identifier))
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
      inner_ip0 = (ip4_header_t *) (echo0 + 1);
      l4_header = ip4_next_header (inner_ip0);

      if (!ip4_header_checksum_is_valid (inner_ip0))
	{
	  next0 = SNAT_IN2OUT_NEXT_DROP;
	  goto out;
	}

      /* update inner destination IP address */
      old_addr0 = inner_ip0->dst_address.as_u32;
      inner_ip0->dst_address = sm0.addr;
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
      sum0 = ip_csum_update (sum0, old_checksum0, new_checksum0, ip4_header_t,
			     checksum);
      icmp0->checksum = ip_csum_fold (sum0);

      switch (protocol)
	{
	case SNAT_PROTOCOL_ICMP:
	  inner_icmp0 = (icmp46_header_t *) l4_header;
	  inner_echo0 = (icmp_echo_header_t *) (inner_icmp0 + 1);

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
	  old_id0 = ((tcp_udp_header_t *) l4_header)->dst_port;
	  new_id0 = sm0.port;
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

  if (vnet_buffer (b0)->sw_if_index[VLIB_TX] == ~0)
    {
      if (sm->deterministic ||
	  0 != snat_icmp_hairpinning (sm, b0, ip0, icmp0,
				      sm->endpoint_dependent))
	vnet_buffer (b0)->sw_if_index[VLIB_TX] = sm0.fib_index;
    }

out:
  return next0;
}

static inline u32
icmp_in2out_slow_path (snat_main_t * sm,
		       vlib_buffer_t * b0,
		       ip4_header_t * ip0,
		       icmp46_header_t * icmp0,
		       u32 sw_if_index0,
		       u32 rx_fib_index0,
		       vlib_node_runtime_t * node,
		       u32 next0,
		       f64 now, u32 thread_index, snat_session_t ** p_s0)
{
  next0 = icmp_in2out (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
		       next0, thread_index, p_s0, 0);
  snat_session_t *s0 = *p_s0;
  if (PREDICT_TRUE (next0 != SNAT_IN2OUT_NEXT_DROP && s0))
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

static int
nat_in2out_sm_unknown_proto (snat_main_t * sm,
			     vlib_buffer_t * b,
			     ip4_header_t * ip, u32 rx_fib_index)
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
  if (vnet_buffer (b)->sw_if_index[VLIB_TX] == ~0)
    {
      vnet_buffer (b)->sw_if_index[VLIB_TX] = m->fib_index;
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
  u32 n_left_from, *from, *to_next;
  snat_in2out_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t *sm = &snat_main;
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

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 sw_if_index0, sw_if_index1;
	  ip4_header_t *ip0, *ip1;
	  ip_csum_t sum0, sum1;
	  u32 new_addr0, old_addr0, new_addr1, old_addr1;
	  u16 old_port0, new_port0, old_port1, new_port1;
	  udp_header_t *udp0, *udp1;
	  tcp_header_t *tcp0, *tcp1;
	  icmp46_header_t *icmp0, *icmp1;
	  snat_session_key_t key0, key1;
	  u32 rx_fib_index0, rx_fib_index1;
	  u32 proto0, proto1;
	  snat_session_t *s0 = 0, *s1 = 0;
	  clib_bihash_kv_8_8_t kv0, value0, kv1, value1;
	  u32 iph_offset0 = 0, iph_offset1 = 0;

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

	  if (is_output_feature)
	    iph_offset0 = vnet_buffer (b0)->ip.save_rewrite_length;

	  ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
				  iph_offset0);

	  udp0 = ip4_next_header (ip0);
	  tcp0 = (tcp_header_t *) udp0;
	  icmp0 = (icmp46_header_t *) udp0;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 = vec_elt (sm->ip4_main->fib_index_by_sw_if_index,
				   sw_if_index0);

	  next0 = next1 = SNAT_IN2OUT_NEXT_LOOKUP;

	  if (PREDICT_FALSE (ip0->ttl == 1))
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
		  if (nat_in2out_sm_unknown_proto
		      (sm, b0, ip0, rx_fib_index0))
		    {
		      next0 = SNAT_IN2OUT_NEXT_DROP;
		      b0->error =
			node->errors[SNAT_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
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
	      if (PREDICT_FALSE (proto0 == ~0))
		{
		  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
		  goto trace00;
		}

	      if (ip4_is_fragment (ip0))
		{
		  next0 = SNAT_IN2OUT_NEXT_REASS;
		  goto trace00;
		}

	      if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
		{
		  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
		  goto trace00;
		}
	    }

	  key0.addr = ip0->src_address;
	  key0.port = udp0->src_port;
	  key0.protocol = proto0;
	  key0.fib_index = rx_fib_index0;

	  kv0.key = key0.as_u64;

	  if (PREDICT_FALSE
	      (clib_bihash_search_8_8
	       (&sm->per_thread_data[thread_index].in2out, &kv0,
		&value0) != 0))
	    {
	      if (is_slow_path)
		{
		  if (is_output_feature)
		    {
		      if (PREDICT_FALSE (nat_not_translate_output_feature (sm,
									   ip0,
									   proto0,
									   udp0->src_port,
									   udp0->dst_port,
									   thread_index,
									   sw_if_index0)))
			goto trace00;
		    }
		  else
		    {
		      if (PREDICT_FALSE
			  (snat_not_translate
			   (sm, node, sw_if_index0, ip0, proto0,
			    rx_fib_index0, thread_index)))
			goto trace00;
		    }

		  next0 = slow_path (sm, b0, ip0, rx_fib_index0, &key0,
				     &s0, node, next0, thread_index, now);
		  if (PREDICT_FALSE (next0 == SNAT_IN2OUT_NEXT_DROP))
		    goto trace00;

		  if (PREDICT_FALSE (!s0))
		    goto trace00;
		}
	      else
		{
		  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
		  goto trace00;
		}
	    }
	  else
	    s0 =
	      pool_elt_at_index (sm->per_thread_data[thread_index].sessions,
				 value0.value);

	  b0->flags |= VNET_BUFFER_F_IS_NATED;

	  old_addr0 = ip0->src_address.as_u32;
	  ip0->src_address = s0->out2in.addr;
	  new_addr0 = ip0->src_address.as_u32;
	  if (!is_output_feature)
	    vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
				 ip4_header_t,
				 src_address /* changed member */ );
	  ip0->checksum = ip_csum_fold (sum0);

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
	      mss_clamping (sm, tcp0, &sum0);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  else
	    {
	      old_port0 = udp0->src_port;
	      udp0->src_port = s0->out2in.port;
	      udp0->checksum = 0;
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
	      snat_in2out_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->is_slow_path = is_slow_path;
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->session_index = ~0;
	      if (s0)
		t->session_index =
		  s0 - sm->per_thread_data[thread_index].sessions;
	    }

	  pkts_processed += next0 != SNAT_IN2OUT_NEXT_DROP;

	  if (is_output_feature)
	    iph_offset1 = vnet_buffer (b1)->ip.save_rewrite_length;

	  ip1 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b1) +
				  iph_offset1);

	  udp1 = ip4_next_header (ip1);
	  tcp1 = (tcp_header_t *) udp1;
	  icmp1 = (icmp46_header_t *) udp1;

	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	  rx_fib_index1 = vec_elt (sm->ip4_main->fib_index_by_sw_if_index,
				   sw_if_index1);

	  if (PREDICT_FALSE (ip1->ttl == 1))
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
		  if (nat_in2out_sm_unknown_proto
		      (sm, b1, ip1, rx_fib_index1))
		    {
		      next1 = SNAT_IN2OUT_NEXT_DROP;
		      b1->error =
			node->errors[SNAT_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
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
	      if (PREDICT_FALSE (proto1 == ~0))
		{
		  next1 = SNAT_IN2OUT_NEXT_SLOW_PATH;
		  goto trace01;
		}

	      if (ip4_is_fragment (ip1))
		{
		  next1 = SNAT_IN2OUT_NEXT_REASS;
		  goto trace01;
		}

	      if (PREDICT_FALSE (proto1 == SNAT_PROTOCOL_ICMP))
		{
		  next1 = SNAT_IN2OUT_NEXT_SLOW_PATH;
		  goto trace01;
		}
	    }

	  key1.addr = ip1->src_address;
	  key1.port = udp1->src_port;
	  key1.protocol = proto1;
	  key1.fib_index = rx_fib_index1;

	  kv1.key = key1.as_u64;

	  if (PREDICT_FALSE
	      (clib_bihash_search_8_8
	       (&sm->per_thread_data[thread_index].in2out, &kv1,
		&value1) != 0))
	    {
	      if (is_slow_path)
		{
		  if (is_output_feature)
		    {
		      if (PREDICT_FALSE (nat_not_translate_output_feature (sm,
									   ip1,
									   proto1,
									   udp1->src_port,
									   udp1->dst_port,
									   thread_index,
									   sw_if_index1)))
			goto trace01;
		    }
		  else
		    {
		      if (PREDICT_FALSE
			  (snat_not_translate
			   (sm, node, sw_if_index1, ip1, proto1,
			    rx_fib_index1, thread_index)))
			goto trace01;
		    }

		  next1 = slow_path (sm, b1, ip1, rx_fib_index1, &key1,
				     &s1, node, next1, thread_index, now);
		  if (PREDICT_FALSE (next1 == SNAT_IN2OUT_NEXT_DROP))
		    goto trace01;

		  if (PREDICT_FALSE (!s1))
		    goto trace01;
		}
	      else
		{
		  next1 = SNAT_IN2OUT_NEXT_SLOW_PATH;
		  goto trace01;
		}
	    }
	  else
	    s1 =
	      pool_elt_at_index (sm->per_thread_data[thread_index].sessions,
				 value1.value);

	  b1->flags |= VNET_BUFFER_F_IS_NATED;

	  old_addr1 = ip1->src_address.as_u32;
	  ip1->src_address = s1->out2in.addr;
	  new_addr1 = ip1->src_address.as_u32;
	  if (!is_output_feature)
	    vnet_buffer (b1)->sw_if_index[VLIB_TX] = s1->out2in.fib_index;

	  sum1 = ip1->checksum;
	  sum1 = ip_csum_update (sum1, old_addr1, new_addr1,
				 ip4_header_t,
				 src_address /* changed member */ );
	  ip1->checksum = ip_csum_fold (sum1);

	  if (PREDICT_TRUE (proto1 == SNAT_PROTOCOL_TCP))
	    {
	      old_port1 = tcp1->src_port;
	      tcp1->src_port = s1->out2in.port;
	      new_port1 = tcp1->src_port;

	      sum1 = tcp1->checksum;
	      sum1 = ip_csum_update (sum1, old_addr1, new_addr1,
				     ip4_header_t,
				     dst_address /* changed member */ );
	      sum1 = ip_csum_update (sum1, old_port1, new_port1,
				     ip4_header_t /* cheat */ ,
				     length /* changed member */ );
	      mss_clamping (sm, tcp1, &sum1);
	      tcp1->checksum = ip_csum_fold (sum1);
	    }
	  else
	    {
	      old_port1 = udp1->src_port;
	      udp1->src_port = s1->out2in.port;
	      udp1->checksum = 0;
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
	      snat_in2out_trace_t *t =
		vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->sw_if_index = sw_if_index1;
	      t->next_index = next1;
	      t->session_index = ~0;
	      if (s1)
		t->session_index =
		  s1 - sm->per_thread_data[thread_index].sessions;
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
	  u32 next0;
	  u32 sw_if_index0;
	  ip4_header_t *ip0;
	  ip_csum_t sum0;
	  u32 new_addr0, old_addr0;
	  u16 old_port0, new_port0;
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;
	  icmp46_header_t *icmp0;
	  snat_session_key_t key0;
	  u32 rx_fib_index0;
	  u32 proto0;
	  snat_session_t *s0 = 0;
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

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 = vec_elt (sm->ip4_main->fib_index_by_sw_if_index,
				   sw_if_index0);

	  if (PREDICT_FALSE (ip0->ttl == 1))
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
		  if (nat_in2out_sm_unknown_proto
		      (sm, b0, ip0, rx_fib_index0))
		    {
		      next0 = SNAT_IN2OUT_NEXT_DROP;
		      b0->error =
			node->errors[SNAT_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
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
	      if (PREDICT_FALSE (proto0 == ~0))
		{
		  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
		  goto trace0;
		}

	      if (ip4_is_fragment (ip0))
		{
		  next0 = SNAT_IN2OUT_NEXT_REASS;
		  goto trace0;
		}

	      if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
		{
		  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
		  goto trace0;
		}
	    }

	  key0.addr = ip0->src_address;
	  key0.port = udp0->src_port;
	  key0.protocol = proto0;
	  key0.fib_index = rx_fib_index0;

	  kv0.key = key0.as_u64;

	  if (clib_bihash_search_8_8
	      (&sm->per_thread_data[thread_index].in2out, &kv0, &value0))
	    {
	      if (is_slow_path)
		{
		  if (is_output_feature)
		    {
		      if (PREDICT_FALSE (nat_not_translate_output_feature (sm,
									   ip0,
									   proto0,
									   udp0->src_port,
									   udp0->dst_port,
									   thread_index,
									   sw_if_index0)))
			goto trace0;
		    }
		  else
		    {
		      if (PREDICT_FALSE
			  (snat_not_translate
			   (sm, node, sw_if_index0, ip0, proto0,
			    rx_fib_index0, thread_index)))
			goto trace0;
		    }

		  next0 = slow_path (sm, b0, ip0, rx_fib_index0, &key0,
				     &s0, node, next0, thread_index, now);

		  if (PREDICT_FALSE (next0 == SNAT_IN2OUT_NEXT_DROP))
		    goto trace0;

		  if (PREDICT_FALSE (!s0))
		    goto trace0;
		}
	      else
		{
		  next0 = SNAT_IN2OUT_NEXT_SLOW_PATH;
		  goto trace0;
		}
	    }
	  else
	    s0 =
	      pool_elt_at_index (sm->per_thread_data[thread_index].sessions,
				 value0.value);

	  b0->flags |= VNET_BUFFER_F_IS_NATED;

	  old_addr0 = ip0->src_address.as_u32;
	  ip0->src_address = s0->out2in.addr;
	  new_addr0 = ip0->src_address.as_u32;
	  if (!is_output_feature)
	    vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
				 ip4_header_t,
				 src_address /* changed member */ );
	  ip0->checksum = ip_csum_fold (sum0);

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
	      mss_clamping (sm, tcp0, &sum0);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  else
	    {
	      old_port0 = udp0->src_port;
	      udp0->src_port = s0->out2in.port;
	      udp0->checksum = 0;
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
	      snat_in2out_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->is_slow_path = is_slow_path;
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->session_index = ~0;
	      if (s0)
		t->session_index =
		  s0 - sm->per_thread_data[thread_index].sessions;
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
			  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return snat_in2out_node_fn_inline (vm, node, frame, 0 /* is_slow_path */ ,
				     0);
}

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_node, snat_in2out_fast_path_fn);

static uword
snat_in2out_output_fast_path_fn (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  return snat_in2out_node_fn_inline (vm, node, frame, 0 /* is_slow_path */ ,
				     1);
}

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_output_node,
			      snat_in2out_output_fast_path_fn);

static uword
snat_in2out_slow_path_fn (vlib_main_t * vm,
			  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return snat_in2out_node_fn_inline (vm, node, frame, 1 /* is_slow_path */ ,
				     0);
}

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_slowpath_node,
			      snat_in2out_slow_path_fn);

static uword
snat_in2out_output_slow_path_fn (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  return snat_in2out_node_fn_inline (vm, node, frame, 1 /* is_slow_path */ ,
				     1);
}

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_output_slowpath_node,
			      snat_in2out_output_slow_path_fn);

static uword
nat44_in2out_reass_node_fn (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame)
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
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;
	  icmp46_header_t *icmp0;
	  snat_session_key_t key0;
	  clib_bihash_kv_8_8_t kv0, value0;
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
	  next0 = SNAT_IN2OUT_NEXT_LOOKUP;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 =
	    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						 sw_if_index0);

	  if (PREDICT_FALSE (nat_reass_is_drop_frag (0)))
	    {
	      next0 = SNAT_IN2OUT_NEXT_DROP;
	      b0->error = node->errors[SNAT_IN2OUT_ERROR_DROP_FRAGMENT];
	      goto trace0;
	    }

	  ip0 = (ip4_header_t *) vlib_buffer_get_current (b0);
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
	      next0 = SNAT_IN2OUT_NEXT_DROP;
	      b0->error = node->errors[SNAT_IN2OUT_ERROR_MAX_REASS];
	      nat_log_notice ("maximum reassemblies exceeded");
	      goto trace0;
	    }

	  if (PREDICT_FALSE (ip4_is_first_fragment (ip0)))
	    {
	      if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
		{
		  next0 = icmp_in2out_slow_path
		    (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
		     next0, now, thread_index, &s0);

		  if (PREDICT_TRUE (next0 != SNAT_IN2OUT_NEXT_DROP))
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

	      key0.addr = ip0->src_address;
	      key0.port = udp0->src_port;
	      key0.protocol = proto0;
	      key0.fib_index = rx_fib_index0;
	      kv0.key = key0.as_u64;

	      if (clib_bihash_search_8_8
		  (&per_thread_data->in2out, &kv0, &value0))
		{
		  if (PREDICT_FALSE
		      (snat_not_translate
		       (sm, node, sw_if_index0, ip0, proto0, rx_fib_index0,
			thread_index)))
		    goto trace0;

		  next0 = slow_path (sm, b0, ip0, rx_fib_index0, &key0,
				     &s0, node, next0, thread_index, now);

		  if (PREDICT_FALSE (next0 == SNAT_IN2OUT_NEXT_DROP))
		    goto trace0;

		  if (PREDICT_FALSE (!s0))
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
	      if (PREDICT_FALSE (reass0->sess_index == (u32) ~ 0))
		{
		  if (nat_ip4_reass_add_fragment
		      (reass0, bi0, &fragments_to_drop))
		    {
		      b0->error = node->errors[SNAT_IN2OUT_ERROR_MAX_FRAG];
		      nat_log_notice
			("maximum fragments per reassembly exceeded");
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
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
				 ip4_header_t,
				 src_address /* changed member */ );
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
		  tcp0->checksum = ip_csum_fold (sum0);
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
				   s0->ext_host_port, proto0, 0);

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
		  _clib_memcpy (from, fragments_to_loopback,
				sizeof (u32) * len);
		  n_left_from = len;
		  vec_reset_length (fragments_to_loopback);
		}
	      else
		{
		  _clib_memcpy (from,
				fragments_to_loopback + (len -
							 VLIB_FRAME_SIZE),
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_in2out_reass_node) = {
  .function = nat44_in2out_reass_node_fn,
  .name = "nat44-in2out-reass",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_reass_trace,
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
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat44_in2out_reass_node,
			      nat44_in2out_reass_node_fn);

static uword
snat_in2out_fast_static_map_fn (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  snat_in2out_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t *sm = &snat_main;
  u32 stats_node_index;

  stats_node_index = snat_in2out_fast_node.index;

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

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 =
	    ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

	  if (PREDICT_FALSE (ip0->ttl == 1))
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
	      next0 = icmp_in2out (sm, b0, ip0, icmp0, sw_if_index0,
				   rx_fib_index0, node, next0, ~0, 0, 0);
	      goto trace0;
	    }

	  key0.addr = ip0->src_address;
	  key0.protocol = proto0;
	  key0.port = udp0->src_port;
	  key0.fib_index = rx_fib_index0;

	  if (snat_static_mapping_match (sm, key0, &sm0, 0, 0, 0, 0, 0, 0))
	    {
	      b0->error = node->errors[SNAT_IN2OUT_ERROR_NO_TRANSLATION];
	      next0 = SNAT_IN2OUT_NEXT_DROP;
	      goto trace0;
	    }

	  new_addr0 = sm0.addr.as_u32;
	  new_port0 = sm0.port;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sm0.fib_index;
	  old_addr0 = ip0->src_address.as_u32;
	  ip0->src_address.as_u32 = new_addr0;

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
				 ip4_header_t,
				 src_address /* changed member */ );
	  ip0->checksum = ip_csum_fold (sum0);

	  if (PREDICT_FALSE (new_port0 != udp0->dst_port))
	    {
	      if (PREDICT_TRUE (proto0 == SNAT_PROTOCOL_TCP))
		{
		  old_port0 = tcp0->src_port;
		  tcp0->src_port = new_port0;

		  sum0 = tcp0->checksum;
		  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
					 ip4_header_t,
					 dst_address /* changed member */ );
		  sum0 = ip_csum_update (sum0, old_port0, new_port0,
					 ip4_header_t /* cheat */ ,
					 length /* changed member */ );
		  mss_clamping (sm, tcp0, &sum0);
		  tcp0->checksum = ip_csum_fold (sum0);
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
	      if (PREDICT_TRUE (proto0 == SNAT_PROTOCOL_TCP))
		{
		  sum0 = tcp0->checksum;
		  sum0 = ip_csum_update (sum0, old_addr0, new_addr0,
					 ip4_header_t,
					 dst_address /* changed member */ );
		  mss_clamping (sm, tcp0, &sum0);
		  tcp0->checksum = ip_csum_fold (sum0);
		}
	    }

	  /* Hairpinning */
	  snat_hairpinning (sm, b0, ip0, udp0, tcp0, proto0, 0);

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
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


/* *INDENT-OFF* */
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
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (snat_in2out_fast_node,
			      snat_in2out_fast_static_map_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
