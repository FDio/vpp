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
 * @brief NAT44 hairpinning
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/fib/ip4_fib.h>
#include <nat/nat.h>
#include <nat/nat_inlines.h>

typedef enum
{
  SNAT_HAIRPIN_SRC_NEXT_DROP,
  SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT,
  SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT_WH,
  SNAT_HAIRPIN_SRC_NEXT_INTERFACE_OUTPUT,
  SNAT_HAIRPIN_SRC_N_NEXT,
} snat_hairpin_src_next_t;

typedef enum
{
  NAT_HAIRPIN_NEXT_LOOKUP,
  NAT_HAIRPIN_NEXT_DROP,
  NAT_HAIRPIN_N_NEXT,
} nat_hairpin_next_t;

#define foreach_nat44_hairpin_error                       \
_(PROCESSED, "NAT44 hairpinning packets processed")

typedef enum
{
#define _(sym,str) NAT44_HAIRPIN_ERROR_##sym,
  foreach_nat44_hairpin_error
#undef _
    NAT44_HAIRPIN_N_ERROR,
} nat44_hairpin_error_t;

static char *nat44_hairpin_error_strings[] = {
#define _(sym,string) string,
  foreach_nat44_hairpin_error
#undef _
};

extern vnet_feature_arc_registration_t vnet_feat_arc_ip4_local;

static_always_inline int
is_hairpinning (snat_main_t * sm, ip4_address_t * dst_addr)
{
  snat_address_t *ap;
  clib_bihash_kv_8_8_t kv, value;
  snat_session_key_t m_key;

  /* *INDENT-OFF* */
  vec_foreach (ap, sm->addresses)
    {
      if (ap->addr.as_u32 == dst_addr->as_u32)
        return 1;
    }
  /* *INDENT-ON* */

  m_key.addr.as_u32 = dst_addr->as_u32;
  m_key.fib_index = 0;
  m_key.port = 0;
  m_key.protocol = 0;
  kv.key = m_key.as_u64;
  if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    return 1;

  return 0;
}

#ifndef CLIB_MARCH_VARIANT
int
snat_hairpinning (snat_main_t * sm,
		  vlib_buffer_t * b0,
		  ip4_header_t * ip0,
		  udp_header_t * udp0,
		  tcp_header_t * tcp0, u32 proto0, int is_ed)
{
  snat_session_key_t key0, sm0;
  snat_session_t *s0;
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
  if (!snat_static_mapping_match (sm, key0, &sm0, 1, 0, 0, 0, 0, 0))
    {
      new_dst_addr0 = sm0.addr.as_u32;
      new_dst_port0 = sm0.port;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = sm0.fib_index;
    }
  /* or active session */
  else
    {
      if (sm->num_workers > 1)
	ti =
	  (clib_net_to_host_u16 (udp0->dst_port) -
	   1024) / sm->port_per_thread;
      else
	ti = sm->num_workers;

      if (is_ed)
	{
	  clib_bihash_kv_16_8_t ed_kv, ed_value;
	  make_ed_kv (&ip0->dst_address, &ip0->src_address,
		      ip0->protocol, sm->outside_fib_index, udp0->dst_port,
		      udp0->src_port, ~0ULL, &ed_kv);
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
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;
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
      if (PREDICT_TRUE (new_dst_port0 != old_dst_port0))
	{
	  if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	    {
	      tcp0->dst = new_dst_port0;
	      sum0 = tcp0->checksum;
	      sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
				     ip4_header_t, dst_address);
	      sum0 = ip_csum_update (sum0, old_dst_port0, new_dst_port0,
				     ip4_header_t /* cheat */ , length);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  else
	    {
	      udp0->dst_port = new_dst_port0;
	      udp0->checksum = 0;
	    }
	}
      else
	{
	  if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	    {
	      sum0 = tcp0->checksum;
	      sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
				     ip4_header_t, dst_address);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	}
      return 1;
    }
  return 0;
}
#endif

#ifndef CLIB_MARCH_VARIANT
u32
snat_icmp_hairpinning (snat_main_t * sm,
		       vlib_buffer_t * b0,
		       ip4_header_t * ip0, icmp46_header_t * icmp0, int is_ed)
{
  snat_session_key_t key0;
  clib_bihash_kv_8_8_t kv0, value0;
  u32 old_dst_addr0, new_dst_addr0;
  u32 old_addr0, new_addr0;
  u16 old_port0, new_port0;
  u16 old_checksum0, new_checksum0;
  u32 si, ti = 0;
  ip_csum_t sum0;
  snat_session_t *s0;
  snat_static_mapping_t *m0;

  if (icmp_type_is_error_message
      (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags))
    {
      ip4_header_t *inner_ip0 = 0;
      tcp_udp_header_t *l4_header = 0;

      inner_ip0 = (ip4_header_t *) ((icmp_echo_header_t *) (icmp0 + 1) + 1);
      l4_header = ip4_next_header (inner_ip0);
      u32 protocol = ip_proto_to_nat_proto (inner_ip0->protocol);

      if (protocol != NAT_PROTOCOL_TCP && protocol != NAT_PROTOCOL_UDP)
	return 1;

      if (is_ed)
	{
	  clib_bihash_kv_16_8_t ed_kv, ed_value;
	  make_ed_kv (&ip0->dst_address, &ip0->src_address,
		      inner_ip0->protocol, sm->outside_fib_index,
		      l4_header->src_port, l4_header->dst_port, ~0ULL,
		      &ed_kv);
	  if (clib_bihash_search_16_8
	      (&sm->per_thread_data[ti].out2in_ed, &ed_kv, &ed_value))
	    return 1;
	  si = ed_value.value;
	}
      else
	{
	  key0.addr = ip0->dst_address;
	  key0.port = l4_header->src_port;
	  key0.protocol = protocol;
	  key0.fib_index = sm->outside_fib_index;
	  kv0.key = key0.as_u64;
	  if (clib_bihash_search_8_8 (&sm->per_thread_data[ti].out2in, &kv0,
				      &value0))
	    return 1;
	  si = value0.value;
	}
      s0 = pool_elt_at_index (sm->per_thread_data[ti].sessions, si);
      new_dst_addr0 = s0->in2out.addr.as_u32;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;

      /* update inner source IP address */
      old_addr0 = inner_ip0->src_address.as_u32;
      inner_ip0->src_address.as_u32 = new_dst_addr0;
      new_addr0 = inner_ip0->src_address.as_u32;
      sum0 = icmp0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			     src_address);
      icmp0->checksum = ip_csum_fold (sum0);

      /* update inner IP header checksum */
      old_checksum0 = inner_ip0->checksum;
      sum0 = inner_ip0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			     src_address);
      inner_ip0->checksum = ip_csum_fold (sum0);
      new_checksum0 = inner_ip0->checksum;
      sum0 = icmp0->checksum;
      sum0 = ip_csum_update (sum0, old_checksum0, new_checksum0, ip4_header_t,
			     checksum);
      icmp0->checksum = ip_csum_fold (sum0);

      /* update inner source port */
      old_port0 = l4_header->src_port;
      l4_header->src_port = s0->in2out.port;
      new_port0 = l4_header->src_port;
      sum0 = icmp0->checksum;
      sum0 = ip_csum_update (sum0, old_port0, new_port0, tcp_udp_header_t,
			     src_port);
      icmp0->checksum = ip_csum_fold (sum0);
    }
  else
    {
      key0.addr = ip0->dst_address;
      key0.port = 0;
      key0.protocol = 0;
      key0.fib_index = sm->outside_fib_index;
      kv0.key = key0.as_u64;

      if (clib_bihash_search_8_8
	  (&sm->static_mapping_by_external, &kv0, &value0))
	{
	  if (!is_ed)
	    {
	      icmp_echo_header_t *echo0 = (icmp_echo_header_t *) (icmp0 + 1);
	      u16 icmp_id0 = echo0->identifier;
	      key0.addr = ip0->dst_address;
	      key0.port = icmp_id0;
	      key0.protocol = NAT_PROTOCOL_ICMP;
	      key0.fib_index = sm->outside_fib_index;
	      kv0.key = key0.as_u64;
	      if (sm->num_workers > 1)
		ti =
		  (clib_net_to_host_u16 (icmp_id0) -
		   1024) / sm->port_per_thread;
	      else
		ti = sm->num_workers;
	      int rv =
		clib_bihash_search_8_8 (&sm->per_thread_data[ti].out2in, &kv0,
					&value0);
	      if (!rv)
		{
		  si = value0.value;
		  s0 =
		    pool_elt_at_index (sm->per_thread_data[ti].sessions, si);
		  new_dst_addr0 = s0->in2out.addr.as_u32;
		  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
		    s0->in2out.fib_index;
		  echo0->identifier = s0->in2out.port;
		  sum0 = icmp0->checksum;
		  sum0 = ip_csum_update (sum0, icmp_id0, s0->in2out.port,
					 icmp_echo_header_t, identifier);
		  icmp0->checksum = ip_csum_fold (sum0);
		  goto change_addr;
		}
	    }

	  return 1;
	}

      m0 = pool_elt_at_index (sm->static_mappings, value0.value);

      new_dst_addr0 = m0->local_addr.as_u32;
      if (vnet_buffer (b0)->sw_if_index[VLIB_TX] == ~0)
	vnet_buffer (b0)->sw_if_index[VLIB_TX] = m0->fib_index;
    }
change_addr:
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
  return 0;
}
#endif

#ifndef CLIB_MARCH_VARIANT
void
nat_hairpinning_sm_unknown_proto (snat_main_t * sm,
				  vlib_buffer_t * b, ip4_header_t * ip)
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

  if (vnet_buffer (b)->sw_if_index[VLIB_TX] == ~0)
    vnet_buffer (b)->sw_if_index[VLIB_TX] = m->fib_index;
}
#endif

#ifndef CLIB_MARCH_VARIANT
void
nat44_ed_hairpinning_unknown_proto (snat_main_t * sm,
				    vlib_buffer_t * b, ip4_header_t * ip)
{
  u32 old_addr, new_addr = 0, ti = 0;
  clib_bihash_kv_8_8_t kv, value;
  clib_bihash_kv_16_8_t s_kv, s_value;
  snat_static_mapping_t *m;
  ip_csum_t sum;
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm;

  if (sm->num_workers > 1)
    ti = sm->worker_out2in_cb (b, ip, sm->outside_fib_index, 0);
  else
    ti = sm->num_workers;
  tsm = &sm->per_thread_data[ti];

  old_addr = ip->dst_address.as_u32;
  make_ed_kv (&ip->dst_address, &ip->src_address, ip->protocol,
	      sm->outside_fib_index, 0, 0, ~0ULL, &s_kv);
  if (clib_bihash_search_16_8 (&tsm->out2in_ed, &s_kv, &s_value))
    {
      make_sm_kv (&kv, &ip->dst_address, 0, 0, 0);
      if (clib_bihash_search_8_8
	  (&sm->static_mapping_by_external, &kv, &value))
	return;

      m = pool_elt_at_index (sm->static_mappings, value.value);
      if (vnet_buffer (b)->sw_if_index[VLIB_TX] == ~0)
	vnet_buffer (b)->sw_if_index[VLIB_TX] = m->fib_index;
      new_addr = ip->dst_address.as_u32 = m->local_addr.as_u32;
    }
  else
    {
      s = pool_elt_at_index (sm->per_thread_data[ti].sessions, s_value.value);
      if (vnet_buffer (b)->sw_if_index[VLIB_TX] == ~0)
	vnet_buffer (b)->sw_if_index[VLIB_TX] = s->in2out.fib_index;
      new_addr = ip->dst_address.as_u32 = s->in2out.addr.as_u32;
    }
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
  ip->checksum = ip_csum_fold (sum);
}
#endif

static inline uword
nat44_hairpinning_fn_inline (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * frame, int is_ed)
{
  u32 n_left_from, *from, *to_next, stats_node_index;
  nat_hairpin_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t *sm = &snat_main;
  vnet_feature_main_t *fm = &feature_main;
  u8 arc_index = vnet_feat_arc_ip4_local.feature_arc_index;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc_index];

  stats_node_index = is_ed ? sm->ed_hairpinning_node_index :
    sm->hairpinning_node_index;
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
	  ip4_header_t *ip0;
	  u32 proto0;
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;

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

	  proto0 = ip_proto_to_nat_proto (ip0->protocol);

	  vnet_get_config_data (&cm->config_main, &b0->current_config_index,
				&next0, 0);

	  if (snat_hairpinning (sm, b0, ip0, udp0, tcp0, proto0, is_ed))
	    next0 = NAT_HAIRPIN_NEXT_LOOKUP;

	  pkts_processed += next0 != NAT_HAIRPIN_NEXT_DROP;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
			       NAT44_HAIRPIN_ERROR_PROCESSED, pkts_processed);
  return frame->n_vectors;
}

VLIB_NODE_FN (nat44_hairpinning_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * frame)
{
  return nat44_hairpinning_fn_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_hairpinning_node) = {
  .name = "nat44-hairpinning",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat44_hairpin_error_strings),
  .error_strings = nat44_hairpin_error_strings,
  .n_next_nodes = NAT_HAIRPIN_N_NEXT,
  .next_nodes = {
    [NAT_HAIRPIN_NEXT_DROP] = "error-drop",
    [NAT_HAIRPIN_NEXT_LOOKUP] = "ip4-lookup",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (nat44_ed_hairpinning_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return nat44_hairpinning_fn_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_hairpinning_node) = {
  .name = "nat44-ed-hairpinning",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat44_hairpin_error_strings),
  .error_strings = nat44_hairpin_error_strings,
  .n_next_nodes = NAT_HAIRPIN_N_NEXT,
  .next_nodes = {
    [NAT_HAIRPIN_NEXT_DROP] = "error-drop",
    [NAT_HAIRPIN_NEXT_LOOKUP] = "ip4-lookup",
  },
};
/* *INDENT-ON* */

static inline uword
snat_hairpin_dst_fn_inline (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * frame, int is_ed)
{
  u32 n_left_from, *from, *to_next, stats_node_index;
  nat_hairpin_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t *sm = &snat_main;

  stats_node_index = is_ed ? sm->ed_hairpin_dst_node_index :
    sm->hairpin_dst_node_index;

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
	  ip4_header_t *ip0;
	  u32 proto0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  next0 = NAT_HAIRPIN_NEXT_LOOKUP;
	  ip0 = vlib_buffer_get_current (b0);

	  proto0 = ip_proto_to_nat_proto (ip0->protocol);

	  vnet_buffer (b0)->snat.flags = 0;
	  if (PREDICT_FALSE (is_hairpinning (sm, &ip0->dst_address)))
	    {
	      if (proto0 == NAT_PROTOCOL_TCP || proto0 == NAT_PROTOCOL_UDP)
		{
		  udp_header_t *udp0 = ip4_next_header (ip0);
		  tcp_header_t *tcp0 = (tcp_header_t *) udp0;

		  snat_hairpinning (sm, b0, ip0, udp0, tcp0, proto0, is_ed);
		}
	      else if (proto0 == NAT_PROTOCOL_ICMP)
		{
		  icmp46_header_t *icmp0 = ip4_next_header (ip0);

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

	  pkts_processed += next0 != NAT_HAIRPIN_NEXT_DROP;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
			       NAT44_HAIRPIN_ERROR_PROCESSED, pkts_processed);
  return frame->n_vectors;
}

VLIB_NODE_FN (snat_hairpin_dst_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return snat_hairpin_dst_fn_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (snat_hairpin_dst_node) = {
  .name = "nat44-hairpin-dst",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat44_hairpin_error_strings),
  .error_strings = nat44_hairpin_error_strings,
  .n_next_nodes = NAT_HAIRPIN_N_NEXT,
  .next_nodes = {
    [NAT_HAIRPIN_NEXT_DROP] = "error-drop",
    [NAT_HAIRPIN_NEXT_LOOKUP] = "ip4-lookup",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (nat44_ed_hairpin_dst_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return snat_hairpin_dst_fn_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_hairpin_dst_node) = {
  .name = "nat44-ed-hairpin-dst",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat44_hairpin_error_strings),
  .error_strings = nat44_hairpin_error_strings,
  .n_next_nodes = NAT_HAIRPIN_N_NEXT,
  .next_nodes = {
    [NAT_HAIRPIN_NEXT_DROP] = "error-drop",
    [NAT_HAIRPIN_NEXT_LOOKUP] = "ip4-lookup",
  },
};
/* *INDENT-ON* */

static inline uword
snat_hairpin_src_fn_inline (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * frame, int is_ed)
{
  u32 n_left_from, *from, *to_next, stats_node_index;
  snat_hairpin_src_next_t next_index;
  u32 pkts_processed = 0;
  snat_main_t *sm = &snat_main;

  stats_node_index = is_ed ? sm->ed_hairpin_src_node_index :
    sm->hairpin_src_node_index;

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
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  vnet_feature_next (&next0, b0);

          /* *INDENT-OFF* */
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
          /* *INDENT-ON* */

	  pkts_processed += next0 != SNAT_HAIRPIN_SRC_NEXT_DROP;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
			       NAT44_HAIRPIN_ERROR_PROCESSED, pkts_processed);
  return frame->n_vectors;
}

VLIB_NODE_FN (snat_hairpin_src_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return snat_hairpin_src_fn_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (snat_hairpin_src_node) = {
  .name = "nat44-hairpin-src",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat44_hairpin_error_strings),
  .error_strings = nat44_hairpin_error_strings,
  .n_next_nodes = SNAT_HAIRPIN_SRC_N_NEXT,
  .next_nodes = {
     [SNAT_HAIRPIN_SRC_NEXT_DROP] = "error-drop",
     [SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT] = "nat44-in2out-output",
     [SNAT_HAIRPIN_SRC_NEXT_INTERFACE_OUTPUT] = "interface-output",
     [SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT_WH] = "nat44-in2out-output-worker-handoff",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (nat44_ed_hairpin_src_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return snat_hairpin_src_fn_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_hairpin_src_node) = {
  .name = "nat44-ed-hairpin-src",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat44_hairpin_error_strings),
  .error_strings = nat44_hairpin_error_strings,
  .n_next_nodes = SNAT_HAIRPIN_SRC_N_NEXT,
  .next_nodes = {
     [SNAT_HAIRPIN_SRC_NEXT_DROP] = "error-drop",
     [SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT] = "nat44-ed-in2out-output",
     [SNAT_HAIRPIN_SRC_NEXT_INTERFACE_OUTPUT] = "interface-output",
     [SNAT_HAIRPIN_SRC_NEXT_SNAT_IN2OUT_WH] = "nat44-in2out-output-worker-handoff",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
