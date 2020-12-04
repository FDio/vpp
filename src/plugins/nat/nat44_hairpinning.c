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

typedef struct
{
  ip4_address_t addr;
  u16 port;
  u32 fib_index;
  u32 session_index;
} nat_hairpin_trace_t;

static u8 *
format_nat_hairpin_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat_hairpin_trace_t *t = va_arg (*args, nat_hairpin_trace_t *);

  s =
    format (s, "new dst addr %U port %u fib-index %u", format_ip4_address,
	    &t->addr, clib_net_to_host_u16 (t->port), t->fib_index);
  if (~0 == t->session_index)
    {
      s = format (s, " is-static-mapping");
    }
  else
    {
      s = format (s, " session-index %u", t->session_index);
    }

  return s;
}

extern vnet_feature_arc_registration_t vnet_feat_arc_ip4_local;

static_always_inline int
is_hairpinning (snat_main_t * sm, ip4_address_t * dst_addr)
{
  snat_address_t *ap;
  clib_bihash_kv_8_8_t kv, value;

  /* *INDENT-OFF* */
  vec_foreach (ap, sm->addresses)
    {
      if (ap->addr.as_u32 == dst_addr->as_u32)
        return 1;
    }
  /* *INDENT-ON* */

  init_nat_k (&kv, *dst_addr, 0, 0, 0);
  if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    return 1;

  return 0;
}

#ifndef CLIB_MARCH_VARIANT
int
snat_hairpinning (vlib_main_t * vm, vlib_node_runtime_t * node,
		  snat_main_t * sm, vlib_buffer_t * b0, ip4_header_t * ip0,
		  udp_header_t * udp0, tcp_header_t * tcp0, u32 proto0,
		  int is_ed, int do_trace)
{
  snat_session_t *s0 = NULL;
  clib_bihash_kv_8_8_t kv0, value0;
  ip_csum_t sum0;
  u32 new_dst_addr0 = 0, old_dst_addr0, ti = 0, si = ~0;
  u16 new_dst_port0 = ~0, old_dst_port0;
  int rv;
  ip4_address_t sm0_addr;
  u16 sm0_port;
  u32 sm0_fib_index;
  u32 old_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
  /* Check if destination is static mappings */
  if (!snat_static_mapping_match
      (sm, ip0->dst_address, udp0->dst_port, sm->outside_fib_index, proto0,
       &sm0_addr, &sm0_port, &sm0_fib_index, 1, 0, 0, 0, 0, 0, 0))
    {
      new_dst_addr0 = sm0_addr.as_u32;
      new_dst_port0 = sm0_port;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = sm0_fib_index;
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
	  init_ed_k (&ed_kv, ip0->dst_address, udp0->dst_port,
		     ip0->src_address, udp0->src_port, sm->outside_fib_index,
		     ip0->protocol);
	  rv = clib_bihash_search_16_8 (&sm->out2in_ed, &ed_kv, &ed_value);
	  ASSERT (ti == ed_value_get_thread_index (&ed_value));
	  si = ed_value_get_session_index (&ed_value);
	}
      else
	{

	  init_nat_k (&kv0, ip0->dst_address, udp0->dst_port,
		      sm->outside_fib_index, proto0);
	  rv =
	    clib_bihash_search_8_8 (&sm->per_thread_data[ti].out2in, &kv0,
				    &value0);
	  si = value0.value;
	}
      if (rv)
	{
	  rv = 0;
	  goto trace;
	}

      s0 = pool_elt_at_index (sm->per_thread_data[ti].sessions, si);
      new_dst_addr0 = s0->in2out.addr.as_u32;
      new_dst_port0 = s0->in2out.port;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;
    }

  /* Check if anything has changed and if not, then return 0. This
     helps avoid infinite loop, repeating the three nodes
     nat44-hairpinning-->ip4-lookup-->ip4-local, in case nothing has
     changed. */
  old_dst_addr0 = ip0->dst_address.as_u32;
  old_dst_port0 = tcp0->dst;
  if(new_dst_addr0 == old_dst_addr0
     && new_dst_port0 == old_dst_port0
     && vnet_buffer (b0)->sw_if_index[VLIB_TX] == old_sw_if_index)
    return 0;

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
      rv = 1;
      goto trace;
    }
  rv = 0;
trace:
  if (do_trace && PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
				 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
    {
      nat_hairpin_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
      t->addr.as_u32 = new_dst_addr0;
      t->port = new_dst_port0;
      t->fib_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      if (s0)
	{
	  t->session_index = si;
	}
      else
	{
	  t->session_index = ~0;
	}
    }
  return rv;
}
#endif

#ifndef CLIB_MARCH_VARIANT
u32
snat_icmp_hairpinning (snat_main_t * sm,
		       vlib_buffer_t * b0,
		       ip4_header_t * ip0, icmp46_header_t * icmp0, int is_ed)
{
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
	  init_ed_k (&ed_kv, ip0->dst_address, l4_header->src_port,
		     ip0->src_address, l4_header->dst_port,
		     sm->outside_fib_index, inner_ip0->protocol);
	  if (clib_bihash_search_16_8 (&sm->out2in_ed, &ed_kv, &ed_value))
	    return 1;
	  ASSERT (ti == ed_value_get_thread_index (&ed_value));
	  si = ed_value_get_session_index (&ed_value);
	}
      else
	{
	  init_nat_k (&kv0, ip0->dst_address, l4_header->src_port,
		      sm->outside_fib_index, protocol);
	  if (clib_bihash_search_8_8
	      (&sm->per_thread_data[ti].out2in, &kv0, &value0))
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
      init_nat_k (&kv0, ip0->dst_address, 0, sm->outside_fib_index, 0);
      if (clib_bihash_search_8_8
	  (&sm->static_mapping_by_external, &kv0, &value0))
	{
	  if (!is_ed)
	    {
	      icmp_echo_header_t *echo0 = (icmp_echo_header_t *) (icmp0 + 1);
	      u16 icmp_id0 = echo0->identifier;
	      init_nat_k (&kv0, ip0->dst_address, icmp_id0,
			  sm->outside_fib_index, NAT_PROTOCOL_ICMP);
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

  init_nat_k (&kv, ip->dst_address, 0, 0, 0);
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

  if (sm->num_workers > 1)
    ti = sm->worker_out2in_cb (b, ip, sm->outside_fib_index, 0);
  else
    ti = sm->num_workers;

  old_addr = ip->dst_address.as_u32;
  init_ed_k (&s_kv, ip->dst_address, 0, ip->src_address, 0,
	     sm->outside_fib_index, ip->protocol);
  if (clib_bihash_search_16_8 (&sm->out2in_ed, &s_kv, &s_value))
    {
      init_nat_k (&kv, ip->dst_address, 0, 0, 0);
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
      ASSERT (ti == ed_value_get_thread_index (&s_value));
      s =
	pool_elt_at_index (sm->per_thread_data[ti].sessions,
			   ed_value_get_session_index (&s_value));
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
  u32 n_left_from, *from, *to_next;
  nat_hairpin_next_t next_index;
  snat_main_t *sm = &snat_main;
  vnet_feature_main_t *fm = &feature_main;
  u8 arc_index = vnet_feat_arc_ip4_local.feature_arc_index;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc_index];

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
	  u32 sw_if_index0;

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
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  proto0 = ip_proto_to_nat_proto (ip0->protocol);

	  vnet_get_config_data (&cm->config_main, &b0->current_config_index,
				&next0, 0);

	  if (snat_hairpinning
	      (vm, node, sm, b0, ip0, udp0, tcp0, proto0, is_ed,
	       1 /* do_trace */ ))
	    next0 = NAT_HAIRPIN_NEXT_LOOKUP;

	  if (next0 != NAT_HAIRPIN_NEXT_DROP)
	    {
	      vlib_increment_simple_counter (&sm->counters.hairpinning,
					     vm->thread_index, sw_if_index0,
					     1);
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
  .format_trace = format_nat_hairpin_trace,
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
  .format_trace = format_nat_hairpin_trace,
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
  u32 n_left_from, *from, *to_next;
  nat_hairpin_next_t next_index;
  snat_main_t *sm = &snat_main;

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
	  u32 sw_if_index0;

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
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  proto0 = ip_proto_to_nat_proto (ip0->protocol);

	  vnet_buffer (b0)->snat.flags = 0;
	  if (PREDICT_FALSE (is_hairpinning (sm, &ip0->dst_address)))
	    {
	      if (proto0 == NAT_PROTOCOL_TCP || proto0 == NAT_PROTOCOL_UDP)
		{
		  udp_header_t *udp0 = ip4_next_header (ip0);
		  tcp_header_t *tcp0 = (tcp_header_t *) udp0;

		  snat_hairpinning (vm, node, sm, b0, ip0, udp0, tcp0, proto0,
				    is_ed, 1 /* do_trace */ );
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


	  if (next0 != NAT_HAIRPIN_NEXT_DROP)
	    {
	      vlib_increment_simple_counter (&sm->counters.hairpinning,
					     vm->thread_index, sw_if_index0,
					     1);
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
  .format_trace = format_nat_hairpin_trace,
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
  .format_trace = format_nat_hairpin_trace,
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
  u32 n_left_from, *from, *to_next;
  snat_hairpin_src_next_t next_index;
  snat_main_t *sm = &snat_main;

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

	  if (next0 != SNAT_HAIRPIN_SRC_NEXT_DROP)
	    {
	      vlib_increment_simple_counter (&sm->counters.hairpinning,
					     vm->thread_index, sw_if_index0,
					     1);
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
