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

#include <nat/nat44-ed/nat44_ed.h>
#include <nat/nat44-ed/nat44_ed_inlines.h>

typedef struct
{
  ip4_address_t addr;
  u16 port;
  u32 fib_index;
  u32 session_index;
} nat_hairpin_trace_t;

#ifndef CLIB_MARCH_VARIANT
int
snat_hairpinning (vlib_main_t *vm, vlib_node_runtime_t *node, snat_main_t *sm,
		  vlib_buffer_t *b0, ip4_header_t *ip0, udp_header_t *udp0,
		  tcp_header_t *tcp0, u32 proto0, int do_trace)
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
  if (!snat_static_mapping_match (
	sm, ip0->dst_address, udp0->dst_port, sm->outside_fib_index, proto0,
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
	  (clib_net_to_host_u16 (udp0->dst_port) - 1024) / sm->port_per_thread;
      else
	ti = sm->num_workers;

      init_nat_k (&kv0, ip0->dst_address, udp0->dst_port,
		  sm->outside_fib_index, proto0);
      rv = clib_bihash_search_8_8 (&sm->per_thread_data[ti].out2in, &kv0,
				   &value0);
      if (rv)
	{
	  rv = 0;
	  goto trace;
	}

      si = value0.value;
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
  if (new_dst_addr0 == old_dst_addr0 && new_dst_port0 == old_dst_port0 &&
      vnet_buffer (b0)->sw_if_index[VLIB_TX] == old_sw_if_index)
    return 0;

  /* Destination is behind the same NAT, use internal address and port */
  if (new_dst_addr0)
    {
      old_dst_addr0 = ip0->dst_address.as_u32;
      ip0->dst_address.as_u32 = new_dst_addr0;
      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0, ip4_header_t,
			     dst_address);
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
				     ip4_header_t /* cheat */, length);
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
  if (do_trace && PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
				 (b0->flags & VLIB_BUFFER_IS_TRACED)))
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
snat_icmp_hairpinning (snat_main_t *sm, vlib_buffer_t *b0, ip4_header_t *ip0,
		       icmp46_header_t *icmp0)
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

  if (icmp_type_is_error_message (
	vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags))
    {
      ip4_header_t *inner_ip0 = 0;
      tcp_udp_header_t *l4_header = 0;

      inner_ip0 = (ip4_header_t *) ((icmp_echo_header_t *) (icmp0 + 1) + 1);
      l4_header = ip4_next_header (inner_ip0);
      u32 protocol = ip_proto_to_nat_proto (inner_ip0->protocol);

      if (protocol != NAT_PROTOCOL_TCP && protocol != NAT_PROTOCOL_UDP)
	return 1;

      init_nat_k (&kv0, ip0->dst_address, l4_header->src_port,
		  sm->outside_fib_index, protocol);
      if (clib_bihash_search_8_8 (&sm->per_thread_data[ti].out2in, &kv0,
				  &value0))
	return 1;
      si = value0.value;
      s0 = pool_elt_at_index (sm->per_thread_data[ti].sessions, si);
      new_dst_addr0 = s0->in2out.addr.as_u32;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;

      /* update inner source IP address */
      old_addr0 = inner_ip0->src_address.as_u32;
      inner_ip0->src_address.as_u32 = new_dst_addr0;
      new_addr0 = inner_ip0->src_address.as_u32;
      sum0 = icmp0->checksum;
      sum0 =
	ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t, src_address);
      icmp0->checksum = ip_csum_fold (sum0);

      /* update inner IP header checksum */
      old_checksum0 = inner_ip0->checksum;
      sum0 = inner_ip0->checksum;
      sum0 =
	ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t, src_address);
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
      if (clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv0,
				  &value0))
	{
	  icmp_echo_header_t *echo0 = (icmp_echo_header_t *) (icmp0 + 1);
	  u16 icmp_id0 = echo0->identifier;
	  init_nat_k (&kv0, ip0->dst_address, icmp_id0, sm->outside_fib_index,
		      NAT_PROTOCOL_ICMP);
	  if (sm->num_workers > 1)
	    ti =
	      (clib_net_to_host_u16 (icmp_id0) - 1024) / sm->port_per_thread;
	  else
	    ti = sm->num_workers;
	  int rv = clib_bihash_search_8_8 (&sm->per_thread_data[ti].out2in,
					   &kv0, &value0);
	  if (!rv)
	    {
	      si = value0.value;
	      s0 = pool_elt_at_index (sm->per_thread_data[ti].sessions, si);
	      new_dst_addr0 = s0->in2out.addr.as_u32;
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;
	      echo0->identifier = s0->in2out.port;
	      sum0 = icmp0->checksum;
	      sum0 = ip_csum_update (sum0, icmp_id0, s0->in2out.port,
				     icmp_echo_header_t, identifier);
	      icmp0->checksum = ip_csum_fold (sum0);
	      goto change_addr;
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
      sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0, ip4_header_t,
			     dst_address);
      ip0->checksum = ip_csum_fold (sum0);
    }
  return 0;
}
#endif

#ifndef CLIB_MARCH_VARIANT
void
nat_hairpinning_sm_unknown_proto (snat_main_t *sm, vlib_buffer_t *b,
				  ip4_header_t *ip)
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
