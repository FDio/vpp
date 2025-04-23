/*
 * l2/l2_arp_term.c: IP v4 ARP L2 BD termination
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#include <vlibmemory/api.h>

#include <vnet/l2/l2_arp_term.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/icmp6.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip.api_enum.h>
#include <vnet/ip/format.h>
#include <vnet/ip-neighbor/ip_neighbor_types.h>
#include <vnet/ethernet/arp_packet.h>

static const u8 vrrp_prefix[] = { 0x00, 0x00, 0x5E, 0x00, 0x01 };

l2_arp_term_main_t l2_arp_term_main;

/*
 * ARP/ND Termination in a L2 Bridge Domain based on IP4/IP6 to MAC
 * hash tables mac_by_ip4 and mac_by_ip6 for each BD.
 */
typedef enum
{
  ARP_TERM_NEXT_L2_OUTPUT,
  ARP_TERM_NEXT_DROP,
  ARP_TERM_N_NEXT,
} arp_term_next_t;

u32 arp_term_next_node_index[32];

typedef struct
{
  u8 packet_data[64];
} ethernet_arp_input_trace_t;

#define foreach_ethernet_arp_error					\
  _ (replies_sent, "ARP replies sent")					\
  _ (l2_type_not_ethernet, "L2 type not ethernet")			\
  _ (l3_type_not_ip4, "L3 type not IP4")				\
  _ (l3_src_address_not_local, "IP4 source address not local to subnet") \
  _ (l3_dst_address_not_local, "IP4 destination address not local to subnet") \
  _ (l3_dst_address_unset, "IP4 destination address is unset")          \
  _ (l3_src_address_is_local, "IP4 source address matches local interface") \
  _ (l3_src_address_learned, "ARP request IP4 source address learned")  \
  _ (replies_received, "ARP replies received")				\
  _ (opcode_not_request, "ARP opcode not request")                      \
  _ (proxy_arp_replies_sent, "Proxy ARP replies sent")			\
  _ (l2_address_mismatch, "ARP hw addr does not match L2 frame src addr") \
  _ (gratuitous_arp, "ARP probe or announcement dropped") \
  _ (interface_no_table, "Interface is not mapped to an IP table") \
  _ (interface_not_ip_enabled, "Interface is not IP enabled") \
  _ (unnumbered_mismatch, "RX interface is unnumbered to different subnet") \

typedef enum
{
#define _(sym,string) ETHERNET_ARP_ERROR_##sym,
  foreach_ethernet_arp_error
#undef _
    ETHERNET_ARP_N_ERROR,
} ethernet_arp_reply_error_t;

static char *ethernet_arp_error_strings[] = {
#define _(sym,string) string,
  foreach_ethernet_arp_error
#undef _
};

static u8 *
format_arp_term_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ethernet_arp_input_trace_t *t = va_arg (*va, ethernet_arp_input_trace_t *);

  /* arp-term trace data saved is either arp or ip6/icmp6 packet:
     - for arp, the 1st 16-bit field is hw type of value of 0x0001.
     - for ip6, the first nibble has value of 6. */
  s = format (s, "%U", t->packet_data[0] == 0 ?
	      format_ethernet_arp_header : format_ip6_header,
	      t->packet_data, sizeof (t->packet_data));

  return s;
}

void
l2_arp_term_set_publisher_node (bool on)
{
  l2_arp_term_main_t *l2am = &l2_arp_term_main;

  l2am->publish = on;
}

static int
l2_arp_term_publish (l2_arp_term_publish_event_t * ctx)
{
  l2_arp_term_main_t *l2am = &l2_arp_term_main;

  vec_add1 (l2am->publish_events, *ctx);

  vlib_process_signal_event (vlib_get_main (),
			     l2_arp_term_process_node.index,
			     L2_ARP_TERM_EVENT_PUBLISH, 0);

  return 0;
}

static inline void
l2_arp_term_publish_v4_dp (u32 sw_if_index,
			   const ethernet_arp_ip4_over_ethernet_address_t * a)
{
  l2_arp_term_main_t *l2am = &l2_arp_term_main;

  if (!l2am->publish)
    return;

  l2_arp_term_publish_event_t args = {
    .sw_if_index = sw_if_index,
    .type = IP46_TYPE_IP4,
    .ip.ip4 = a->ip4,
    .mac = a->mac,
  };

  vl_api_rpc_call_main_thread (l2_arp_term_publish, (u8 *) & args,
			       sizeof (args));
}

static inline void
l2_arp_term_publish_v6_dp (u32 sw_if_index,
			   const ip6_address_t * addr,
			   const mac_address_t * mac)
{
  l2_arp_term_main_t *l2am = &l2_arp_term_main;

  if (!l2am->publish)
    return;

  l2_arp_term_publish_event_t args = {
    .sw_if_index = sw_if_index,
    .type = IP46_TYPE_IP6,
    .ip.ip6 = *addr,
    .mac = *mac,
  };

  vl_api_rpc_call_main_thread (l2_arp_term_publish, (u8 *) & args,
			       sizeof (args));
}

static inline int
vnet_ip6_nd_term (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_buffer_t * p0,
		  ethernet_header_t * eth,
		  ip6_header_t * ip, u32 sw_if_index, u16 bd_index)
{
  icmp6_neighbor_solicitation_or_advertisement_header_t *ndh;
  mac_address_t mac;

  mac_address_from_bytes (&mac, eth->src_address);
  ndh = ip6_next_header (ip);
  if (ndh->icmp.type != ICMP6_neighbor_solicitation &&
      ndh->icmp.type != ICMP6_neighbor_advertisement)
    return 0;

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
		     (p0->flags & VLIB_BUFFER_IS_TRACED)))
    {
      u8 *t0 = vlib_add_trace (vm, node, p0,
			       sizeof (icmp6_input_trace_t));
      clib_memcpy (t0, ip, sizeof (icmp6_input_trace_t));
    }

  /* Check if anyone want ND events for L2 BDs */
  if (PREDICT_FALSE (!ip6_address_is_link_local_unicast (&ip->src_address)))
    {
      l2_arp_term_publish_v6_dp (sw_if_index, &ip->src_address, &mac);
    }

  /* Check if MAC entry exsist for solicited target IP */
  if (ndh->icmp.type == ICMP6_neighbor_solicitation)
    {
      icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *opt;
      l2_bridge_domain_t *bd_config;
      u8 *macp;

      opt = (void *) (ndh + 1);
      if ((opt->header.type !=
	   ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address) ||
	  (opt->header.n_data_u64s != 1))
	return 0;		/* source link layer address option not present */

      vlib_increment_simple_counter(
          &ip_neighbor_counters[AF_IP6].ipnc[VLIB_RX][IP_NEIGHBOR_CTR_REQUEST],
          vm->thread_index, sw_if_index, 1);

      bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index);
      macp =
	(u8 *) hash_get_mem (bd_config->mac_by_ip6, &ndh->target_address);
      if (macp)
	{			/* found ip-mac entry, generate eighbor advertisement response */
	  int bogus_length;
	  vlib_node_runtime_t *error_node =
	    vlib_node_get_runtime (vm, ip6_icmp_input_node.index);
	  ip->dst_address = ip->src_address;
	  ip->src_address = ndh->target_address;
	  ip->hop_limit = 255;
	  opt->header.type =
	    ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address;
	  clib_memcpy (opt->ethernet_address, macp, 6);
	  ndh->icmp.type = ICMP6_neighbor_advertisement;
	  ndh->advertisement_flags = clib_host_to_net_u32
	    (ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED |
	     ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE);
	  ndh->icmp.checksum = 0;
	  ndh->icmp.checksum =
	    ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip, &bogus_length);
	  clib_memcpy (eth->dst_address, eth->src_address, 6);
	  clib_memcpy (eth->src_address, macp, 6);
	  vlib_increment_simple_counter (
	      &ip_neighbor_counters[AF_IP6].ipnc[VLIB_TX][IP_NEIGHBOR_CTR_REPLY],
	      vm->thread_index, sw_if_index, 1);
	  vlib_error_count (vm, error_node->node_index,
			    ICMP6_ERROR_NEIGHBOR_ADVERTISEMENTS_TX, 1);
	  return 1;
	}
    }

  return 0;

}

static uword
arp_term_l2bd (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  l2input_main_t *l2im = &l2input_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 n_replies_sent = 0;
  u16 last_bd_index = ~0;
  l2_bridge_domain_t *last_bd_config = 0;
  l2_input_config_t *cfg0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ethernet_header_t *eth0;
	  ethernet_arp_header_t *arp0;
	  ip6_header_t *iph0;
	  u8 *l3h0;
	  u32 pi0, error0, next0, sw_if_index0;
	  u16 ethertype0;
	  u16 bd_index0;
	  u32 ip0;
	  u8 *macp0;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  // Terminate only local (SHG == 0) ARP
	  if (vnet_buffer (p0)->l2.shg != 0)
	    goto next_l2_feature;

	  eth0 = vlib_buffer_get_current (p0);
	  l3h0 = (u8 *) eth0 + vnet_buffer (p0)->l2.l2_len;
	  ethertype0 = clib_net_to_host_u16 (*(u16 *) (l3h0 - 2));
	  arp0 = (ethernet_arp_header_t *) l3h0;

	  if (p0->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED)
	    goto next_l2_feature;

	  if (ethertype0 != ETHERNET_TYPE_ARP)
	    goto check_ip6_nd;

	  if ((arp0->opcode !=
	       clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request)) &&
	      (arp0->opcode !=
	       clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply)))
	    goto check_ip6_nd;

	  /* Must be ARP request/reply packet here */
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (p0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      u8 *t0 = vlib_add_trace (vm, node, p0,
				       sizeof (ethernet_arp_input_trace_t));
	      clib_memcpy_fast (t0, l3h0,
				sizeof (ethernet_arp_input_trace_t));
	    }

	  error0 = 0;
	  error0 =
	    (arp0->l2_type !=
	     clib_net_to_host_u16 (ETHERNET_ARP_HARDWARE_TYPE_ethernet)
	     ? ETHERNET_ARP_ERROR_l2_type_not_ethernet : error0);
	  error0 =
	    (arp0->l3_type !=
	     clib_net_to_host_u16 (ETHERNET_TYPE_IP4) ?
	     ETHERNET_ARP_ERROR_l3_type_not_ip4 : error0);

	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  if (error0)
	    goto drop;

	  if (arp0->opcode == clib_host_to_net_u16(ETHERNET_ARP_OPCODE_request))
	    {
	      vlib_increment_simple_counter(
	          &ip_neighbor_counters[AF_IP4].ipnc[VLIB_RX][IP_NEIGHBOR_CTR_REQUEST],
	          vm->thread_index, sw_if_index0, 1);
	    }

	  /* Trash ARP packets whose ARP-level source addresses do not
	     match, or if requester address is mcast */
	  if (PREDICT_FALSE
	      (!ethernet_mac_address_equal (eth0->src_address,
					    arp0->ip4_over_ethernet[0].
					    mac.bytes))
	      || ethernet_address_cast (arp0->ip4_over_ethernet[0].mac.bytes))
	    {
	      /* VRRP virtual MAC may be different to SMAC in ARP reply */
	      if (clib_memcmp (arp0->ip4_over_ethernet[0].mac.bytes,
			       vrrp_prefix, sizeof (vrrp_prefix)) != 0)
		{
		  error0 = ETHERNET_ARP_ERROR_l2_address_mismatch;
		  goto drop;
		}
	    }
	  if (PREDICT_FALSE
	      (ip4_address_is_multicast (&arp0->ip4_over_ethernet[0].ip4)))
	    {
	      error0 = ETHERNET_ARP_ERROR_l3_src_address_not_local;
	      goto drop;
	    }

	  /* Check if anyone want ARP request events for L2 BDs */
	  l2_arp_term_publish_v4_dp (sw_if_index0,
				     &arp0->ip4_over_ethernet[0]);

	  /* lookup BD mac_by_ip4 hash table for MAC entry */
	  ip0 = arp0->ip4_over_ethernet[1].ip4.as_u32;
	  bd_index0 = vnet_buffer (p0)->l2.bd_index;
	  if (PREDICT_FALSE ((bd_index0 != last_bd_index)
			     || (last_bd_index == (u16) ~ 0)))
	    {
	      last_bd_index = bd_index0;
	      last_bd_config = vec_elt_at_index (l2im->bd_configs, bd_index0);
	    }
	  macp0 = (u8 *) hash_get (last_bd_config->mac_by_ip4, ip0);

	  if (PREDICT_FALSE (!macp0))
	    goto next_l2_feature;	/* MAC not found */
	  if (PREDICT_FALSE (arp0->ip4_over_ethernet[0].ip4.as_u32 ==
			     arp0->ip4_over_ethernet[1].ip4.as_u32))
	    goto next_l2_feature;	/* GARP */

	  /* MAC found, send ARP reply -
	     Convert ARP request packet to ARP reply */
	  arp0->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply);
	  arp0->ip4_over_ethernet[1] = arp0->ip4_over_ethernet[0];
	  arp0->ip4_over_ethernet[0].ip4.as_u32 = ip0;
	  mac_address_from_bytes (&arp0->ip4_over_ethernet[0].mac, macp0);
	  clib_memcpy_fast (eth0->dst_address, eth0->src_address, 6);
	  clib_memcpy_fast (eth0->src_address, macp0, 6);
	  vlib_increment_simple_counter(
		&ip_neighbor_counters[AF_IP4].ipnc[VLIB_TX][IP_NEIGHBOR_CTR_REPLY],
		vm->thread_index, sw_if_index0, 1);
	  n_replies_sent += 1;

	output_response:
	  /* For BVI, need to use l2-fwd node to send ARP reply as
	     l2-output node cannot output packet to BVI properly */
	  cfg0 = vec_elt_at_index (l2im->configs, sw_if_index0);
	  if (PREDICT_FALSE (l2_input_is_bvi (cfg0)))
	    {
	      vnet_buffer (p0)->l2.feature_bitmap |= L2INPUT_FEAT_FWD;
	      vnet_buffer (p0)->sw_if_index[VLIB_RX] = 0;
	      goto next_l2_feature;
	    }

	  /* Send ARP/ND reply back out input interface through l2-output */
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;
	  next0 = ARP_TERM_NEXT_L2_OUTPUT;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	  continue;

	check_ip6_nd:
	  /* IP6 ND event notification or solicitation handling to generate
	     local response instead of flooding */
	  iph0 = (ip6_header_t *) l3h0;
	  if (PREDICT_FALSE (ethertype0 == ETHERNET_TYPE_IP6 &&
			     iph0->protocol == IP_PROTOCOL_ICMP6 &&
			     !ip6_address_is_unspecified
			     (&iph0->src_address)))
	    {
	      sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	      if (vnet_ip6_nd_term
		  (vm, node, p0, eth0, iph0, sw_if_index0,
		   vnet_buffer (p0)->l2.bd_index))
		goto output_response;
	    }

	next_l2_feature:
	  {
	    next0 = vnet_l2_feature_next (p0, arp_term_next_node_index,
					  L2INPUT_FEAT_ARP_TERM);
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					     to_next, n_left_to_next,
					     pi0, next0);
	    continue;
	  }

	drop:
	  if (0 == arp0->ip4_over_ethernet[0].ip4.as_u32 ||
	      (arp0->ip4_over_ethernet[0].ip4.as_u32 ==
	       arp0->ip4_over_ethernet[1].ip4.as_u32))
	    {
	      error0 = ETHERNET_ARP_ERROR_gratuitous_arp;
	    }
	  next0 = ARP_TERM_NEXT_DROP;
	  p0->error = node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_error_count (vm, node->node_index,
		    ETHERNET_ARP_ERROR_replies_sent, n_replies_sent);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (arp_term_l2bd_node, static) = {
  .function = arp_term_l2bd,
  .name = "arp-term-l2bd",
  .vector_size = sizeof (u32),
  .n_errors = ETHERNET_ARP_N_ERROR,
  .error_strings = ethernet_arp_error_strings,
  .n_next_nodes = ARP_TERM_N_NEXT,
  .next_nodes = {
    [ARP_TERM_NEXT_L2_OUTPUT] = "l2-output",
    [ARP_TERM_NEXT_DROP] = "error-drop",
  },
  .format_buffer = format_ethernet_arp_header,
  .format_trace = format_arp_term_input_trace,
};

clib_error_t *
arp_term_init (vlib_main_t * vm)
{
  // Initialize the feature next-node indexes
  feat_bitmap_init_next_nodes (vm,
			       arp_term_l2bd_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       arp_term_next_node_index);
  return 0;
}

VLIB_INIT_FUNCTION (arp_term_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
