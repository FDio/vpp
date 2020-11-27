/*
 * ip/ip6_neighbor.c: IP6 neighbor handling
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

#include <vnet/ip6-nd/ip6_nd.h>

#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip-neighbor/ip_neighbor_dp.h>

#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ip/ip6_ll_table.h>

/**
 * @file
 * @brief IPv6 Neighbor Adjacency and Neighbor Discovery.
 *
 * The files contains the API and CLI code for managing IPv6 neighbor
 * adjacency tables and neighbor discovery logic.
 */

#define DEF_MAX_RADV_INTERVAL 200
#define DEF_MIN_RADV_INTERVAL .75 * DEF_MAX_RADV_INTERVAL

typedef struct ip6_nd_t_
{
  /* local information */
  u32 sw_if_index;

  /* stats */
  u32 n_solicitations_rcvd;
  u32 n_solicitations_dropped;
} ip6_nd_t;

static ip6_link_delegate_id_t ip6_nd_delegate_id;
static ip6_nd_t *ip6_nd_pool;


typedef enum
{
  ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP,
  ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY,
  ICMP6_NEIGHBOR_SOLICITATION_N_NEXT,
} icmp6_neighbor_solicitation_or_advertisement_next_t;

static_always_inline uword
icmp6_neighbor_solicitation_or_advertisement (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * frame,
					      uword is_solicitation)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_main_t *im = &ip6_main;
  uword n_packets = frame->n_vectors;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next_index, n_advertisements_sent;
  icmp6_neighbor_discovery_option_type_t option_type;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_icmp_input_node.index);
  int bogus_length;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp6_input_trace_t));

  option_type =
    (is_solicitation
     ? ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address
     : ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address);
  n_advertisements_sent = 0;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  icmp6_neighbor_solicitation_or_advertisement_header_t *h0;
	  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *o0;
	  u32 bi0, options_len0, sw_if_index0, next0, error0;
	  u32 ip6_sadd_link_local, ip6_sadd_unspecified;
	  int is_rewrite0;
	  u32 ni0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  h0 = ip6_next_header (ip0);
	  options_len0 =
	    clib_net_to_host_u16 (ip0->payload_length) - sizeof (h0[0]);

	  error0 = ICMP6_ERROR_NONE;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	  ip6_sadd_link_local =
	    ip6_address_is_link_local_unicast (&ip0->src_address);
	  ip6_sadd_unspecified =
	    ip6_address_is_unspecified (&ip0->src_address);

	  /* Check that source address is unspecified, link-local or else on-link. */
	  if (!ip6_sadd_unspecified && !ip6_sadd_link_local)
	    {
	      u32 src_adj_index0 = ip6_src_lookup_for_packet (im, p0, ip0);

	      if (ADJ_INDEX_INVALID != src_adj_index0)
		{
		  ip_adjacency_t *adj0 = adj_get (src_adj_index0);

		  /* Allow all realistic-looking rewrite adjacencies to pass */
		  ni0 = adj0->lookup_next_index;
		  is_rewrite0 = (ni0 >= IP_LOOKUP_NEXT_ARP) &&
		    (ni0 < IP6_LOOKUP_N_NEXT);
		  vnet_buffer (p0)->ip.adj_index = src_adj_index0;

		  error0 = ((adj0->rewrite_header.sw_if_index != sw_if_index0
			     || !is_rewrite0)
			    ?
			    ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_NOT_ON_LINK
			    : error0);
		}
	      else
		{
		  error0 =
		    ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_NOT_ON_LINK;
		}
	    }

	  o0 = (void *) (h0 + 1);
	  o0 = ((options_len0 == 8 && o0->header.type == option_type
		 && o0->header.n_data_u64s == 1) ? o0 : 0);

	  /* If src address unspecified or link local, donot learn neighbor MAC */
	  if (PREDICT_TRUE (error0 == ICMP6_ERROR_NONE && o0 != 0 &&
			    !ip6_sadd_unspecified))
	    {
              /* *INDENT-OFF* */
	      ip_neighbor_learn_t learn = {
		.sw_if_index = sw_if_index0,
		.ip = {
                  .version = AF_IP6,
                  .ip.ip6 = (is_solicitation ?
                             ip0->src_address :
                             h0->target_address),
                }
	      };
              /* *INDENT-ON* */
	      memcpy (&learn.mac, o0->ethernet_address, sizeof (learn.mac));
	      ip_neighbor_learn_dp (&learn);
	    }

	  if (is_solicitation && error0 == ICMP6_ERROR_NONE)
	    {
	      /* Check that target address is local to this router. */
	      fib_node_index_t fei;
	      u32 fib_index;

	      fib_index =
		ip6_fib_table_get_index_for_sw_if_index (sw_if_index0);

	      if (~0 == fib_index)
		{
		  error0 = ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_UNKNOWN;
		}
	      else
		{
		  if (ip6_address_is_link_local_unicast (&h0->target_address))
		    {
		      fei = ip6_fib_table_lookup_exact_match
			(ip6_ll_fib_get (sw_if_index0),
			 &h0->target_address, 128);
		    }
		  else
		    {
		      fei = ip6_fib_table_lookup_exact_match (fib_index,
							      &h0->target_address,
							      128);
		    }

		  if (FIB_NODE_INDEX_INVALID == fei)
		    {
		      /* The target address is not in the FIB */
		      error0 =
			ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_UNKNOWN;
		    }
		  else
		    {
		      if (FIB_ENTRY_FLAG_LOCAL &
			  fib_entry_get_flags_for_source (fei,
							  FIB_SOURCE_INTERFACE))
			{
			  /* It's an address that belongs to one of our interfaces
			   * that's good. */
			}
		      else
			if (fib_entry_is_sourced
			    (fei, FIB_SOURCE_IP6_ND_PROXY) ||
			    fib_entry_is_sourced (fei, FIB_SOURCE_IP6_ND))
			{
			  /* The address was added by IPv6 Proxy ND config.
			   * We should only respond to these if the NS arrived on
			   * the link that has a matching covering prefix */
			}
		      else
			{
			  error0 =
			    ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_UNKNOWN;
			}
		    }
		}
	    }

	  if (is_solicitation)
	    next0 = (error0 != ICMP6_ERROR_NONE
		     ? ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP
		     : ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY);
	  else
	    {
	      next0 = 0;
	      error0 = error0 == ICMP6_ERROR_NONE ?
		ICMP6_ERROR_NEIGHBOR_ADVERTISEMENTS_RX : error0;
	    }

	  if (is_solicitation && error0 == ICMP6_ERROR_NONE)
	    {
	      vnet_sw_interface_t *sw_if0;
	      ethernet_interface_t *eth_if0;
	      ethernet_header_t *eth0;

	      /* dst address is either source address or the all-nodes mcast addr */
	      if (!ip6_sadd_unspecified)
		ip0->dst_address = ip0->src_address;
	      else
		ip6_set_reserved_multicast_address (&ip0->dst_address,
						    IP6_MULTICAST_SCOPE_link_local,
						    IP6_MULTICAST_GROUP_ID_all_hosts);

	      ip0->src_address = h0->target_address;
	      ip0->hop_limit = 255;
	      h0->icmp.type = ICMP6_neighbor_advertisement;

	      sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index0);
	      ASSERT (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
	      eth_if0 =
		ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);
	      if (eth_if0 && o0)
		{
		  clib_memcpy (o0->ethernet_address, &eth_if0->address, 6);
		  o0->header.type =
		    ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address;
		}

	      h0->advertisement_flags = clib_host_to_net_u32
		(ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED
		 | ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE);

	      h0->icmp.checksum = 0;
	      h0->icmp.checksum =
		ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip0,
						   &bogus_length);
	      ASSERT (bogus_length == 0);

	      /* Reuse current MAC header, copy SMAC to DMAC and
	       * interface MAC to SMAC */
	      vlib_buffer_advance (p0, -ethernet_buffer_header_size (p0));
	      eth0 = vlib_buffer_get_current (p0);
	      clib_memcpy (eth0->dst_address, eth0->src_address, 6);
	      if (eth_if0)
		clib_memcpy (eth0->src_address, &eth_if0->address, 6);

	      /* Setup input and output sw_if_index for packet */
	      ASSERT (vnet_buffer (p0)->sw_if_index[VLIB_RX] == sw_if_index0);
	      vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;
	      vnet_buffer (p0)->sw_if_index[VLIB_RX] =
		vnet_main.local_interface_sw_if_index;

	      n_advertisements_sent++;
	    }

	  p0->error = error_node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Account for advertisements sent. */
  vlib_error_count (vm, error_node->node_index,
		    ICMP6_ERROR_NEIGHBOR_ADVERTISEMENTS_TX,
		    n_advertisements_sent);

  return frame->n_vectors;
}

static const ethernet_interface_t *
ip6_nd_get_eth_itf (u32 sw_if_index)
{
  const vnet_sw_interface_t *sw;

  /* lookup radv container  - ethernet interfaces only */
  sw = vnet_get_sup_sw_interface (vnet_get_main (), sw_if_index);
  if (sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
    return (ethernet_get_interface (&ethernet_main, sw->hw_if_index));

  return (NULL);
}

/**
 * @brief called when IP6 is enabled on a link.
 * create and initialize router advertisement parameters with default
 * values for this intfc
 */
static void
ip6_nd_link_enable (u32 sw_if_index)
{
  const ethernet_interface_t *eth;
  ip6_nd_t *ind;

  eth = ip6_nd_get_eth_itf (sw_if_index);

  if (NULL == eth)
    return;

  ASSERT (INDEX_INVALID == ip6_link_delegate_get (sw_if_index,
						  ip6_nd_delegate_id));

  pool_get_zero (ip6_nd_pool, ind);

  ind->sw_if_index = sw_if_index;

  ip6_link_delegate_update (sw_if_index, ip6_nd_delegate_id,
			    ind - ip6_nd_pool);
}

static void
ip6_nd_delegate_disable (index_t indi)
{
  ip6_nd_t *ind;

  ind = pool_elt_at_index (ip6_nd_pool, indi);

  pool_put (ip6_nd_pool, ind);
}

static uword
icmp6_neighbor_solicitation (vlib_main_t * vm,
			     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return icmp6_neighbor_solicitation_or_advertisement (vm, node, frame,
						       /* is_solicitation */
						       1);
}

static uword
icmp6_neighbor_advertisement (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  return icmp6_neighbor_solicitation_or_advertisement (vm, node, frame,
						       /* is_solicitation */
						       0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_icmp_neighbor_solicitation_node,static) =
{
  .function = icmp6_neighbor_solicitation,
  .name = "icmp6-neighbor-solicitation",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = ICMP6_NEIGHBOR_SOLICITATION_N_NEXT,
  .next_nodes = {
    [ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP] = "ip6-drop",
    [ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY] = "interface-output",
  },
};

VLIB_REGISTER_NODE (ip6_icmp_neighbor_advertisement_node,static) =
{
  .function = icmp6_neighbor_advertisement,
  .name = "icmp6-neighbor-advertisement",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip6-punt",
  },
};
/* *INDENT-ON* */

static u8 *
format_ip6_nd (u8 * s, va_list * args)
{
  CLIB_UNUSED (index_t indi) = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);

  s = format (s, "%UNeighbor Discovery: enabled\n",
	      format_white_space, indent);

  s = format (s, "%UICMP redirects are disabled\n",
	      format_white_space, indent + 2);
  s = format (s, "%UICMP unreachables are not sent\n",
	      format_white_space, indent + 2);
  s = format (s, "%UND DAD is disabled\n", format_white_space, indent + 2);
  //s = format (s, "%UND reachable time is %d milliseconds\n",);

  return (s);
}

/**
 * VFT to act as an implementation of a neighbour protocol
 */
const static ip_neighbor_vft_t ip6_nd_impl_vft = {
  .inv_proxy6_add = ip6_nd_proxy_add,
  .inv_proxy6_del = ip6_nd_proxy_del,
};

/**
 * VFT for registering as a delegate to an IP6 link
 */
const static ip6_link_delegate_vft_t ip6_nd_delegate_vft = {
  .ildv_disable = ip6_nd_delegate_disable,
  .ildv_enable = ip6_nd_link_enable,
  .ildv_format = format_ip6_nd,
};

static clib_error_t *
ip6_nd_init (vlib_main_t * vm)
{
  icmp6_register_type (vm, ICMP6_neighbor_solicitation,
		       ip6_icmp_neighbor_solicitation_node.index);
  icmp6_register_type (vm, ICMP6_neighbor_advertisement,
		       ip6_icmp_neighbor_advertisement_node.index);

  ip_neighbor_register (AF_IP6, &ip6_nd_impl_vft);

  ip6_nd_delegate_id = ip6_link_delegate_register (&ip6_nd_delegate_vft);

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (ip6_nd_init) =
{
  .runs_after = VLIB_INITS("icmp6_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
