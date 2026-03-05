/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2010 Cisco and/or its affiliates.
 */

/* ip/ip6_neighbor.c: IP6 neighbor handling */

#include <vnet/ip6-nd/ip6_nd.h>
#include <vnet/ip6-nd/ip6_nd_inline.h>
#include <vnet/ip6-nd/ip6_dad.h>

#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip-neighbor/ip_neighbor_dp.h>

#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/fib_entry_src.h>
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

static int
ip6_nd_unnumbered (u32 input_sw_if_index, u32 conn_sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *vim = &vnm->interface_main;
  vnet_sw_interface_t *si;

  /* verify that the input interface is unnumbered to the
   * connected interface on which the subnet is configured */
  si = &vim->sw_interfaces[input_sw_if_index];

  if (!(si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED &&
	(si->unnumbered_sw_if_index == conn_sw_if_index)))
    /* the input interface is not unnumbered to the interface on
     * which the covering connected/attached prefix is configured;
     * so, this is not the case for unnumbered */
    return 0;

  return !0;
}

static u32
ip6_nd_src_is_on_link (u32 sw_if_index, const ip6_address_t *src_addr)
{
  fib_node_index_t src_fei, src_first_fei;
  fib_entry_t *src_fib_entry;
  fib_entry_src_t *src;
  fib_entry_flag_t src_flags;
  fib_source_t source;
  const fib_prefix_t *pfx;
  u32 fib_index, conn_sw_if_index;
  int attached, mask;

  fib_index = ip6_fib_table_get_index_for_sw_if_index (sw_if_index);
  if (~0 == fib_index)
    return ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_NOT_ON_LINK;

  attached = 0;
  mask = 128;
  src_first_fei = FIB_NODE_INDEX_INVALID;

  /* walk towards shorter covering prefixes until an attached/connected
   * source is found or the default route is reached */
  do
    {
      src_fei = ip6_fib_table_lookup (fib_index, src_addr, mask);
      src_fib_entry = fib_entry_get (src_fei);
      if (FIB_NODE_INDEX_INVALID == src_first_fei)
	src_first_fei = src_fei;

      /*
       * check all FIB entry sources; we only accept if any source marks the
       * prefix connected/attached and reject if any source marks it local */
      FOR_EACH_SRC_ADDED (src_fib_entry, src, source, ({
			    src_flags = fib_entry_get_flags_for_source (src_fei, source);

			    /* reject packets claiming one of our own addresses as the ND source */
			    if (FIB_ENTRY_FLAG_LOCAL & src_flags)
			      return ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_NOT_ON_LINK;

			    if (FIB_SOURCE_IP6_ND_PROXY == source)
			      {
				/* consider a source explicitly configured by ND proxy as valid */
				attached = 1;
				break;
			      }

			    if ((FIB_ENTRY_FLAG_ATTACHED & src_flags) ||
				(FIB_ENTRY_FLAG_CONNECTED & src_flags))
			      {
				/* source must be local to the subnet of the receiving interface */
				attached = 1;
				break;
			      }
			    /*
			     * else, the packet was sent from an address that is neither
			     * connected nor attached, i.e. not covered by a link subnet
			     * and not an already learned host response */
			  }));
      /* shorter mask lookup for the next iteration */
      pfx = fib_entry_get_prefix (src_fei);
      if (0 == pfx->fp_len)
	break;
      mask = pfx->fp_len - 1;
    }
  /* continue until we hit the default route or we find the attached we are looking for */
  while (!attached && !fib_entry_is_sourced (src_fei, FIB_SOURCE_DEFAULT_ROUTE));

  /* If no attached/connected cover is found, preserve ARP-like fallback
   * based on the original source lookup result. */
  conn_sw_if_index = fib_entry_get_any_resolving_interface (attached ? src_fei : src_first_fei);

  if (!attached)
    {
      if (~0 == conn_sw_if_index)
	{
	  const vnet_sw_interface_t *si;

	  si = vnet_get_sw_interface (vnet_get_main (), sw_if_index);
	  if (!(si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED))
	    return ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_NOT_ON_LINK;
	}
      else if (!ip6_nd_unnumbered (sw_if_index, conn_sw_if_index))
	return ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_NOT_ON_LINK;
    }

  /* if attached/connected source exists, it must resolve to RX interface
   * unless RX interface is explicitly unnumbered to the resolving interface */
  if (attached && sw_if_index != conn_sw_if_index &&
      !ip6_nd_unnumbered (sw_if_index, conn_sw_if_index))
    return ICMP6_ERROR_NEIGHBOR_SOLICITATION_SOURCE_NOT_ON_LINK;

  return ICMP6_ERROR_NONE;
}

static_always_inline uword
icmp6_neighbor_solicitation_or_advertisement (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * frame,
					      uword is_solicitation)
{
  uword n_packets = frame->n_vectors;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next_index, n_advertisements_sent;
  icmp6_neighbor_discovery_option_type_t option_type;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_icmp_input_node.index);

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
	  ip_neighbor_counter_type_t c_type;

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

	  /* For non-unspecified/non-link-local sources, validate on-link
	   * using control-plane FIB flags (not forwarding adjacency) */
	  if (!ip6_sadd_unspecified && !ip6_sadd_link_local)
	    error0 = ip6_nd_src_is_on_link (sw_if_index0, &ip0->src_address);

	  o0 = (void *) (h0 + 1);
	  o0 = ((options_len0 == 8 && o0->header.type == option_type
		 && o0->header.n_data_u64s == 1) ? o0 : 0);

	  /* If src address unspecified or link local, donot learn neighbor MAC */
	  if (PREDICT_TRUE (error0 == ICMP6_ERROR_NONE && o0 != 0 &&
			    !ip6_sadd_unspecified))
	    {
	      ip_neighbor_learn_t learn = {
		.sw_if_index = sw_if_index0,
		.ip = {
                  .version = AF_IP6,
                  .ip.ip6 = (is_solicitation ?
                             ip0->src_address :
                             h0->target_address),
                }
	      };
	      memcpy (&learn.mac, o0->ethernet_address, sizeof (learn.mac));
	      ip_neighbor_learn_dp (&learn);
	    }
	  /* Check if this NA conflicts with an ongoing DAD */
	  if (!is_solicitation)
	    {
	      ip6_dad_na_received_dp (sw_if_index0, &h0->target_address);
	    }
	  /* Check if this NS conflicts with an ongoing DAD (RFC 4862 5.4.3) */
	  else if (is_solicitation)
	    {
	      /* Conflict if NS target matches our tentative address and source is NOT
	       * :: (unspecified). RFC 4862: If source is ::, the sender is performing
	       * DAD for the target address - this is not a conflict. If source is NOT
	       * ::, it indicates the address is already in use - this IS a conflict. */
	      if (!ip6_address_is_unspecified (&ip0->src_address))
		{
		  ip6_dad_na_received_dp (sw_if_index0, &h0->target_address);
		}
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
		      else if (FIB_ENTRY_FLAG_LOCAL &
			       fib_entry_get_flags_for_source (
				 fei, FIB_SOURCE_IP6_ND))
			{
			  /* It's one of our link local addresses
			   * that's good. */
			}
		      else if (fib_entry_is_sourced (fei,
						     FIB_SOURCE_IP6_ND_PROXY))
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
	    {
	      next0 = (error0 != ICMP6_ERROR_NONE ?
			       ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP :
			       ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY);
	      c_type = IP_NEIGHBOR_CTR_REQUEST;
	    }
	  else
	    {
	      next0 = 0;
	      error0 = error0 == ICMP6_ERROR_NONE ?
		ICMP6_ERROR_NEIGHBOR_ADVERTISEMENTS_RX : error0;
	      c_type = IP_NEIGHBOR_CTR_REPLY;
	    }

	  vlib_increment_simple_counter (
	    &ip_neighbor_counters[AF_IP6].ipnc[VLIB_RX][c_type],
	    vm->thread_index, sw_if_index0, 1);

	  if (is_solicitation && error0 == ICMP6_ERROR_NONE)
	    {
	      icmp6_send_neighbor_advertisement (vm, p0, ip0, h0, o0,
						 sw_if_index0);
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

VLIB_INIT_FUNCTION (ip6_nd_init) = {
  .runs_after = VLIB_INITS ("icmp6_init"),
};
