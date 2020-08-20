/*
 * ethernet/arp.c: IP v4 ARP node
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

#include <vnet/arp/arp.h>
#include <vnet/arp/arp_packet.h>

#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_entry_src.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/adj/adj_mcast.h>

#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip-neighbor/ip_neighbor_dp.h>

#include <vlibmemory/api.h>

/**
 * @file
 * @brief IPv4 ARP.
 *
 * This file contains code to manage the IPv4 ARP tables (IP Address
 * to MAC Address lookup).
 */

/**
 * @brief Per-interface ARP configuration and state
 */
typedef struct ethernet_arp_interface_t_
{
  /**
   * Is ARP enabled on this interface
   */
  u32 enabled;
} ethernet_arp_interface_t;

typedef struct
{
  /* Hash tables mapping name to opcode. */
  uword *opcode_by_name;

  /** Per interface state */
  ethernet_arp_interface_t *ethernet_arp_by_sw_if_index;

  /* ARP feature arc index */
  u8 feature_arc_index;
} ethernet_arp_main_t;

static ethernet_arp_main_t ethernet_arp_main;

static const u8 vrrp_prefix[] = { 0x00, 0x00, 0x5E, 0x00, 0x01 };

static uword
unformat_ethernet_arp_opcode_host_byte_order (unformat_input_t * input,
					      va_list * args)
{
  int *result = va_arg (*args, int *);
  ethernet_arp_main_t *am = &ethernet_arp_main;
  int x, i;

  /* Numeric opcode. */
  if (unformat (input, "0x%x", &x) || unformat (input, "%d", &x))
    {
      if (x >= (1 << 16))
	return 0;
      *result = x;
      return 1;
    }

  /* Named type. */
  if (unformat_user (input, unformat_vlib_number_by_name,
		     am->opcode_by_name, &i))
    {
      *result = i;
      return 1;
    }

  return 0;
}

static uword
unformat_ethernet_arp_opcode_net_byte_order (unformat_input_t * input,
					     va_list * args)
{
  int *result = va_arg (*args, int *);
  if (!unformat_user
      (input, unformat_ethernet_arp_opcode_host_byte_order, result))
    return 0;

  *result = clib_host_to_net_u16 ((u16) * result);
  return 1;
}

typedef struct
{
  u8 packet_data[64];
} ethernet_arp_input_trace_t;

static u8 *
format_ethernet_arp_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ethernet_arp_input_trace_t *t = va_arg (*va, ethernet_arp_input_trace_t *);

  s = format (s, "%U",
	      format_ethernet_arp_header,
	      t->packet_data, sizeof (t->packet_data));

  return s;
}

static int
arp_is_enabled (ethernet_arp_main_t * am, u32 sw_if_index)
{
  if (vec_len (am->ethernet_arp_by_sw_if_index) <= sw_if_index)
    return 0;

  return (am->ethernet_arp_by_sw_if_index[sw_if_index].enabled);
}

static void
arp_enable (ethernet_arp_main_t * am, u32 sw_if_index)
{
  if (arp_is_enabled (am, sw_if_index))
    return;

  vec_validate (am->ethernet_arp_by_sw_if_index, sw_if_index);

  am->ethernet_arp_by_sw_if_index[sw_if_index].enabled = 1;

  vnet_feature_enable_disable ("arp", "arp-reply", sw_if_index, 1, NULL, 0);
  vnet_feature_enable_disable ("arp", "arp-disabled", sw_if_index, 0, NULL,
			       0);
}

static void
arp_disable (ethernet_arp_main_t * am, u32 sw_if_index)
{
  if (!arp_is_enabled (am, sw_if_index))
    return;

  vnet_feature_enable_disable ("arp", "arp-disabled", sw_if_index, 1, NULL,
			       0);
  vnet_feature_enable_disable ("arp", "arp-reply", sw_if_index, 0, NULL, 0);

  am->ethernet_arp_by_sw_if_index[sw_if_index].enabled = 0;
}

static int
arp_unnumbered (vlib_buffer_t * p0,
		u32 input_sw_if_index, u32 conn_sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *vim = &vnm->interface_main;
  vnet_sw_interface_t *si;

  /* verify that the input interface is unnumbered to the connected.
   * the connected interface is the interface on which the subnet is
   * configured */
  si = &vim->sw_interfaces[input_sw_if_index];

  if (!(si->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED &&
	(si->unnumbered_sw_if_index == conn_sw_if_index)))
    {
      /* the input interface is not unnumbered to the interface on which
       * the sub-net is configured that covers the ARP request.
       * So this is not the case for unnumbered.. */
      return 0;
    }

  return !0;
}

always_inline u32
arp_learn (u32 sw_if_index,
	   const ethernet_arp_ip4_over_ethernet_address_t * addr)
{
  /* *INDENT-OFF* */
  ip_neighbor_learn_t l = {
    .ip = {
      .ip.ip4 = addr->ip4,
      .version = AF_IP4,
    },
    .mac = addr->mac,
    .sw_if_index = sw_if_index,
  };
  /* *INDENT-ON* */

  ip_neighbor_learn_dp (&l);

  return (ETHERNET_ARP_ERROR_l3_src_address_learned);
}

typedef enum arp_input_next_t_
{
  ARP_INPUT_NEXT_DROP,
  ARP_INPUT_NEXT_DISABLED,
  ARP_INPUT_N_NEXT,
} arp_input_next_t;

static uword
arp_input (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, next_index, *from, *to_next, n_left_to_next;
  ethernet_arp_main_t *am = &ethernet_arp_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (ethernet_arp_input_trace_t));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const ethernet_arp_header_t *arp0;
	  arp_input_next_t next0;
	  vlib_buffer_t *p0;
	  u32 pi0, error0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  arp0 = vlib_buffer_get_current (p0);

	  error0 = ETHERNET_ARP_ERROR_replies_sent;
	  next0 = ARP_INPUT_NEXT_DROP;

	  error0 =
	    (arp0->l2_type !=
	     clib_net_to_host_u16 (ETHERNET_ARP_HARDWARE_TYPE_ethernet) ?
	     ETHERNET_ARP_ERROR_l2_type_not_ethernet : error0);
	  error0 =
	    (arp0->l3_type !=
	     clib_net_to_host_u16 (ETHERNET_TYPE_IP4) ?
	     ETHERNET_ARP_ERROR_l3_type_not_ip4 : error0);
	  error0 =
	    (0 == arp0->ip4_over_ethernet[0].ip4.as_u32 ?
	     ETHERNET_ARP_ERROR_l3_dst_address_unset : error0);

	  if (ETHERNET_ARP_ERROR_replies_sent == error0)
	    {
	      next0 = ARP_INPUT_NEXT_DISABLED;
	      vnet_feature_arc_start (am->feature_arc_index,
				      vnet_buffer (p0)->sw_if_index[VLIB_RX],
				      &next0, p0);
	    }
	  else
	    p0->error = node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

typedef enum arp_disabled_next_t_
{
  ARP_DISABLED_NEXT_DROP,
  ARP_DISABLED_N_NEXT,
} arp_disabled_next_t;

#define foreach_arp_disabled_error					\
  _ (DISABLED, "ARP Disabled on this interface")                    \

typedef enum
{
#define _(sym,string) ARP_DISABLED_ERROR_##sym,
  foreach_arp_disabled_error
#undef _
    ARP_DISABLED_N_ERROR,
} arp_disabled_error_t;

static char *arp_disabled_error_strings[] = {
#define _(sym,string) string,
  foreach_arp_disabled_error
#undef _
};

static uword
arp_disabled (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, next_index, *from, *to_next, n_left_to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (ethernet_arp_input_trace_t));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  arp_disabled_next_t next0 = ARP_DISABLED_NEXT_DROP;
	  vlib_buffer_t *p0;
	  u32 pi0, error0;

	  next0 = ARP_DISABLED_NEXT_DROP;
	  error0 = ARP_DISABLED_ERROR_DISABLED;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  p0->error = node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

enum arp_dst_fib_type
{
  ARP_DST_FIB_NONE,
  ARP_DST_FIB_ADJ,
  ARP_DST_FIB_CONN
};

/*
 * we're looking for FIB sources that indicate the destination
 * is attached. There may be interposed DPO prior to the one
 * we are looking for
 */
static enum arp_dst_fib_type
arp_dst_fib_check (const fib_node_index_t fei, fib_entry_flag_t * flags)
{
  const fib_entry_t *entry = fib_entry_get (fei);
  const fib_entry_src_t *entry_src;
  fib_source_t src;
  /* *INDENT-OFF* */
  FOR_EACH_SRC_ADDED(entry, entry_src, src,
  ({
    *flags = fib_entry_get_flags_for_source (fei, src);
    if (fib_entry_is_sourced (fei, FIB_SOURCE_ADJ))
        return ARP_DST_FIB_ADJ;
      else if (FIB_ENTRY_FLAG_CONNECTED & *flags)
        return ARP_DST_FIB_CONN;
  }))
  /* *INDENT-ON* */

  return ARP_DST_FIB_NONE;
}

static uword
arp_reply (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 n_left_from, next_index, *from, *to_next;
  u32 n_replies_sent = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (ethernet_arp_input_trace_t));

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ethernet_arp_header_t *arp0;
	  ethernet_header_t *eth_rx;
	  const ip4_address_t *if_addr0;
	  u32 pi0, error0, next0, sw_if_index0, conn_sw_if_index0, fib_index0;
	  u8 dst_is_local0, is_vrrp_reply0;
	  fib_node_index_t dst_fei, src_fei;
	  const fib_prefix_t *pfx0;
	  fib_entry_flag_t src_flags, dst_flags;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  arp0 = vlib_buffer_get_current (p0);
	  /* Fill in ethernet header. */
	  eth_rx = ethernet_buffer_get_header (p0);

	  next0 = ARP_REPLY_NEXT_DROP;
	  error0 = ETHERNET_ARP_ERROR_replies_sent;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  /* Check that IP address is local and matches incoming interface. */
	  fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
	  if (~0 == fib_index0)
	    {
	      error0 = ETHERNET_ARP_ERROR_interface_no_table;
	      goto drop;

	    }

	  {
	    /*
	     * we're looking for FIB entries that indicate the source
	     * is attached. There may be more specific non-attached
	     * routes that match the source, but these do not influence
	     * whether we respond to an ARP request, i.e. they do not
	     * influence whether we are the correct way for the sender
	     * to reach us, they only affect how we reach the sender.
	     */
	    fib_entry_t *src_fib_entry;
	    const fib_prefix_t *pfx;
	    fib_entry_src_t *src;
	    fib_source_t source;
	    int attached;
	    int mask;

	    mask = 32;
	    attached = 0;

	    do
	      {
		src_fei = ip4_fib_table_lookup (ip4_fib_get (fib_index0),
						&arp0->
						ip4_over_ethernet[0].ip4,
						mask);
		src_fib_entry = fib_entry_get (src_fei);

		/*
		 * It's possible that the source that provides the
		 * flags we need, or the flags we must not have,
		 * is not the best source, so check then all.
		 */
                /* *INDENT-OFF* */
                FOR_EACH_SRC_ADDED(src_fib_entry, src, source,
                ({
                  src_flags = fib_entry_get_flags_for_source (src_fei, source);

                  /* Reject requests/replies with our local interface
                     address. */
                  if (FIB_ENTRY_FLAG_LOCAL & src_flags)
                    {
                      error0 = ETHERNET_ARP_ERROR_l3_src_address_is_local;
                      /*
                       * When VPP has an interface whose address is also
                       * applied to a TAP interface on the host, then VPP's
                       * TAP interface will be unnumbered  to the 'real'
                       * interface and do proxy ARP from the host.
                       * The curious aspect of this setup is that ARP requests
                       * from the host will come from the VPP's own address.
                       * So don't drop immediately here, instead go see if this
                       * is a proxy ARP case.
                       */
                      goto next_feature;
                    }
                  /* A Source must also be local to subnet of matching
                   * interface address. */
                  if ((FIB_ENTRY_FLAG_ATTACHED & src_flags) ||
                      (FIB_ENTRY_FLAG_CONNECTED & src_flags))
                    {
                      attached = 1;
                      break;
                    }
                  /*
                   * else
                   *  The packet was sent from an address that is not
                   *  connected nor attached i.e. it is not from an
                   *  address that is covered by a link's sub-net,
                   *  nor is it a already learned host resp.
                   */
                }));
                /* *INDENT-ON* */

		/*
		 * shorter mask lookup for the next iteration.
		 */
		pfx = fib_entry_get_prefix (src_fei);
		mask = pfx->fp_len - 1;

		/*
		 * continue until we hit the default route or we find
		 * the attached we are looking for. The most likely
		 * outcome is we find the attached with the first source
		 * on the first lookup.
		 */
	      }
	    while (!attached &&
		   !fib_entry_is_sourced (src_fei, FIB_SOURCE_DEFAULT_ROUTE));

	    if (!attached)
	      {
		/*
		 * the matching route is a not attached, i.e. it was
		 * added as a result of routing, rather than interface/ARP
		 * configuration. If the matching route is not a host route
		 * (i.e. a /32)
		 */
		error0 = ETHERNET_ARP_ERROR_l3_src_address_not_local;
		goto drop;
	      }
	  }

	  dst_fei = ip4_fib_table_lookup (ip4_fib_get (fib_index0),
					  &arp0->ip4_over_ethernet[1].ip4,
					  32);
	  switch (arp_dst_fib_check (dst_fei, &dst_flags))
	    {
	    case ARP_DST_FIB_ADJ:
	      /*
	       * We matched an adj-fib on ths source subnet (a /32 previously
	       * added as a result of ARP). If this request is a gratuitous
	       * ARP, then learn from it.
	       * The check for matching an adj-fib, is to prevent hosts
	       * from spamming us with gratuitous ARPS that might otherwise
	       * blow our ARP cache
	       */
	      if (arp0->ip4_over_ethernet[0].ip4.as_u32 ==
		  arp0->ip4_over_ethernet[1].ip4.as_u32)
		error0 =
		  arp_learn (sw_if_index0, &arp0->ip4_over_ethernet[0]);
	      goto drop;
	    case ARP_DST_FIB_CONN:
	      /* destination is connected, continue to process */
	      break;
	    case ARP_DST_FIB_NONE:
	      /* destination is not connected, stop here */
	      error0 = ETHERNET_ARP_ERROR_l3_dst_address_not_local;
	      goto next_feature;
	    }

	  dst_is_local0 = (FIB_ENTRY_FLAG_LOCAL & dst_flags);
	  pfx0 = fib_entry_get_prefix (dst_fei);
	  if_addr0 = &pfx0->fp_addr.ip4;

	  is_vrrp_reply0 =
	    ((arp0->opcode ==
	      clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply))
	     &&
	     (!memcmp
	      (arp0->ip4_over_ethernet[0].mac.bytes, vrrp_prefix,
	       sizeof (vrrp_prefix))));

	  /* Trash ARP packets whose ARP-level source addresses do not
	     match their L2-frame-level source addresses, unless it's
	     a reply from a VRRP virtual router */
	  if (!ethernet_mac_address_equal
	      (eth_rx->src_address,
	       arp0->ip4_over_ethernet[0].mac.bytes) && !is_vrrp_reply0)
	    {
	      error0 = ETHERNET_ARP_ERROR_l2_address_mismatch;
	      goto drop;
	    }

	  /* Learn or update sender's mapping only for replies to addresses
	   * that are local to the subnet */
	  if (arp0->opcode ==
	      clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply))
	    {
	      if (dst_is_local0)
		error0 =
		  arp_learn (sw_if_index0, &arp0->ip4_over_ethernet[0]);
	      else
		/* a reply for a non-local destination could be a GARP.
		 * GARPs for hosts we know were handled above, so this one
		 * we drop */
		error0 = ETHERNET_ARP_ERROR_l3_dst_address_not_local;

	      goto next_feature;
	    }
	  else if (arp0->opcode ==
		   clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request) &&
		   (dst_is_local0 == 0))
	    {
	      goto next_feature;
	    }

	  /* Honor unnumbered interface, if any */
	  conn_sw_if_index0 = fib_entry_get_resolving_interface (dst_fei);
	  if (sw_if_index0 != conn_sw_if_index0 ||
	      sw_if_index0 != fib_entry_get_resolving_interface (src_fei))
	    {
	      /*
	       * The interface the ARP is sent to or was received on is not the
	       * interface on which the covering prefix is configured.
	       * Maybe this is a case for unnumbered.
	       */
	      if (!arp_unnumbered (p0, sw_if_index0, conn_sw_if_index0))
		{
		  error0 = ETHERNET_ARP_ERROR_unnumbered_mismatch;
		  goto drop;
		}
	    }
	  if (arp0->ip4_over_ethernet[0].ip4.as_u32 ==
	      arp0->ip4_over_ethernet[1].ip4.as_u32)
	    {
	      error0 = ETHERNET_ARP_ERROR_gratuitous_arp;
	      goto drop;
	    }

	  next0 = arp_mk_reply (vnm, p0, sw_if_index0,
				if_addr0, arp0, eth_rx);

	  /* We are going to reply to this request, so, in the absence of
	     errors, learn the sender */
	  if (!error0)
	    error0 = arp_learn (sw_if_index0, &arp0->ip4_over_ethernet[1]);

	  n_replies_sent += 1;
	  goto enqueue;

	next_feature:
	  vnet_feature_next (&next0, p0);
	  goto enqueue;

	drop:
	  p0->error = node->errors[error0];

	enqueue:
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_error_count (vm, node->node_index,
		    ETHERNET_ARP_ERROR_replies_sent, n_replies_sent);

  return frame->n_vectors;
}


static char *ethernet_arp_error_strings[] = {
#define _(sym,string) string,
  foreach_ethernet_arp_error
#undef _
};

/* *INDENT-OFF* */

VLIB_REGISTER_NODE (arp_input_node, static) =
{
  .function = arp_input,
  .name = "arp-input",
  .vector_size = sizeof (u32),
  .n_errors = ETHERNET_ARP_N_ERROR,
  .error_strings = ethernet_arp_error_strings,
  .n_next_nodes = ARP_INPUT_N_NEXT,
  .next_nodes = {
    [ARP_INPUT_NEXT_DROP] = "error-drop",
    [ARP_INPUT_NEXT_DISABLED] = "arp-disabled",
  },
  .format_buffer = format_ethernet_arp_header,
  .format_trace = format_ethernet_arp_input_trace,
};

VLIB_REGISTER_NODE (arp_disabled_node, static) =
{
  .function = arp_disabled,
  .name = "arp-disabled",
  .vector_size = sizeof (u32),
  .n_errors = ARP_DISABLED_N_ERROR,
  .error_strings = arp_disabled_error_strings,
  .n_next_nodes = ARP_DISABLED_N_NEXT,
  .next_nodes = {
    [ARP_INPUT_NEXT_DROP] = "error-drop",
  },
  .format_buffer = format_ethernet_arp_header,
  .format_trace = format_ethernet_arp_input_trace,
};

VLIB_REGISTER_NODE (arp_reply_node, static) =
{
  .function = arp_reply,
  .name = "arp-reply",
  .vector_size = sizeof (u32),
  .n_errors = ETHERNET_ARP_N_ERROR,
  .error_strings = ethernet_arp_error_strings,
  .n_next_nodes = ARP_REPLY_N_NEXT,
  .next_nodes = {
    [ARP_REPLY_NEXT_DROP] = "error-drop",
    [ARP_REPLY_NEXT_REPLY_TX] = "interface-output",
  },
  .format_buffer = format_ethernet_arp_header,
  .format_trace = format_ethernet_arp_input_trace,
};

/* Built-in ARP rx feature path definition */
VNET_FEATURE_ARC_INIT (arp_feat, static) =
{
  .arc_name = "arp",
  .start_nodes = VNET_FEATURES ("arp-input"),
  .last_in_arc = "error-drop",
  .arc_index_ptr = &ethernet_arp_main.feature_arc_index,
};

VNET_FEATURE_INIT (arp_reply_feat_node, static) =
{
  .arc_name = "arp",
  .node_name = "arp-reply",
  .runs_before = VNET_FEATURES ("arp-disabled"),
};

VNET_FEATURE_INIT (arp_proxy_feat_node, static) =
{
  .arc_name = "arp",
  .node_name = "arp-proxy",
  .runs_after = VNET_FEATURES ("arp-reply"),
  .runs_before = VNET_FEATURES ("arp-disabled"),
};

VNET_FEATURE_INIT (arp_disabled_feat_node, static) =
{
  .arc_name = "arp",
  .node_name = "arp-disabled",
  .runs_before = VNET_FEATURES ("error-drop"),
};

VNET_FEATURE_INIT (arp_drop_feat_node, static) =
{
  .arc_name = "arp",
  .node_name = "error-drop",
  .runs_before = 0,	/* last feature */
};

/* *INDENT-ON* */

typedef struct
{
  pg_edit_t l2_type, l3_type;
  pg_edit_t n_l2_address_bytes, n_l3_address_bytes;
  pg_edit_t opcode;
  struct
  {
    pg_edit_t mac;
    pg_edit_t ip4;
  } ip4_over_ethernet[2];
} pg_ethernet_arp_header_t;

static inline void
pg_ethernet_arp_header_init (pg_ethernet_arp_header_t * p)
{
  /* Initialize fields that are not bit fields in the IP header. */
#define _(f) pg_edit_init (&p->f, ethernet_arp_header_t, f);
  _(l2_type);
  _(l3_type);
  _(n_l2_address_bytes);
  _(n_l3_address_bytes);
  _(opcode);
  _(ip4_over_ethernet[0].mac);
  _(ip4_over_ethernet[0].ip4);
  _(ip4_over_ethernet[1].mac);
  _(ip4_over_ethernet[1].ip4);
#undef _
}

uword
unformat_pg_arp_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_ethernet_arp_header_t *p;
  u32 group_index;

  p = pg_create_edit_group (s, sizeof (p[0]), sizeof (ethernet_arp_header_t),
			    &group_index);
  pg_ethernet_arp_header_init (p);

  /* Defaults. */
  pg_edit_set_fixed (&p->l2_type, ETHERNET_ARP_HARDWARE_TYPE_ethernet);
  pg_edit_set_fixed (&p->l3_type, ETHERNET_TYPE_IP4);
  pg_edit_set_fixed (&p->n_l2_address_bytes, 6);
  pg_edit_set_fixed (&p->n_l3_address_bytes, 4);

  if (!unformat (input, "%U: %U/%U -> %U/%U",
		 unformat_pg_edit,
		 unformat_ethernet_arp_opcode_net_byte_order, &p->opcode,
		 unformat_pg_edit,
		 unformat_mac_address_t, &p->ip4_over_ethernet[0].mac,
		 unformat_pg_edit,
		 unformat_ip4_address, &p->ip4_over_ethernet[0].ip4,
		 unformat_pg_edit,
		 unformat_mac_address_t, &p->ip4_over_ethernet[1].mac,
		 unformat_pg_edit,
		 unformat_ip4_address, &p->ip4_over_ethernet[1].ip4))
    {
      /* Free up any edits we may have added. */
      pg_free_edit_group (s);
      return 0;
    }
  return 1;
}

/*
 * callback when an interface address is added or deleted
 */
static void
arp_enable_disable_interface (ip4_main_t * im,
			      uword opaque, u32 sw_if_index, u32 is_enable)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;

  if (is_enable)
    arp_enable (am, sw_if_index);
  else
    arp_disable (am, sw_if_index);
}

/*
 * Remove any arp entries associated with the specified interface
 */
static clib_error_t *
vnet_arp_add_del_sw_interface (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;

  if (!is_add && sw_if_index != ~0)
    {
      arp_disable (am, sw_if_index);
    }
  else if (is_add)
    {
      vnet_feature_enable_disable ("arp", "arp-disabled",
				   sw_if_index, 1, NULL, 0);
    }

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (vnet_arp_add_del_sw_interface);

const static ip_neighbor_vft_t arp_vft = {
  .inv_proxy4_add = arp_proxy_add,
  .inv_proxy4_del = arp_proxy_del,
  .inv_proxy4_enable = arp_proxy_disable,
  .inv_proxy4_disable = arp_proxy_disable,
};

static clib_error_t *
ethernet_arp_init (vlib_main_t * vm)
{
  ethernet_arp_main_t *am = &ethernet_arp_main;
  ip4_main_t *im = &ip4_main;
  pg_node_t *pn;

  ethernet_register_input_type (vm, ETHERNET_TYPE_ARP, arp_input_node.index);

  pn = pg_get_node (arp_input_node.index);
  pn->unformat_edit = unformat_pg_arp_header;

  am->opcode_by_name = hash_create_string (0, sizeof (uword));
#define _(o) hash_set_mem (am->opcode_by_name, #o, ETHERNET_ARP_OPCODE_##o);
  foreach_ethernet_arp_opcode;
#undef _

  /* don't trace ARP error packets */
  {
    vlib_node_runtime_t *rt =
      vlib_node_get_runtime (vm, arp_input_node.index);

#define _(a,b)                                  \
    vnet_pcap_drop_trace_filter_add_del         \
        (rt->errors[ETHERNET_ARP_ERROR_##a],    \
         1 /* is_add */);
    foreach_ethernet_arp_error
#undef _
  }

  {
    ip4_enable_disable_interface_callback_t cb = {
      .function = arp_enable_disable_interface,
    };
    vec_add1 (im->enable_disable_interface_callbacks, cb);
  }

  ip_neighbor_register (AF_IP4, &arp_vft);

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (ethernet_arp_init) =
{
  .runs_after = VLIB_INITS("ethernet_init",
                           "ip_neighbor_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
