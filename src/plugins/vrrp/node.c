/*
 * node.c - vrrp packet handling node definitions
 *
 * Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include <vlib/vlib.h>
#include <vlibmemory/api.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/fib/fib_sas.h>
#include <vppinfra/error.h>
#include <vrrp/vrrp.h>
#include <vrrp/vrrp_packet.h>

typedef struct
{
  u32 sw_if_index;
  u8 is_ipv6;
  vrrp_header_t vrrp;
  u8 addrs[256];		/* print up to 64 IPv4 or 16 IPv6 addresses */
} vrrp_trace_t;

/* packet trace format function */
static u8 *
format_vrrp_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vrrp_trace_t *t = va_arg (*args, vrrp_trace_t *);
  int i;

  s = format (s, "VRRP: sw_if_index %d IPv%d\n",
	      t->sw_if_index, (t->is_ipv6) ? 6 : 4);
  s = format (s, "    %U\n", format_vrrp_packet_hdr, &t->vrrp);
  s = format (s, "    addresses: ");

  for (i = 0; i < t->vrrp.n_addrs; i++)
    {
      if (t->is_ipv6)
	s = format (s, "%U ", format_ip6_address,
		    (ip6_address_t *) (t->addrs + i * 16));
      else
	s = format (s, "%U ", format_ip4_address,
		    (ip4_address_t *) (t->addrs + i * 4));
    }

  return s;
}

extern vlib_node_registration_t vrrp4_input_node;
extern vlib_node_registration_t vrrp6_input_node;
extern vlib_node_registration_t vrrp4_arp_input_node;
extern vlib_node_registration_t vrrp6_nd_input_node;

#define foreach_vrrp_error					  \
_(RECEIVED, "VRRP packets processed")				  \
_(BAD_TTL, "VRRP advertisement TTL is not 255")			  \
_(NOT_VERSION_3, "VRRP version is not 3")			  \
_(INCOMPLETE_PKT, "VRRP packet has wrong size")			  \
_(BAD_CHECKSUM, "VRRP checksum is invalid")			  \
_(UNKNOWN_VR, "VRRP message does not match known VRs")		  \
_(ADDR_MISMATCH, "VR addrs do not match configuration")

typedef enum
{
#define _(sym,str) VRRP_ERROR_##sym,
  foreach_vrrp_error
#undef _
    VRRP_N_ERROR,
} vrrp_error_t;

static char *vrrp_error_strings[] = {
#define _(sym,string) string,
  foreach_vrrp_error
#undef _
};

typedef enum
{
  VRRP_INPUT_NEXT_DROP,
  VRRP_INPUT_N_NEXT,
} vrrp_next_t;

typedef struct vrrp_input_process_args
{
  u32 vr_index;
  vrrp_header_t *pkt;
} vrrp_input_process_args_t;

/* Given a VR and a pointer to the VRRP header of an incoming packet,
 * compare the local src address to the peers. Return < 0 if the local
 * address < the peer address, 0 if they're equal, > 0 if
 * the local address > the peer address
 */
static int
vrrp_vr_addr_cmp (vrrp_vr_t * vr, vrrp_header_t * pkt)
{
  vrrp_vr_config_t *vrc = &vr->config;
  void *peer_addr, *local_addr;
  ip46_address_t addr;
  int addr_size;

  clib_memset (&addr, 0, sizeof (addr));

  if (vrrp_vr_is_ipv6 (vr))
    {
      peer_addr = &(((ip6_header_t *) pkt) - 1)->src_address;
      local_addr = &addr.ip6;
      addr_size = 16;
      ip6_address_copy (local_addr,
			ip6_get_link_local_address (vrc->sw_if_index));
    }
  else
    {
      peer_addr = &(((ip4_header_t *) pkt) - 1)->src_address;
      local_addr = &addr.ip4;
      addr_size = 4;
      fib_sas4_get (vrc->sw_if_index, NULL, local_addr);
    }

  return memcmp (local_addr, peer_addr, addr_size);
}

static void
vrrp_input_process_master (vrrp_vr_t * vr, vrrp_header_t * pkt)
{
  /* received priority 0, another VR is shutting down. send an adv and
   * remain in the master state
   */
  if (pkt->priority == 0)
    {
      clib_warning ("Received shutdown message from a peer on VR %U",
		    format_vrrp_vr_key, vr);
      vrrp_adv_send (vr, 0);
      vrrp_vr_timer_set (vr, VRRP_VR_TIMER_ADV);
      return;
    }

  /* if either:
   * - received priority > adjusted priority, or
   * - received priority == adjusted priority and peer addr > local addr
   * allow the local VR to be preempted by the peer
   */
  if ((pkt->priority > vrrp_vr_priority (vr)) ||
      ((pkt->priority == vrrp_vr_priority (vr)) &&
       (vrrp_vr_addr_cmp (vr, pkt) < 0)))
    {
      vrrp_vr_transition (vr, VRRP_VR_STATE_BACKUP, pkt);

      return;
    }

  /* if we made it this far, eiher received prority < adjusted priority or
   * received == adjusted and local addr > peer addr. Ignore.
   */
  return;
}

/* RFC 5798 section 6.4.2 */
static void
vrrp_input_process_backup (vrrp_vr_t * vr, vrrp_header_t * pkt)
{
  vrrp_vr_config_t *vrc = &vr->config;
  vrrp_vr_runtime_t *vrt = &vr->runtime;

  /* master shutting down, ready for election */
  if (pkt->priority == 0)
    {
      clib_warning ("Master for VR %U is shutting down", format_vrrp_vr_key,
		    vr);
      vrt->master_down_int = vrt->skew;
      vrrp_vr_timer_set (vr, VRRP_VR_TIMER_MASTER_DOWN);
      return;
    }

  /* no preempt set or adv from a higher priority router, update timers */
  if (!(vrc->flags & VRRP_VR_PREEMPT) ||
      (pkt->priority >= vrrp_vr_priority (vr)))
    {
      vrt->master_adv_int = clib_net_to_host_u16 (pkt->rsvd_and_max_adv_int);
      vrt->master_adv_int &= ((u16) 0x0fff);	/* ignore rsvd bits */

      vrrp_vr_skew_compute (vr);
      vrrp_vr_master_down_compute (vr);
      vrrp_vr_timer_set (vr, VRRP_VR_TIMER_MASTER_DOWN);
      return;
    }

  /* preempt set or our priority > received, continue to wait on master down */
  return;
}

always_inline void
vrrp_input_process (vrrp_input_process_args_t * args)
{
  vrrp_vr_t *vr;

  vr = vrrp_vr_lookup_index (args->vr_index);

  if (!vr)
    {
      clib_warning ("Error retrieving VR with index %u", args->vr_index);
      return;
    }

  switch (vr->runtime.state)
    {
    case VRRP_VR_STATE_INIT:
      return;
    case VRRP_VR_STATE_BACKUP:
      /* this is usually the only state an advertisement should be received */
      vrrp_input_process_backup (vr, args->pkt);
      break;
    case VRRP_VR_STATE_MASTER:
      /* might be getting preempted. or have a misbehaving peer */
      clib_warning ("Received advertisement for master VR %U",
		    format_vrrp_vr_key, vr);
      vrrp_input_process_master (vr, args->pkt);
      break;
    default:
      clib_warning ("Received advertisement for VR %U in unknown state %d",
		    format_vrrp_vr_key, vr, vr->runtime.state);
      break;
    }

  return;
}

typedef struct
{
  ip46_address_t ip;
  u32 vr_index;
  u8 vr_id;
  u8 is_ipv6;
} vrrp_arp_nd_trace_t;


static u8 *
format_vrrp_arp_nd_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  vrrp_arp_nd_trace_t *t = va_arg (*va, vrrp_arp_nd_trace_t *);

  s = format (s, "address %U",
	      (t->is_ipv6) ? format_ip6_address : format_ip4_address,
	      (t->is_ipv6) ? (void *) &t->ip.ip6 : (void *) &t->ip.ip4);

  if (t->vr_index != ~0)
    s = format (s, ": vr_index %u vr_id %u", t->vr_index, t->vr_id);

  return s;
}

typedef enum
{
  VRRP_ARP_INPUT_NEXT_DROP,
  VRRP_ARP_INPUT_NEXT_REPLY_TX,
  VRRP_ARP_N_NEXT,
} vrrp_arp_next_t;

typedef enum
{
  VRRP_ND_INPUT_NEXT_DROP,
  VRRP_ND_INPUT_NEXT_REPLY_TX,
  VRRP_ND_N_NEXT,
} vrrp_nd_next_t;

static_always_inline void
vrrp_arp_nd_next (vlib_buffer_t * b, u32 * next_index, u32 * vr_index,
		  u8 is_ipv6)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  ethernet_header_t *eth, *eth_new;
  void *lookup_addr = 0;
  vrrp_vr_t *vr;
  u32 sw_if_index;
  vnet_link_t link_type;
  u8 *rewrite, rewrite_len;
  int bogus_length;
  /* ND vars */
  ip6_header_t *ip6 = 0;
  icmp6_neighbor_solicitation_or_advertisement_header_t *sol_adv = 0;
  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *lladdr = 0;
  /* ARP vars */
  ethernet_arp_header_t *arp;
  ip4_address_t ip4_addr;

  if (is_ipv6)
    {
      ip6 = vlib_buffer_get_current (b);

      /* we only care about about ICMP6 neighbor solicitiations */
      if (ip6->protocol != IP_PROTOCOL_ICMP6)
	return;

      sol_adv = ip6_next_header (ip6);
      lladdr = (void *) (sol_adv + 1);

      /* skip anything other than neighbor solicitations */
      if (sol_adv->icmp.type != ICMP6_neighbor_solicitation)
	return;

      lookup_addr = &sol_adv->target_address;
      link_type = VNET_LINK_IP6;
    }
  else
    {
      arp = vlib_buffer_get_current (b);

      /* skip non-request packets */
      if (arp->opcode != clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request))
	return;

      lookup_addr = &arp->ip4_over_ethernet[1].ip4;
      link_type = VNET_LINK_ARP;
    }

  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

  /* Don't bother with a hash lookup if no VRs configured on this interface */
  if (!vrrp_intf_num_vrs (sw_if_index, is_ipv6))
    return;

  /* skip requests that are not for VRRP addresses */
  *vr_index = vrrp_vr_lookup_address (sw_if_index, is_ipv6, lookup_addr);
  if (*vr_index == ~0)
    return;

  vr = vrrp_vr_lookup_index (*vr_index);
  if (!vr || vr->runtime.state != VRRP_VR_STATE_MASTER)
    {
      /* RFC 5798 - section 6.4.2 - Backup "MUST NOT respond" to ARP/ND.
       * So we must drop the request rather than allowing it to continue
       * on the feature arc.
       */
      *next_index = VRRP_ARP_INPUT_NEXT_DROP;
      return;
    }

  /* RFC 5798 section 6.4.3: Master "MUST respond" to ARP/ND. */
  eth = ethernet_buffer_get_header (b);
  rewrite = ethernet_build_rewrite (vnm, sw_if_index, link_type,
				    eth->src_address);
  rewrite_len = vec_len (rewrite);
  if (rewrite_len == 0)
    return;

  /* send the reply out the incoming interface */
  *next_index = VRRP_ARP_INPUT_NEXT_REPLY_TX;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;

  /* the outbound ethernet & vlan headers may have a different length than
   * the received header, so get a pointer to the new start of the packet
   * and write the header there.
   */
  vlib_buffer_advance (b, -rewrite_len);
  eth_new = vlib_buffer_get_current (b);
  clib_memcpy_fast (eth_new, rewrite, rewrite_len);
  vec_free (rewrite);

  if (is_ipv6)
    {
      if (ip6_address_is_unspecified (&ip6->src_address))
	ip6_set_reserved_multicast_address (&ip6->dst_address,
					    IP6_MULTICAST_SCOPE_link_local,
					    IP6_MULTICAST_GROUP_ID_all_hosts);
      else
	ip6->dst_address = ip6->src_address;

      ip6->src_address = sol_adv->target_address;
      ip6->hop_limit = 255;
      sol_adv->icmp.type = ICMP6_neighbor_advertisement;
      sol_adv->icmp.checksum = 0;
      sol_adv->advertisement_flags =
	clib_host_to_net_u32 (ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_ROUTER
			      | ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED
			      | ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE);

      clib_memcpy (lladdr->ethernet_address, vr->runtime.mac.bytes,
		   sizeof (mac_address_t));
      lladdr->header.type =
	ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address;

      sol_adv->icmp.checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus_length);

    }
  else
    {
      ip4_addr = arp->ip4_over_ethernet[1].ip4;

      arp->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply);
      arp->ip4_over_ethernet[1] = arp->ip4_over_ethernet[0];

      arp->ip4_over_ethernet[0].mac = vr->runtime.mac;
      arp->ip4_over_ethernet[0].ip4 = ip4_addr;
    }
}

static_always_inline uword
vrrp_arp_nd_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, u8 is_ipv6)
{
  u32 n_left_from, *from, next_index, *to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{

	  vlib_buffer_t *b0;
	  u32 bi0;
	  u32 next0;
	  u32 vr_index = ~0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  vnet_feature_next (&next0, b0);
	  vrrp_arp_nd_next (b0, &next0, &vr_index, is_ipv6);

	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vrrp_arp_nd_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      vrrp_vr_t *vr;

	      if (is_ipv6)
		{
		  ip6_header_t *ip0;
		  icmp6_neighbor_solicitation_or_advertisement_header_t
		    * sol_adv0;

		  ip0 = vlib_buffer_get_current (b0);
		  sol_adv0 = ip6_next_header (ip0);
		  t->ip.ip6 = sol_adv0->target_address;
		}
	      else
		{
		  ethernet_arp_header_t *arp0;

		  arp0 = vlib_buffer_get_current (b0);
		  t->ip.ip4 = arp0->ip4_over_ethernet[0].ip4;
		}

	      vr = vrrp_vr_lookup_index (vr_index);
	      if (vr)
		t->vr_id = vr->config.vr_id;

	      t->vr_index = vr_index;
	      t->is_ipv6 = is_ipv6;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (vrrp4_arp_input_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return vrrp_arp_nd_input_inline (vm, node, frame, 0 /* is_ipv6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vrrp4_arp_input_node) =
{
  .name = "vrrp4-arp-input",
  .vector_size = sizeof (u32),
  .format_trace = format_vrrp_arp_nd_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vrrp_error_strings),
  .error_strings = vrrp_error_strings,

  .n_next_nodes = VRRP_ARP_N_NEXT,

  .next_nodes = {
        [VRRP_ARP_INPUT_NEXT_DROP] = "error-drop",
        [VRRP_ARP_INPUT_NEXT_REPLY_TX] = "interface-output",
  },
};

VNET_FEATURE_INIT (vrrp4_arp_feat_node, static) =
{
  .arc_name = "arp",
  .node_name = "vrrp4-arp-input",
  .runs_before = VNET_FEATURES ("arp-reply"),
};

VLIB_NODE_FN (vrrp6_nd_input_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return vrrp_arp_nd_input_inline (vm, node, frame, 1 /* is_ipv6 */);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vrrp6_nd_input_node) =
{
  .name = "vrrp6-nd-input",
  .vector_size = sizeof (u32),
  .format_trace = format_vrrp_arp_nd_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vrrp_error_strings),
  .error_strings = vrrp_error_strings,

  .n_next_nodes = VRRP_ND_N_NEXT,

  .next_nodes = {
        [VRRP_ND_INPUT_NEXT_DROP] = "error-drop",
        [VRRP_ND_INPUT_NEXT_REPLY_TX] = "interface-output",
  },
};

VNET_FEATURE_INIT (vrrp6_nd_feat_node, static) =
{
  .arc_name = "ip6-local",
  .node_name = "vrrp6-nd-input",
  .runs_before = VNET_FEATURES ("ip6-local-end-of-arc"),
};

static_always_inline uword
vrrp_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame, u8 is_ipv6)
{
  u32 n_left_from, *from;
  vrrp_main_t *vmp = &vrrp_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0, error0;
      void *ip0;
      vrrp_header_t *vrrp0;
      vrrp_vr_t *vr0;
      vrrp_input_process_args_t args0;
      u8 *ttl0;
      u16 rx_csum0;
      u16 payload_len0;
      int addr_len;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      ip0 = vlib_buffer_get_current (b0);

      if (is_ipv6)
	{
	  ip6_header_t *ip6 = ip0;

	  vrrp0 = (vrrp_header_t *) (ip6 + 1);
	  ttl0 = &ip6->hop_limit;
	  addr_len = 16;
	  payload_len0 = clib_net_to_host_u16 (ip6->payload_length);
	  vlib_buffer_advance (b0, sizeof (*ip6));
	}
      else
	{
	  ip4_header_t *ip4 = ip0;

	  vrrp0 = (vrrp_header_t *) (ip4 + 1);
	  ttl0 = &ip4->ttl;
	  addr_len = 4;
	  payload_len0 = clib_net_to_host_u16 (ip4->length) - sizeof(*ip4);
	  vlib_buffer_advance (b0, sizeof (*ip4));
	}

      next0 = VRRP_INPUT_NEXT_DROP;

      error0 = VRRP_ERROR_RECEIVED;

      /* Validation from RFC 5798 sec 7.1 */

      /* checksum set to 0 for calculation, save original value */
      rx_csum0 = vrrp0->checksum;
      vrrp0->checksum = 0;

      /* Mandatory - TTL/hop limit must be 255 */
      if (*ttl0 != 255)
	{
	  error0 = VRRP_ERROR_BAD_TTL;
	  goto trace;
	}

      /* Mandatory - VRRP version must be 3 */
      if ((vrrp0->vrrp_version_and_type >> 4) != 3)
	{
	  error0 = VRRP_ERROR_NOT_VERSION_3;
	  goto trace;
	}

      /* Mandatory - packet must be complete */
      if (b0->current_length < sizeof (*vrrp0) +
          ((u32) vrrp0->n_addrs) * addr_len)
	{
	  error0 = VRRP_ERROR_INCOMPLETE_PKT;
	  goto trace;
	}

      /* Mandatory - checksum must be correct */
      if (rx_csum0 != vrrp_adv_csum (ip0, vrrp0, is_ipv6, payload_len0))
	{
	  error0 = VRRP_ERROR_BAD_CHECKSUM;
	  goto trace;
	}

      /* Mandatory - VR must be configured on the interface adv received on */
      if (!(vr0 =
	      vrrp_vr_lookup (vnet_buffer(b0)->sw_if_index[VLIB_RX],
			      vrrp0->vr_id, is_ipv6)))
	{
	  error0 = VRRP_ERROR_UNKNOWN_VR;
	  goto trace;
	}

      /* Optional - count of addresses should match configuration */
      /* Could also check that addresses match, but likely to be O(n^2) */
      if (vrrp0->n_addrs != vec_len (vr0->config.vr_addrs))
	{
	  error0 = VRRP_ERROR_ADDR_MISMATCH;
	  goto trace;
	}

      /* signal main thread to process contents of packet */
      args0.vr_index = vr0 - vmp->vrs;
      args0.pkt = vrrp0;

      vl_api_rpc_call_main_thread (vrrp_input_process, (u8 *) &args0,
				   sizeof (args0));

    trace:
      vrrp0->checksum = rx_csum0; /* restore csum for correct trace output */
      b0->error = node->errors[error0];

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  vrrp_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  size_t addr_len = (is_ipv6 ? 16 : 4);

	  t->sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  t->is_ipv6 = is_ipv6;
	  clib_memcpy_fast (&t->vrrp, vrrp0, sizeof (*vrrp0));
	  clib_memcpy_fast (t->addrs, (void *) (vrrp0 + 1),
			    (size_t) vrrp0->n_addrs * addr_len);
	}

      /* always drop, never forward or reply here */
      vlib_set_next_frame_buffer (vm, node, next0, bi0);

      from += 1;
      n_left_from -= 1;
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (vrrp4_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return vrrp_input_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vrrp4_input_node) =
{
  .name = "vrrp4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_vrrp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vrrp_error_strings),
  .error_strings = vrrp_error_strings,

  .n_next_nodes = VRRP_INPUT_N_NEXT,

  .next_nodes = {
        [VRRP_INPUT_NEXT_DROP] = "error-drop",
  },
};

VLIB_NODE_FN (vrrp6_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return vrrp_input_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (vrrp6_input_node) =
{
  .name = "vrrp6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_vrrp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vrrp_error_strings),
  .error_strings = vrrp_error_strings,

  .n_next_nodes = VRRP_INPUT_N_NEXT,

  .next_nodes = {
        [VRRP_INPUT_NEXT_DROP] = "error-drop",
  },
};

typedef struct
{
  u32 sw_if_index;
  u8 is_ipv6;
  ip46_address_t src, dst;
} vrrp_accept_owner_trace_t;

/* packet trace format function */
static u8 *
format_vrrp_accept_owner_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vrrp_accept_owner_trace_t *t = va_arg (*args, vrrp_accept_owner_trace_t *);
  int ip_ver = 4, ip_type = IP46_TYPE_IP4;

  if (t->is_ipv6)
    {
      ip_ver = 6;
      ip_type = IP46_TYPE_IP6;
    }

  s = format (s, "IPv%d sw_if_index %d %U -> %U",
	      ip_ver, t->sw_if_index,
	      format_ip46_address, &t->src, ip_type,
	      format_ip46_address, &t->dst, ip_type);

  return s;
}

#define foreach_vrrp_accept_owner_error				  \
_(RECEIVED, "VRRP owner accept packets received")		  \
_(PROCESSED, "VRRP owner accept advertisements processed")

typedef enum
{
#define _(sym,str) VRRP_ACCEPT_OWNER_ERROR_##sym,
  foreach_vrrp_accept_owner_error
#undef _
    VRRP_ACCEPT_OWNER_N_ERROR,
} vrrp_accept_owner_error_t;

static char *vrrp_accept_owner_error_strings[] = {
#define _(sym,string) string,
  foreach_vrrp_accept_owner_error
#undef _
};

typedef enum
{
  VRRP_ACCEPT_OWNER_NEXT_PROCESS,
  VRRP_ACCEPT_OWNER_N_NEXT,
} vrrp_accept_owner_next_t;

static_always_inline void
vrrp_accept_owner_next_node (u32 sw_if_index, u8 vr_id, u8 is_ipv6,
			     u32 *next_index, u32 *error)
{
  vrrp_vr_t *vr = vrrp_vr_lookup (sw_if_index, vr_id, is_ipv6);

  if (vr && (vr->runtime.state == VRRP_VR_STATE_MASTER) &&
      (vr->config.flags & VRRP_VR_ACCEPT))
    {
      *next_index = VRRP_ACCEPT_OWNER_NEXT_PROCESS;
      *error = VRRP_ACCEPT_OWNER_ERROR_PROCESSED;
    }
}

static_always_inline uword
vrrp_accept_owner_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame, u8 is_ipv6)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 2 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 error0, error1;
	  vrrp_header_t *vrrp0, *vrrp1;
	  ip4_header_t *ip40, *ip41;
	  ip6_header_t *ip60, *ip61;
	  u32 sw_if_index0, sw_if_index1;

	  bi0 = from[0];
	  bi1 = from[1];

	  to_next[0] = bi0;
	  to_next[1] = bi1;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* most packets will follow feature arc */
	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  error0 = error1 = VRRP_ACCEPT_OWNER_ERROR_RECEIVED;

	  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

	  /* find VRRP advertisements which should be sent to VRRP node */
	  if (is_ipv6)
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      ip61 = vlib_buffer_get_current (b1);

	      if (PREDICT_FALSE (ip60->protocol == IP_PROTOCOL_VRRP))
		{
		  vrrp0 = (vrrp_header_t *) (ip60 + 1);
		  vrrp_accept_owner_next_node (sw_if_index0, vrrp0->vr_id,
					       is_ipv6, &next0, &error0);
		}
	      if (PREDICT_FALSE (ip61->protocol == IP_PROTOCOL_VRRP))
		{
		  vrrp1 = (vrrp_header_t *) (ip61 + 1);
		  vrrp_accept_owner_next_node (sw_if_index1, vrrp1->vr_id,
					       is_ipv6, &next1, &error1);
		}
	    }
	  else
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      ip41 = vlib_buffer_get_current (b1);

	      if (PREDICT_FALSE (ip40->protocol == IP_PROTOCOL_VRRP))
		{
		  vrrp0 = (vrrp_header_t *) (ip40 + 1);
		  vrrp_accept_owner_next_node (sw_if_index0, vrrp0->vr_id,
					       is_ipv6, &next0, &error0);
		}
	      if (PREDICT_FALSE (ip41->protocol == IP_PROTOCOL_VRRP))
		{
		  vrrp1 = (vrrp_header_t *) (ip41 + 1);
		  vrrp_accept_owner_next_node (sw_if_index1, vrrp1->vr_id,
					       is_ipv6, &next1, &error1);
		}
	    }

      	  b0->error = node->errors[error0];
      	  b1->error = node->errors[error1];

	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vrrp_accept_owner_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));

	      t->sw_if_index = sw_if_index0;
	      t->is_ipv6 = is_ipv6;
	      if (is_ipv6)
		{
		  ip6_address_copy (&t->src.ip6, &ip60->src_address);
		  ip6_address_copy (&t->dst.ip6, &ip60->dst_address);
		}
	      else
		{
		  t->src.ip4.as_u32 = ip40->src_address.as_u32;
		  t->dst.ip4.as_u32 = ip40->dst_address.as_u32;
		}
	    }

	  if (b1->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vrrp_accept_owner_trace_t *t =
		vlib_add_trace (vm, node, b1, sizeof (*t));

	      t->sw_if_index = sw_if_index1;
	      t->is_ipv6 = is_ipv6;
	      if (is_ipv6)
		{
		  ip6_address_copy (&t->src.ip6, &ip61->src_address);
		  ip6_address_copy (&t->dst.ip6, &ip61->dst_address);
		}
	      else
		{
		  t->src.ip4.as_u32 = ip41->src_address.as_u32;
		  t->dst.ip4.as_u32 = ip41->dst_address.as_u32;
		}
	    }

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 error0;
	  vrrp_header_t *vrrp0;
	  ip4_header_t *ip4;
	  ip6_header_t *ip6;
	  u32 sw_if_index0;

	  bi0 = from[0];
	  to_next[0] = bi0;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* most packets will follow feature arc */
	  vnet_feature_next (&next0, b0);

	  error0 = VRRP_ACCEPT_OWNER_ERROR_RECEIVED;

	  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

	  /* find VRRP advertisements which should be sent to VRRP node */
	  if (is_ipv6)
	    {
	      ip6 = vlib_buffer_get_current (b0);

	      if (PREDICT_FALSE (ip6->protocol == IP_PROTOCOL_VRRP))
		{
		  vrrp0 = (vrrp_header_t *) (ip6 + 1);
		  vrrp_accept_owner_next_node (sw_if_index0, vrrp0->vr_id,
					       is_ipv6, &next0, &error0);
		}
	    }
	  else
	    {
	      ip4 = vlib_buffer_get_current (b0);

	      if (PREDICT_FALSE (ip4->protocol == IP_PROTOCOL_VRRP))
		{
		  vrrp0 = (vrrp_header_t *) (ip4 + 1);
		  vrrp_accept_owner_next_node (sw_if_index0, vrrp0->vr_id,
					       is_ipv6, &next0, &error0);
		}
	    }

      	  b0->error = node->errors[error0];

	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vrrp_accept_owner_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));

	      t->sw_if_index = sw_if_index0;
	      t->is_ipv6 = is_ipv6;
	      if (is_ipv6)
		{
		  ip6_address_copy (&t->src.ip6, &ip6->src_address);
		  ip6_address_copy (&t->dst.ip6, &ip6->dst_address);
		}
	      else
		{
		  t->src.ip4.as_u32 = ip4->src_address.as_u32;
		  t->dst.ip4.as_u32 = ip4->dst_address.as_u32;
		}
	    }

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (vrrp4_accept_owner_input_node) (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * frame)
{
  return vrrp_accept_owner_input_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (vrrp4_accept_owner_input_node) =
{
  .name = "vrrp4-accept-owner-input",
  .vector_size = sizeof (u32),
  .format_trace = format_vrrp_accept_owner_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vrrp_accept_owner_error_strings),
  .error_strings = vrrp_accept_owner_error_strings,

  .n_next_nodes = VRRP_ACCEPT_OWNER_N_NEXT,

  .next_nodes = {
        [VRRP_ACCEPT_OWNER_NEXT_PROCESS] = "vrrp4-input",
  },
};

VNET_FEATURE_INIT (vrrp4_accept_owner_mc, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "vrrp4-accept-owner-input",
  .runs_before = VNET_FEATURES ("ip4-mfib-forward-lookup"),
};

VLIB_NODE_FN (vrrp6_accept_owner_input_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * frame)
{
  return vrrp_accept_owner_input_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (vrrp6_accept_owner_input_node) =
{
  .name = "vrrp6-accept-owner-input",
  .vector_size = sizeof (u32),
  .format_trace = format_vrrp_accept_owner_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vrrp_accept_owner_error_strings),
  .error_strings = vrrp_accept_owner_error_strings,

  .n_next_nodes = VRRP_ACCEPT_OWNER_N_NEXT,

  .next_nodes = {
        [VRRP_ACCEPT_OWNER_NEXT_PROCESS] = "vrrp6-input",
  },
};

VNET_FEATURE_INIT (vrrp6_accept_owner_mc, static) =
{
  .arc_name = "ip6-multicast",
  .node_name = "vrrp6-accept-owner-input",
  .runs_before = VNET_FEATURES ("ip6-mfib-forward-lookup"),
};

static clib_error_t *
vrrp_input_init (vlib_main_t *vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, vrrp_init)))
    return error;

  ip4_register_protocol (IP_PROTOCOL_VRRP, vrrp4_input_node.index);
  ip6_register_protocol (IP_PROTOCOL_VRRP, vrrp6_input_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (vrrp_input_init);

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
