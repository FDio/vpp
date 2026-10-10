/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 DriveNets Ltd.
 */

/**
 * @file
 * @brief Seamless BFD (RFC 7880, RFC 7881) reflector
 */

#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/bfd/bfd_api.h>
#include <vnet/bfd/bfd_main.h>
#include <vnet/bfd/bfd.api_enum.h>

typedef enum
{
  BFD_SBFD_REFLECTOR_NEXT_DROP,
  BFD_SBFD_REFLECTOR_NEXT_LOOKUP,
  BFD_SBFD_REFLECTOR_N_NEXT,
} bfd_sbfd_reflector_next_t;

static vlib_node_registration_t bfd_sbfd_reflector4_input_node;
static vlib_node_registration_t bfd_sbfd_reflector6_input_node;

static void
bfd_sbfd_reflector_udp_register (vlib_main_t *vm, int is_add)
{
  if (is_add)
    {
      udp_register_dst_port (vm, UDP_DST_PORT_sbfd4, bfd_sbfd_reflector4_input_node.index, 1);
      udp_register_dst_port (vm, UDP_DST_PORT_sbfd6, bfd_sbfd_reflector6_input_node.index, 0);
    }
  else
    {
      udp_unregister_dst_port (vm, UDP_DST_PORT_sbfd4, 1);
      udp_unregister_dst_port (vm, UDP_DST_PORT_sbfd6, 0);
    }
}

vnet_api_error_t
bfd_sbfd_reflector_add (u32 discriminator, u8 admin_up, u32 required_min_rx_usec)
{
  bfd_main_t *bm = &bfd_main;
  u32 disc = clib_host_to_net_u32 (discriminator);
  bfd_sbfd_reflector_t *r;

  if (0 == discriminator)
    {
      vlib_log_err (bm->log_class, "S-BFD discriminator must be non-zero");
      return VNET_API_ERROR_INVALID_VALUE;
    }
  if (0 == required_min_rx_usec)
    {
      vlib_log_err (bm->log_class, "S-BFD required min rx interval must be non-zero");
      return VNET_API_ERROR_INVALID_VALUE;
    }
  if (hash_get (bm->sbfd_reflector_by_disc, disc))
    {
      vlib_log_err (bm->log_class, "S-BFD discriminator %u already exists", discriminator);
      return VNET_API_ERROR_BFD_EEXIST;
    }

  pool_get_zero (bm->sbfd_reflectors, r);
  r->discriminator = disc;
  r->admin_up = admin_up;
  r->required_min_rx_usec = required_min_rx_usec;
  hash_set (bm->sbfd_reflector_by_disc, disc, r - bm->sbfd_reflectors);
  if (1 == pool_elts (bm->sbfd_reflectors))
    bfd_sbfd_reflector_udp_register (vlib_get_main (), 1);
  vlib_log_info (bm->log_class, "add S-BFD reflector discriminator %u", discriminator);
  return 0;
}

vnet_api_error_t
bfd_sbfd_reflector_mod (u32 discriminator, u8 admin_up, u32 required_min_rx_usec)
{
  bfd_main_t *bm = &bfd_main;
  uword *p = hash_get (bm->sbfd_reflector_by_disc, clib_host_to_net_u32 (discriminator));
  bfd_sbfd_reflector_t *r;

  if (!p)
    {
      vlib_log_err (bm->log_class, "S-BFD discriminator %u not found", discriminator);
      return VNET_API_ERROR_BFD_ENOENT;
    }
  if (0 == required_min_rx_usec)
    {
      vlib_log_err (bm->log_class, "S-BFD required min rx interval must be non-zero");
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /* in place, without removing the discriminator */
  r = pool_elt_at_index (bm->sbfd_reflectors, p[0]);
  r->admin_up = admin_up;
  r->required_min_rx_usec = required_min_rx_usec;
  vlib_log_info (bm->log_class, "modify S-BFD reflector discriminator %u", discriminator);
  return 0;
}

vnet_api_error_t
bfd_sbfd_reflector_del (u32 discriminator)
{
  bfd_main_t *bm = &bfd_main;
  u32 disc = clib_host_to_net_u32 (discriminator);
  uword *p = hash_get (bm->sbfd_reflector_by_disc, disc);
  u32 idx;

  if (!p)
    {
      vlib_log_err (bm->log_class, "S-BFD discriminator %u not found", discriminator);
      return VNET_API_ERROR_BFD_ENOENT;
    }
  idx = p[0];
  hash_unset (bm->sbfd_reflector_by_disc, disc);
  pool_put_index (bm->sbfd_reflectors, idx);
  if (0 == pool_elts (bm->sbfd_reflectors))
    bfd_sbfd_reflector_udp_register (vlib_get_main (), 0);
  vlib_log_info (bm->log_class, "delete S-BFD reflector discriminator %u", discriminator);
  return 0;
}

/* RFC 7881 section 7: do not act on martian addresses */
static_always_inline int
bfd_sbfd_ip4_is_unicast (const ip4_address_t *a)
{
  /* not 0/8, 127/8, multicast, class E or limited broadcast */
  return a->data[0] != 0 && a->data[0] != 127 && a->data[0] < 224;
}

static_always_inline int
bfd_sbfd_ip6_is_unicast (const ip6_address_t *a)
{
  return !ip6_address_is_unspecified (a) && !ip6_address_is_loopback (a) &&
	 !ip6_address_is_multicast (a);
}

/* checks shared by IPv4 and IPv6: RFC 7880 section 7.2, RFC 7881 section 6 */
static_always_inline vl_counter_bfd_sbfd_enum_t
bfd_sbfd_check_request (const vlib_buffer_t *b, const bfd_pkt_t *pkt, const udp_header_t *udp,
			u16 sbfd_port)
{
  if ((b->flags & VLIB_BUFFER_NEXT_PRESENT) || b->current_length < sizeof (*pkt) ||
      clib_net_to_host_u16 (udp->length) < sizeof (*udp) + pkt->head.length ||
      BFD_ERROR_NONE != bfd_verify_pkt_common (pkt))
    return BFD_SBFD_ERROR_BAD;
  if (bfd_pkt_get_auth_present (pkt))
    return BFD_SBFD_ERROR_AUTH;
  if (udp->src_port == clib_host_to_net_u16 (sbfd_port))
    return BFD_SBFD_ERROR_BAD_SPORT;
  /* already reflected, answering it would loop */
  if (!bfd_pkt_get_demand (pkt))
    return BFD_SBFD_ERROR_DEMAND_CLEAR;
  return BFD_SBFD_ERROR_REFLECTED;
}

static_always_inline const bfd_sbfd_reflector_t *
bfd_sbfd_reflector_find (u32 disc)
{
  bfd_main_t *bm = &bfd_main;
  /* no lock: the table only changes with the worker barrier held */
  uword *p = hash_get (bm->sbfd_reflector_by_disc, disc);

  return p ? pool_elt_at_index (bm->sbfd_reflectors, p[0]) : NULL;
}

/* RFC 7880 section 7.2.2, the other fields as per RFC 5880 section 6.8.7 */
static_always_inline void
bfd_sbfd_init_reply (bfd_pkt_t *pkt, const bfd_sbfd_reflector_t *r)
{
  u32 my_disc = pkt->your_disc;
  u32 your_disc = pkt->my_disc;
  u32 des_min_tx = pkt->des_min_tx;
  u8 detect_mult = pkt->head.detect_mult;
  u8 poll = bfd_pkt_get_poll (pkt);

  /* D, P, A, C and M stay clear, required min echo rx stays 0 */
  clib_memset (pkt, 0, sizeof (*pkt));
  bfd_pkt_set_version (pkt, 1);
  if (r->admin_up)
    bfd_pkt_set_state (pkt, BFD_STATE_up);
  else
    {
      bfd_pkt_set_diag_code (pkt, BFD_DIAG_CODE_admin_down);
      bfd_pkt_set_state (pkt, BFD_STATE_admin_down);
    }
  if (poll)
    bfd_pkt_set_final (pkt);
  pkt->head.detect_mult = detect_mult;
  pkt->head.length = sizeof (*pkt);
  pkt->my_disc = my_disc;
  pkt->your_disc = your_disc;
  pkt->des_min_tx = des_min_tx;
  pkt->req_min_rx = clib_host_to_net_u32 (r->required_min_rx_usec);
}

/* The reply is a new packet. Drop request state that egress features
   would otherwise act on:
   - checksum offload request and RX checksum verdict
   - recorded QoS, which egress marking would apply over the BFD TOS
   Then point the L3/L4 header offsets at the reply headers. */
static_always_inline void
bfd_sbfd_reset_buffer (vlib_buffer_t *b, u16 l3_hdr_size)
{
  vnet_buffer_offload_flags_clear (b, vnet_buffer (b)->oflags);
  b->flags &= ~(VNET_BUFFER_F_L4_CHECKSUM_COMPUTED | VNET_BUFFER_F_L4_CHECKSUM_CORRECT |
		VNET_BUFFER_F_QOS_DATA_VALID);
  vnet_buffer (b)->l3_hdr_offset = b->current_data;
  vnet_buffer (b)->l4_hdr_offset = b->current_data + l3_hdr_size;
  b->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
}

static_always_inline vl_counter_bfd_sbfd_enum_t
bfd_sbfd_reflect4 (vlib_buffer_t *b)
{
  bfd_pkt_t *pkt = vlib_buffer_get_current (b);
  udp_header_t *udp = (udp_header_t *) pkt - 1;
  ip4_header_t *ip4 = (ip4_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
  const bfd_sbfd_reflector_t *r;
  vl_counter_bfd_sbfd_enum_t err;
  ip4_address_t src, dst;
  u16 dst_port;

  /* the UDP datagram must fit in the IPv4 total length: the buffer is not
     trimmed to it and ip4-local's UDP length check leaves out the header */
  if (clib_net_to_host_u16 (ip4->length) <
      ip4_header_bytes (ip4) + clib_net_to_host_u16 (udp->length))
    return BFD_SBFD_ERROR_BAD;
  err = bfd_sbfd_check_request (b, pkt, udp, UDP_DST_PORT_sbfd4);
  if (BFD_SBFD_ERROR_REFLECTED != err)
    return err;
  if (!bfd_sbfd_ip4_is_unicast (&ip4->src_address) || !bfd_sbfd_ip4_is_unicast (&ip4->dst_address))
    return BFD_SBFD_ERROR_NON_UNICAST;
  if (!(r = bfd_sbfd_reflector_find (pkt->your_disc)))
    return BFD_SBFD_ERROR_NO_DISC;

  /* RFC 7881 section 6.1: swap addresses and ports */
  src = ip4->dst_address;
  dst = ip4->src_address;
  dst_port = udp->src_port;
  bfd_sbfd_init_reply (pkt, r);
  b->current_length = sizeof (*pkt);

  vlib_buffer_advance (b, -(word) (sizeof (*ip4) + sizeof (*udp)));
  ip4 = vlib_buffer_get_current (b);
  udp = (udp_header_t *) (ip4 + 1);
  bfd_sbfd_reset_buffer (b, sizeof (*ip4));
  clib_memset (ip4, 0, sizeof (*ip4) + sizeof (*udp));
  ip4->ip_version_and_header_length = 0x45;
  ip4->tos = bfd_main.tos;
  ip4->ttl = 255;
  ip4->protocol = IP_PROTOCOL_UDP;
  ip4->src_address = src;
  ip4->dst_address = dst;
  ip4->length = clib_host_to_net_u16 (b->current_length);
  ip4->checksum = ip4_header_checksum (ip4);
  udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_sbfd4);
  udp->dst_port = dst_port;
  udp->length = clib_host_to_net_u16 (sizeof (*udp) + sizeof (*pkt));
  /* the UDP checksum is optional for IPv4, classic BFD leaves it 0 too */
  return BFD_SBFD_ERROR_REFLECTED;
}

static_always_inline vl_counter_bfd_sbfd_enum_t
bfd_sbfd_reflect6 (vlib_main_t *vm, vlib_buffer_t *b)
{
  bfd_pkt_t *pkt = vlib_buffer_get_current (b);
  udp_header_t *udp = (udp_header_t *) pkt - 1;
  ip6_header_t *ip6 = (ip6_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
  const bfd_sbfd_reflector_t *r;
  vl_counter_bfd_sbfd_enum_t err;
  ip6_address_t src, dst;
  u16 dst_port;
  int bogus = 0;

  err = bfd_sbfd_check_request (b, pkt, udp, UDP_DST_PORT_sbfd6);
  if (BFD_SBFD_ERROR_REFLECTED != err)
    return err;
  if (!bfd_sbfd_ip6_is_unicast (&ip6->src_address) || !bfd_sbfd_ip6_is_unicast (&ip6->dst_address))
    return BFD_SBFD_ERROR_NON_UNICAST;
  if (!(r = bfd_sbfd_reflector_find (pkt->your_disc)))
    return BFD_SBFD_ERROR_NO_DISC;

  /* RFC 7881 section 6.1: swap addresses and ports */
  src = ip6->dst_address;
  dst = ip6->src_address;
  dst_port = udp->src_port;
  bfd_sbfd_init_reply (pkt, r);
  b->current_length = sizeof (*pkt);

  vlib_buffer_advance (b, -(word) (sizeof (*ip6) + sizeof (*udp)));
  ip6 = vlib_buffer_get_current (b);
  udp = (udp_header_t *) (ip6 + 1);
  bfd_sbfd_reset_buffer (b, sizeof (*ip6));
  clib_memset (ip6, 0, sizeof (*ip6) + sizeof (*udp));
  ip6->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 ((0x6 << 28) | (bfd_main.tos << 20));
  ip6->payload_length = clib_host_to_net_u16 (sizeof (*udp) + sizeof (*pkt));
  ip6->protocol = IP_PROTOCOL_UDP;
  ip6->hop_limit = 255;
  ip6->src_address = src;
  ip6->dst_address = dst;
  udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_sbfd6);
  udp->dst_port = dst_port;
  udp->length = ip6->payload_length;
  /* the UDP checksum is mandatory for IPv6 */
  udp->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
  ASSERT (bogus == 0);
  if (0 == udp->checksum)
    udp->checksum = 0xffff;
  return BFD_SBFD_ERROR_REFLECTED;
}

static_always_inline uword
bfd_sbfd_reflector_input (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f, int is_ip6)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (f);
  u32 n_left = f->n_vectors;
  u32 n_reflected = 0;

  vlib_get_buffers (vm, from, bufs, n_left);
  while (n_left > 0)
    {
      vl_counter_bfd_sbfd_enum_t err;

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  bfd_input_trace_t *t = vlib_add_trace (vm, rt, b[0], sizeof (*t));
	  t->len = clib_min (b[0]->current_length, sizeof (t->data));
	  clib_memcpy_fast (t->data, vlib_buffer_get_current (b[0]), t->len);
	}

      err = is_ip6 ? bfd_sbfd_reflect6 (vm, b[0]) : bfd_sbfd_reflect4 (b[0]);
      if (BFD_SBFD_ERROR_REFLECTED == err)
	{
	  /* keep TTL 255 and route the reply in the table of the request */
	  b[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = ~0;
	  next[0] = BFD_SBFD_REFLECTOR_NEXT_LOOKUP;
	  n_reflected++;
	}
      else
	{
	  b[0]->error = rt->errors[err];
	  next[0] = BFD_SBFD_REFLECTOR_NEXT_DROP;
	}

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_node_increment_counter (vm, rt->node_index, BFD_SBFD_ERROR_REFLECTED, n_reflected);
  vlib_buffer_enqueue_to_next (vm, rt, from, nexts, f->n_vectors);
  return f->n_vectors;
}

static uword
bfd_sbfd_reflector4_input (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  return bfd_sbfd_reflector_input (vm, rt, f, 0 /* is_ip6 */);
}

VLIB_REGISTER_NODE (bfd_sbfd_reflector4_input_node, static) = {
  .function = bfd_sbfd_reflector4_input,
  .name = "bfd-sbfd-reflector4-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = BFD_SBFD_N_ERROR,
  .error_counters = bfd_sbfd_error_counters,

  .format_trace = bfd_input_format_trace,

  .n_next_nodes = BFD_SBFD_REFLECTOR_N_NEXT,
  .next_nodes = {
    [BFD_SBFD_REFLECTOR_NEXT_DROP] = "error-drop",
    [BFD_SBFD_REFLECTOR_NEXT_LOOKUP] = "ip4-lookup",
  },
};

static uword
bfd_sbfd_reflector6_input (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  return bfd_sbfd_reflector_input (vm, rt, f, 1 /* is_ip6 */);
}

VLIB_REGISTER_NODE (bfd_sbfd_reflector6_input_node, static) = {
  .function = bfd_sbfd_reflector6_input,
  .name = "bfd-sbfd-reflector6-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = BFD_SBFD_N_ERROR,
  .error_counters = bfd_sbfd_error_counters,

  .format_trace = bfd_input_format_trace,

  .n_next_nodes = BFD_SBFD_REFLECTOR_N_NEXT,
  .next_nodes = {
    [BFD_SBFD_REFLECTOR_NEXT_DROP] = "error-drop",
    [BFD_SBFD_REFLECTOR_NEXT_LOOKUP] = "ip6-lookup",
  },
};
