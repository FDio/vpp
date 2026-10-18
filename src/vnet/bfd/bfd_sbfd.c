/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 DriveNets Ltd.
 */

/**
 * @file
 * @brief Seamless BFD (RFC 7880, RFC 7881) reflector
 */

#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip_sas.h>
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

/* IPv4-mapped IPv6 addresses, ::ffff:0:0/96 */
static_always_inline int
bfd_sbfd_ip6_is_ip4_mapped (const ip6_address_t *a)
{
  return a->as_u64[0] == 0 && a->as_u32[2] == clib_host_to_net_u32 (0xffff);
}

/* RFC 7881 section 5.1: requests sent over MPLS paths go to 127/8 ... */
static_always_inline int
bfd_sbfd_ip4_is_loopback (const ip4_address_t *a)
{
  return a->data[0] == 127;
}

/* ... or to ::ffff:127.0.0.0/104 */
static_always_inline int
bfd_sbfd_ip6_is_mapped_loopback (const ip6_address_t *a)
{
  return bfd_sbfd_ip6_is_ip4_mapped (a) && a->as_u8[12] == 127;
}

/* RFC 7881 section 7: do not act on martian addresses */
static_always_inline int
bfd_sbfd_ip4_is_unicast (const ip4_address_t *a)
{
  /* not 0/8, 127/8, multicast, class E or limited broadcast */
  return a->data[0] != 0 && !bfd_sbfd_ip4_is_loopback (a) && a->data[0] < 224;
}

static_always_inline int
bfd_sbfd_ip6_is_unicast (const ip6_address_t *a)
{
  /* not ::, ::1, IPv4-mapped (RFC 6890: not a source) or multicast */
  return !ip6_address_is_unspecified (a) && !ip6_address_is_loopback (a) &&
	 !bfd_sbfd_ip6_is_ip4_mapped (a) && !ip6_address_is_multicast (a);
}

/* FIB source of the entries which deliver requests sent over MPLS paths */
static fib_source_t bfd_sbfd_fib_source;

/* DPO type of those entries; there is one DPO per protocol, its index is the
   protocol and it is never freed, so it keeps no locks */
static dpo_type_t bfd_sbfd_dpo_type;

static void
bfd_sbfd_dpo_lock (dpo_id_t *dpo)
{
}

static void
bfd_sbfd_dpo_unlock (dpo_id_t *dpo)
{
}

static u8 *
format_bfd_sbfd_dpo (u8 *s, va_list *args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return format (s, "bfd-sbfd-reflector %U", format_dpo_proto, index);
}

static const dpo_vft_t bfd_sbfd_dpo_vft = {
  .dv_lock = bfd_sbfd_dpo_lock,
  .dv_unlock = bfd_sbfd_dpo_unlock,
  .dv_format = format_bfd_sbfd_dpo,
};

static const char *const bfd_sbfd_dpo_ip4_nodes[] = {
  "bfd-sbfd-reflector4-dpo",
  NULL,
};

static const char *const bfd_sbfd_dpo_ip6_nodes[] = {
  "bfd-sbfd-reflector6-dpo",
  NULL,
};

static const char *const *const bfd_sbfd_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = bfd_sbfd_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = bfd_sbfd_dpo_ip6_nodes,
};

/* RFC 7881 section 5.1: destinations of requests sent over MPLS paths */
static const fib_prefix_t bfd_sbfd_mpls_path_prefixes[] = {
  {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 8,
    .fp_addr.ip4.data = { 127, 0, 0, 0 },
  },
  {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 104,
    .fp_addr.ip6.as_u8 = { [10] = 0xff, [11] = 0xff, [12] = 127 },
  },
};

/* Requests sent over MPLS paths arrive as plain IP after the last label is
   popped, or with an Explicit NULL label, and are looked up in the table of
   the receiving interface. Cover the default tables with an entry for each
   prefix that takes S-BFD requests to the reflector and drops all other
   packets: these addresses are not forwardable (RFC 1122 section 3.2.1.3,
   RFC 6890). The source has a high priority, so the entries replace any
   route to the same prefixes while a reflector exists. */
static void
bfd_sbfd_reflector_fib_update (int is_add)
{
  int i;

  for (i = 0; i < ARRAY_LEN (bfd_sbfd_mpls_path_prefixes); i++)
    {
      const fib_prefix_t *pfx = &bfd_sbfd_mpls_path_prefixes[i];
      u32 fib_index = fib_table_find (pfx->fp_proto, 0);

      if (is_add)
	{
	  dpo_proto_t proto = fib_proto_to_dpo (pfx->fp_proto);
	  dpo_id_t dpo = DPO_INVALID;

	  dpo_set (&dpo, bfd_sbfd_dpo_type, proto, proto);
	  fib_table_entry_special_dpo_add (fib_index, pfx, bfd_sbfd_fib_source,
					   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
	  dpo_reset (&dpo);
	}
      else
	fib_table_entry_special_remove (fib_index, pfx, bfd_sbfd_fib_source);
    }
}

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

/* checks shared by add and mod */
static vnet_api_error_t
bfd_sbfd_reflector_check (u32 required_min_rx_usec, const ip4_address_t *src_ip4,
			  const ip6_address_t *src_ip6)
{
  bfd_main_t *bm = &bfd_main;

  if (0 == required_min_rx_usec)
    {
      vlib_log_err (bm->log_class, "S-BFD required min rx interval must be non-zero");
      return VNET_API_ERROR_INVALID_VALUE;
    }
  /* RFC 7881 section 6.1: a local address the initiator can reach */
  if (src_ip4 && src_ip4->as_u32 && !bfd_sbfd_ip4_is_unicast (src_ip4))
    {
      vlib_log_err (bm->log_class, "S-BFD source %U is not unicast", format_ip4_address, src_ip4);
      return VNET_API_ERROR_INVALID_SRC_ADDRESS;
    }
  if (src_ip6 && !ip6_address_is_zero (src_ip6) &&
      (!bfd_sbfd_ip6_is_unicast (src_ip6) || ip6_address_is_link_local_unicast (src_ip6)))
    {
      vlib_log_err (bm->log_class, "S-BFD source %U is not global unicast", format_ip6_address,
		    src_ip6);
      return VNET_API_ERROR_INVALID_SRC_ADDRESS;
    }
  return 0;
}

/* values set by add and mod; a NULL source is none */
static void
bfd_sbfd_reflector_set (bfd_sbfd_reflector_t *r, u8 admin_up, u32 required_min_rx_usec,
			const ip4_address_t *src_ip4, const ip6_address_t *src_ip6)
{
  r->admin_up = admin_up;
  r->required_min_rx_usec = required_min_rx_usec;
  r->src_ip4.as_u32 = src_ip4 ? src_ip4->as_u32 : 0;
  if (src_ip6)
    r->src_ip6 = *src_ip6;
  else
    ip6_address_set_zero (&r->src_ip6);
}

vnet_api_error_t
bfd_sbfd_reflector_add (u32 discriminator, u8 admin_up, u32 required_min_rx_usec,
			const ip4_address_t *src_ip4, const ip6_address_t *src_ip6)
{
  bfd_main_t *bm = &bfd_main;
  u32 disc = clib_host_to_net_u32 (discriminator);
  bfd_sbfd_reflector_t *r;
  vnet_api_error_t rv;

  if (0 == discriminator)
    {
      vlib_log_err (bm->log_class, "S-BFD discriminator must be non-zero");
      return VNET_API_ERROR_INVALID_VALUE;
    }
  if ((rv = bfd_sbfd_reflector_check (required_min_rx_usec, src_ip4, src_ip6)))
    return rv;
  if (hash_get (bm->sbfd_reflector_by_disc, disc))
    {
      vlib_log_err (bm->log_class, "S-BFD discriminator %u already exists", discriminator);
      return VNET_API_ERROR_BFD_EEXIST;
    }

  pool_get_zero (bm->sbfd_reflectors, r);
  r->discriminator = disc;
  bfd_sbfd_reflector_set (r, admin_up, required_min_rx_usec, src_ip4, src_ip6);
  hash_set (bm->sbfd_reflector_by_disc, disc, r - bm->sbfd_reflectors);
  if (1 == pool_elts (bm->sbfd_reflectors))
    {
      bfd_sbfd_reflector_udp_register (vlib_get_main (), 1);
      bfd_sbfd_reflector_fib_update (1);
    }
  vlib_log_info (bm->log_class, "add S-BFD reflector discriminator %u", discriminator);
  return 0;
}

vnet_api_error_t
bfd_sbfd_reflector_mod (u32 discriminator, u8 admin_up, u32 required_min_rx_usec,
			const ip4_address_t *src_ip4, const ip6_address_t *src_ip6)
{
  bfd_main_t *bm = &bfd_main;
  uword *p = hash_get (bm->sbfd_reflector_by_disc, clib_host_to_net_u32 (discriminator));
  vnet_api_error_t rv;

  if (!p)
    {
      vlib_log_err (bm->log_class, "S-BFD discriminator %u not found", discriminator);
      return VNET_API_ERROR_BFD_ENOENT;
    }
  if ((rv = bfd_sbfd_reflector_check (required_min_rx_usec, src_ip4, src_ip6)))
    return rv;

  /* in place, without removing the discriminator: the UDP port and the FIB
     entries stay */
  bfd_sbfd_reflector_set (pool_elt_at_index (bm->sbfd_reflectors, p[0]), admin_up,
			  required_min_rx_usec, src_ip4, src_ip6);
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
    {
      bfd_sbfd_reflector_fib_update (0);
      bfd_sbfd_reflector_udp_register (vlib_get_main (), 0);
    }
  vlib_log_info (bm->log_class, "delete S-BFD reflector discriminator %u", discriminator);
  return 0;
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

/* RFC 7881 section 6.1: a request sent over an MPLS path is answered from
   the configured source, else from an address of the receiving interface,
   chosen as for ICMP errors */
static_always_inline int
bfd_sbfd_reply_src4 (u32 sw_if_index, const bfd_sbfd_reflector_t *r, const ip4_address_t *dst,
		     ip4_address_t *src)
{
  if (r->src_ip4.as_u32)
    {
      *src = r->src_ip4;
      return 1;
    }
  return ip4_sas_by_sw_if_index (sw_if_index, dst, src) && bfd_sbfd_ip4_is_unicast (src);
}

static_always_inline int
bfd_sbfd_reply_src6 (u32 sw_if_index, const bfd_sbfd_reflector_t *r, const ip6_address_t *dst,
		     ip6_address_t *src)
{
  if (!ip6_address_is_zero (&r->src_ip6))
    {
      *src = r->src_ip6;
      return 1;
    }
  return ip6_sas_by_sw_if_index (sw_if_index, dst, src) && bfd_sbfd_ip6_is_unicast (src);
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
  int mpls_path;

  /* the UDP datagram must fit in the IPv4 total length: the buffer is not
     trimmed to it and ip4-local's UDP length check leaves out the header */
  if (clib_net_to_host_u16 (ip4->length) <
      ip4_header_bytes (ip4) + clib_net_to_host_u16 (udp->length))
    return BFD_SBFD_ERROR_BAD;
  err = bfd_sbfd_check_request (b, pkt, udp, UDP_DST_PORT_sbfd4);
  if (BFD_SBFD_ERROR_REFLECTED != err)
    return err;
  if (!bfd_sbfd_ip4_is_unicast (&ip4->src_address))
    return BFD_SBFD_ERROR_NON_UNICAST;
  /* RFC 7881 section 5.1 has requests over MPLS paths sent with TTL 1,
     which uniform-mode label disposition can turn into the label's, so take
     any TTL but 0. ip4-input and label disposition drop TTL 0 and send an
     ICMP Time Exceeded; a request with an Explicit NULL label skips both,
     whatever its destination. */
  if (0 == ip4->ttl)
    return BFD_SBFD_ERROR_BAD_TTL;
  /* RFC 7881 section 5.1: sent over an MPLS path, to 127/8 */
  mpls_path = bfd_sbfd_ip4_is_loopback (&ip4->dst_address);
  if (!mpls_path && !bfd_sbfd_ip4_is_unicast (&ip4->dst_address))
    return BFD_SBFD_ERROR_NON_UNICAST;
  if (!(r = bfd_sbfd_reflector_find (pkt->your_disc)))
    return BFD_SBFD_ERROR_NO_DISC;

  /* RFC 7881 section 6.1: swap addresses and ports */
  src = ip4->dst_address;
  dst = ip4->src_address;
  if (mpls_path && !bfd_sbfd_reply_src4 (vnet_buffer (b)->sw_if_index[VLIB_RX], r, &dst, &src))
    return BFD_SBFD_ERROR_NO_SRC_ADDR;
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
  int mpls_path;
  int bogus = 0;

  err = bfd_sbfd_check_request (b, pkt, udp, UDP_DST_PORT_sbfd6);
  if (BFD_SBFD_ERROR_REFLECTED != err)
    return err;
  if (!bfd_sbfd_ip6_is_unicast (&ip6->src_address))
    return BFD_SBFD_ERROR_NON_UNICAST;
  /* any hop limit but 0, as for IPv4; ip6-input and label disposition drop
     0 the same way */
  if (0 == ip6->hop_limit)
    return BFD_SBFD_ERROR_BAD_TTL;
  /* RFC 7881 section 5.1: sent over an MPLS path, to ::ffff:127.0.0.0/104 */
  mpls_path = bfd_sbfd_ip6_is_mapped_loopback (&ip6->dst_address);
  if (!mpls_path && !bfd_sbfd_ip6_is_unicast (&ip6->dst_address))
    return BFD_SBFD_ERROR_NON_UNICAST;
  if (!(r = bfd_sbfd_reflector_find (pkt->your_disc)))
    return BFD_SBFD_ERROR_NO_DISC;

  /* RFC 7881 section 6.1: swap addresses and ports */
  src = ip6->dst_address;
  dst = ip6->src_address;
  if (mpls_path && !bfd_sbfd_reply_src6 (vnet_buffer (b)->sw_if_index[VLIB_RX], r, &dst, &src))
    return BFD_SBFD_ERROR_NO_SRC_ADDR;
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

typedef enum
{
  BFD_SBFD_DPO_NEXT_LOCAL,
  BFD_SBFD_DPO_NEXT_DROP,
  BFD_SBFD_DPO_N_NEXT,
} bfd_sbfd_dpo_next_t;

typedef struct
{
  u8 error;
} bfd_sbfd_dpo_trace_t;

static u8 *
format_bfd_sbfd_dpo_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  bfd_sbfd_dpo_trace_t *t = va_arg (*args, bfd_sbfd_dpo_trace_t *);

  return format (s, "%s", bfd_sbfd_dpo_error_counters[t->error].desc);
}

/* An S-BFD request is a UDP datagram to port 7784, not a fragment of one.
   With an Explicit NULL label it skips ip4-input, and ip4-local does not
   repeat its header checks, so check the header here as ip4-input does.
   Take no options: ip4-input punts them, and ip4-local finds the UDP header
   right after a 20-byte header. */
static_always_inline vl_counter_bfd_sbfd_dpo_enum_t
bfd_sbfd_dpo_check4 (vlib_main_t *vm, vlib_buffer_t *b)
{
  ip4_header_t *ip4 = vlib_buffer_get_current (b);
  udp_header_t *udp = (udp_header_t *) (ip4 + 1);
  u16 ip_len;

  if (b->current_length < sizeof (*ip4))
    return BFD_SBFD_DPO_ERROR_BAD_LENGTH;
  if ((ip4->ip_version_and_header_length & 0xf0) != 0x40)
    return BFD_SBFD_DPO_ERROR_BAD_VERSION;
  if (ip4->ip_version_and_header_length != 0x45)
    return BFD_SBFD_DPO_ERROR_BAD_IHL;
  if (!ip4_header_checksum_is_valid (ip4))
    return BFD_SBFD_DPO_ERROR_BAD_CHECKSUM;
  ip_len = clib_net_to_host_u16 (ip4->length);
  if (ip_len < sizeof (*ip4) || ip_len > vlib_buffer_length_in_chain (vm, b))
    return BFD_SBFD_DPO_ERROR_BAD_LENGTH;
  if (IP_PROTOCOL_UDP != ip4->protocol || ip4_is_fragment (ip4) ||
      b->current_length < sizeof (*ip4) + sizeof (*udp) ||
      clib_host_to_net_u16 (UDP_DST_PORT_sbfd4) != udp->dst_port)
    return BFD_SBFD_DPO_ERROR_NOT_REQUEST;
  return BFD_SBFD_DPO_ERROR_REQUEST;
}

/* As for IPv4: check the version, as ip6-input does, and that the payload
   fits in the packet, which ip6-input does not check */
static_always_inline vl_counter_bfd_sbfd_dpo_enum_t
bfd_sbfd_dpo_check6 (vlib_main_t *vm, vlib_buffer_t *b)
{
  ip6_header_t *ip6 = vlib_buffer_get_current (b);
  udp_header_t *udp = (udp_header_t *) (ip6 + 1);

  if (b->current_length < sizeof (*ip6))
    return BFD_SBFD_DPO_ERROR_BAD_LENGTH;
  if ((clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label) >> 28) != 6)
    return BFD_SBFD_DPO_ERROR_BAD_VERSION;
  if (sizeof (*ip6) + clib_net_to_host_u16 (ip6->payload_length) >
      vlib_buffer_length_in_chain (vm, b))
    return BFD_SBFD_DPO_ERROR_BAD_LENGTH;
  if (IP_PROTOCOL_UDP != ip6->protocol || b->current_length < sizeof (*ip6) + sizeof (*udp) ||
      clib_host_to_net_u16 (UDP_DST_PORT_sbfd6) != udp->dst_port)
    return BFD_SBFD_DPO_ERROR_NOT_REQUEST;
  return BFD_SBFD_DPO_ERROR_REQUEST;
}

/* S-BFD requests go to ip4-local / ip6-local, and from there through
   udp-local to the reflector, as requests to a local address do; all
   other packets are dropped */
static_always_inline uword
bfd_sbfd_dpo_input (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f, int is_ip6)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (f);
  u32 n_left = f->n_vectors;
  u32 n_requests = 0;

  vlib_get_buffers (vm, from, bufs, n_left);
  while (n_left > 0)
    {
      vl_counter_bfd_sbfd_dpo_enum_t err =
	is_ip6 ? bfd_sbfd_dpo_check6 (vm, b[0]) : bfd_sbfd_dpo_check4 (vm, b[0]);

      if (BFD_SBFD_DPO_ERROR_REQUEST == err)
	{
	  next[0] = BFD_SBFD_DPO_NEXT_LOCAL;
	  n_requests++;
	}
      else
	{
	  b[0]->error = rt->errors[err];
	  next[0] = BFD_SBFD_DPO_NEXT_DROP;
	}
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  bfd_sbfd_dpo_trace_t *t = vlib_add_trace (vm, rt, b[0], sizeof (*t));
	  t->error = err;
	}

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_node_increment_counter (vm, rt->node_index, BFD_SBFD_DPO_ERROR_REQUEST, n_requests);
  vlib_buffer_enqueue_to_next (vm, rt, from, nexts, f->n_vectors);
  return f->n_vectors;
}

static uword
bfd_sbfd_reflector4_dpo (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  return bfd_sbfd_dpo_input (vm, rt, f, 0 /* is_ip6 */);
}

VLIB_REGISTER_NODE (bfd_sbfd_reflector4_dpo_node, static) = {
  .function = bfd_sbfd_reflector4_dpo,
  .name = "bfd-sbfd-reflector4-dpo",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = BFD_SBFD_DPO_N_ERROR,
  .error_counters = bfd_sbfd_dpo_error_counters,

  .format_trace = format_bfd_sbfd_dpo_trace,

  .n_next_nodes = BFD_SBFD_DPO_N_NEXT,
  .next_nodes = {
    [BFD_SBFD_DPO_NEXT_LOCAL] = "ip4-local",
    [BFD_SBFD_DPO_NEXT_DROP] = "ip4-drop",
  },
};

static uword
bfd_sbfd_reflector6_dpo (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  return bfd_sbfd_dpo_input (vm, rt, f, 1 /* is_ip6 */);
}

VLIB_REGISTER_NODE (bfd_sbfd_reflector6_dpo_node, static) = {
  .function = bfd_sbfd_reflector6_dpo,
  .name = "bfd-sbfd-reflector6-dpo",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = BFD_SBFD_DPO_N_ERROR,
  .error_counters = bfd_sbfd_dpo_error_counters,

  .format_trace = format_bfd_sbfd_dpo_trace,

  .n_next_nodes = BFD_SBFD_DPO_N_NEXT,
  .next_nodes = {
    [BFD_SBFD_DPO_NEXT_LOCAL] = "ip6-local",
    [BFD_SBFD_DPO_NEXT_DROP] = "ip6-drop",
  },
};

static clib_error_t *
bfd_sbfd_init (vlib_main_t *vm)
{
  bfd_sbfd_fib_source = fib_source_allocate ("sbfd", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_SIMPLE);
  bfd_sbfd_dpo_type = dpo_register_new_type (&bfd_sbfd_dpo_vft, bfd_sbfd_dpo_nodes);
  return 0;
}

VLIB_INIT_FUNCTION (bfd_sbfd_init) = {
  .runs_after = VLIB_INITS ("fib_module_init"),
};
