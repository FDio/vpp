/*
 * vrrp.c - vrrp plugin action functions
 *
 * Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_sas.h>
#include <vnet/ip/igmp_packet.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ethernet/arp_packet.h>

#include <vrrp/vrrp.h>
#include <vrrp/vrrp_packet.h>

#include <vpp/app/version.h>

static const u8 vrrp4_dst_mac[6] = { 0x1, 0x0, 0x5e, 0x0, 0x0, 0x12 };
static const u8 vrrp6_dst_mac[6] = { 0x33, 0x33, 0x0, 0x0, 0x0, 0x12 };
static const u8 vrrp_src_mac_prefix[4] = { 0x0, 0x0, 0x5e, 0x0 };

static int
vrrp_adv_l2_build_multicast (vrrp_vr_t * vr, vlib_buffer_t * b)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_link_t link_type;
  ethernet_header_t *eth;
  int n_bytes = 0;
  const void *dst_mac;
  u8 mac_byte_ipver;
  u8 *rewrite;

  eth = vlib_buffer_get_current (b);

  if (vrrp_vr_is_ipv6 (vr))
    {
      dst_mac = vrrp6_dst_mac;
      link_type = VNET_LINK_IP6;
      mac_byte_ipver = 0x2;
    }
  else
    {
      dst_mac = vrrp4_dst_mac;
      link_type = VNET_LINK_IP4;
      mac_byte_ipver = 0x1;
    }

  rewrite = ethernet_build_rewrite (vnm, vr->config.sw_if_index, link_type,
				    dst_mac);
  clib_memcpy (eth, rewrite, vec_len (rewrite));

  /* change the source mac from the HW addr to the VRRP virtual MAC */
  clib_memcpy
    (eth->src_address, vrrp_src_mac_prefix, sizeof (vrrp_src_mac_prefix));
  eth->src_address[4] = mac_byte_ipver;
  eth->src_address[5] = vr->config.vr_id;

  n_bytes += vec_len (rewrite);

  vlib_buffer_chain_increase_length (b, b, n_bytes);
  vlib_buffer_advance (b, n_bytes);

  vec_free (rewrite);

  return n_bytes;
}

#define VRRP4_MCAST_ADDR_AS_U8 { 224, 0, 0, 18 }
#define VRRP6_MCAST_ADDR_AS_U8 \
{ 0xff, 0x2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12 }

static const ip46_address_t vrrp4_mcast_addr = {
  .ip4 = {.as_u8 = VRRP4_MCAST_ADDR_AS_U8,},
};

static const ip46_address_t vrrp6_mcast_addr = {
  .ip6 = {.as_u8 = VRRP6_MCAST_ADDR_AS_U8,},
};

/* size of static parts of header + (# addrs * addr length) */
always_inline u16
vrrp_adv_payload_len (vrrp_vr_t * vr)
{
  u16 addr_len = vrrp_vr_is_ipv6 (vr) ? 16 : 4;

  return sizeof (vrrp_header_t) + (vec_len (vr->config.vr_addrs) * addr_len);
}

static int
vrrp_adv_l3_build (vrrp_vr_t * vr, vlib_buffer_t * b,
		   const ip46_address_t * dst)
{
  if (!vrrp_vr_is_ipv6 (vr))	/* IPv4 */
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b);

      clib_memset (ip4, 0, sizeof (*ip4));
      ip4->ip_version_and_header_length = 0x45;
      ip4->ttl = 255;
      ip4->protocol = IP_PROTOCOL_VRRP;
      clib_memcpy (&ip4->dst_address, &dst->ip4, sizeof (dst->ip4));
      fib_sas4_get (vr->config.sw_if_index, NULL, &ip4->src_address);
      ip4->length = clib_host_to_net_u16 (sizeof (*ip4) +
					  vrrp_adv_payload_len (vr));
      ip4->checksum = ip4_header_checksum (ip4);

      vlib_buffer_chain_increase_length (b, b, sizeof (*ip4));
      vlib_buffer_advance (b, sizeof (*ip4));

      return sizeof (*ip4);
    }
  else
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b);

      clib_memset (ip6, 0, sizeof (*ip6));
      ip6->ip_version_traffic_class_and_flow_label = 0x00000060;
      ip6->hop_limit = 255;
      ip6->protocol = IP_PROTOCOL_VRRP;
      clib_memcpy (&ip6->dst_address, &dst->ip6, sizeof (dst->ip6));
      ip6_address_copy (&ip6->src_address,
			ip6_get_link_local_address (vr->config.sw_if_index));
      ip6->payload_length = clib_host_to_net_u16 (vrrp_adv_payload_len (vr));

      vlib_buffer_chain_increase_length (b, b, sizeof (*ip6));
      vlib_buffer_advance (b, sizeof (*ip6));

      return sizeof (*ip6);
    }
}


u16
vrrp_adv_csum (void *l3_hdr, void *payload, u8 is_ipv6, u16 len)
{
  ip_csum_t csum = 0;
  u8 proto = IP_PROTOCOL_VRRP;
  int addr_len;
  int word_size = sizeof (uword);
  void *src_addr;
  int i;

  if (is_ipv6)
    {
      addr_len = 16;
      src_addr = &(((ip6_header_t *) l3_hdr)->src_address);
    }
  else
    {
      addr_len = 4;
      src_addr = &(((ip4_header_t *) l3_hdr)->src_address);
    }

  for (i = 0; i < (2 * addr_len); i += word_size)
    {
      if (word_size == sizeof (u64))
	csum =
	  ip_csum_with_carry (csum, clib_mem_unaligned (src_addr + i, u64));
      else
	csum =
	  ip_csum_with_carry (csum, clib_mem_unaligned (src_addr + i, u32));
    }

  csum = ip_csum_with_carry (csum,
			     clib_host_to_net_u32 (len + (proto << 16)));

  /* now do the payload */
  csum = ip_incremental_checksum (csum, payload, len);

  csum = ~ip_csum_fold (csum);

  return (u16) csum;
}

static int
vrrp_adv_payload_build (vrrp_vr_t * vr, vlib_buffer_t * b, int shutdown)
{
  vrrp_header_t *vrrp = vlib_buffer_get_current (b);
  void *l3_hdr;
  ip46_address_t *vr_addr;
  void *hdr_addr;
  u8 is_ipv6;
  u8 n_addrs;
  int len;

  n_addrs = vec_len (vr->config.vr_addrs);
  is_ipv6 = vrrp_vr_is_ipv6 (vr);

  if (is_ipv6)
    {
      ip6_header_t *ip6;

      len = sizeof (*vrrp) + n_addrs * sizeof (ip6_address_t);;
      l3_hdr = vlib_buffer_get_current (b) - sizeof (ip6_header_t);
      ip6 = l3_hdr;
      ip6->payload_length = clib_host_to_net_u16 (len);
    }
  else
    {
      len = sizeof (*vrrp) + n_addrs * sizeof (ip4_address_t);
      l3_hdr = vlib_buffer_get_current (b) - sizeof (ip4_header_t);
    }

  vrrp->vrrp_version_and_type = 0x31;
  vrrp->vr_id = vr->config.vr_id;
  vrrp->priority = (shutdown) ? 0 : vrrp_vr_priority (vr);
  vrrp->n_addrs = vec_len (vr->config.vr_addrs);
  vrrp->rsvd_and_max_adv_int = clib_host_to_net_u16 (vr->config.adv_interval);
  vrrp->checksum = 0;

  hdr_addr = (void *) (vrrp + 1);

  vec_foreach (vr_addr, vr->config.vr_addrs)
  {
    if (is_ipv6)
      {
	clib_memcpy (hdr_addr, &vr_addr->ip6, 16);
	hdr_addr += 16;
      }
    else
      {
	clib_memcpy (hdr_addr, &vr_addr->ip4, 4);
	hdr_addr += 4;
      }
  }

  vlib_buffer_chain_increase_length (b, b, vrrp_adv_payload_len (vr));

  vrrp->checksum =
    vrrp_adv_csum (l3_hdr, vrrp, is_ipv6, vrrp_adv_payload_len (vr));

  return len;
}

static_always_inline u32
vrrp_adv_next_node (vrrp_vr_t * vr)
{
  if (vrrp_vr_is_unicast (vr))
    {
      if (vrrp_vr_is_ipv6 (vr))
	return ip6_lookup_node.index;
      else
	return ip4_lookup_node.index;
    }
  else
    {
      vrrp_main_t *vmp = &vrrp_main;

      return vmp->intf_output_node_idx;
    }
}

static_always_inline const ip46_address_t *
vrrp_adv_mcast_addr (vrrp_vr_t * vr)
{
  if (vrrp_vr_is_ipv6 (vr))
    return &vrrp6_mcast_addr;

  return &vrrp4_mcast_addr;
}

int
vrrp_adv_send (vrrp_vr_t * vr, int shutdown)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_frame_t *to_frame;
  int i, n_buffers = 1;
  u32 node_index, *to_next, *bi = 0;
  u8 is_unicast = vrrp_vr_is_unicast (vr);

  node_index = vrrp_adv_next_node (vr);

  if (is_unicast)
    n_buffers = vec_len (vr->config.peer_addrs);

  if (n_buffers < 1)
    {
      /* A unicast VR will not start without peers added so this should
       * not happen. Just avoiding a crash if it happened somehow.
       */
      clib_warning ("Unicast VR configuration corrupted for %U",
		    format_vrrp_vr_key, vr);
      return -1;
    }

  vec_validate (bi, n_buffers - 1);
  if (vlib_buffer_alloc (vm, bi, n_buffers) != n_buffers)
    {
      clib_warning ("Buffer allocation failed for %U", format_vrrp_vr_key,
		    vr);
      vec_free (bi);
      return -1;
    }

  to_frame = vlib_get_frame_to_node (vm, node_index);
  to_next = vlib_frame_vector_args (to_frame);

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b;
      u32 bi0;
      const ip46_address_t *dst = vrrp_adv_mcast_addr (vr);

      bi0 = vec_elt (bi, i);
      b = vlib_get_buffer (vm, bi0);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
      b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (b)->sw_if_index[VLIB_TX] = vr->config.sw_if_index;

      if (is_unicast)
	{
	  dst = vec_elt_at_index (vr->config.peer_addrs, i);
	  vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
	}
      else
	vrrp_adv_l2_build_multicast (vr, b);

      vrrp_adv_l3_build (vr, b, dst);
      vrrp_adv_payload_build (vr, b, shutdown);

      vlib_buffer_reset (b);

      to_next[i] = bi0;
    }

  to_frame->n_vectors = n_buffers;

  vlib_put_frame_to_node (vm, node_index, to_frame);

  vec_free (bi);

  return 0;
}

static void
vrrp6_na_pkt_build (vrrp_vr_t * vr, vlib_buffer_t * b, ip6_address_t * addr6)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  ethernet_header_t *eth;
  ip6_header_t *ip6;
  icmp6_neighbor_solicitation_or_advertisement_header_t *na;
  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *ll_opt;
  int payload_length, bogus_length;
  int rewrite_bytes = 0;
  u8 *rewrite;
  u8 dst_mac[6];

  /* L2 headers */
  eth = vlib_buffer_get_current (b);

  ip6_multicast_ethernet_address (dst_mac, IP6_MULTICAST_GROUP_ID_all_hosts);
  rewrite =
    ethernet_build_rewrite (vnm, vr->config.sw_if_index, VNET_LINK_IP6,
			    dst_mac);
  rewrite_bytes += vec_len (rewrite);
  clib_memcpy (eth, rewrite, vec_len (rewrite));
  vec_free (rewrite);

  b->current_length += rewrite_bytes;
  vlib_buffer_advance (b, rewrite_bytes);

  /* IPv6 */
  ip6 = vlib_buffer_get_current (b);

  b->current_length += sizeof (*ip6);
  clib_memset (ip6, 0, sizeof (*ip6));

  ip6->ip_version_traffic_class_and_flow_label = 0x00000060;
  ip6->protocol = IP_PROTOCOL_ICMP6;
  ip6->hop_limit = 255;
  ip6_set_reserved_multicast_address (&ip6->dst_address,
				      IP6_MULTICAST_SCOPE_link_local,
				      IP6_MULTICAST_GROUP_ID_all_hosts);
  ip6_address_copy (&ip6->src_address,
		    ip6_get_link_local_address (vr->config.sw_if_index));


  /* ICMPv6 */
  na = (icmp6_neighbor_solicitation_or_advertisement_header_t *) (ip6 + 1);
  ll_opt =
    (icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *) (na +
								       1);

  payload_length = sizeof (*na) + sizeof (*ll_opt);
  b->current_length += payload_length;
  clib_memset (na, 0, payload_length);

  na->icmp.type = ICMP6_neighbor_advertisement;	/* icmp code, csum are 0 */
  na->target_address = *addr6;
  na->advertisement_flags = clib_host_to_net_u32
    (ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE
     | ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_ROUTER);

  ll_opt->header.type =
    ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address;
  ll_opt->header.n_data_u64s = 1;
  clib_memcpy (ll_opt->ethernet_address, vr->runtime.mac.bytes,
	       sizeof (vr->runtime.mac));

  ip6->payload_length = clib_host_to_net_u16 (payload_length);
  na->icmp.checksum =
    ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus_length);
}

const mac_address_t broadcast_mac = {
  .bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,},
};

static void
vrrp4_garp_pkt_build (vrrp_vr_t * vr, vlib_buffer_t * b, ip4_address_t * ip4)
{
  vnet_main_t *vnm = vnet_get_main ();
  ethernet_header_t *eth;
  ethernet_arp_header_t *arp;
  int rewrite_bytes;
  u8 *rewrite;

  eth = vlib_buffer_get_current (b);

  rewrite =
    ethernet_build_rewrite (vnm, vr->config.sw_if_index, VNET_LINK_ARP,
			    broadcast_mac.bytes);
  rewrite_bytes = vec_len (rewrite);
  clib_memcpy (eth, rewrite, rewrite_bytes);
  vec_free (rewrite);

  b->current_length += rewrite_bytes;
  vlib_buffer_advance (b, rewrite_bytes);

  arp = vlib_buffer_get_current (b);
  b->current_length += sizeof (*arp);

  clib_memset (arp, 0, sizeof (*arp));

  arp->l2_type = clib_host_to_net_u16 (ETHERNET_ARP_HARDWARE_TYPE_ethernet);
  arp->l3_type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);
  arp->n_l2_address_bytes = 6;
  arp->n_l3_address_bytes = 4;
  arp->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request);
  arp->ip4_over_ethernet[0].mac = vr->runtime.mac;
  arp->ip4_over_ethernet[0].ip4 = *ip4;
  arp->ip4_over_ethernet[1].mac = broadcast_mac;
  arp->ip4_over_ethernet[1].ip4 = *ip4;
}

int
vrrp_garp_or_na_send (vrrp_vr_t * vr)
{
  vlib_main_t *vm = vlib_get_main ();
  vrrp_main_t *vmp = &vrrp_main;
  vlib_frame_t *to_frame;
  u32 *bi = 0;
  u32 n_buffers;
  u32 *to_next;
  int i;

  if (vec_len (vr->config.peer_addrs))
    return 0;			/* unicast is used in routed environments - don't garp */

  n_buffers = vec_len (vr->config.vr_addrs);
  if (!n_buffers)
    {
      clib_warning ("Unable to send gratuitous ARP for VR %U - no addresses",
		    format_vrrp_vr_key, vr);
      return -1;
    }

  /* need to send a packet for each VR address */
  vec_validate (bi, n_buffers - 1);

  if (vlib_buffer_alloc (vm, bi, n_buffers) != n_buffers)
    {
      clib_warning ("Buffer allocation failed for %U", format_vrrp_vr_key,
		    vr);
      vec_free (bi);
      return -1;
    }

  to_frame = vlib_get_frame_to_node (vm, vmp->intf_output_node_idx);
  to_frame->n_vectors = 0;
  to_next = vlib_frame_vector_args (to_frame);

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b;
      ip46_address_t *addr;

      addr = vec_elt_at_index (vr->config.vr_addrs, i);
      b = vlib_get_buffer (vm, bi[i]);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
      b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (b)->sw_if_index[VLIB_TX] = vr->config.sw_if_index;

      if (vrrp_vr_is_ipv6 (vr))
	vrrp6_na_pkt_build (vr, b, &addr->ip6);
      else
	vrrp4_garp_pkt_build (vr, b, &addr->ip4);

      vlib_buffer_reset (b);

      to_next[i] = bi[i];
      to_frame->n_vectors++;
    }

  vlib_put_frame_to_node (vm, vmp->intf_output_node_idx, to_frame);

  return 0;
}

#define IGMP4_MCAST_ADDR_AS_U8 { 224, 0, 0, 22 }

static const ip4_header_t igmp_ip4_mcast = {
  .ip_version_and_header_length = 0x46,	/* there's options! */
  .ttl = 1,
  .protocol = IP_PROTOCOL_IGMP,
  .tos = 0xc0,
  .dst_address = {.as_u8 = IGMP4_MCAST_ADDR_AS_U8,},
};

static void
vrrp_igmp_pkt_build (vrrp_vr_t * vr, vlib_buffer_t * b)
{
  ip4_header_t *ip4;
  u8 *ip4_options;
  igmp_membership_report_v3_t *report;
  igmp_membership_group_v3_t *group;

  ip4 = vlib_buffer_get_current (b);
  clib_memcpy (ip4, &igmp_ip4_mcast, sizeof (*ip4));
  fib_sas4_get (vr->config.sw_if_index, NULL, &ip4->src_address);

  vlib_buffer_chain_increase_length (b, b, sizeof (*ip4));
  vlib_buffer_advance (b, sizeof (*ip4));

  ip4_options = (u8 *) (ip4 + 1);
  ip4_options[0] = 0x94;	/* 10010100 == the router alert option */
  ip4_options[1] = 0x04;	/* length == 4 bytes */
  ip4_options[2] = 0x0;		/* value == Router shall examine packet */
  ip4_options[3] = 0x0;		/* reserved */

  vlib_buffer_chain_increase_length (b, b, 4);
  vlib_buffer_advance (b, 4);

  report = vlib_buffer_get_current (b);

  report->header.type = IGMP_TYPE_membership_report_v3;
  report->header.code = 0;
  report->header.checksum = 0;
  report->unused = 0;
  report->n_groups = clib_host_to_net_u16 (1);

  vlib_buffer_chain_increase_length (b, b, sizeof (*report));
  vlib_buffer_advance (b, sizeof (*report));

  group = vlib_buffer_get_current (b);
  group->type = IGMP_MEMBERSHIP_GROUP_change_to_exclude;
  group->n_aux_u32s = 0;
  group->n_src_addresses = 0;
  group->group_address.as_u32 = clib_host_to_net_u32 (0xe0000012);

  vlib_buffer_chain_increase_length (b, b, sizeof (*group));
  vlib_buffer_advance (b, sizeof (*group));

  ip4->length = clib_host_to_net_u16 (b->current_data);
  ip4->checksum = ip4_header_checksum (ip4);

  int payload_len = vlib_buffer_get_current (b) - ((void *) report);
  report->header.checksum =
    ~ip_csum_fold (ip_incremental_checksum (0, report, payload_len));

  vlib_buffer_reset (b);
}

/* multicast listener report packet format for ethernet. */
typedef CLIB_PACKED (struct
		     {
		     ip6_hop_by_hop_ext_t ext_hdr;
		     ip6_router_alert_option_t alert;
		     ip6_padN_option_t pad;
		     icmp46_header_t icmp;
		     u16 rsvd;
		     u16 num_addr_records;
		     icmp6_multicast_address_record_t records[0];
		     }) icmp6_multicast_listener_report_header_t;

static void
vrrp_icmp6_mlr_pkt_build (vrrp_vr_t * vr, vlib_buffer_t * b)
{
  vlib_main_t *vm = vlib_get_main ();
  ip6_header_t *ip6;
  icmp6_multicast_listener_report_header_t *rh;
  icmp6_multicast_address_record_t *rr;
  ip46_address_t *vr_addr;
  int bogus_length, n_addrs;
  u16 payload_length;

  n_addrs = vec_len (vr->config.vr_addrs) + 1;
  payload_length = sizeof (*rh) + (n_addrs * sizeof (*rr));
  b->current_length = sizeof (*ip6) + payload_length;
  b->error = ICMP6_ERROR_NONE;

  ip6 = vlib_buffer_get_current (b);
  rh = (icmp6_multicast_listener_report_header_t *) (ip6 + 1);
  rr = (icmp6_multicast_address_record_t *) (rh + 1);

  /* IP header */
  clib_memset (ip6, 0, b->current_length);
  ip6->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x60000000);
  ip6->hop_limit = 1;
  ip6->protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS;
  ip6_set_reserved_multicast_address (&ip6->dst_address,
				      IP6_MULTICAST_SCOPE_link_local,
				      IP6_MULTICAST_GROUP_ID_mldv2_routers);
  ip6_address_copy (&ip6->src_address,
		    ip6_get_link_local_address (vr->config.sw_if_index));

  clib_memset (rh, 0, sizeof (*rh));

  /* v6 hop by hop extension header */
  rh->ext_hdr.next_hdr = IP_PROTOCOL_ICMP6;
  rh->ext_hdr.n_data_u64s = 0;

  rh->alert.type = IP6_MLDP_ALERT_TYPE;
  rh->alert.len = 2;
  rh->alert.value = 0;

  rh->pad.type = 1;
  rh->pad.len = 0;

  /* icmp6 header */
  rh->icmp.type = ICMP6_multicast_listener_report_v2;
  rh->icmp.checksum = 0;

  rh->rsvd = 0;
  rh->num_addr_records = clib_host_to_net_u16 (n_addrs);

  /* group addresses */

  /* All VRRP routers group */
  rr->type = 4;
  rr->aux_data_len_u32s = 0;
  rr->num_sources = 0;
  clib_memcpy
    (&rr->mcast_addr, &vrrp6_mcast_addr.ip6, sizeof (ip6_address_t));

  /* solicited node multicast addresses for VR addrs */
  vec_foreach (vr_addr, vr->config.vr_addrs)
  {
    u32 id;

    rr++;
    rr->type = 4;
    rr->aux_data_len_u32s = 0;
    rr->num_sources = 0;

    id = clib_net_to_host_u32 (vr_addr->ip6.as_u32[3]) & 0x00ffffff;
    ip6_set_solicited_node_multicast_address (&rr->mcast_addr, id);
  }

  ip6->payload_length = clib_host_to_net_u16 (payload_length);
  rh->icmp.checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6,
							 &bogus_length);
}

int
vrrp_vr_multicast_group_join (vrrp_vr_t * vr)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t *b;
  vlib_frame_t *f;
  vnet_main_t *vnm = vnet_get_main ();
  vrrp_intf_t *intf;
  u32 bi = 0, *to_next;
  int n_buffers = 1;
  u8 is_ipv6;
  u32 node_index;

  if (!vnet_sw_interface_is_up (vnm, vr->config.sw_if_index))
    return 0;

  if (vlib_buffer_alloc (vm, &bi, n_buffers) != n_buffers)
    {
      clib_warning ("Buffer allocation failed for %U", format_vrrp_vr_key,
		    vr);
      return -1;
    }

  is_ipv6 = vrrp_vr_is_ipv6 (vr);

  b = vlib_get_buffer (vm, bi);

  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = vr->config.sw_if_index;

  intf = vrrp_intf_get (vr->config.sw_if_index);
  vnet_buffer (b)->ip.adj_index[VLIB_TX] = intf->mcast_adj_index[is_ipv6];

  if (is_ipv6)
    {
      vrrp_icmp6_mlr_pkt_build (vr, b);
      node_index = ip6_rewrite_mcast_node.index;
    }
  else
    {
      vrrp_igmp_pkt_build (vr, b);
      node_index = ip4_rewrite_mcast_node.index;
    }

  f = vlib_get_frame_to_node (vm, node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, node_index, f);

  return f->n_vectors;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
