
/*
 * vrrp_packet.h - vrrp protocol/packet definitions
 *
 * Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef __included_vrrp_packet_h__
#define __included_vrrp_packet_h__

#include <vnet/vnet.h>

typedef CLIB_PACKED (struct
		     {
		     /* 4 bits for version (always 2 or 3), 4 bits for type (always 1) */
		     u8 vrrp_version_and_type;
		     /* VR ID */
		     u8 vr_id;
		     /* priority of sender on this VR. value of 0 means a master is abdicating */
		     u8 priority;
		     /* count of addresses being backed up by the VR */
		     u8 n_addrs;
		     /* max advertisement interval - first 4 bits are reserved and must be 0 */
		     u16 rsvd_and_max_adv_int;
		     /* checksum */
		     u16 checksum;
		     }) vrrp_header_t;

typedef CLIB_PACKED (struct
		     {
		     ip4_header_t ip4; vrrp_header_t vrrp;
		     }) ip4_and_vrrp_header_t;

typedef CLIB_PACKED (struct
		     {
		     ip6_header_t ip6; vrrp_header_t vrrp;
		     }) ip6_and_vrrp_header_t;

/* the high 4 bits of the advertisement interval are "reserved" and
 * should be ignored on reception. swap byte order and mask out those bits.
 */
always_inline u16
vrrp_adv_int_from_packet (vrrp_header_t * pkt)
{
  return clib_net_to_host_u16 (pkt->rsvd_and_max_adv_int) & ((u16) 0x0fff);
}

#endif /* __included_vrrp_packet_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
