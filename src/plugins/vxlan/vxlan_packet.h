/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef __included_vxlan_packet_h__
#define __included_vxlan_packet_h__ 1

/*
 * From RFC-7348
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |R|R|R|R|I|R|R|R|            Reserved                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                VXLAN Network Identifier (VNI) |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * VXLAN Header:  This is an 8-byte field that has:
 *
 * - Flags (8 bits): where the I flag MUST be set to 1 for a valid
 * VXLAN Network ID (VNI).  The other 7 bits (designated "R") are
 * reserved fields and MUST be set to zero on transmission and
 * ignored on receipt.
 *
 * - VXLAN Segment ID/VXLAN Network Identifier (VNI): this is a
 * 24-bit value used to designate the individual VXLAN overlay
 * network on which the communicating VMs are situated.  VMs in
 * different VXLAN overlay networks cannot communicate with each
 * other.
 *
 * - Reserved fields (24 bits and 8 bits): MUST be set to zero on
 * transmission and ignored on receipt.
 *
 */

typedef struct
{
  u8 flags;
  u8 res1;
  u8 res2;
  u8 res3;
  u32 vni_reserved;
} vxlan_header_t;

#define VXLAN_FLAGS_I 0x08

static inline u32
vnet_get_vni (vxlan_header_t * h)
{
  u32 vni_reserved_host_byte_order;

  vni_reserved_host_byte_order = clib_net_to_host_u32 (h->vni_reserved);
  return vni_reserved_host_byte_order >> 8;
}

static inline void
vnet_set_vni_and_flags (vxlan_header_t * h, u32 vni)
{
  h->vni_reserved = clib_host_to_net_u32 (vni << 8);
  *(u32 *) h = 0;
  h->flags = VXLAN_FLAGS_I;
}

#endif /* __included_vxlan_packet_h__ */
