/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#ifndef __included_vxlan_gbp_packet_h__
#define __included_vxlan_gbp_packet_h__ 1

/*
 * From draft-smith-vxlan-group-policy-04.txt
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |G|R|R|R|I|R|R|R|R|D|E|S|A|R|R|R|        Group Policy ID        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                VXLAN Network Identifier (VNI) |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * G bit: Bit 0 of the initial word is defined as the G (Group Based
 *   Policy Extension) bit.
 *
 * I bit: where the I flag MUST be set to 1 for a valid
 *   VXLAN Network ID (VNI).
 *
 * D bit: Bit 9 of the initial word is defined as the Don't Learn bit.
 *   When set, this bit indicates that the egress VTEP MUST NOT learn the
 *   source address of the encapsulated frame.
 *
 * E bit: Bit 10 of the initial word is defined as the bounce packet.
 *   When set, this bit indicates that packet is bounced and must be
 *   dropped.
 *
 * S bit: Bit 11 of the initial word is defined as the source policy
 *   applied bit.
 *
 *
 *
 * A bit: Bit 12 of the initial word is defined as the A (Policy
 *   Applied) bit.  This bit is only defined as the A bit when the G bit
 *   is set to 1.
 *
 *    A = 1 indicates that the group policy has already been applied to
 *    this packet.  Policies MUST NOT be applied by devices when the A
 *    bit is set.
 *
 *    A = 0 indicates that the group policy has not been applied to this
 *    packet.  Group policies MUST be applied by devices when the A bit
 *    is set to 0 and the destination Group has been determined.
 *    Devices that apply the Group policy MUST set the A bit to 1 after
 *    the policy has been applied.
 *
 * Group Policy ID: 16 bit identifier that indicates the source TSI
 *   Group membership being encapsulated by VXLAN. Its value is source
 *   class id.
 *
 */

typedef struct
{
  u16 flags;
  u16 sclass;
  u32 vni_reserved;
} vxlan_gbp_header_t;

#define foreach_vxlan_gbp \
_ (0x8000, G)             \
_ (0x0800, I)             \
_ (0x0040, D)             \
_ (0x0020, E)             \
_ (0x0010, S)             \
_ (0x0008, A)

typedef enum
{
#define _(n,f) VXLAN_GBP_FLAGS_##f = n,
  foreach_vxlan_gbp
#undef _
} vxlan_gbp_flag_t;

static inline u32
vnet_get_vni (vxlan_gbp_header_t * h)
{
  u32 vni_reserved_host_byte_order;

  vni_reserved_host_byte_order = clib_net_to_host_u32 (h->vni_reserved);
  return vni_reserved_host_byte_order >> 8;
}

static inline u16
vnet_get_sclass (vxlan_gbp_header_t * h)
{
  u16 sclass_host_byte_order;

  sclass_host_byte_order = clib_net_to_host_u16 (h->sclass);
  return sclass_host_byte_order;
}

static inline u16
vnet_get_flags (vxlan_gbp_header_t * h)
{
  u16 flags_host_byte_order;

  flags_host_byte_order = clib_net_to_host_u16 (h->flags);
  return flags_host_byte_order;
}

static inline void
vnet_set_vxlan_gbp_header (vxlan_gbp_header_t * h, u32 vni, u16 flags,
			   u16 sclass)
{
  h->vni_reserved = clib_host_to_net_u32 (vni << 8);
  *(u32 *) h = 0;
  h->flags = clib_host_to_net_u16 (flags);
  h->sclass = clib_host_to_net_u16 (sclass);
}

#endif /* __included_vxlan_gbp_packet_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
