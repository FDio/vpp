/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ethernet/packet.h: ethernet packet format. */

#ifndef included_ethernet_packet_h
#define included_ethernet_packet_h

#include <vnet/interface.h>

typedef enum
{
#define ethernet_type(n,s) ETHERNET_TYPE_##s = n,
#include <vnet/ethernet/types.def>
#undef ethernet_type
} __clib_packed ethernet_type_t;
STATIC_ASSERT (sizeof (ethernet_type_t) == 2, "Ethernet type should be 2 bytes");

typedef struct
{
  /* Source/destination address. */
  u8 dst_address[6];
  u8 src_address[6];

  /* Ethernet type. */
  u16 type;
} ethernet_header_t;

#define ETHERNET_ADDRESS_UNICAST 0
#define ETHERNET_ADDRESS_MULTICAST 1

/* I/G bit: individual (unicast)/group (broadcast/multicast). */
always_inline uword
ethernet_address_cast (const u8 * a)
{
  return (a[0] >> 0) & 1;
}

always_inline int
ethernet_address_is_broadcast (const u8 * a)
{
  return clib_mem_unaligned (a, u32) == 0xffffffff &&
    clib_mem_unaligned (a + 4, u16) == 0xffff;
}

always_inline uword
ethernet_address_is_locally_administered (const u8 * a)
{
  return (a[0] >> 1) & 1;
}

always_inline void
ethernet_address_set_locally_administered (u8 * a)
{
  a[0] |= 1 << 1;
}

always_inline int
eh_dst_addr_to_rx_ctype (const ethernet_header_t * eh)
{
  if (PREDICT_TRUE (ethernet_address_cast (eh->dst_address) ==
		    ETHERNET_ADDRESS_UNICAST))
    {
      return VNET_INTERFACE_COUNTER_RX_UNICAST;
    }
  else if (ethernet_address_is_broadcast (eh->dst_address))
    {
      return VNET_INTERFACE_COUNTER_RX_BROADCAST;
    }
  else
    {
      return VNET_INTERFACE_COUNTER_RX_MULTICAST;
    }
}

always_inline int
eh_dst_addr_to_tx_ctype (const ethernet_header_t * eh)
{
  if (PREDICT_TRUE (ethernet_address_cast (eh->dst_address) ==
		    ETHERNET_ADDRESS_UNICAST))
    {
      return VNET_INTERFACE_COUNTER_TX_UNICAST;
    }
  else if (ethernet_address_is_broadcast (eh->dst_address))
    {
      return VNET_INTERFACE_COUNTER_TX_BROADCAST;
    }
  else
    {
      return VNET_INTERFACE_COUNTER_TX_MULTICAST;
    }
}

/* For VLAN ethernet type. */
typedef struct
{
  /* 3 bit priority, 1 bit CFI and 12 bit vlan id. */
  u16 priority_cfi_and_id;

#define ETHERNET_N_VLAN (1 << 12)

  /* Inner ethernet type. */
  u16 type;
} ethernet_vlan_header_t;

always_inline void
ethernet_vlan_header_set_priority_net_order (ethernet_vlan_header_t * h,
					     u8 prio)
{
  u8 *bytes = (u8 *) (&h->priority_cfi_and_id);

  bytes[0] &= 0x0f;
  bytes[0] |= (prio & 0xf) << 4;
}

always_inline u8
ethernet_vlan_header_get_priority_net_order (ethernet_vlan_header_t * h)
{
  u8 *bytes = (u8 *) (&h->priority_cfi_and_id);

  return (bytes[0] >> 4);
}

/* VLAN with ethertype first and vlan id second */
typedef struct
{
  /* vlan type */
  u16 type;

  /* 3 bit priority, 1 bit CFI and 12 bit vlan id. */
  u16 priority_cfi_and_id;
} ethernet_vlan_header_tv_t;

/* PBB header with B-TAG - backbone VLAN indicator and I-TAG - service encapsulation */
typedef struct
{
  /* Backbone source/destination address. */
  u8 b_dst_address[6];
  u8 b_src_address[6];

  /* B-tag */
  u16 b_type;
  /* 3 bit priority, 1 bit DEI and 12 bit vlan id */
  u16 priority_dei_id;

  /* I-tag */
  u16 i_type;
  /* 3 bit priority, 1 bit DEI, 1 bit UCA, 3 bit RES and 24 bit I_SID (service identifier) */
  u32 priority_dei_uca_res_sid;

#define ETHERNET_N_PBB (1 << 24)
} ethernet_pbb_header_t;

typedef CLIB_PACKED (struct
{
  /* Backbone source/destination address. */
  u8 b_dst_address[6];
  u8 b_src_address[6];

  /* B-tag */
  u16 b_type;
  /* 3 bit priority, 1 bit DEI and 12 bit vlan id */
  u16 priority_dei_id;

  /* I-tag */
  u16 i_type;
  /* 3 bit priority, 1 bit DEI, 1 bit UCA, 3 bit RES and 24 bit I_SID (service identifier) */
  u32 priority_dei_uca_res_sid;
}) ethernet_pbb_header_packed_t;

#endif /* included_ethernet_packet_h */
