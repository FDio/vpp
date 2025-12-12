/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2009 Eliot Dresselhaus
 */

/* HDLC packet format */

#ifndef included_vnet_hdlc_packet_h
#define included_vnet_hdlc_packet_h

#define foreach_hdlc_protocol			\
  _ (0x0800, ip4)				\
  _ (0x2000, cdp)				\
  _ (0x8035, slarp)				\
  _ (0x8847, mpls_unicast)			\
  _ (0x8848, mpls_multicast)			\
  _ (0x86dd, ip6)				\
  _ (0xfefe, osi)

typedef enum
{
#define _(n,f) HDLC_PROTOCOL_##f = n,
  foreach_hdlc_protocol
#undef _
} hdlc_protocol_t;

typedef struct
{
  /* Set to 0x0f for unicast; 0x8f for broadcast. */
  u8 address;

  /* Always zero. */
  u8 control;

  /* Layer 3 protocol for this packet. */
  u16 protocol;

  /* Layer 3 payload. */
  u8 payload[0];
} hdlc_header_t;

#endif /* included_vnet_hdlc_packet_h */
