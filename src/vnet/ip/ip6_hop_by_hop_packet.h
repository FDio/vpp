/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef __included_ip6_hop_by_hop_packet_h__
#define __included_ip6_hop_by_hop_packet_h__

typedef struct
{
  /* Protocol for next header */
  u8 protocol;
  /*
   * Length of hop_by_hop header in 8 octet units,
   * not including the first 8 octets
   */
  u8 length;
} ip6_hop_by_hop_header_t;

typedef struct
{
  /* Option Type */
#define HBH_OPTION_TYPE_SKIP_UNKNOWN (0x00)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN (0x40)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN_ICMP (0x80)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN_ICMP_NOT_MCAST (0xc0)
#define HBH_OPTION_TYPE_HIGH_ORDER_BITS (0xc0)
#define HBH_OPTION_TYPE_DATA_CHANGE_ENROUTE (1<<5)
  u8 type;
  /* Length in octets of the option data field */
  u8 length;
} ip6_hop_by_hop_option_t;

/* $$$$ IANA banana constants */
#define HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST 59	/* Third highest bit set (change en-route) */
#define HBH_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT 60	/* Third highest bit set (change en-route) */
#define HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE 29

#endif /* __included_ip6_hop_by_hop_packet_h__ */
