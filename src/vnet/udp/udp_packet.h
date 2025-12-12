/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015-2019 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip4/udp_packet.h: UDP packet format */

#ifndef included_udp_packet_h
#define included_udp_packet_h

#include <vppinfra/clib.h>

typedef struct
{
  /* Source and destination port. */
  u16 src_port, dst_port;

  /* Length of UDP header plus payload. */
  u16 length;

  /* Checksum of UDP pseudo-header and data or
     zero if checksum is disabled. */
  u16 checksum;
} udp_header_t;

#endif /* included_udp_packet_h */
