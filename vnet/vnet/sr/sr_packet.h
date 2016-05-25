#ifndef included_vnet_sr_packet_h
#define included_vnet_sr_packet_h

#include <vnet/ip/ip.h>

/*
 * ipv6 segment-routing header format
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

/*
 *   The Segment Routing Header (SRH) is defined as follows:
 *
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | Next Header   |  Hdr Ext Len  | Routing Type  | Segments Left |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | First Segment |             Flags             |  HMAC Key ID  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    |            Segment List[0] (128 bits ipv6 address)            |
 *    |                                                               |
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    |                                                               |
 *                                  ...
 *    |                                                               |
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    |            Segment List[n] (128 bits ipv6 address)            |
 *    |                                                               |
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    |            Policy List[0] (optional)                          |
 *    |                                                               |
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    |            Policy List[1] (optional)                          |
 *    |                                                               |
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    |            Policy List[2] (optional)                          |
 *    |                                                               |
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    |                                                               |
 *    |                                                               |
 *    |                       HMAC (256 bits)                         |
 *    |                        (optional)                             |
 *    |                                                               |
 *    |                                                               |
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   where:
 *
 *   o  Next Header: 8-bit selector.  Identifies the type of header
 *      immediately following the SRH.
 *
 *   o  Hdr Ext Len: 8-bit unsigned integer, is the length of the SRH
 *      header in 8-octet units, not including the first 8 octets.
 *
 *   o  Routing Type: TBD, to be assigned by IANA (suggested value: 4).
 *
 *   o  Segments Left.  Defined in [RFC2460], it contains the index, in
 *      the Segment List, of the next segment to inspect.  Segments Left
 *      is decremented at each segment and it is used as an index in the
 *      segment list.
 *
 *   o  First Segment: offset in the SRH, not including the first 8 octets
 *      and expressed in 16-octet units, pointing to the last element of
 *      the segment list, which is in fact the first segment of the
 *      segment routing path.
 *
 *   o  Flags: 16 bits of flags.  Following flags are defined:
 *
 *                              1
 *          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *         |C|P|R|R|    Policy Flags       |
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *         C-flag: Clean-up flag.  Set when the SRH has to be removed from
 *         the packet when packet reaches the last segment.
 *
 *         P-flag: Protected flag.  Set when the packet has been rerouted
 *         through FRR mechanism by a SR endpoint node.  See Section 6.3
 *         for more details.
 *
 *         R-flags.  Reserved and for future use.
 *
 *         Policy Flags.  Define the type of the IPv6 addresses encoded
 *         into the Policy List (see below).  The following have been
 *         defined:
 *
 *            Bits 4-6: determine the type of the first element after the
 *            segment list.
 *
 *            Bits 7-9: determine the type of the second element.
 *
 *            Bits 10-12: determine the type of the third element.
 *
 *            Bits 13-15: determine the type of the fourth element.
 *
 *         The following values are used for the type:
 *
 *            0x0: Not present.  If value is set to 0x0, it means the
 *            element represented by these bits is not present.
 *
 *            0x1: SR Ingress.
 *
 *            0x2: SR Egress.
 *
 *            0x3: Original Source Address.
 *
 *   o  HMAC Key ID and HMAC field, and their use are defined in
 *      [I-D.vyncke-6man-segment-routing-security].
 *
 *   o  Segment List[n]: 128 bit IPv6 addresses representing the nth
 *      segment in the Segment List.  The Segment List is encoded starting
 *      from the last segment of the path.  I.e., the first element of the
 *      segment list (Segment List [0]) contains the last segment of the
 *      path while the last segment of the Segment List (Segment List[n])
 *      contains the first segment of the path.  The index contained in
 *      "Segments Left" identifies the current active segment.
 *
 *   o  Policy List.  Optional addresses representing specific nodes in
 *      the SR path such as:
 *
 *         SR Ingress: a 128 bit generic identifier representing the
 *         ingress in the SR domain (i.e.: it needs not to be a valid IPv6
 *         address).
 *
 *         SR Egress: a 128 bit generic identifier representing the egress
 *         in the SR domain (i.e.: it needs not to be a valid IPv6
 *         address).
 *
 *         Original Source Address: IPv6 address originally present in the
 *         SA field of the packet.
 *
 *      The segments in the Policy List are encoded after the segment list
 *      and they are optional.  If none are in the SRH, all bits of the
 *      Policy List Flags MUST be set to 0x0.
 */

#ifndef IPPROTO_IPV6_ROUTE
#define IPPROTO_IPV6_ROUTE        43
#endif

#define ROUTING_HEADER_TYPE_SR    4

typedef struct {
  /* Protocol for next header. */
  u8 protocol;
  /*
   * Length of routing header in 8 octet units, 
   * not including the first 8 octets
   */
  u8 length;

  /* Type of routing header; type 4 = segement routing */
  u8 type;

  /* Next segment in the segment list */
  u8 segments_left;

  /* 
   * Policy list pointer: offset in the SRH of the policy
   * list - in 16-octet units - not including the first 8 octets.
   */
  u8 first_segment;

  /* Flag bits */
#define IP6_SR_HEADER_FLAG_CLEANUP    (0x8000)
#define IP6_SR_HEADER_FLAG_PROTECTED  (0x4000)
#define IP6_SR_HEADER_FLAG_RESERVED   (0x3000)

#define IP6_SR_HEADER_FLAG_PL_ELT_NOT_PRESENT (0x0)
#define IP6_SR_HEADER_FLAG_PL_ELT_INGRESS_PE (0x1)
#define IP6_SR_HEADER_FLAG_PL_ELT_EGRESS_PE (0x2)
#define IP6_SR_HEADER_FLAG_PL_ELT_ORIG_SRC_ADDR (0x3)
  /* values 0x4 - 0x7 are reserved */
  u16 flags;
  u8 hmac_key;
  
  /* The segment + policy list elts */
  ip6_address_t segments[0];
} __attribute__((packed)) ip6_sr_header_t; 

static inline int
ip6_sr_policy_list_shift_from_index (int pl_index)
{
  return (-3 * pl_index) + 12;
}

/* pl_index is one-origined, to match the text above */
static inline int 
ip6_sr_policy_list_flags (u16 flags_host_byte_order, int pl_index)
{
  int shift;

  if (pl_index <= 0 || pl_index > 4)
    return 0;

  shift = (-3 * pl_index) + 12;
  flags_host_byte_order >>= shift;

  return (flags_host_byte_order & 7);
}

#endif /* included_vnet_sr_packet_h */
