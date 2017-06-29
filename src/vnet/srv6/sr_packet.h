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
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Next Header   |  Hdr Ext Len  | Routing Type  | Segments Left |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | First Segment |     Flags     |           RESERVED            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |            Segment List[0] (128 bits IPv6 address)            |
 *   |                                                               |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |                                                               |
 *                                 ...
 *   |                                                               |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |            Segment List[n] (128 bits IPv6 address)            |
 *   |                                                               |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   //                                                             //
 *   //         Optional Type Length Value objects (variable)       //
 *   //                                                             //
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
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
 *      is decremented at each segment.
 *
 *   o  First Segment: contains the index, in the Segment List, of the
 *      first segment of the path which is in fact the last element of the
 *      Segment List.
 *
 *   o  Flags: 8 bits of flags.  Following flags are defined:
 *
 *         0 1 2 3 4 5 6 7
 *        +-+-+-+-+-+-+-+-+
 *        |U|P|O|A|H|  U  |
 *        +-+-+-+-+-+-+-+-+
 *
 *        U: Unused and for future use.  SHOULD be unset on transmission
 *        and MUST be ignored on receipt.
 *
 *        P-flag: Protected flag.  Set when the packet has been rerouted
 *        through FRR mechanism by an SR endpoint node.
 *
 *        O-flag: OAM flag.  When set, it indicates that this packet is
 *        an operations and management (OAM) packet.
 *
 *        A-flag: Alert flag.  If present, it means important Type Length
 *        Value (TLV) objects are present.  See Section 3.1 for details
 *        on TLVs objects.
 *
 *        H-flag: HMAC flag.  If set, the HMAC TLV is present and is
 *        encoded as the last TLV of the SRH.  In other words, the last
 *        36 octets of the SRH represent the HMAC information.  See
 *        Section 3.1.5 for details on the HMAC TLV.
 *
 *   o  RESERVED: SHOULD be unset on transmission and MUST be ignored on
 *      receipt.
 *
 *   o  Segment List[n]: 128 bit IPv6 addresses representing the nth
 *      segment in the Segment List.  The Segment List is encoded starting
 *      from the last segment of the path.  I.e., the first element of the
 *      segment list (Segment List [0]) contains the last segment of the
 *      path while the last segment of the Segment List (Segment List[n])
 *      contains the first segment of the path.  The index contained in
 *      "Segments Left" identifies the current active segment.
 *
 *   o  Type Length Value (TLV) are described in Section 3.1.
 *
 */

#ifndef IPPROTO_IPV6_ROUTE
#define IPPROTO_IPV6_ROUTE        43
#endif

#define ROUTING_HEADER_TYPE_SR    4

typedef struct
{
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

  /* Pointer to the first segment in the header */
  u8 first_segment;

  /* Flag bits */
#define IP6_SR_HEADER_FLAG_PROTECTED  (0x40)
#define IP6_SR_HEADER_FLAG_OAM        (0x20)
#define IP6_SR_HEADER_FLAG_ALERT      (0x10)
#define IP6_SR_HEADER_FLAG_HMAC       (0x80)

  /* values 0x0, 0x4 - 0x7 are reserved */
  u8 flags;
  u16 reserved;

  /* The segment elts */
  ip6_address_t segments[0];
} __attribute__ ((packed)) ip6_sr_header_t;

typedef struct
{
  u8 type;
  u8 length;
  u16 reserved;
  u32 data[0];
} __attribute__ ((packed)) ip6_sr_tlv_header_t;

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/

#endif /* included_vnet_sr_packet_h */
