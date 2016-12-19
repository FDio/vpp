/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
/**
 *  @file
 *  @brief LISP-GPE packet header structure
 *
 */

#ifndef included_lisp_gpe_packet_h
#define included_lisp_gpe_packet_h

/*
 *   From draft-lewis-lisp-gpe-02.txt
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |N|L|E|V|I|P|R|O|Ver|      Reserved             | Next Protocol |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Instance ID/Locator-Status-Bits               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   N: The N-bit is the nonce-present bit.  When this bit is set to 1,
 *     the low-order 24 bits of the first 32 bits of the LISP header
 *     contain a Nonce.  See Section 6.3.1 for details.  Both N- and
 *     V-bits MUST NOT be set in the same packet.  If they are, a
 *     decapsulating ETR MUST treat the 'Nonce/Map-Version' field as
 *     having a Nonce value present.
 *
 *  L: The L-bit is the 'Locator-Status-Bits' field enabled bit.  When
 *     this bit is set to 1, the Locator-Status-Bits in the second
 *     32 bits of the LISP header are in use.
 *
 *  E: The E-bit is the echo-nonce-request bit.  This bit MUST be ignored
 *     and has no meaning when the N-bit is set to 0.  When the N-bit is
 *     set to 1 and this bit is set to 1, an ITR is requesting that the
 *     nonce value in the 'Nonce' field be echoed back in LISP-
 *     encapsulated packets when the ITR is also an ETR.  See
 *     Section 6.3.1 for details.
 *
 *  V: The V-bit is the Map-Version present bit.  When this bit is set to
 *     1, the N-bit MUST be 0.  Refer to Section 6.6.3 for more details.
 *
 *  I: The I-bit is the Instance ID bit.  See Section 5.5 for more
 *     details.  When this bit is set to 1, the 'Locator-Status-Bits'
 *     field is reduced to 8 bits and the high-order 24 bits are used as
 *     an Instance ID.  If the L-bit is set to 0, then the low-order
 *     8 bits are transmitted as zero and ignored on receipt.
 *
 * P Bit:  Flag bit 5 is defined as the Next Protocol bit.  The P bit
 *    MUST be set to 1 to indicate the presence of the 8 bit next
 *    protocol field.
 *
 *    P = 0 indicates that the payload MUST conform to LISP as defined
 *    in [RFC6830].
 *
 *    Flag bit 5 was chosen as the P bit because this flag bit is
 *    currently unallocated in LISP [RFC6830].
 *
 *  O: Flag bit 7 is defined as the O bit.  When the O bit is set to 1, the
 *  packet is an OAM packet and OAM processing MUST occur.  The OAM
 *  protocol details are out of scope for this document.  As with the
 *  P-bit, bit 7 is currently a reserved flag in [RFC6830].
 *
 * Next Protocol Field:  The lower 8 bits of the first word are used to
 *    carry a next protocol.  This next protocol field contains the
 *    protocol of the encapsulated payload packet.
 *
 *    LISP [RFC6830] uses the lower 16 bits of the first word for either
 *    a nonce, an echo-nonce ([RFC6830]) or to support map-versioning
 *    ([RFC6834]).  These are all optional capabilities that are
 *    indicated by setting the N, E, and the V bit respectively.
 *
 *    To maintain the desired data plane compatibility, when the P bit
 *    is set, the N, E, and V bits MUST be set to zero.
 *
 * A new protocol registry will be requested from IANA for the Next
 * Protocol field.  This draft defines the following Next Protocol
 * values:
 *
 *    0x1 : IPv4
 *    0x2 : IPv6
 *    0x3 : Ethernet
 *    0x4: Network Service Header
 */

/** LISP-GPE header */
typedef struct
{
  u8 flags;
  u8 ver_res;
  u8 res;
  u8 next_protocol;
  u32 iid;
} lisp_gpe_header_t;

#define foreach_lisp_gpe_flag_bit               \
_(N, 0x80)                                      \
_(L, 0x40)                                      \
_(E, 0x20)                                      \
_(V, 0x10)                                      \
_(I, 0x08)                                      \
_(P, 0x04)                                      \
_(O, 0x01)

typedef enum
{
#define _(n,v) LISP_GPE_FLAGS_##n = v,
  foreach_lisp_gpe_flag_bit
#undef _
} vnet_lisp_gpe_flag_bit_t;

#define LISP_GPE_VERSION 0x0

#define LISP_GPE_NEXT_PROTOCOL_IP4 0x1
#define LISP_GPE_NEXT_PROTOCOL_IP6 0x2
#define LISP_GPE_NEXT_PROTOCOL_ETHERNET 0x3
#define LISP_GPE_NEXT_PROTOCOL_NSH 0x4

typedef enum
{
  LISP_GPE_NEXT_PROTO_IP4 = 1,
  LISP_GPE_NEXT_PROTO_IP6,
  LISP_GPE_NEXT_PROTO_ETHERNET,
  LISP_GPE_NEXT_PROTO_NSH,
  LISP_GPE_NEXT_PROTOS
} lisp_gpe_next_protocol_e;

#endif /* included_lisp_gpe_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
