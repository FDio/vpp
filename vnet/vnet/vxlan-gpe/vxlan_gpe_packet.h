/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 *  @brief VXLAN GPE packet header structure
 *
*/
#ifndef included_vxlan_gpe_packet_h
#define included_vxlan_gpe_packet_h

/**
 *   From draft-quinn-vxlan-gpe-03.txt
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |R|R|R|R|I|P|R|O|Ver|   Reserved                |Next Protocol  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                VXLAN Network Identifier (VNI) |   Reserved    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   I Bit: Flag bit 4 indicates that the VNI is valid. 
 *
 *   P Bit:  Flag bit 5 is defined as the Next Protocol bit.  The P bit
 *      MUST be set to 1 to indicate the presence of the 8 bit next
 *      protocol field.
 *
 *   O Bit: Flag bit 7 is defined as the O bit. When the O bit is set to 1, 
 *
 *      the packet is an OAM packet and OAM processing MUST occur.  The OAM
 *      protocol details are out of scope for this document.  As with the
 *      P-bit, bit 7 is currently a reserved flag in VXLAN.
 *
 *   VXLAN-gpe bits 8 and 9 are defined as version bits.  These bits are
 *   reserved in VXLAN.  The version field is used to ensure backward
 *   compatibility going forward with future VXLAN-gpe updates.
 *
 *   The initial version for VXLAN-gpe is 0.
 *
 *   This draft defines the following Next Protocol values:
 *
 *      0x1 : IPv4
 *      0x2 : IPv6
 *      0x3 : Ethernet
 *      0x4 : Network Service Header [NSH]
 */

/**
 * @brief VXLAN GPE support inner protocol definition.
 * 1 - IP4
 * 2 - IP6
 * 3 - ETHERNET
 * 4 - NSH
 */
#define foreach_vxlan_gpe_protocol \
_ (0x01, IP4)                         \
_ (0x02, IP6)                         \
_ (0x03, ETHERNET)		     \
_ (0x04, NSH)		     \
_ (0x05, IOAM)


/**
 * @brief Struct for VXLAN GPE support inner protocol definition.
 * 1 - IP4
 * 2 - IP6
 * 3 - ETHERNET
 * 4 - NSH
 * 5 - IOAM
 */
typedef enum {
#define _(n,f) VXLAN_GPE_PROTOCOL_##f = n,
  foreach_vxlan_gpe_protocol
#undef _
  VXLAN_GPE_PROTOCOL_MAX,
} vxlan_gpe_protocol_t;

/**
 * @brief VXLAN GPE Header definition
 */
typedef struct {
  u8 flags;
  /** Version and Reserved */
  u8 ver_res;
  /** Reserved */
  u8 res;
  /** see vxlan_gpe_protocol_t */
  u8 protocol;
  /** VNI and Reserved */
  u32 vni_res;
} vxlan_gpe_header_t;

#define VXLAN_GPE_FLAGS_I 0x08
#define VXLAN_GPE_FLAGS_P 0x04
#define VXLAN_GPE_FLAGS_O 0x01
#define VXLAN_GPE_VERSION 0x0

#endif /* included_vxlan_gpe_packet_h */
