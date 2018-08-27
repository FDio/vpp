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
#ifndef included_nsh_packet_h
#define included_nsh_packet_h

/*
 * NSH packet format from draft-quinn-sfc-nsh-03.txt
 *
 * NSH Base Header
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Ver|O|C|    TTL    |   Length  |    MD Type    | Next Protocol |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * 
 * Base Header Field Descriptions:
 * 
 * Version: The version field is used to ensure backward compatibility
 * going forward with future NSH updates.
 * 
 * O bit: Indicates that this packet is an operations and management
 * (OAM) packet.  SFF and SFs nodes MUST examine the payload and take
 * appropriate action (e.g. return status information).
 * 
 * OAM message specifics and handling details are outside the scope of
 * this document.
 * 
 * C bit: Indicates that a critical metadata TLV is present (see section
 * 7).  This bit acts as an indication for hardware implementers to
 * decide how to handle the presence of a critical TLV without
 * necessarily needing to parse all TLVs present.  The C bit MUST be set
 * to 1 if one or more critical TLVs are present.
 * 
 * All other flag fields are reserved.
 * 
 * Length: total length, in 4 byte words, of the NSH header, including
 * optional variable TLVs.  Length must be equal or greater than 6.
 * 
 * MD Type: indicates the format of NSH beyond the base header and the
 * type of metadata being carried.  This typing is used to describe the
 * use for the metadata.  A new registry will be requested from IANA for
 * the MD Type.  NSH defines one type, type = 0x1 which indicates that
 * the format of the header is as per this draft.
 * 
 * The format of the base header is invariant, and not described by MD
 * Type.
 * 
 * Next Protocol: indicates the protocol type of the original packet.  A
 * new IANA registry will be created for protocol type.
 * 
 * This draft defines the following Next Protocol values:
 * 
 * 0x1 : IPv4
 * 0x2 : IPv6
 * 0x3 : Ethernet
 */

typedef CLIB_PACKED(struct {
  u8 ver_o_c; //TTL: high 4 bit
  u8 length;  //TTL: low 2 bit
  u8 md_type;
  u8 next_protocol;
  u32 nsp_nsi; // nsp 24 bits, nsi 8 bits
}) nsh_base_header_t;

typedef CLIB_PACKED(struct {
  /* Context headers, always present */
  u32 c1;
  u32 c2;
  u32 c3;
  u32 c4;
}) nsh_md1_data_t;

typedef CLIB_PACKED(struct {
  u16 class;
  u8 type;
  u8 length;
}) nsh_tlv_header_t;

typedef nsh_tlv_header_t nsh_md2_data_t;

typedef CLIB_PACKED(struct {
  nsh_base_header_t nsh_base;
  union {
     nsh_md1_data_t md1_data;
     nsh_md2_data_t md2_data;
   } md;
}) nsh_header_t;

#define NSH_VERSION (0<<6)
#define NSH_O_BIT (1<<5)
#define NSH_C_BIT (1<<4)

#define NSH_TTL_H4_MASK 0xF
#define NSH_TTL_L2_MASK 0xC0
#define NSH_LEN_MASK 0x3F

/* Network byte order shift / mask */
#define NSH_NSI_MASK 0xFF
#define NSH_NSP_MASK (0x00FFFFFF)
#define NSH_NSP_SHIFT 8

#endif /* included_nsh_packet_h */
