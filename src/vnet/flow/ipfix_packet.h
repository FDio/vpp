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
#ifndef __included_ipfix_packet_h__
#define __included_ipfix_packet_h__

#include <vnet/flow/ipfix_info_elements.h>

/* From RFC-7011:
 * https://tools.ietf.org/html/rfc7011
 */

typedef struct
{
  u32 version_length;
  u32 export_time;
  u32 sequence_number;
  u32 domain_id;
} ipfix_message_header_t;

static inline u32
version_length (u16 length)
{
  return clib_host_to_net_u32 (0x000a0000 | length);
}


/*
 *   The Field Specifier format is shown in Figure G.
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |E|  Information Element ident. |        Field Length           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                      Enterprise Number                        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *                     Figure G: Field Specifier Format
 *
 *   Where:
 *
 *   E
 *
 *      Enterprise bit.  This is the first bit of the Field Specifier.  If
 *      this bit is zero, the Information Element identifier identifies an
 *      Information Element in [IANA-IPFIX], and the four-octet Enterprise
 *      Number field MUST NOT be present.  If this bit is one, the
 *      Information Element identifier identifies an enterprise-specific
 *      Information Element, and the Enterprise Number field MUST be
 *      present.
 */

typedef struct
{
  u32 e_id_length;
  u32 enterprise;
} ipfix_enterprise_field_specifier_t;

typedef struct
{
  u32 e_id_length;
} ipfix_field_specifier_t;

static inline u32
ipfix_e_id_length (int e, u16 id, u16 length)
{
  u32 value;
  value = (e << 31) | ((id & 0x7FFF) << 16) | length;
  return clib_host_to_net_u32 (value);
}

/*
 *   Every Set contains a common header.  This header is defined in
 *   Figure I.
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |          Set ID               |          Length               |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *                        Figure I: Set Header Format
 *
 *   Each Set Header field is exported in network format.  The fields are
 *   defined as follows:
 *
 *   Set ID
 *
 *      Identifies the Set.  A value of 2 is reserved for Template Sets.
 *      A value of 3 is reserved for Options Template Sets.  Values from 4
 *      to 255 are reserved for future use.  Values 256 and above are used
 *      for Data Sets.  The Set ID values of 0 and 1 are not used, for
 *      historical reasons [RFC3954].
 *
 *   Length
 *
 *      Total length of the Set, in octets, including the Set Header, all
 *      records, and the optional padding.  Because an individual Set MAY
 *      contain multiple records, the Length value MUST be used to
 *      determine the position of the next Set.
 */

typedef struct
{
  u32 set_id_length;
} ipfix_set_header_t;

static inline u32
ipfix_set_id_length (u16 set_id, u16 length)
{
  return clib_host_to_net_u32 ((set_id << 16) | length);
}

/*
 *   The format of the Template Record is shown in Figure J.  It consists
 *   of a Template Record Header and one or more Field Specifiers.  Field
 *   Specifiers are defined in Figure G above.
 *
 *           +--------------------------------------------------+
 *           | Template Record Header                           |
 *           +--------------------------------------------------+
 *           | Field Specifier                                  |
 *           +--------------------------------------------------+
 *           | Field Specifier                                  |
 *           +--------------------------------------------------+
 *            ...
 *           +--------------------------------------------------+
 *           | Field Specifier                                  |
 *           +--------------------------------------------------+
 *
 *                     Figure J: Template Record Format
 *
 *   The format of the Template Record Header is shown in Figure K.
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |      Template ID (> 255)      |         Field Count           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *                  Figure K: Template Record Header Format
 *
 *   The Template Record Header Field definitions are as follows:
 *
 *   Template ID
 *
 *      Each Template Record is given a unique Template ID in the range
 *      256 to 65535.  This uniqueness is local to the Transport Session
 *      and Observation Domain that generated the Template ID.  Since
 *      Template IDs are used as Set IDs in the Sets they describe (see
 *      Section 3.4.3), values 0-255 are reserved for special Set types
 *      (e.g., Template Sets themselves), and Templates and Options
 *      Templates (see Section 3.4.2) cannot share Template IDs within a
 *      Transport Session and Observation Domain.  There are no
 *      constraints regarding the order of the Template ID allocation.  As
 *      Exporting Processes are free to allocate Template IDs as they see
 *      fit, Collecting Processes MUST NOT assume incremental Template
 *      IDs, or anything about the contents of a Template based on its
 *      Template ID alone.
 *
 *   Field Count
 *
 *      Number of fields in this Template Record.
 */

typedef struct
{
  u32 id_count;
} ipfix_template_header_t;

static inline u32
ipfix_id_count (u16 id, u16 count)
{
  return clib_host_to_net_u32 ((id << 16) | count);
}

/* Template packet */
typedef struct
{
  ipfix_message_header_t h;
  ipfix_set_header_t s;
  ipfix_template_header_t t;
  ipfix_field_specifier_t fields[0];
} ipfix_template_packet_t;

#endif /* __included_ipfix_packet_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
