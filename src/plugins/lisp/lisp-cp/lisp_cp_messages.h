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

#ifndef VNET_LISP_GPE_LISP_CP_MESSAGES_H_
#define VNET_LISP_GPE_LISP_CP_MESSAGES_H_

#include <vnet/vnet.h>

#define MAX_IP_PKT_LEN 4096
#define MAX_IP_HDR_LEN 40	/* without options or IPv6 hdr extensions */
#define UDP_HDR_LEN 8
#define LISP_DATA_HDR_LEN 8
#define LISP_ECM_HDR_LEN 4
#define MAX_LISP_MSG_ENCAP_LEN  2*(MAX_IP_HDR_LEN + UDP_HDR_LEN)+ LISP_ECM_HDR_LEN
#define MAX_LISP_PKT_ENCAP_LEN  MAX_IP_HDR_LEN + UDP_HDR_LEN + LISP_DATA_HDR_LEN

#define LISP_CONTROL_PORT 4342

/*
 * EID RECORD FIELD
 */

/*
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \ |                       EID-prefix  ...                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


typedef struct _eid_prefix_record_hdr
{
  u8 reserved;
  u8 eid_prefix_length;
} __attribute__ ((__packed__)) eid_record_hdr_t;

void eid_rec_hdr_init (eid_record_hdr_t * ptr);

#define EID_REC_CAST(h_) ((eid_record_hdr_t *)(h_))
#define EID_REC_MLEN(h_) EID_REC_CAST((h_))->eid_prefix_length
#define EID_REC_ADDR(h) (u8 *)(h) + sizeof(eid_record_hdr_t)

/* LISP Types */
typedef enum
{
  NOT_LISP_MSG,
  LISP_MAP_REQUEST = 1,
  LISP_MAP_REPLY,
  LISP_MAP_REGISTER,
  LISP_MAP_NOTIFY,
  LISP_INFO_NAT = 7,
  LISP_ENCAP_CONTROL_TYPE = 8,
  LISP_MSG_TYPES
} lisp_msg_type_e;

/*
 * ENCAPSULATED CONTROL MESSAGE
 */

/*
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   / |                       IPv4 or IPv6 Header                     |
 * OH  |                      (uses RLOC addresses)                    |
 *   \ |                                                               |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   / |       Source Port = xxxx      |       Dest Port = 4342        |
 * UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   \ |           UDP Length          |        UDP Checksum           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * LH  |Type=8 |S|                  Reserved                           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   / |                       IPv4 or IPv6 Header                     |
 * IH  |                  (uses RLOC or EID addresses)                 |
 *   \ |                                                               |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   / |       Source Port = xxxx      |       Dest Port = yyyy        |
 * UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   \ |           UDP Length          |        UDP Checksum           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * LCM |                      LISP Control Message                     |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


/*
 * Encapsulated control message header. This is followed by the IP
 * header of the encapsulated LISP control message.
 *
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Type=8 |S|                 Reserved                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct
{
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  u8 reserved:3;
  u8 s_bit:1;
  u8 type:4;
#else
  u8 type:4;
  u8 s_bit:1;
  u8 reserved:3;
#endif
  u8 reserved2[3];
} ecm_hdr_t;

char *ecm_hdr_to_char (ecm_hdr_t * h);

#define ECM_TYPE(h_) ((ecm_hdr_t *)(h_))->type

/*
 * MAP-REQUEST MESSAGE
 */

/*
 * Map-Request Message Format
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=1 |A|M|P|S|p|s|    Reserved     |   IRC   | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         Source-EID-AFI        |   Source EID Address  ...     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                              ...                              |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \ |                       EID-prefix  ...                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                   Map-Reply Record  ...                       |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


/*
 * Fixed size portion of the map request. Variable size source EID
 * address, originating ITR RLOC AFIs and addresses and then map
 * request records follow.
 */
typedef struct
{
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  u8 solicit_map_request:1;
  u8 rloc_probe:1;
  u8 map_data_present:1;
  u8 authoritative:1;
  u8 type:4;
#else
  u8 type:4;
  u8 authoritative:1;
  u8 map_data_present:1;
  u8 rloc_probe:1;
  u8 solicit_map_request:1;
#endif
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  u8 reserved1:6;
  u8 smr_invoked:1;
  u8 pitr:1;
#else
  u8 pitr:1;
  u8 smr_invoked:1;
  u8 reserved1:6;
#endif
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  u8 additional_itr_rloc_count:5;
  u8 reserved2:3;
#else
  u8 reserved2:3;
  u8 additional_itr_rloc_count:5;
#endif
  u8 record_count;
  u64 nonce;
} __attribute__ ((__packed__)) map_request_hdr_t;

void map_request_hdr_init (void *ptr);
char *map_request_hdr_to_char (map_request_hdr_t * h);

#define MREQ_TYPE(h_) (h_)->type
#define MREQ_HDR_CAST(h_) ((map_request_hdr_t *)(h_))
#define MREQ_REC_COUNT(h_) (MREQ_HDR_CAST(h_))->record_count
#define MREQ_RLOC_PROBE(h_) (MREQ_HDR_CAST(h_))->rloc_probe
#define MREQ_ITR_RLOC_COUNT(h_) (MREQ_HDR_CAST(h_))->additional_itr_rloc_count
#define MREQ_NONCE(h_) (MREQ_HDR_CAST(h_))->nonce
#define MREQ_SMR(h_) (MREQ_HDR_CAST(h_))->solicit_map_request
#define MREQ_SMR_INVOKED(h_) (MREQ_HDR_CAST(h_))->smr_invoked

/*
 * MAP-REPLY MESSAGE
 */

 /*
  * Map-Reply Message Format
  *
  *       0                   1                   2                   3
  *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *      |Type=2 |P|E|S|         Reserved                | Record Count  |
  *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *      |                         Nonce . . .                           |
  *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *      |                         . . . Nonce                           |
  *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |   |                          Record  TTL                          |
  *  |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
  *  e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
  *  o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  r   |                          EID-prefix                           |
  *  d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
  *  | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  | o |        Unused Flags     |L|p|R|           Loc-AFI             |
  *  | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |  \|                            Locator                            |
  *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *      |                     Mapping Protocol Data                     |
  *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */

 /*
  * Fixed size portion of the map reply.
  */
typedef struct
{
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  u8 reserved1:1;
  u8 security:1;
  u8 echo_nonce:1;
  u8 rloc_probe:1;
  u8 type:4;
#else
  u8 type:4;
  u8 rloc_probe:1;
  u8 echo_nonce:1;
  u8 security:1;
  u8 reserved1:1;
#endif
  u8 reserved2;
  u8 reserved3;
  u8 record_count;
  u64 nonce;
} __attribute__ ((__packed__)) map_reply_hdr_t;

void map_reply_hdr_init (void *ptr);
char *map_reply_hdr_to_char (map_reply_hdr_t * h);

#define MREP_TYPE(h_) MREP_HDR_CAST(h_)->type
#define MREP_HDR_CAST(h_) ((map_reply_hdr_t *)(h_))
#define MREP_REC_COUNT(h_) MREP_HDR_CAST(h_)->record_count
#define MREP_RLOC_PROBE(h_) MREP_HDR_CAST(h_)->rloc_probe
#define MREP_NONCE(h_) MREP_HDR_CAST(h_)->nonce


always_inline lisp_msg_type_e
lisp_msg_type (void *b)
{
  ecm_hdr_t *hdr = b;
  if (!hdr)
    {
      return (NOT_LISP_MSG);
    }
  return (hdr->type);
}

always_inline void
increment_record_count (void *b)
{
  switch (lisp_msg_type (b))
    {
    case LISP_MAP_REQUEST:
      MREQ_REC_COUNT (b) += 1;
      break;
    case LISP_MAP_REPLY:
      MREP_REC_COUNT (b) += 1;
      break;
    default:
      return;
    }
}


/*
 * LOCATOR FIELD
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *   L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *   c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \|                            Locator                            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Fixed portion of the mapping record locator. Variable length
 * locator address follows.
 */
typedef struct _locator_hdr
{
  u8 priority;
  u8 weight;
  u8 mpriority;
  u8 mweight;
  u8 unused1;
#ifdef CLIB_ARCH_IS_LITTLE_ENDIAN
  u8 reachable:1;
  u8 probed:1;
  u8 local:1;
  u8 unused2:5;
#else
  u8 unused2:5;
  u8 local:1;
  u8 probed:1;
  u8 reachable:1;
#endif
} __attribute__ ((__packed__)) locator_hdr_t;

#define LOC_CAST(h_) ((locator_hdr_t *)(h_))
#define LOC_PROBED(h_) LOC_CAST(h_)->probed
#define LOC_PRIORITY(h_) LOC_CAST(h_)->priority
#define LOC_WEIGHT(h_) LOC_CAST(h_)->weight
#define LOC_MPRIORITY(h_) LOC_CAST(h_)->mpriority
#define LOC_MWEIGHT(h_) LOC_CAST(h_)->mweight
#define LOC_REACHABLE(h_) LOC_CAST(h_)->reachable
#define LOC_LOCAL(h_) LOC_CAST(h_)->local
#define LOC_ADDR(h_) ((u8 *)(h_)  + sizeof(locator_hdr_t))

/*
 * MAPPING RECORD
 *
 * Mapping record used in all LISP control messages.
 *
 *  +--->  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      |                          Record  TTL                          |
 *  |      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  R      | Locator Count | EID mask-len  | ACT |A|       Reserved        |
 *  e      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  c      | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *  o      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  r      |                          EID-prefix                           |
 *  d      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *  |    / +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Loc |         Unused Flags    |L|p|R|           Loc-AFI             |
 *  |    \ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     \|                             Locator                           |
 *  +--->  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Fixed portion of the mapping record. EID prefix address and
 * locators follow.
 */

typedef struct _mapping_record_hdr_t
{
  u32 ttl;
  u8 locator_count;
  u8 eid_prefix_length;
#ifdef CLIB_ARCH_IS_LITTLE_ENDIAN
  u8 reserved1:4;
  u8 authoritative:1;
  u8 action:3;
#else
  u8 action:3;
  u8 authoritative:1;
  u8 reserved1:4;
#endif
  u8 reserved2;
#ifdef CLIB_ARCH_IS_LITTLE_ENDIAN
  u8 version_hi:4;
  u8 reserved3:4;
#else
  u8 reserved3:4;
  u8 version_hi:4;
#endif
  u8 version_low;
} __attribute__ ((__packed__)) mapping_record_hdr_t;

void mapping_record_init_hdr (mapping_record_hdr_t * h);

#define MAP_REC_EID_PLEN(h) ((mapping_record_hdr_t *)(h))->eid_prefix_length
#define MAP_REC_LOC_COUNT(h) ((mapping_record_hdr_t *)(h))->locator_count
#define MAP_REC_ACTION(h) ((mapping_record_hdr_t *)(h))->action
#define MAP_REC_AUTH(h) ((mapping_record_hdr_t *)(h))->authoritative
#define MAP_REC_TTL(h) ((mapping_record_hdr_t *)(h))->ttl
#define MAP_REC_EID(h) (u8 *)(h)+sizeof(mapping_record_hdr_t)
#define MAP_REC_VERSION(h) (h)->version_hi << 8 | (h)->version_low

typedef enum
{
  LISP_NO_ACTION,
  LISP_FORWARD_NATIVE,
  LISP_SEND_MAP_REQUEST,
  LISP_DROP
} lisp_action_e;

typedef enum lisp_authoritative
{
  A_NO_AUTHORITATIVE = 0,
  A_AUTHORITATIVE
} lisp_authoritative_e;

/*
 * LISP Canonical Address Format Encodings
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           AFI = 16387         |     Rsvd1     |     Flags     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Type       |     Rsvd2     |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct _lcaf_hdr_t
{
  u8 reserved1;
  u8 flags;
  u8 type;
  u8 reserved2;
  u16 len;
} __attribute__ ((__packed__)) lcaf_hdr_t;

#define LCAF_TYPE(h) ((lcaf_hdr_t *)(h))->type
#define LCAF_LENGTH(h) ((lcaf_hdr_t *)(h))->len
#define LCAF_RES2(h) ((lcaf_hdr_t *)(h))->reserved2
#define LCAF_FLAGS(h) ((lcaf_hdr_t *)(h))->flags
#define LCAF_PAYLOAD(h) (u8 *)(h)+sizeof(lcaf_hdr_t)

/*
 * Source/Dest Key Canonical Address Format:
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            Reserved           |   Source-ML   |    Dest-ML    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct _lcaf_src_dst_hdr_t
{
  u16 reserved;
  u8 src_mask_len;
  u8 dst_mask_len;
} __attribute__ ((__packed__)) lcaf_src_dst_hdr_t;

#define LCAF_SD_SRC_ML(_h) (_h)->src_mask_len
#define LCAF_SD_DST_ML(_h) (_h)->dst_mask_len

/*
 * SPI LCAF
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              Service Path ID                  | Service index |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct _lcaf_spi_hdr_t
{
  u32 spi_si;
} __attribute__ ((__packed__)) lcaf_spi_hdr_t;

#define LCAF_SPI_SI(_h) (_h)->spi_si

/*
 * The Map-Register message format is:
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=3 |P|            Reserved               |M| Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |            Key ID             |  Authentication Data Length   |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      ~                     Authentication Data                       ~
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   |                          Record TTL                           |
 *  |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *  e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  c   | Rsvd  |  Map-Version Number   |        EID-Prefix-AFI         |
 *  o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  r   |                          EID-Prefix                           |
 *  d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *  | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *  | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  \|                             Locator                           |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct
{
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  u8 res1:3;
  u8 proxy_map_reply:1;
  u8 type:4;
#else
  u8 type:4;
  u8 proxy_map_reply:1;
  u8 res1:3;
#endif

  u8 res2;

#if CLIB_ARCH_IS_LITTLE_ENDIAN
  u8 want_map_notify:1;
  u8 res3:7;
#else
  u8 res3:7;
  u8 want_map_notify:1;
#endif

  u8 record_count;
  u64 nonce;
  u16 key_id;
  u16 auth_data_len;
  u8 data[0];
} __attribute__ ((__packed__)) map_register_hdr_t;

#define MREG_TYPE(h_) (h_)->type
#define MREG_HDR_CAST(h_) ((map_register_hdr_t *)(h_))
#define MREG_PROXY_MR(h_) (MREG_HDR_CAST(h_))->proxy_map_reply
#define MREG_WANT_MAP_NOTIFY(h_) (MREG_HDR_CAST(h_))->want_map_notify
#define MREG_REC_COUNT(h_) (MREG_HDR_CAST(h_))->record_count
#define MREG_NONCE(h_) (MREG_HDR_CAST(h_))->nonce
#define MREG_KEY_ID(h_) (MREG_HDR_CAST(h_))->key_id
#define MREG_AUTH_DATA_LEN(h_) (MREG_HDR_CAST(h_))->auth_data_len
#define MREG_DATA(h_) (MREG_HDR_CAST(h_))->data

/*
 * The Map-Notify message format is:
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=4 |              Reserved                 | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |            Key ID             |  Authentication Data Length   |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      ~                     Authentication Data                       ~
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   |                          Record TTL                           |
 *  |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *  e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  c   | Rsvd  |  Map-Version Number   |         EID-Prefix-AFI        |
 *  o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  r   |                          EID-Prefix                           |
 *  d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *  | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *  | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  \|                             Locator                           |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef struct
{
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  u8 res1:4;
  u8 type:4;
#else
  u8 type:4;
  u8 res1:4;
#endif

  u16 res2;

  u8 record_count;
  u64 nonce;
  u16 key_id;
  u16 auth_data_len;
  u8 data[0];
} __attribute__ ((__packed__)) map_notify_hdr_t;

#define MNOTIFY_TYPE(h_) (h_)->type
#define MNOTIFY_HDR_CAST(h_) ((map_register_hdr_t *)(h_))
#define MNOTIFY_REC_COUNT(h_) (MREG_HDR_CAST(h_))->record_count
#define MNOTIFY_NONCE(h_) (MREG_HDR_CAST(h_))->nonce
#define MNOTIFY_KEY_ID(h_) (MREG_HDR_CAST(h_))->key_id
#define MNOTIFY_AUTH_DATA_LEN(h_) (MREG_HDR_CAST(h_))->auth_data_len
#define MNOTIFY_DATA(h_) (MREG_HDR_CAST(h_))->data

/*
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Ver|O|C|R|R|R|R|R|R|   Length  |  MD type=0x1  | Next Protocol |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Service Path Identifer               | Service Index |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct
{
  u32 header;
  u32 spi_si;
} __attribute__ ((__packed__)) lisp_nsh_hdr_t;

#endif /* VNET_LISP_GPE_LISP_CP_MESSAGES_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
