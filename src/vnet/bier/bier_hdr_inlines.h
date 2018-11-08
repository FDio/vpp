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
 * @brief The BIER inline functions acting on the bier header
 */

#ifndef __BIER_HDR_INLINES_H__
#define __BIER_HDR_INLINES_H__

#include <vppinfra/byte_order.h>
#include <vppinfra/string.h>

#include <vnet/bier/bier_types.h>
#include <vnet/bier/bier_bit_string.h>
#include <vnet/ip/ip6_packet.h>

/**
 * Special Value of the BIER RX interface
 */
#define BIER_RX_ITF (~0 - 1)

/**
 * Mask and shift values for the fields incorporated
 * into the header's first word
 */
#define BIER_HDR_1ST_NIBBLE_MASK    0xf0000000
#define BIER_HDR_VERSION_FIELD_MASK 0x0f000000
#define BIER_HDR_LEN_FIELD_MASK     0x00f00000
#define BIER_HDR_ENTROPY_FIELD_MASK 0x000fffff

#define BIER_HDR_1ST_NIBBLE_SHIFT    28
#define BIER_HDR_VERSION_FIELD_SHIFT 24
#define BIER_HDR_LEN_FIELD_SHIFT     20
#define BIER_HDR_ENTROPY_FIELD_SHIFT  0

#define BIER_HDR_1ST_NIBBLE_VALUE 0x5

/**
 * Mask and shift values for fields in the headers trainling word
 */
#define BIER_HDR_PROTO_FIELD_MASK   0x003f
#define BIER_HDR_OAM_FIELD_MASK     0xc000
#define BIER_HDR_DSCP_FIELD_MASK    0x0fc0
#define BIER_HDR_DSCP_FIELD_SHIFT   6
#define BIER_HDR_PROTO_FIELD_SHIFT  0
#define BIER_HDR_OAM_FIELD_SHIFT    14

static inline bier_hdr_version_t
bier_hdr_get_version (const bier_hdr_t *bier_hdr)
{
    return ((bier_hdr->bh_first_word &
             BIER_HDR_VERSION_FIELD_MASK) >>
            BIER_HDR_VERSION_FIELD_SHIFT);
}

static inline bier_hdr_len_id_t
bier_hdr_get_len_id (const bier_hdr_t *bier_hdr)
{
    return ((bier_hdr->bh_first_word &
             BIER_HDR_LEN_FIELD_MASK) >>
            BIER_HDR_LEN_FIELD_SHIFT);
}

static inline bier_hdr_entropy_t
bier_hdr_get_entropy (const bier_hdr_t *bier_hdr)
{
    return ((bier_hdr->bh_first_word &
             BIER_HDR_ENTROPY_FIELD_MASK) >>
            BIER_HDR_ENTROPY_FIELD_SHIFT);
}

static inline void
bier_hdr_1st_nibble (bier_hdr_t *hdr)
{
    hdr->bh_first_word &= ~(BIER_HDR_1ST_NIBBLE_MASK);
    hdr->bh_first_word |= (BIER_HDR_1ST_NIBBLE_VALUE <<
                           BIER_HDR_1ST_NIBBLE_SHIFT);
}

static inline u8
bier_hdr_get_1st_nibble (bier_hdr_t *hdr)
{
    return ((hdr->bh_first_word & BIER_HDR_1ST_NIBBLE_MASK) >>
            BIER_HDR_1ST_NIBBLE_SHIFT);
}

static inline void
bier_hdr_set_version (bier_hdr_t *hdr,
                      bier_hdr_version_t version)
{
    hdr->bh_first_word &= ~(BIER_HDR_VERSION_FIELD_MASK);
    hdr->bh_first_word |= (version << BIER_HDR_VERSION_FIELD_SHIFT);
}

static inline void
bier_hdr_set_len_id (bier_hdr_t *hdr,
                     bier_hdr_len_id_t len)
{
    hdr->bh_first_word &= ~(BIER_HDR_LEN_FIELD_MASK);
    hdr->bh_first_word |= (len << BIER_HDR_LEN_FIELD_SHIFT);
}

static inline void
bier_hdr_set_entropy (bier_hdr_t *hdr,
                      bier_hdr_entropy_t entropy)
{
    entropy = entropy & BIER_HDR_ENTROPY_FIELD_MASK;
    hdr->bh_first_word &= ~(BIER_HDR_ENTROPY_FIELD_MASK);
    hdr->bh_first_word |= (entropy << BIER_HDR_ENTROPY_FIELD_SHIFT);
}

#define BIER_HDR_FIRST_WORD(version, len, entropy)          \
    ((BIER_HDR_1ST_NIBBLE_VALUE <<                          \
      BIER_HDR_1ST_NIBBLE_SHIFT) |                          \
     (version << BIER_HDR_VERSION_FIELD_SHIFT) |            \
     (len     << BIER_HDR_LEN_FIELD_SHIFT)     |            \
     ((entropy & BIER_HDR_ENTROPY_FIELD_MASK)               \
      << BIER_HDR_ENTROPY_FIELD_SHIFT))

static inline void
bier_hdr_ntoh (bier_hdr_t *bier_hdr)
{
    bier_hdr->bh_first_word = clib_net_to_host_u32(bier_hdr->bh_first_word);
    bier_hdr->bh_oam_dscp_proto = clib_net_to_host_u16(bier_hdr->bh_oam_dscp_proto);
    bier_hdr->bh_bfr_id = clib_net_to_host_u16(bier_hdr->bh_bfr_id);
}

static inline void
bier_hdr_hton (bier_hdr_t *bier_hdr)
{
    bier_hdr->bh_first_word = clib_host_to_net_u32(bier_hdr->bh_first_word);
    bier_hdr->bh_oam_dscp_proto = clib_host_to_net_u16(bier_hdr->bh_oam_dscp_proto);
    bier_hdr->bh_bfr_id = clib_host_to_net_u16(bier_hdr->bh_bfr_id);
}

static inline bier_hdr_src_id_t
bier_hdr_get_src_id (const bier_hdr_t *bier_hdr)
{
    return (bier_hdr->bh_bfr_id);
}

static inline void
bier_hdr_set_src_id (bier_hdr_t *bier_hdr,
                     bier_hdr_src_id_t src_id)
{
    bier_hdr->bh_bfr_id = src_id;
}
static inline void
bier_hdr_set_proto_id (bier_hdr_t *bier_hdr,
                       bier_hdr_proto_id_t proto)
{
    bier_hdr->bh_oam_dscp_proto &= ~(BIER_HDR_PROTO_FIELD_MASK);
    bier_hdr->bh_oam_dscp_proto |= (proto << BIER_HDR_PROTO_FIELD_SHIFT);
}

static inline bier_hdr_proto_id_t
bier_hdr_get_proto_id (const bier_hdr_t *bier_hdr)
{
    return ((bier_hdr->bh_oam_dscp_proto & BIER_HDR_PROTO_FIELD_MASK) >>
            BIER_HDR_PROTO_FIELD_SHIFT);
}

static inline void
bier_hdr_clear (bier_hdr_t *bier_hdr)
{
    memset(&bier_hdr->bh_bit_string, 0,
           bier_hdr_len_id_to_num_buckets(
               bier_hdr_get_len_id(bier_hdr)));
}

static inline void
bier_hdr_init (bier_hdr_t *bier_hdr,
               bier_hdr_version_t version,
               bier_hdr_proto_id_t proto,
               bier_hdr_len_id_t len,
               bier_hdr_entropy_t entropy,
               bier_bp_t src)
{
    bier_hdr_1st_nibble(bier_hdr);
    bier_hdr_set_version(bier_hdr, version);
    bier_hdr_set_len_id(bier_hdr, len);
    bier_hdr_set_entropy(bier_hdr, entropy);
    bier_hdr_set_proto_id(bier_hdr, proto);
    bier_hdr_set_src_id(bier_hdr, src);
    bier_hdr_clear(bier_hdr);
}

static inline size_t
bier_hdr_str_num_bytes (const bier_hdr_t *bier_hdr)
{
    return (bier_hdr_len_id_to_num_bytes(
                bier_hdr_get_len_id(bier_hdr)));
}

static inline size_t
bier_hdr_num_bytes (const bier_hdr_t *bier_hdr)
{
    return (sizeof(bier_hdr_t) +
            bier_hdr_str_num_bytes(bier_hdr));
}

static inline void
bier_bit_string_init_from_hdr (bier_hdr_t *bier_hdr,
                               bier_bit_string_t *bit_string)
{
    bit_string->bbs_len = bier_hdr_str_num_bytes(bier_hdr);
    bit_string->bbs_buckets = bier_hdr->bh_bit_string;
}

#endif
