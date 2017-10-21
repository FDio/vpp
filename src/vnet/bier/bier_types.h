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

#ifndef __BIER_TYPES_H__
#define __BIER_TYPES_H__

#include <vlib/vlib.h>
#include <vnet/dpo/dpo.h>

/**
 * @brief Flags to control show output
 */
typedef enum bier_show_flags_t_ {
    BIER_SHOW_BRIEF,
    BIER_SHOW_DETAIL = (1 << 0),
} bier_show_flags_t;

/**
 * Types of BIER tables
 */
typedef enum bier_table_type_t_ {
    /**
     * BIER over MPLS with SPF
     */
    BIER_TABLE_MPLS_SPF,

    /**
     * BIER over MPLS for TE
     */
    BIER_TABLE_MPLS_TE,
} __attribute__((packed)) bier_table_type_t;

#define BIER_TABLE_TYPES {              \
    [BIER_TABLE_MPLS_SPF] = "mpls-spf", \
    [BIER_TABLE_MPLS_TE]  = "mpls-te",  \
}

/**
 * bier_hdr_len_id_t enumerator
 **/
typedef enum bier_hdr_len_id_t_ {
    BIER_HDR_LEN_64 = 0,
    BIER_HDR_LEN_128,
    BIER_HDR_LEN_256,
    BIER_HDR_LEN_512,
    BIER_HDR_LEN_1024,
    BIER_HDR_LEN_2048,
    BIER_HDR_LEN_4096,
    BIER_HDR_LEN_INVALID,
} __attribute__((packed)) bier_hdr_len_id_t;

#define BIER_HDR_LEN_IDS {             \
    [BIER_HDR_LEN_INVALID] = "invalid",\
    [BIER_HDR_LEN_64]      = "64",     \
    [BIER_HDR_LEN_128]     = "128",    \
    [BIER_HDR_LEN_256]     = "256",    \
    [BIER_HDR_LEN_512]     = "512",    \
    [BIER_HDR_LEN_1024]    = "1024",   \
    [BIER_HDR_LEN_2048]    = "2048",   \
    [BIER_HDR_LEN_4096]    = "4096",   \
}

#define FOR_EACH_BIER_HDR_LEN(_len)    \
    for (_item = BIER_HDR_LEN_64;      \
         _item <= BIER_HDR_LEN_4096;   \
         _item++)

/**
 * Format the header length field
 */
extern u8 *format_bier_hdr_len_id(u8 *s, va_list *ap);

/*
 * convert from prefix len to hdr ID
 */
static inline bier_hdr_len_id_t
bier_prefix_len_to_hdr_id (u16 prfx_len) {

    switch (prfx_len) {
    case 7:
        return (BIER_HDR_LEN_64);
    case 8:
        return (BIER_HDR_LEN_128);
    case 9:
        return (BIER_HDR_LEN_256);
    case 10:
        return (BIER_HDR_LEN_512);
    case 11:
        return (BIER_HDR_LEN_1024);
    case 12:
        return (BIER_HDR_LEN_2048);
    case 13:
        return (BIER_HDR_LEN_4096);
    default:
        break;
    }

    return (BIER_HDR_LEN_INVALID);
}

static inline bier_hdr_len_id_t
bier_hdr_byte_len_to_id (u32 bytes)
{
    switch (bytes) {
    case 8:
        return (BIER_HDR_LEN_64);
    case 16:
        return (BIER_HDR_LEN_128);
    case 32:
        return (BIER_HDR_LEN_256);
    case 64:
        return (BIER_HDR_LEN_512);
    case 128:
        return (BIER_HDR_LEN_1024);
    case 256:
        return (BIER_HDR_LEN_2048);
    case 512:
        return (BIER_HDR_LEN_4096);
    }

    return (BIER_HDR_LEN_INVALID);
}

static inline bier_hdr_len_id_t
bier_hdr_bit_len_to_id (u32 bytes)
{
    switch (bytes) {
    case 64:
        return (BIER_HDR_LEN_64);
    case 128:
        return (BIER_HDR_LEN_128);
    case 256:
        return (BIER_HDR_LEN_256);
    case 512:
        return (BIER_HDR_LEN_512);
    case 1024:
        return (BIER_HDR_LEN_1024);
    case 2048:
        return (BIER_HDR_LEN_2048);
    case 4096:
        return (BIER_HDR_LEN_4096);
    }

    return (BIER_HDR_LEN_INVALID);
}

/**
 * bier_hdr_len_num_buckets_t enumerator
 **/
typedef enum bier_hdr_len_num_buckets_t_ {
    BIER_HDR_BUCKETS_64 = 8,
    BIER_HDR_BUCKETS_128 = 16,
    BIER_HDR_BUCKETS_256 = 32,
    BIER_HDR_BUCKETS_512 = 64,
    BIER_HDR_BUCKETS_1024 = 128,
    BIER_HDR_BUCKETS_2048 = 256,
    BIER_HDR_BUCKETS_4096 = 512,
} bier_hdr_len_num_buckets_t;

/**
 * BIER header protocol payload types
 **/
typedef enum bier_hdr_proto_id_t_ {
    BIER_HDR_PROTO_INVALID = 0,
    BIER_HDR_PROTO_MPLS_DOWN_STREAM,
    BIER_HDR_PROTO_MPLS_UP_STREAM,
    BIER_HDR_PROTO_ETHERNET,
    BIER_HDR_PROTO_IPV4,
    BIER_HDR_PROTO_IPV6,
    BIER_HDR_PROTO_VXLAN,
    BIER_HDR_PROTO_CTRL,
    BIER_HDR_PROTO_OAM,
} __attribute__((packed)) bier_hdr_proto_id_t;

#define BIER_HDR_N_PROTO (BIER_HDR_PROTO_OAM + 1)

#define BIER_HDR_PROTO_ID_NAMES {                               \
    [BIER_HDR_PROTO_INVALID] = "invalid",			\
    [BIER_HDR_PROTO_MPLS_DOWN_STREAM] = "mpls-down-stream",     \
    [BIER_HDR_PROTO_MPLS_UP_STREAM] = "mpls-up-stream",         \
    [BIER_HDR_PROTO_ETHERNET] = "ethernet",                     \
    [BIER_HDR_PROTO_IPV4] = "ipv4",                             \
    [BIER_HDR_PROTO_IPV6] = "ipv6",                             \
    [BIER_HDR_PROTO_VXLAN] = "vxlan",                           \
    [BIER_HDR_PROTO_CTRL] = "control-plane",                    \
    [BIER_HDR_PROTO_OAM] = "oam",                               \
}

#define FOR_EACH_BIER_HDR_PROTO(_proto)                 \
    for (_proto = BIER_HDR_PROTO_MPLS_DOWN_STREAM;      \
         _proto <= BIER_HDR_PROTO_OAM;                  \
         _proto++)

/**
 * Format the header length field
 */
extern u8 *format_bier_hdr_proto(u8 *s, va_list *ap);

/**
 * Convert from BIER next-hop proto to DPO proto
 */
extern dpo_proto_t bier_hdr_proto_to_dpo(bier_hdr_proto_id_t bproto);

/**
 * BIER header versions
 **/
typedef enum bier_hdr_version_t_ {
    BIER_HDR_VERSION_1 = 0,
} __attribute__((packed)) bier_hdr_version_t;

/**
 * bier_hdr_code_t enumerator
 **/
typedef enum bier_hdr_code_t_ {
    BIER_HDR_CODE_OAM_IPV4 = 0,
    BIER_HDR_CODE_OAM_IPV6 = 1,
    BIER_HDR_CODE_CTRL_IPV4 = 2,
    BIER_HDR_CODE_CTRL_IPV6 = 3,
} __attribute__((packed)) bier_hdr_code_t;

/**
 * bier_hdr_oam_sub_code_t enumerator
 */
typedef enum bier_hdr_oam_sub_code_t_ {
    BIER_HDR_SUB_CODE_OAM_PING_REQ = 0,
    BIER_HDR_SUB_CODE_OAM_PING_RESP = 1,
} __attribute__((packed)) bier_hdr_oam_sub_code_t;

/**
 * bier_hdr_ctrl_sub_code_t enumerator
 */
typedef enum bier_hdr_ctrl_sub_code_t_ {
    BIER_HDR_SUB_CODE_CTRL_MEMBER_REQ = 0,
    BIER_HDR_SUB_CODE_CTRL_ATTACHED_NET = 1,
} __attribute__((packed)) bier_hdr_ctrl_sub_code_t;

/**
 * A bucket is a byte. The byte string is thus always in network byte order.
 */
typedef u8 bier_bit_mask_bucket_t;

/**
 * A BIER Bit-String value of length 64 bits.
 */
typedef struct bier_bit_mask_64_t_ {
    bier_bit_mask_bucket_t bits[BIER_HDR_BUCKETS_64];
} bier_bit_mask_64_t;

/**
 * A BIER Bit-String value of length 128 bits.
 */
typedef struct bier_bit_mask_128_t_ {
    bier_bit_mask_bucket_t bits[BIER_HDR_BUCKETS_128];
} bier_bit_mask_128_t;

/**
 * A BIER Bit-String value of length 256 bits.
 */
typedef struct bier_bit_mask_256_t_ {
    bier_bit_mask_bucket_t bits[BIER_HDR_BUCKETS_256];
} bier_bit_mask_256_t;

/**
 * A BIER Bit-String value of length 512 bits.
 */
typedef struct bier_bit_mask_512_t_ {
    bier_bit_mask_bucket_t bits[BIER_HDR_BUCKETS_512];
} bier_bit_mask_512_t;

/**
 * A BIER Bit-String value of length 1024 bits.
 */
typedef struct bier_bit_mask_1024_t_ {
    bier_bit_mask_bucket_t bits[BIER_HDR_BUCKETS_1024];
} bier_bit_mask_1024_t;

/**
 * A BIER Bit-String value of length 2048 bits.
 */
typedef struct bier_bit_mask_2048_t_ {
    bier_bit_mask_bucket_t bits[BIER_HDR_BUCKETS_2048];
} bier_bit_mask_2048_t;

/**
 * A BIER Bit-String value of length 4096 bits.
 */
typedef struct bier_bit_mask_4096_t_ {
    bier_bit_mask_bucket_t bits[BIER_HDR_BUCKETS_4096];
} bier_bit_mask_4096_t;


/**
 * 256 bits = 32 bytes
 */
#define BIER_BIT_MASK_NUM_BUCKETS 32
#define BIER_BIT_MASK_MAX_BUCKET (BIER_BIT_MASK_NUM_BUCKETS - 1)

/**
 * number of bits in a bucket
 */
#define BIER_BIT_MASK_BITS_PER_BUCKET 8

/**
 * Supported bit-posiotn range
 */
#define BIER_BIT_MASK_MIN_POS (1)

/**
 * A Variable length BitString
 */
typedef struct bier_bit_string_t_ {
    /**
     * The length of the string in BYTES
     */
    u16 bbs_len;

    /**
     * The buckets in the string
     */
    bier_bit_mask_bucket_t *bbs_buckets;
} bier_bit_string_t;

/**
 * A BIER Bit-mask value
 *
 * The size of this mask represents this platforms BIER capabilities
 */
typedef bier_bit_mask_256_t bier_bit_mask_t;

/**
 * A bit positon
 *  as assigned to egress PEs
 */
typedef u32 bier_bp_t;

#define BIER_BP_TO_INDEX(bp) (bp - 1)

/**
 * The maximum BP that can be assigned
 */
#define BIER_BP_MAX 0x10000

/**
 * An identifier of the sender of BIER packets
 * this is the source of the 'tree' - the BFIR
 */
typedef u16 bier_hdr_src_id_t;

/**
 * An entropy value in a BIER header
 */
typedef u32 bier_hdr_entropy_t;

#define BIER_BP_INVALID 0

/**
 * A BIER header of variable length
 * The encoding follows:
 *   https://tools.ietf.org/html/draft-ietf-bier-mpls-encapsulation-10
 */
typedef struct bier_hdr_t_ {
    /**
     * The first nibble is always set to 0101
     * to ensure that when carried over MPLS, the BIER packet
     * is not mistaken for IPv[46]:
     *   type: bier_hdr_version_t
     *
     * The second nibble is the version - this is 0:
     *   type: bier_hdr_version_t
     *
     * The third nibble is header length ID
     *   type: bier_hdr_len_id_t
     *
     * The next 20 bits are entropy
     * An entropy value, calculated by the head end, used
     * at the head and mid-points for load-balance hash
     *   type: bier_hdr_entropy_t
     */
    u32 bh_first_word;

    /**
     * The second word comprises:
     *  2 bits of OAM for passive perf measurement
     *  2 reserved bits;
     *  6 bits of DSCP
     *  6 bits for the next-proto field of type;
     *     bier_hdr_proto_id_t
     */
    u16 bh_oam_dscp_proto;

    /**
     * The BFR-ID of the sender
     */
    u16 bh_bfr_id;

    /**
     * The variable length bit-string
     */
    bier_bit_mask_bucket_t bh_bit_string[0];
} bier_hdr_t;

/**
 * Format a BIER header
 */
extern u8 *format_bier_hdr(u8 *s, va_list *ap);

/**
 * The BIER Set ID assigned to a BIER table
 */
typedef u32 bier_table_set_id_t;

#define BIER_TABLE_SET_INVALID_ID 0xffffffff

/**
 * The BIER Sub-domain ID assigned to a BIER table
 */
typedef u32 bier_table_sub_domain_id_t;

#define BIER_TABLE_SUB_DOMAIN_INVALID_ID 0xffffffff

/**
 * An ID or instance number of a BIER sub-table
 */
typedef u32 bier_table_ecmp_id_t;

/**
 * Definition of the ID of the BIER main table
 */
#define BIER_ECMP_TABLE_ID_MAIN 0xFFFF

/**
 * The ID of a table
 */
typedef struct bier_table_id_t_ {
    /**
     * The SET-ID
     *  The control plane divdies the bit-position space
     * into sets in the case the max bit-position is greater
     * than the table's bit-string size
     */
    bier_table_set_id_t bti_set;

    /**
     * The Sub-Domain-ID
     * The control plane has the configuration option to specify multiple
     * domains or topologies.
     */
    bier_table_sub_domain_id_t bti_sub_domain;

    /**
     * The SUB/ECMP-ID
     * Constructed by FIB to achieve ECMP between BFR-NBRs
     */
    bier_table_ecmp_id_t bti_ecmp;

    /**
     * The size of the bit string processed by this table.
     */
    bier_hdr_len_id_t bti_hdr_len;

   /**
     * The type of the table; SPF or TE, MPLS or IPv6
     */
    bier_table_type_t bti_type;
} bier_table_id_t;

/**
 * Format a BIER table ID
 */
extern u8 *format_bier_table_id(u8 *s, va_list *ap);

/**
 * Compare to BIER table IDs for equality
 */
extern int bier_table_id_cmp(const bier_table_id_t *btid1,
                             const bier_table_id_t *btid2);

/**
 * Conversion functions for the enumerated bit-string length
 * values, to bit and bytes
 */
extern u32 bier_hdr_len_id_to_num_buckets(bier_hdr_len_id_t id);
extern u32 bier_hdr_len_id_to_num_bytes(bier_hdr_len_id_t id);
extern u32 bier_hdr_len_id_to_max_bucket(bier_hdr_len_id_t id);
extern u32 bier_hdr_len_id_to_num_bits(bier_hdr_len_id_t id);
extern u32 bier_hdr_len_id_to_max_bit(bier_hdr_len_id_t id);
extern u32 bier_hdr_len_id_to_prefix_len(bier_hdr_len_id_t id);

#define BIER_OK 0
#define BIER_ERR_NO_TABLE 1
#define BIER_ERR_DUPLICATE_TABLE 2
#define BIER_ERR_PANIC 3
typedef int bier_rc;

#endif /* __BIER_TYPES_H__ */
