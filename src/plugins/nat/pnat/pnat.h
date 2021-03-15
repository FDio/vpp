/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef included_pnat_h
#define included_pnat_h

#include <stdbool.h>
#include <vnet/ip/ip4_packet.h>
#include <vppinfra/bihash_16_8.h>

#define PNAT_FLOW_HASH_BUCKETS 256

/* Definitions from pnat.api */
#include <pnat/pnat.api_types.h>
typedef vl_api_pnat_match_tuple_t pnat_match_tuple_t;
typedef vl_api_pnat_rewrite_tuple_t pnat_rewrite_tuple_t;
typedef vl_api_pnat_mask_t pnat_mask_t;
typedef vl_api_pnat_attachment_point_t pnat_attachment_point_t;

/* Rewrite instructions */
typedef enum {
    PNAT_INSTR_NONE = 1 << 0,
    PNAT_INSTR_SOURCE_ADDRESS = 1 << 1,
    PNAT_INSTR_SOURCE_PORT = 1 << 2,
    PNAT_INSTR_DESTINATION_ADDRESS = 1 << 3,
    PNAT_INSTR_DESTINATION_PORT = 1 << 4,
    PNAT_INSTR_COPY_BYTE = 1 << 5,
    PNAT_INSTR_CLEAR_BYTE = 1 << 6,
} pnat_instructions_t;

typedef struct {
    u64 as_u64[2];
} pnat_mask_fast_t;

typedef struct {
    union {
        u64 as_u64[3];
        u8 as_u8[24];
    };

} pnat_u64x3_t;


/* Session cache entries */
typedef struct {
    /* Used by data plane */
    pnat_u64x3_t pre_mask;
    pnat_u64x3_t post_mask;
    pnat_u64x3_t post;
    u16 l4_checksum_offset;
    u16 max_rewrite;


    /* What to translate to */
    pnat_instructions_t instructions;

    /* Stored in network byte order */
    ip4_address_t post_sa;
    ip4_address_t post_da;
    u16 post_sp;
    u16 post_dp;

    /* Byte copy inside of packet */
    u8 from_offset;
    u8 to_offset;

    u8 clear_offset; /* Clear byte */

    /* Used for trace/show commands */
    pnat_match_tuple_t match;
    pnat_rewrite_tuple_t rewrite;
} pnat_translation_t;

/* Interface object */
typedef struct {
    u32 sw_if_index;
    pnat_mask_t lookup_mask[PNAT_ATTACHMENT_POINT_MAX];
    pnat_mask_fast_t lookup_mask_fast[PNAT_ATTACHMENT_POINT_MAX];

    /* Feature chain enabled on interface */
    bool enabled[PNAT_ATTACHMENT_POINT_MAX];

    u32 refcount;
} pnat_interface_t;

/* Globals */
typedef struct {
    bool enabled;

    clib_bihash_16_8_t flowhash; /* Bi-directional */

    /* Interface pool */
    pnat_interface_t *interfaces;
    u32 *interface_by_sw_if_index;

    /* Translations pool */
    pnat_translation_t *translations;

    u16 msg_id_base;
} pnat_main_t;
extern pnat_main_t pnat_main;

pnat_interface_t *pnat_interface_by_sw_if_index(u32 sw_if_index);

/* Packet trace information */
typedef struct {
    u32 pool_index;
    pnat_match_tuple_t match;
    pnat_rewrite_tuple_t rewrite;
} pnat_trace_t;

int pnat_binding_add(pnat_match_tuple_t *match, pnat_rewrite_tuple_t *rewrite,
                     u32 *binding_index);
int pnat_binding_del(u32 binding_index);
int pnat_binding_attach(u32 sw_if_index, pnat_attachment_point_t attachment,
                        u32 binding_index);
int pnat_binding_detach(u32 sw_if_index, pnat_attachment_point_t attachment,
                        u32 binding_index);
u32 pnat_flow_lookup(u32 sw_if_index, pnat_attachment_point_t attachment,
                     pnat_match_tuple_t *match);

static inline void
pnat_calc_key(u32 sw_if_index, pnat_attachment_point_t attachment,
              ip4_address_t src, ip4_address_t dst, u8 protocol, u16 sport,
              u16 dport, pnat_mask_fast_t mask, clib_bihash_kv_16_8_t *kv) {
    kv->key[0] = (u64)src.as_u32 << 32 | dst.as_u32;
    kv->key[0] &= mask.as_u64[0];
    kv->key[1] =
        (u64)protocol << 56 | (u64)sw_if_index << 36 | (u64)attachment << 32;
    kv->key[1] |= (u32)sport << 16 | dport;
    kv->key[1] &= mask.as_u64[1];
}

#endif
