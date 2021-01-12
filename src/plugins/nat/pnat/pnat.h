/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

/* Definitions from pnat.api */
#include <pnat/pnat.api_types.h>
typedef vl_api_pnat_5tuple_t pnat_5tuple_t;
typedef vl_api_pnat_mask_t pnat_mask_t;

/* Rewrite instructions */
typedef enum {
  PNAT_INSTR_NO_TRANSLATE           = 1 << 0,
  PNAT_INSTR_SOURCE_ADDRESS         = 1 << 1,
  PNAT_INSTR_SOURCE_PORT            = 1 << 2,
  PNAT_INSTR_DESTINATION_ADDRESS    = 1 << 3,
  PNAT_INSTR_DESTINATION_PORT       = 1 << 4,
} pnat_instructions_t;

/* Flow hash 6-tuple key. 16 octets */
typedef struct {
  union {
    struct {
      ip4_address_t sa;
      ip4_address_t da;
      u32 proto:8, sw_if_index:23, input:1;
      u16 sp;
      u16 dp;
    };
    u64 as_u64[2];
  };
} __clib_packed pnat_key_t;
STATIC_ASSERT_SIZEOF (pnat_key_t, 16);

/* Session cache entries */
typedef struct {
  /* What to translate to */
  pnat_instructions_t instructions;
  u32 fib_index;

  /* Stored in network byte order */
  ip4_address_t post_sa;
  ip4_address_t post_da;
  u16 post_sp;
  u16 post_dp;

  /* Used for trace/show commands */
  pnat_5tuple_t match;
  pnat_5tuple_t rewrite;
  pnat_key_t key;
} pnat_translation_t;

/* Interface object */
typedef struct {
  u32 sw_if_index;
  pnat_mask_t input_lookup_mask;
  pnat_mask_t output_lookup_mask;

  /* Feature chain enabled on interface */
  bool input_enabled;
  bool output_enabled;
} pnat_interface_t;

/* Globals */
typedef struct {
  bool enabled;

  clib_bihash_16_8_t flowhash;	/* Bi-directional */

  /* Interface pool */
  pnat_interface_t *interfaces;
  u32 *interface_by_sw_if_index;

  /* Translations pool */
  pnat_translation_t *translations;

  u16 msg_id_base;
} pnat_main_t;
extern pnat_main_t pnat_main;

pnat_interface_t *pnat_interface_by_sw_if_index (u32 sw_if_index);

#endif
