/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _BM_LOOKUP_H
#define _BM_LOOKUP_H


#include <vppinfra/vec.h>
#include <vppinfra/random.h>
#include <vppinfra/error.h>
#include <vppinfra/bitops.h>    /* for count_set_bits */
#include <acl/sparse_bitmap.h>
#include <acl/types.h>
#include <acl/acl.h>

typedef struct l4_sbmv_t {
  sbmv_u16_t tcp_sbmv[2];
  sbmv_u16_t udp_sbmv[2];
  sbmv_u16_t icmp_sbmv[2];
} l4_sbmv_t;

typedef struct {
  /* original non-compiled ACL */
  u32 acl_index;
  u32 ace_index;
  /*
   * number of hits on this entry
   */
  u64 hitcount;
  /*
   * acl position in vector of ACLs within lookup context
   */
  u32 acl_position;
  /*
   * Action of this applied ACE
   */
  u8 action;
} bm_applied_ace_entry_t;


typedef struct acl_sbmatch_t {
  sbmv_u16_t l3_sbmv_ip4[4];
  sbmv_u16_t l3_sbmv_ip6[16];

  sbitmap_t *l3_match_bitmap[2];
  sbmv_u16_t proto_sbmv[2];
  l4_sbmv_t l4_sbmvs[2];

  acl_rule_t *all_rules;
  bm_applied_ace_entry_t *all_applied_entries;
  u32 *applied_acls;
  u32 *acl_start_indices;
  u32 *acl_lengths;
} acl_sbmatch_t;

typedef struct bm_main_t {
  acl_sbmatch_t *match_contexts;
  sbitmap_t *lookup_result;
  sbitmap_t **lookup_intermediates;
} bm_main_t;

void
bm_acl_add(acl_main_t *am, u32 lc_index, int acl_index);


void
bm_acl_remove(acl_main_t *am, u32 lc_index, int acl_index);

int
bm_multi_acl_match_5tuple (void *p_acl_main, u32 lc_index, fa_5tuple_t * pkt_5tuple,
                       int is_ip6, u8 *action, u32 *acl_pos_p, u32 * acl_match_p,
                       u32 * rule_match_p, u32 * trace_bitmap);




#endif

