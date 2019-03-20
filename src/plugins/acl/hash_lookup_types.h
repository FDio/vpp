/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef _ACL_HASH_LOOKUP_TYPES_H_
#define _ACL_HASH_LOOKUP_TYPES_H_

#include "types.h"

/* The structure representing the single entry with hash representation */
typedef struct {
  fa_5tuple_t match;
  /* these two entries refer to the original ACL# and rule# within that ACL */
  u32 acl_index;
  u32 ace_index;

  u32 base_mask_type_index;

  u8 action;
} hash_ace_info_t;

/*
 * The structure holding the information necessary for the hash-based ACL operation
 */
typedef struct {
  /* hash ACL applied on these lookup contexts */
  u32 *lc_index_list;
  hash_ace_info_t *rules;
  /* a boolean flag set when the hash acl info is initialized */
  int hash_acl_exists;
} hash_acl_info_t;


typedef struct {
  acl_rule_t rule;
  u32 acl_index;
  u32 ace_index;
  u32 acl_position;
  u32 applied_entry_index;
} collision_match_rule_t;

typedef struct {
  /* original non-compiled ACL */
  u32 acl_index;
  u32 ace_index;
  /* the index of the hash_ace_info_t */
  u32 hash_ace_info_index;
  /* applied mask type index */
  u32 mask_type_index;
  /*
   * index of applied entry, which owns the colliding_rules vector
   */
  u32 collision_head_ae_index;
  /*
   * Collision rule vector for matching - set only on head entry
   */
  collision_match_rule_t *colliding_rules;
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
} applied_hash_ace_entry_t;

typedef struct {

   /* applied ACLs so we can track them independently from main ACL module */
   u32 *applied_acls;
} applied_hash_acl_info_t;


typedef union {
  u64 as_u64;
  struct {
    u32 applied_entry_index;
    u16 reserved_u16;
    u8 reserved_u8;
    u8 reserved_flags:8;
  };
} hash_acl_lookup_value_t;


typedef struct {
   u32 mask_type_index;
   /* first rule # for this mask */
   u32 first_rule_index;
   /* Debug Information */
   u32 num_entries;
   u32 max_collisions;
} hash_applied_mask_info_t;


#define CT_ASSERT_EQUAL(name, x,y) typedef int assert_ ## name ## _compile_time_assertion_failed[((x) == (y))-1]

CT_ASSERT_EQUAL(hash_acl_lookup_value_t_is_u64, sizeof(hash_acl_lookup_value_t), sizeof(u64));

#undef CT_ASSERT_EQUAL

#endif
