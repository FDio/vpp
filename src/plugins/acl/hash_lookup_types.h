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

/* The structure representing the single entry with hash representation */
typedef struct {
  /* these two entries refer to the original ACL# and rule# within that ACL */
  u32 acl_index;
  u32 ace_index;

  u32 mask_type_index;
  u8 src_portrange_not_powerof2;
  u8 dst_portrange_not_powerof2;

  fa_5tuple_t match;
  u8 action;
} hash_ace_info_t;

/*
 * The structure holding the information necessary for the hash-based ACL operation
 */
typedef struct {
  /* The mask types present in this ACL */
  uword *mask_type_index_bitmap;
  /* hash ACL applied on these interfaces */
  u32 *inbound_sw_if_index_list;
  u32 *outbound_sw_if_index_list;
  hash_ace_info_t *rules;
} hash_acl_info_t;

typedef struct {
  /* original non-compiled ACL */
  u32 acl_index;
  u32 ace_index;
  /* the index of the hash_ace_info_t */
  u32 hash_ace_info_index;
  /*
   * in case of the same key having multiple entries,
   * this holds the index of the next entry.
   */
  u32 next_applied_entry_index;
  /*
   * previous entry in the list of the chained ones,
   * if ~0 then this is entry in the hash.
   */
  u32 prev_applied_entry_index;
  /*
   * chain tail, if this is the first entry
   */
  u32 tail_applied_entry_index;
  /*
   * number of hits on this entry
   */
  u64 hitcount;
  /*
   * Action of this applied ACE
   */
  u8 action;
} applied_hash_ace_entry_t;

typedef struct {
   /*
    * A logical OR of all the applied_ace_hash_entry_t=>
    *                            hash_ace_info_t=>mask_type_index bits set
    */
   uword *mask_type_index_bitmap;
   /* applied ACLs so we can track them independently from main ACL module */
   u32 *applied_acls;
} applied_hash_acl_info_t;


typedef union {
  u64 as_u64;
  struct {
    u32 applied_entry_index;
    u16 reserved_u16;
    u8 reserved_u8;
    /* means there is some other entry in front intersecting with this one */
    u8 shadowed:1;
    u8 need_portrange_check:1;
    u8 reserved_flags:6;
  };
} hash_acl_lookup_value_t;

#define CT_ASSERT_EQUAL(name, x,y) typedef int assert_ ## name ## _compile_time_assertion_failed[((x) == (y))-1]

CT_ASSERT_EQUAL(hash_acl_lookup_value_t_is_u64, sizeof(hash_acl_lookup_value_t), sizeof(u64));

#undef CT_ASSERT_EQUAL

#endif
