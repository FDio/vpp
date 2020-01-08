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

#ifndef __MATCH_TUPLE_H__
#define __MATCH_TUPLE_H__

#include <stddef.h>

/*
 * Do the necessary to logically apply the ACL to the existing vector of ACLs looked up
 * during the packet processing
 */

void hash_acl_apply(acl_main_t *am, u32 lc_index, int acl_index, u32 acl_position);

/* Remove the ACL from the packet processing in a given lookup context */

void hash_acl_unapply(acl_main_t *am, u32 lc_index, int acl_index);

/*
 * Add an ACL or delete an ACL. ACL may already have been referenced elsewhere,
 * so potentially we also need to do the work to enable the lookups.
 */

void hash_acl_add(acl_main_t *am, int acl_index);
void hash_acl_delete(acl_main_t *am, int acl_index);

/* return if there is already a filled-in hash acl info */
int hash_acl_exists(acl_main_t *am, int acl_index);


typedef sturct match_tuple_main_t_
{
  hash_acl_info_t *hash_acl_infos;	/* corresponding hash matching housekeeping info */
  clib_bihash_48_8_t acl_lookup_hash;	/* ACL lookup hash table. */
  u32 hash_lookup_hash_buckets;
  uword hash_lookup_hash_memory;

  /* a pool of all mask types present in all ACEs */
  ace_mask_type_entry_t *ace_mask_type_pool;
applied_hash_ace_entry_t **hash_entry_vec_by_lc_index;
  applied_hash_acl_info_t *applied_hash_acl_info_by_lc_index;

    /* vec of vectors of all info of all mask types present in ACEs contained in each lc_index */
  hash_applied_mask_info_t **hash_applied_mask_info_vec_by_lc_index;
  /* Do we use the TupleMerge for hash ACLs or not */
  int use_tuple_merge;

  /* Max collision vector length before splitting the tuple */
#define TM_SPLIT_THRESHOLD 39
  int tuple_merge_split_threshold;


} matxh_tuple_main_t;


/*
  am->hash_lookup_hash_buckets = ACL_PLUGIN_HASH_LOOKUP_HASH_BUCKETS;
  am->hash_lookup_hash_memory = ACL_PLUGIN_HASH_LOOKUP_HASH_MEMORY;
*/
/* use tuplemerge by default */
//  am->use_tuple_merge = 1;
  /* Set the default threshold */
//  am->tuple_merge_split_threshold = TM_SPLIT_THRESHOLD;

#endif
