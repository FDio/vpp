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

#include <stddef.h>
#include <netinet/in.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/plugin/plugin.h>
#include <acl/acl.h>
#include <vppinfra/bihash_48_8.h>

#include "hash_lookup.h"
#include "hash_lookup_private.h"


static inline applied_hash_ace_entry_t **get_applied_hash_aces(acl_main_t *am, int is_input, u32 sw_if_index)
{
  applied_hash_ace_entry_t **applied_hash_aces = is_input ? vec_elt_at_index(am->input_hash_entry_vec_by_sw_if_index, sw_if_index)
                                                          : vec_elt_at_index(am->output_hash_entry_vec_by_sw_if_index, sw_if_index);
  return applied_hash_aces;
}



/*
 * This returns true if there is indeed a match on the portranges.
 * With all these levels of indirections, this is not going to be very fast,
 * so, best use the individual ports or wildcard ports for performance.
 */
static int
match_portranges(acl_main_t *am, fa_5tuple_t *match, u32 index)
{

  applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, match->pkt.is_input, match->pkt.sw_if_index);
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), index);

  acl_rule_t *r = &(am->acls[pae->acl_index].rules[pae->ace_index]);
  DBG("PORTMATCH: %d <= %d <= %d && %d <= %d <= %d ?",
		r->src_port_or_type_first, match->l4.port[0], r->src_port_or_type_last,
		r->dst_port_or_code_first, match->l4.port[1], r->dst_port_or_code_last);

  return ( ((r->src_port_or_type_first <= match->l4.port[0]) && r->src_port_or_type_last >= match->l4.port[0]) &&
           ((r->dst_port_or_code_first <= match->l4.port[1]) && r->dst_port_or_code_last >= match->l4.port[1]) );
}

static u32
multi_acl_match_get_applied_ace_index(acl_main_t *am, fa_5tuple_t *match)
{
  clib_bihash_kv_48_8_t kv;
  clib_bihash_kv_48_8_t result;
  fa_5tuple_t *kv_key = (fa_5tuple_t *)kv.key;
  hash_acl_lookup_value_t *result_val = (hash_acl_lookup_value_t *)&result.value;
  u64 *pmatch = (u64 *)match;
  u64 *pmask;
  u64 *pkey;
  int mask_type_index;
  u32 curr_match_index = ~0;

  u32 sw_if_index = match->pkt.sw_if_index;
  u8 is_input = match->pkt.is_input;
  applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, is_input, sw_if_index);
  applied_hash_acl_info_t **applied_hash_acls = is_input ? &am->input_applied_hash_acl_info_by_sw_if_index :
                                                    &am->output_applied_hash_acl_info_by_sw_if_index;

  DBG("TRYING TO MATCH: %016llx %016llx %016llx %016llx %016llx %016llx",
	       pmatch[0], pmatch[1], pmatch[2], pmatch[3], pmatch[4], pmatch[5]);

  for(mask_type_index=0; mask_type_index < pool_len(am->ace_mask_type_pool); mask_type_index++) {
    if (!clib_bitmap_get(vec_elt_at_index((*applied_hash_acls), sw_if_index)->mask_type_index_bitmap, mask_type_index)) {
      /* This bit is not set. Avoid trying to match */
      continue;
    }
    ace_mask_type_entry_t *mte = vec_elt_at_index(am->ace_mask_type_pool, mask_type_index);
    pmatch = (u64 *)match;
    pmask = (u64 *)&mte->mask;
    pkey = (u64 *)kv.key;
    /*
    * unrolling the below loop results in a noticeable performance increase.
    int i;
    for(i=0; i<6; i++) {
      kv.key[i] = pmatch[i] & pmask[i];
    }
    */

    *pkey++ = *pmatch++ & *pmask++;
    *pkey++ = *pmatch++ & *pmask++;
    *pkey++ = *pmatch++ & *pmask++;
    *pkey++ = *pmatch++ & *pmask++;
    *pkey++ = *pmatch++ & *pmask++;
    *pkey++ = *pmatch++ & *pmask++;

    kv_key->pkt.mask_type_index_lsb = mask_type_index;
    DBG("        KEY %3d: %016llx %016llx %016llx %016llx %016llx %016llx", mask_type_index,
		kv.key[0], kv.key[1], kv.key[2], kv.key[3], kv.key[4], kv.key[5]);
    int res = BV (clib_bihash_search) (&am->acl_lookup_hash, &kv, &result);
    if (res == 0) {
      DBG("ACL-MATCH! result_val: %016llx", result_val->as_u64);
      if (result_val->applied_entry_index < curr_match_index) {
	if (PREDICT_FALSE(result_val->need_portrange_check)) {
          /*
           * This is going to be slow, since we can have multiple superset
           * entries for narrow-ish portranges, e.g.:
           * 0..42 100..400, 230..60000,
           * so we need to walk linearly and check if they match.
           */

          u32 curr_index = result_val->applied_entry_index;
          while ((curr_index != ~0) && !match_portranges(am, match, curr_index)) {
            /* while no match and there are more entries, walk... */
            applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces),curr_index);
            DBG("entry %d did not portmatch, advancing to %d", curr_index, pae->next_applied_entry_index);
            curr_index = pae->next_applied_entry_index;
          }
          if (curr_index < curr_match_index) {
            DBG("The index %d is the new candidate in portrange matches.", curr_index);
            curr_match_index = curr_index;
          } else {
            DBG("Curr portmatch index %d is too big vs. current matched one %d", curr_index, curr_match_index);
          }
        } else {
          /* The usual path is here. Found an entry in front of the current candiate - so it's a new one */
          DBG("This match is the new candidate");
          curr_match_index = result_val->applied_entry_index;
	  if (!result_val->shadowed) {
          /* new result is known to not be shadowed, so no point to look up further */
            break;
	  }
        }
      }
    }
  }
  DBG("MATCH-RESULT: %d", curr_match_index);
  return curr_match_index;
}

static void
hashtable_add_del(acl_main_t *am, clib_bihash_kv_48_8_t *kv, int is_add)
{
    DBG("HASH ADD/DEL: %016llx %016llx %016llx %016llx %016llx %016llx %016llx add %d",
                        kv->key[0], kv->key[1], kv->key[2],
                        kv->key[3], kv->key[4], kv->key[5], kv->value, is_add);
    BV (clib_bihash_add_del) (&am->acl_lookup_hash, kv, is_add);
}

static void
fill_applied_hash_ace_kv(acl_main_t *am,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 sw_if_index, u8 is_input,
                            u32 new_index, clib_bihash_kv_48_8_t *kv)
{
  fa_5tuple_t *kv_key = (fa_5tuple_t *)kv->key;
  hash_acl_lookup_value_t *kv_val = (hash_acl_lookup_value_t *)&kv->value;
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), new_index);
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);

  memcpy(kv_key, &(vec_elt_at_index(ha->rules, pae->hash_ace_info_index)->match), sizeof(*kv_key));
  /* initialize the sw_if_index and direction */
  kv_key->pkt.sw_if_index = sw_if_index;
  kv_key->pkt.is_input = is_input;
  kv_val->as_u64 = 0;
  kv_val->applied_entry_index = new_index;
  kv_val->need_portrange_check = vec_elt_at_index(ha->rules, pae->hash_ace_info_index)->src_portrange_not_powerof2 ||
				   vec_elt_at_index(ha->rules, pae->hash_ace_info_index)->dst_portrange_not_powerof2;
  /* by default assume all values are shadowed -> check all mask types */
  kv_val->shadowed = 1;
}

static void
add_del_hashtable_entry(acl_main_t *am,
                            u32 sw_if_index, u8 is_input,
                            applied_hash_ace_entry_t **applied_hash_aces,
			    u32 index, int is_add)
{
  clib_bihash_kv_48_8_t kv;

  fill_applied_hash_ace_kv(am, applied_hash_aces, sw_if_index, is_input, index, &kv);
  hashtable_add_del(am, &kv, is_add);
}



static void
activate_applied_ace_hash_entry(acl_main_t *am,
                            u32 sw_if_index, u8 is_input,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 new_index)
{
  clib_bihash_kv_48_8_t kv;
  ASSERT(new_index != ~0);
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), new_index);
  DBG("activate_applied_ace_hash_entry sw_if_index %d is_input %d new_index %d", sw_if_index, is_input, new_index);

  fill_applied_hash_ace_kv(am, applied_hash_aces, sw_if_index, is_input, new_index, &kv);

  DBG("APPLY ADD KY: %016llx %016llx %016llx %016llx %016llx %016llx",
			kv.key[0], kv.key[1], kv.key[2],
			kv.key[3], kv.key[4], kv.key[5]);

  clib_bihash_kv_48_8_t result;
  hash_acl_lookup_value_t *result_val = (hash_acl_lookup_value_t *)&result.value;
  int res = BV (clib_bihash_search) (&am->acl_lookup_hash, &kv, &result);
  ASSERT(new_index != ~0);
  ASSERT(new_index < vec_len((*applied_hash_aces)));
  if (res == 0) {
    /* There already exists an entry or more. Append at the end. */
    u32 first_index = result_val->applied_entry_index;
    ASSERT(first_index != ~0);
    DBG("A key already exists, with applied entry index: %d", first_index);
    applied_hash_ace_entry_t *first_pae = vec_elt_at_index((*applied_hash_aces), first_index);
    u32 last_index = first_pae->tail_applied_entry_index;
    ASSERT(last_index != ~0);
    applied_hash_ace_entry_t *last_pae = vec_elt_at_index((*applied_hash_aces), last_index);
    DBG("...advance to chained entry index: %d", last_index);
    /* link ourseves in */
    last_pae->next_applied_entry_index = new_index;
    pae->prev_applied_entry_index = last_index;
    /* adjust the pointer to the new tail */
    first_pae->tail_applied_entry_index = new_index;
  } else {
    /* It's the very first entry */
    hashtable_add_del(am, &kv, 1);
    ASSERT(new_index != ~0);
    pae->tail_applied_entry_index = new_index;
  }
}

static void
applied_hash_entries_analyze(acl_main_t *am, applied_hash_ace_entry_t **applied_hash_aces)
{
  /*
   * Go over the rules and check which ones are shadowed and which aren't.
   * Naive approach: try to match the match value from every ACE as if it
   * was a live packet, and see if the resulting match happens earlier in the list.
   * if it does not match or it is later in the ACL - then the entry is not shadowed.
   *
   * This approach fails, an example:
   *   deny tcp 2001:db8::/32 2001:db8::/32
   *   permit ip 2001:db8::1/128 2001:db8::2/128
   */
}

static void *
hash_acl_set_heap(acl_main_t *am)
{
  if (0 == am->hash_lookup_mheap) {
    am->hash_lookup_mheap = mheap_alloc (0 /* use VM */ , am->hash_lookup_mheap_size);
    mheap_t *h = mheap_header (am->hash_lookup_mheap);
    h->flags |= MHEAP_FLAG_THREAD_SAFE;
  }
  void *oldheap = clib_mem_set_heap(am->hash_lookup_mheap);
  return oldheap;
}

void
acl_plugin_hash_acl_set_validate_heap(acl_main_t *am, int on)
{
  clib_mem_set_heap(hash_acl_set_heap(am));
  mheap_t *h = mheap_header (am->hash_lookup_mheap);
  if (on) {
    h->flags |= MHEAP_FLAG_VALIDATE;
    h->flags &= ~MHEAP_FLAG_SMALL_OBJECT_CACHE;
    mheap_validate(h);
  } else {
    h->flags &= ~MHEAP_FLAG_VALIDATE;
    h->flags |= MHEAP_FLAG_SMALL_OBJECT_CACHE;
  }
}

void
acl_plugin_hash_acl_set_trace_heap(acl_main_t *am, int on)
{
  clib_mem_set_heap(hash_acl_set_heap(am));
  mheap_t *h = mheap_header (am->hash_lookup_mheap);
  if (on) {
    h->flags |= MHEAP_FLAG_TRACE;
  } else {
    h->flags &= ~MHEAP_FLAG_TRACE;
  }
}

void
hash_acl_apply(acl_main_t *am, u32 sw_if_index, u8 is_input, int acl_index)
{
  int i;

  DBG0("HASH ACL apply: sw_if_index %d is_input %d acl %d", sw_if_index, is_input, acl_index);
  if (!am->acl_lookup_hash_initialized) {
    BV (clib_bihash_init) (&am->acl_lookup_hash, "ACL plugin rule lookup bihash",
                           am->hash_lookup_hash_buckets, am->hash_lookup_hash_memory);
    am->acl_lookup_hash_initialized = 1;
  }

  void *oldheap = hash_acl_set_heap(am);
  if (is_input) {
    vec_validate(am->input_hash_entry_vec_by_sw_if_index, sw_if_index);
  } else {
    vec_validate(am->output_hash_entry_vec_by_sw_if_index, sw_if_index);
  }
  vec_validate(am->hash_acl_infos, acl_index);
  applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, is_input, sw_if_index);

  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  u32 **hash_acl_applied_sw_if_index = is_input ? &ha->inbound_sw_if_index_list
                                                : &ha->outbound_sw_if_index_list;

  int base_offset = vec_len(*applied_hash_aces);

  /* Update the bitmap of the mask types with which the lookup
     needs to happen for the ACLs applied to this sw_if_index */
  applied_hash_acl_info_t **applied_hash_acls = is_input ? &am->input_applied_hash_acl_info_by_sw_if_index :
                                                    &am->output_applied_hash_acl_info_by_sw_if_index;
  vec_validate((*applied_hash_acls), sw_if_index);
  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), sw_if_index);

  /* ensure the list of applied hash acls is initialized and add this acl# to it */
  u32 index = vec_search(pal->applied_acls, acl_index);
  if (index != ~0) {
    clib_warning("BUG: trying to apply twice acl_index %d on sw_if_index %d is_input %d",
                 acl_index, sw_if_index, is_input);
    goto done;
  }
  vec_add1(pal->applied_acls, acl_index);
  u32 index2 = vec_search((*hash_acl_applied_sw_if_index), sw_if_index);
  if (index2 != ~0) {
    clib_warning("BUG: trying to apply twice acl_index %d on (sw_if_index %d) is_input %d",
                 acl_index, sw_if_index, is_input);
    goto done;
  }
  vec_add1((*hash_acl_applied_sw_if_index), sw_if_index);

  pal->mask_type_index_bitmap = clib_bitmap_or(pal->mask_type_index_bitmap,
                                     ha->mask_type_index_bitmap);
  /*
   * if the applied ACL is empty, the current code will cause a
   * different behavior compared to current linear search: an empty ACL will
   * simply fallthrough to the next ACL, or the default deny in the end.
   *
   * This is not a problem, because after vpp-dev discussion,
   * the consensus was it should not be possible to apply the non-existent
   * ACL, so the change adding this code also takes care of that.
   */

  /* expand the applied aces vector by the necessary amount */
  vec_resize((*applied_hash_aces), vec_len(ha->rules));

  /* add the rules from the ACL to the hash table for lookup and append to the vector*/
  for(i=0; i < vec_len(ha->rules); i++) {
    u32 new_index = base_offset + i;
    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), new_index);
    pae->acl_index = acl_index;
    pae->ace_index = ha->rules[i].ace_index;
    pae->action = ha->rules[i].action;
    pae->hitcount = 0;
    pae->hash_ace_info_index = i;
    /* we might link it in later */
    pae->next_applied_entry_index = ~0;
    pae->prev_applied_entry_index = ~0;
    pae->tail_applied_entry_index = ~0;
    activate_applied_ace_hash_entry(am, sw_if_index, is_input, applied_hash_aces, new_index);
  }
  applied_hash_entries_analyze(am, applied_hash_aces);
done:
  clib_mem_set_heap (oldheap);
}

static u32
find_head_applied_ace_index(applied_hash_ace_entry_t **applied_hash_aces, u32 curr_index)
{
  /*
   * find back the first entry. Inefficient so might need to be a bit cleverer
   * if this proves to be a problem..
   */
  u32 an_index = curr_index;
  ASSERT(an_index != ~0);
  applied_hash_ace_entry_t *head_pae = vec_elt_at_index((*applied_hash_aces), an_index);
  while(head_pae->prev_applied_entry_index != ~0) {
    an_index = head_pae->prev_applied_entry_index;
    ASSERT(an_index != ~0);
    head_pae = vec_elt_at_index((*applied_hash_aces), an_index);
  }
  return an_index;
}

static void
move_applied_ace_hash_entry(acl_main_t *am,
                            u32 sw_if_index, u8 is_input,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 old_index, u32 new_index)
{
  ASSERT(old_index != ~0);
  ASSERT(new_index != ~0);
  /* move the entry */
  *vec_elt_at_index((*applied_hash_aces), new_index) = *vec_elt_at_index((*applied_hash_aces), old_index);

  /* update the linkage and hash table if necessary */
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), old_index);

  if (pae->prev_applied_entry_index != ~0) {
    applied_hash_ace_entry_t *prev_pae = vec_elt_at_index((*applied_hash_aces), pae->prev_applied_entry_index);
    ASSERT(prev_pae->next_applied_entry_index == old_index);
    prev_pae->next_applied_entry_index = new_index;
  } else {
    /* first entry - so the hash points to it, update */
    add_del_hashtable_entry(am, sw_if_index, is_input,
                            applied_hash_aces, new_index, 1);
    ASSERT(pae->tail_applied_entry_index != ~0);
  }
  if (pae->next_applied_entry_index != ~0) {
    applied_hash_ace_entry_t *next_pae = vec_elt_at_index((*applied_hash_aces), pae->next_applied_entry_index);
    ASSERT(next_pae->prev_applied_entry_index == old_index);
    next_pae->prev_applied_entry_index = new_index;
  } else {
    /*
     * Moving the very last entry, so we need to update the tail pointer in the first one.
     */
    u32 head_index = find_head_applied_ace_index(applied_hash_aces, old_index);
    ASSERT(head_index != ~0);
    applied_hash_ace_entry_t *head_pae = vec_elt_at_index((*applied_hash_aces), head_index);

    ASSERT(head_pae->tail_applied_entry_index == old_index);
    head_pae->tail_applied_entry_index = new_index;
  }
  /* invalidate the old entry */
  pae->prev_applied_entry_index = ~0;
  pae->next_applied_entry_index = ~0;
  pae->tail_applied_entry_index = ~0;
}

static void
deactivate_applied_ace_hash_entry(acl_main_t *am,
                            u32 sw_if_index, u8 is_input,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 old_index)
{
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), old_index);
  DBG("UNAPPLY DEACTIVATE: sw_if_index %d is_input %d, applied index %d", sw_if_index, is_input, old_index);

  if (pae->prev_applied_entry_index != ~0) {
    DBG("UNAPPLY = index %d has prev_applied_entry_index %d", old_index, pae->prev_applied_entry_index);
    applied_hash_ace_entry_t *prev_pae = vec_elt_at_index((*applied_hash_aces), pae->prev_applied_entry_index);
    ASSERT(prev_pae->next_applied_entry_index == old_index);
    prev_pae->next_applied_entry_index = pae->next_applied_entry_index;
    if (pae->next_applied_entry_index == ~0) {
      /* it was a last entry we removed, update the pointer on the first one */
      u32 head_index = find_head_applied_ace_index(applied_hash_aces, old_index);
      DBG("UNAPPLY = index %d head index to update %d", old_index, head_index);
      ASSERT(head_index != ~0);
      applied_hash_ace_entry_t *head_pae = vec_elt_at_index((*applied_hash_aces), head_index);

      ASSERT(head_pae->tail_applied_entry_index == old_index);
      head_pae->tail_applied_entry_index = pae->prev_applied_entry_index;
    } else {
      applied_hash_ace_entry_t *next_pae = vec_elt_at_index((*applied_hash_aces), pae->next_applied_entry_index);
      next_pae->prev_applied_entry_index = pae->prev_applied_entry_index;
    }
  } else {
    /* It was the first entry. We need either to reset the hash entry or delete it */
    if (pae->next_applied_entry_index != ~0) {
      /* the next element becomes the new first one, so needs the tail pointer to be set */
      applied_hash_ace_entry_t *next_pae = vec_elt_at_index((*applied_hash_aces), pae->next_applied_entry_index);
      ASSERT(pae->tail_applied_entry_index != ~0);
      next_pae->tail_applied_entry_index = pae->tail_applied_entry_index;
      DBG("Resetting the hash table entry from %d to %d, setting tail index to %d", old_index, pae->next_applied_entry_index, pae->tail_applied_entry_index);
      /* unlink from the next element */
      next_pae->prev_applied_entry_index = ~0;
      add_del_hashtable_entry(am, sw_if_index, is_input,
                              applied_hash_aces, pae->next_applied_entry_index, 1);
    } else {
      /* no next entry, so just delete the entry in the hash table */
      add_del_hashtable_entry(am, sw_if_index, is_input,
                              applied_hash_aces, old_index, 0);
    }
  }
  /* invalidate the old entry */
  pae->prev_applied_entry_index = ~0;
  pae->next_applied_entry_index = ~0;
  pae->tail_applied_entry_index = ~0;
}


static void
hash_acl_build_applied_lookup_bitmap(acl_main_t *am, u32 sw_if_index, u8 is_input)
{
  int i;
  uword *new_lookup_bitmap = 0;
  applied_hash_acl_info_t **applied_hash_acls = is_input ? &am->input_applied_hash_acl_info_by_sw_if_index
                                                         : &am->output_applied_hash_acl_info_by_sw_if_index;
  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), sw_if_index);
  for(i=0; i < vec_len(pal->applied_acls); i++) {
    u32 a_acl_index = *vec_elt_at_index((pal->applied_acls), i);
    hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, a_acl_index);
    DBG("Update bitmask = %U or %U (acl_index %d)\n", format_bitmap_hex, new_lookup_bitmap,
          format_bitmap_hex, ha->mask_type_index_bitmap, a_acl_index);
    new_lookup_bitmap = clib_bitmap_or(new_lookup_bitmap,
                                       ha->mask_type_index_bitmap);
  }
  uword *old_lookup_bitmap = pal->mask_type_index_bitmap;
  pal->mask_type_index_bitmap = new_lookup_bitmap;
  clib_bitmap_free(old_lookup_bitmap);
}

void
hash_acl_unapply(acl_main_t *am, u32 sw_if_index, u8 is_input, int acl_index)
{
  int i;

  DBG0("HASH ACL unapply: sw_if_index %d is_input %d acl %d", sw_if_index, is_input, acl_index);
  applied_hash_acl_info_t **applied_hash_acls = is_input ? &am->input_applied_hash_acl_info_by_sw_if_index
                                                         : &am->output_applied_hash_acl_info_by_sw_if_index;
  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), sw_if_index);

  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  u32 **hash_acl_applied_sw_if_index = is_input ? &ha->inbound_sw_if_index_list
                                                : &ha->outbound_sw_if_index_list;

  /* remove this acl# from the list of applied hash acls */
  u32 index = vec_search(pal->applied_acls, acl_index);
  if (index == ~0) {
    clib_warning("BUG: trying to unapply unapplied acl_index %d on sw_if_index %d is_input %d",
                 acl_index, sw_if_index, is_input);
    return;
  }
  vec_del1(pal->applied_acls, index);

  u32 index2 = vec_search((*hash_acl_applied_sw_if_index), sw_if_index);
  if (index2 == ~0) {
    clib_warning("BUG: trying to unapply twice acl_index %d on (sw_if_index %d) is_input %d",
                 acl_index, sw_if_index, is_input);
    return;
  }
  vec_del1((*hash_acl_applied_sw_if_index), index2);

  applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, is_input, sw_if_index);

  for(i=0; i < vec_len((*applied_hash_aces)); i++) {
    if (vec_elt_at_index(*applied_hash_aces,i)->acl_index == acl_index) {
      DBG("Found applied ACL#%d at applied index %d", acl_index, i);
      break;
    }
  }
  if (vec_len((*applied_hash_aces)) <= i) {
    DBG("Did not find applied ACL#%d at sw_if_index %d", acl_index, sw_if_index);
    /* we went all the way without finding any entries. Probably a list was empty. */
    return;
  }

  void *oldheap = hash_acl_set_heap(am);
  int base_offset = i;
  int tail_offset = base_offset + vec_len(ha->rules);
  int tail_len = vec_len((*applied_hash_aces)) - tail_offset;
  DBG("base_offset: %d, tail_offset: %d, tail_len: %d", base_offset, tail_offset, tail_len);

  for(i=0; i < vec_len(ha->rules); i ++) {
    deactivate_applied_ace_hash_entry(am, sw_if_index, is_input,
                                      applied_hash_aces, base_offset + i);
  }
  for(i=0; i < tail_len; i ++) {
    /* move the entry at tail offset to base offset */
    /* that is, from (tail_offset+i) -> (base_offset+i) */
    DBG("UNAPPLY MOVE: sw_if_index %d is_input %d, applied index %d ->", sw_if_index, is_input, tail_offset+i, base_offset + i);
    move_applied_ace_hash_entry(am, sw_if_index, is_input, applied_hash_aces, tail_offset + i, base_offset + i);
  }
  /* trim the end of the vector */
  _vec_len((*applied_hash_aces)) -= vec_len(ha->rules);

  applied_hash_entries_analyze(am, applied_hash_aces);

  /* After deletion we might not need some of the mask-types anymore... */
  hash_acl_build_applied_lookup_bitmap(am, sw_if_index, is_input);
  clib_mem_set_heap (oldheap);
}

/*
 * Create the applied ACEs and update the hash table,
 * taking into account that the ACL may not be the last
 * in the vector of applied ACLs.
 *
 * For now, walk from the end of the vector and unapply the ACLs,
 * then apply the one in question and reapply the rest.
 */

void
hash_acl_reapply(acl_main_t *am, u32 sw_if_index, u8 is_input, int acl_index)
{
  u32 **applied_acls = is_input ? vec_elt_at_index(am->input_acl_vec_by_sw_if_index, sw_if_index)
                                : vec_elt_at_index(am->output_acl_vec_by_sw_if_index, sw_if_index);
  int i;
  int start_index = vec_search((*applied_acls), acl_index);
  /*
   * This function is called after we find out the sw_if_index where ACL is applied.
   * If the by-sw_if_index vector does not have the ACL#, then it's a bug.
   */
  ASSERT(start_index < vec_len(*applied_acls));

  /* unapply all the ACLs till the current one */
  for(i = vec_len(*applied_acls) - 1; i > start_index; i--) {
    hash_acl_unapply(am, sw_if_index, is_input, *vec_elt_at_index(*applied_acls, i));
  }
  for(i = start_index; i < vec_len(*applied_acls); i++) {
    hash_acl_apply(am, sw_if_index, is_input, *vec_elt_at_index(*applied_acls, i));
  }
}

static void
make_address_mask(ip46_address_t *addr, u8 is_ipv6, u8 prefix_len)
{
  if (is_ipv6) {
    ip6_address_mask_from_width(&addr->ip6, prefix_len);
  } else {
    /* FIXME: this may not be correct way */
    ip6_address_mask_from_width(&addr->ip6, prefix_len + 3*32);
    ip46_address_mask_ip4(addr);
  }
}

static u8
make_port_mask(u16 *portmask, u16 port_first, u16 port_last)
{
  if (port_first == port_last) {
    *portmask = 0xffff;
    /* single port is representable by masked value */
    return 0;
  }
  if ((port_first == 0) && (port_last == 65535)) {
    *portmask = 0;
    /* wildcard port is representable by a masked value */
    return 0;
  }

  /*
   * For now match all the ports, later
   * here might be a better optimization which would
   * pick out bitmaskable portranges.
   *
   * However, adding a new mask type potentially
   * adds a per-packet extra lookup, so the benefit is not clear.
   */
  *portmask = 0;
  /* This port range can't be represented via bitmask exactly. */
  return 1;
}

static void
make_mask_and_match_from_rule(fa_5tuple_t *mask, acl_rule_t *r, hash_ace_info_t *hi, int match_nonfirst_fragment)
{
  memset(mask, 0, sizeof(*mask));
  memset(&hi->match, 0, sizeof(hi->match));
  hi->action = r->is_permit;

  /* we will need to be matching based on sw_if_index, direction, and mask_type_index when applied */
  mask->pkt.sw_if_index = ~0;
  mask->pkt.is_input = 1;
  /* we will assign the match of mask_type_index later when we find it*/
  mask->pkt.mask_type_index_lsb = ~0;

  mask->pkt.is_ip6 = 1;
  hi->match.pkt.is_ip6 = r->is_ipv6;

  make_address_mask(&mask->addr[0], r->is_ipv6, r->src_prefixlen);
  hi->match.addr[0] = r->src;
  make_address_mask(&mask->addr[1], r->is_ipv6, r->dst_prefixlen);
  hi->match.addr[1] = r->dst;

  if (r->proto != 0) {
    mask->l4.proto = ~0; /* L4 proto needs to be matched */
    hi->match.l4.proto = r->proto;
    if (match_nonfirst_fragment) {
      /* match the non-first fragments only */
      mask->pkt.is_nonfirst_fragment = 1;
      hi->match.pkt.is_nonfirst_fragment = 1;
    } else {
      /* Calculate the src/dst port masks and make the src/dst port matches accordingly */
      hi->src_portrange_not_powerof2 = make_port_mask(&mask->l4.port[0], r->src_port_or_type_first, r->src_port_or_type_last);
      hi->match.l4.port[0] = r->src_port_or_type_first & mask->l4.port[0];
      hi->dst_portrange_not_powerof2 = make_port_mask(&mask->l4.port[1], r->dst_port_or_code_first, r->dst_port_or_code_last);
      hi->match.l4.port[1] = r->dst_port_or_code_first & mask->l4.port[1];
      /* L4 info must be valid in order to match */
      mask->pkt.l4_valid = 1;
      hi->match.pkt.l4_valid = 1;
      /* And we must set the mask to check that it is an initial fragment */
      mask->pkt.is_nonfirst_fragment = 1;
      hi->match.pkt.is_nonfirst_fragment = 0;
      if ((r->proto == IPPROTO_TCP) && (r->tcp_flags_mask != 0)) {
	/* if we want to match on TCP flags, they must be masked off as well */
	mask->pkt.tcp_flags = r->tcp_flags_mask;
	hi->match.pkt.tcp_flags = r->tcp_flags_value;
	/* and the flags need to be present within the packet being matched */
	mask->pkt.tcp_flags_valid = 1;
	hi->match.pkt.tcp_flags_valid = 1;
      }
    }
  }
  /* Sanitize the mask and the match */
  u64 *pmask = (u64 *)mask;
  u64 *pmatch = (u64 *)&hi->match;
  int j;
  for(j=0; j<6; j++) {
    pmatch[j] = pmatch[j] & pmask[j];
  }
}

static u32
find_mask_type_index(acl_main_t *am, fa_5tuple_t *mask)
{
  ace_mask_type_entry_t *mte;
  /* *INDENT-OFF* */
  pool_foreach(mte, am->ace_mask_type_pool,
  ({
    if(memcmp(&mte->mask, mask, sizeof(*mask)) == 0)
      return (mte - am->ace_mask_type_pool);
  }));
  /* *INDENT-ON* */
  return ~0;
}

static u32
assign_mask_type_index(acl_main_t *am, fa_5tuple_t *mask)
{
  u32 mask_type_index = find_mask_type_index(am, mask);
  ace_mask_type_entry_t *mte;
  if(~0 == mask_type_index) {
    pool_get_aligned (am->ace_mask_type_pool, mte, CLIB_CACHE_LINE_BYTES);
    mask_type_index = mte - am->ace_mask_type_pool;
    clib_memcpy(&mte->mask, mask, sizeof(mte->mask));
    mte->refcount = 0;
    /*
     * We can use only 16 bits, since in the match there is only u16 field.
     * Realistically, once you go to 64K of mask types, it is a huge
     * problem anyway, so we might as well stop half way.
     */
    ASSERT(mask_type_index < 32768);
  }
  mte = am->ace_mask_type_pool + mask_type_index;
  mte->refcount++;
  return mask_type_index;
}

static void
release_mask_type_index(acl_main_t *am, u32 mask_type_index)
{
  ace_mask_type_entry_t *mte = pool_elt_at_index(am->ace_mask_type_pool, mask_type_index);
  mte->refcount--;
  if (mte->refcount == 0) {
    /* we are not using this entry anymore */
    pool_put(am->ace_mask_type_pool, mte);
  }
}

void hash_acl_add(acl_main_t *am, int acl_index)
{
  void *oldheap = hash_acl_set_heap(am);
  DBG("HASH ACL add : %d", acl_index);
  int i;
  acl_list_t *a = &am->acls[acl_index];
  vec_validate(am->hash_acl_infos, acl_index);
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  memset(ha, 0, sizeof(*ha));

  /* walk the newly added ACL entries and ensure that for each of them there
     is a mask type, increment a reference count for that mask type */
  for(i=0; i < a->count; i++) {
    hash_ace_info_t ace_info;
    fa_5tuple_t mask;
    memset(&ace_info, 0, sizeof(ace_info));
    ace_info.acl_index = acl_index;
    ace_info.ace_index = i;

    make_mask_and_match_from_rule(&mask, &a->rules[i], &ace_info, 0);
    ace_info.mask_type_index = assign_mask_type_index(am, &mask);
    /* assign the mask type index for matching itself */
    ace_info.match.pkt.mask_type_index_lsb = ace_info.mask_type_index;
    DBG("ACE: %d mask_type_index: %d", i, ace_info.mask_type_index);
    /* Ensure a given index is set in the mask type index bitmap for this ACL */
    ha->mask_type_index_bitmap = clib_bitmap_set(ha->mask_type_index_bitmap, ace_info.mask_type_index, 1);
    vec_add1(ha->rules, ace_info);
    if (am->l4_match_nonfirst_fragment) {
      /* add the second rule which matches the noninitial fragments with the respective mask */
      make_mask_and_match_from_rule(&mask, &a->rules[i], &ace_info, 1);
      ace_info.mask_type_index = assign_mask_type_index(am, &mask);
      ace_info.match.pkt.mask_type_index_lsb = ace_info.mask_type_index;
      DBG("ACE: %d (non-initial frags) mask_type_index: %d", i, ace_info.mask_type_index);
      /* Ensure a given index is set in the mask type index bitmap for this ACL */
      ha->mask_type_index_bitmap = clib_bitmap_set(ha->mask_type_index_bitmap, ace_info.mask_type_index, 1);
      vec_add1(ha->rules, ace_info);
    }
  }
  /*
   * if an ACL is applied somewhere, fill the corresponding lookup data structures.
   * We need to take care if the ACL is not the last one in the vector of ACLs applied to the interface.
   */
  if (acl_index < vec_len(am->input_sw_if_index_vec_by_acl)) {
    u32 *sw_if_index;
    vec_foreach(sw_if_index, am->input_sw_if_index_vec_by_acl[acl_index]) {
      hash_acl_reapply(am, *sw_if_index, 1, acl_index);
    }
  }
  if (acl_index < vec_len(am->output_sw_if_index_vec_by_acl)) {
    u32 *sw_if_index;
    vec_foreach(sw_if_index, am->output_sw_if_index_vec_by_acl[acl_index]) {
      hash_acl_reapply(am, *sw_if_index, 0, acl_index);
    }
  }
  clib_mem_set_heap (oldheap);
}

void hash_acl_delete(acl_main_t *am, int acl_index)
{
  void *oldheap = hash_acl_set_heap(am);
  DBG0("HASH ACL delete : %d", acl_index);
  /*
   * If the ACL is applied somewhere, remove the references of it (call hash_acl_unapply)
   * this is a different behavior from the linear lookup where an empty ACL is "deny all",
   *
   * However, following vpp-dev discussion the ACL that is referenced elsewhere
   * should not be possible to delete, and the change adding this also adds
   * the safeguards to that respect, so this is not a problem.
   *
   * The part to rememeber is that this routine is called in process of reapplication
   * during the acl_add_replace() API call - the old acl ruleset is deleted, then
   * the new one is added, without the change in the applied ACLs - so this case
   * has to be handled.
   */
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  u32 *interface_list_copy = 0;
  {
    u32 *sw_if_index;
    interface_list_copy = vec_dup(ha->inbound_sw_if_index_list);
    vec_foreach(sw_if_index, interface_list_copy) {
      hash_acl_unapply(am, *sw_if_index, 1, acl_index);
    }
    vec_free(interface_list_copy);
    interface_list_copy = vec_dup(ha->outbound_sw_if_index_list);
    vec_foreach(sw_if_index, interface_list_copy) {
      hash_acl_unapply(am, *sw_if_index, 0, acl_index);
    }
  }

  /* walk the mask types for the ACL about-to-be-deleted, and decrease
   * the reference count, possibly freeing up some of them */
  int i;
  for(i=0; i < vec_len(ha->rules); i++) {
    release_mask_type_index(am, ha->rules[i].mask_type_index);
  }
  clib_bitmap_free(ha->mask_type_index_bitmap);
  vec_free(ha->rules);
  clib_mem_set_heap (oldheap);
}

u8
hash_multi_acl_match_5tuple (u32 sw_if_index, fa_5tuple_t * pkt_5tuple, int is_l2,
                       int is_ip6, int is_input, u32 * acl_match_p,
                       u32 * rule_match_p, u32 * trace_bitmap)
{
  acl_main_t *am = &acl_main;
  applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, is_input, sw_if_index);
  u32 match_index = multi_acl_match_get_applied_ace_index(am, pkt_5tuple);
  if (match_index < vec_len((*applied_hash_aces))) {
    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), match_index);
    pae->hitcount++;
    *acl_match_p = pae->acl_index;
    *rule_match_p = pae->ace_index;
    return pae->action;
  }
  return 0;
}


void
show_hash_acl_hash (vlib_main_t * vm, acl_main_t *am, u32 verbose)
{
  vlib_cli_output(vm, "\nACL lookup hash table:\n%U\n",
                  BV (format_bihash), &am->acl_lookup_hash, verbose);
}
