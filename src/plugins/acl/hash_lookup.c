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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/plugin/plugin.h>
#include <acl/acl.h>
#include <vppinfra/bihash_48_8.h>

#include "hash_lookup.h"
#include "hash_lookup_private.h"

//===Added by Valerio
#ifdef VALE_ELOG_ACL

#include <vppinfra/elog.h>
//#include "generic/rte_cycles.h" // for rdtsc()

#endif




always_inline applied_hash_ace_entry_t **get_applied_hash_aces(acl_main_t *am, u32 lc_index)
{
  applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);

/*is_input ? vec_elt_at_index(am->input_hash_entry_vec_by_sw_if_index, sw_if_index)
                                                          : vec_elt_at_index(am->output_hash_entry_vec_by_sw_if_index, sw_if_index);
*/
  return applied_hash_aces;
}


#ifdef XXX_DELETE
/*
 * This returns true if there is indeed a match on the portranges.
 * With all these levels of indirections, this is not going to be very fast,
 * so, best use the individual ports or wildcard ports for performance.
 */
static int
match_portranges(acl_main_t *am, fa_5tuple_t *match, u32 index)
{

  applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, match->pkt.lc_index);
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), index);

  acl_rule_t *r = &(am->acls[pae->acl_index].rules[pae->ace_index]);
  DBG("PORTMATCH: %d <= %d <= %d && %d <= %d <= %d ?",
		r->src_port_or_type_first, match->l4.port[0], r->src_port_or_type_last,
		r->dst_port_or_code_first, match->l4.port[1], r->dst_port_or_code_last);

  return ( ((r->src_port_or_type_first <= match->l4.port[0]) && r->src_port_or_type_last >= match->l4.port[0]) &&
           ((r->dst_port_or_code_first <= match->l4.port[1]) && r->dst_port_or_code_last >= match->l4.port[1]) );
}

#endif

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
                            u32 lc_index,
                            u32 new_index, clib_bihash_kv_48_8_t *kv)
{
  fa_5tuple_t *kv_key = (fa_5tuple_t *)kv->key;
  hash_acl_lookup_value_t *kv_val = (hash_acl_lookup_value_t *)&kv->value;
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), new_index);
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);

  memcpy(kv_key, &(vec_elt_at_index(ha->rules, pae->hash_ace_info_index)->match), sizeof(*kv_key));
  /* initialize the lc_index and direction */
  kv_key->pkt.lc_index = lc_index;
  kv_val->as_u64 = 0;
  kv_val->applied_entry_index = new_index;
  kv_val->need_portrange_check = vec_elt_at_index(ha->rules, pae->hash_ace_info_index)->src_portrange_not_powerof2 ||
				   vec_elt_at_index(ha->rules, pae->hash_ace_info_index)->dst_portrange_not_powerof2;
  /* by default assume all values are shadowed -> check all mask types */
  kv_val->shadowed = 1;
}

static void
add_del_hashtable_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
			    u32 index, int is_add)
{
  clib_bihash_kv_48_8_t kv;

  fill_applied_hash_ace_kv(am, applied_hash_aces, lc_index, index, &kv);
  hashtable_add_del(am, &kv, is_add);
}



static void
activate_applied_ace_hash_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 new_index)
{
  clib_bihash_kv_48_8_t kv;
  ASSERT(new_index != ~0);
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), new_index);
  DBG("activate_applied_ace_hash_entry lc_index %d new_index %d", lc_index, new_index);

  fill_applied_hash_ace_kv(am, applied_hash_aces, lc_index, new_index, &kv);

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

static void *
hash_acl_set_heap(acl_main_t *am)
{
  if (0 == am->hash_lookup_mheap) {
    am->hash_lookup_mheap = mheap_alloc (0 /* use VM */ , am->hash_lookup_mheap_size);
    if (0 == am->hash_lookup_mheap) {
      clib_error("ACL plugin failed to allocate hash lookup heap of %U bytes, abort", format_memory_size, am->hash_lookup_mheap_size);
    }
    mheap_t *h = mheap_header (am->hash_lookup_mheap);
    h->flags |= MHEAP_FLAG_THREAD_SAFE;
  }
  void *oldheap = clib_mem_set_heap(am->hash_lookup_mheap);
  return oldheap;
}

void
acl_plugin_hash_acl_set_validate_heap(int on)
{
  acl_main_t *am = &acl_main;
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
acl_plugin_hash_acl_set_trace_heap(int on)
{
  acl_main_t *am = &acl_main;
  clib_mem_set_heap(hash_acl_set_heap(am));
  mheap_t *h = mheap_header (am->hash_lookup_mheap);
  if (on) {
    h->flags |= MHEAP_FLAG_TRACE;
  } else {
    h->flags &= ~MHEAP_FLAG_TRACE;
  }
}

void
XXX_OLD_hash_acl_apply(acl_main_t *am, u32 lc_index, int acl_index, u32 acl_position)
{
  int i;

  DBG0("HASH ACL apply: lc_index %d acl %d", lc_index, acl_index);
  if (!am->acl_lookup_hash_initialized) {
    BV (clib_bihash_init) (&am->acl_lookup_hash, "ACL plugin rule lookup bihash",
                           am->hash_lookup_hash_buckets, am->hash_lookup_hash_memory);
    am->acl_lookup_hash_initialized = 1;
  }

  void *oldheap = hash_acl_set_heap(am);
  vec_validate(am->hash_entry_vec_by_lc_index, lc_index);
  vec_validate(am->hash_acl_infos, acl_index);
  applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, lc_index);

  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  u32 **hash_acl_applied_lc_index = &ha->lc_index_list;

  int base_offset = vec_len(*applied_hash_aces);

  /* Update the bitmap of the mask types with which the lookup
     needs to happen for the ACLs applied to this lc_index */
  applied_hash_acl_info_t **applied_hash_acls = &am->applied_hash_acl_info_by_lc_index;
  vec_validate((*applied_hash_acls), lc_index);
  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), lc_index);

  /* ensure the list of applied hash acls is initialized and add this acl# to it */
  u32 index = vec_search(pal->applied_acls, acl_index);
  if (index != ~0) {
    clib_warning("BUG: trying to apply twice acl_index %d on lc_index %d, according to lc",
                 acl_index, lc_index);
    goto done;
  }
  vec_add1(pal->applied_acls, acl_index);
  u32 index2 = vec_search((*hash_acl_applied_lc_index), lc_index);
  if (index2 != ~0) {
    clib_warning("BUG: trying to apply twice acl_index %d on lc_index %d, according to hash h-acl info",
                 acl_index, lc_index);
    goto done;
  }
  vec_add1((*hash_acl_applied_lc_index), lc_index);

  pal->mask_type_index_bitmap = clib_bitmap_or(pal->mask_type_index_bitmap,
                                     ha->base_mask_type_index_bitmap);
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
    pae->acl_position = acl_position;
    pae->action = ha->rules[i].action;
    pae->hitcount = 0;
    pae->hash_ace_info_index = i;
    /* we might link it in later */
    pae->next_applied_entry_index = ~0;
    pae->prev_applied_entry_index = ~0;
    pae->tail_applied_entry_index = ~0;
    activate_applied_ace_hash_entry(am, lc_index, applied_hash_aces, new_index);
  }
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
                            u32 lc_index,
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
    add_del_hashtable_entry(am, lc_index,
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


#ifdef XXX_DELETE
static void
deactivate_applied_ace_hash_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 old_index)
{
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), old_index);
  DBG("UNAPPLY DEACTIVATE: lc_index %d applied index %d", lc_index, old_index);

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
      add_del_hashtable_entry(am, lc_index,
                              applied_hash_aces, pae->next_applied_entry_index, 1);
    } else {
      /* no next entry, so just delete the entry in the hash table */
      add_del_hashtable_entry(am, lc_index,
                              applied_hash_aces, old_index, 0);
    }
  }
  /* invalidate the old entry */
  pae->prev_applied_entry_index = ~0;
  pae->next_applied_entry_index = ~0;
  pae->tail_applied_entry_index = ~0;
}
#endif


static void
hash_acl_build_applied_lookup_bitmap(acl_main_t *am, u32 lc_index)
{
  int i;
  uword *new_lookup_bitmap = 0;

  applied_hash_acl_info_t **applied_hash_acls = &am->applied_hash_acl_info_by_lc_index;
  vec_validate((*applied_hash_acls), lc_index);
  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), lc_index);

  for(i=0; i < vec_len(pal->applied_acls); i++) {
    u32 a_acl_index = *vec_elt_at_index((pal->applied_acls), i);
    hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, a_acl_index);
    DBG("Update bitmask = %U or %U (acl_index %d)\n", format_bitmap_hex, new_lookup_bitmap,
          format_bitmap_hex, ha->base_mask_type_index_bitmap, a_acl_index);
    new_lookup_bitmap = clib_bitmap_or(new_lookup_bitmap,
                                       ha->base_mask_type_index_bitmap);
  }
  uword *old_lookup_bitmap = pal->mask_type_index_bitmap;
  pal->mask_type_index_bitmap = new_lookup_bitmap;
  clib_bitmap_free(old_lookup_bitmap);
}


static void
tm_deactivate_applied_ace_hash_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 index);

static void
tm_remake_mask_type_order_pool(acl_main_t *am,
                            applied_hash_ace_entry_t **applied_hash_aces,
				    u32 lc_index);

void
hash_acl_unapply(acl_main_t *am, u32 lc_index, int acl_index)
{
  int i;

  DBG0("HASH ACL unapply: lc_index %d acl %d", lc_index, acl_index);
  applied_hash_acl_info_t **applied_hash_acls = &am->applied_hash_acl_info_by_lc_index;
  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), lc_index);

  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  u32 **hash_acl_applied_lc_index = &ha->lc_index_list;

  /* remove this acl# from the list of applied hash acls */
  u32 index = vec_search(pal->applied_acls, acl_index);
  if (index == ~0) {
    clib_warning("BUG: trying to unapply unapplied acl_index %d on lc_index %d, according to lc",
                 acl_index, lc_index);
    return;
  }
  vec_del1(pal->applied_acls, index);

  u32 index2 = vec_search((*hash_acl_applied_lc_index), lc_index);
  if (index2 == ~0) {
    clib_warning("BUG: trying to unapply twice acl_index %d on lc_index %d, according to h-acl info",
                 acl_index, lc_index);
    return;
  }
  vec_del1((*hash_acl_applied_lc_index), index2);

  applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, lc_index);

  for(i=0; i < vec_len((*applied_hash_aces)); i++) {
    if (vec_elt_at_index(*applied_hash_aces,i)->acl_index == acl_index) {
      DBG("Found applied ACL#%d at applied index %d", acl_index, i);
      break;
    }
  }
  if (vec_len((*applied_hash_aces)) <= i) {
    DBG("Did not find applied ACL#%d at lc_index %d", acl_index, lc_index);
    /* we went all the way without finding any entries. Probably a list was empty. */
    return;
  }

  void *oldheap = hash_acl_set_heap(am);
  int base_offset = i;
  int tail_offset = base_offset + vec_len(ha->rules);
  int tail_len = vec_len((*applied_hash_aces)) - tail_offset;
  DBG("base_offset: %d, tail_offset: %d, tail_len: %d", base_offset, tail_offset, tail_len);

  for(i=0; i < vec_len(ha->rules); i ++) {
      tm_deactivate_applied_ace_hash_entry(am, lc_index,
				  applied_hash_aces, base_offset + i);
  }
  for(i=0; i < tail_len; i ++) {
    /* move the entry at tail offset to base offset */
    /* that is, from (tail_offset+i) -> (base_offset+i) */
    DBG("UNAPPLY MOVE: lc_index %d, applied index %d -> %d", lc_index, tail_offset+i, base_offset + i);
    move_applied_ace_hash_entry(am, lc_index, applied_hash_aces, tail_offset + i, base_offset + i);
  }
  /* trim the end of the vector */
  _vec_len((*applied_hash_aces)) -= vec_len(ha->rules);

  tm_remake_mask_type_order_pool(am, applied_hash_aces, lc_index);

  /* After deletion we might not need some of the mask-types anymore... */
  hash_acl_build_applied_lookup_bitmap(am, lc_index);
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
hash_acl_reapply(acl_main_t *am, u32 lc_index, int acl_index)
{
  acl_lookup_context_t *acontext = pool_elt_at_index(am->acl_lookup_contexts, lc_index);
  u32 **applied_acls = &acontext->acl_indices;
  int i;
  int start_index = vec_search((*applied_acls), acl_index);

  DBG0("Start index for acl %d in lc_index %d is %d", acl_index, lc_index, start_index);
  /*
   * This function is called after we find out the lc_index where ACL is applied.
   * If the by-lc_index vector does not have the ACL#, then it's a bug.
   */
  ASSERT(start_index < vec_len(*applied_acls));

  /* unapply all the ACLs at the tail side, up to the current one */
  for(i = vec_len(*applied_acls) - 1; i > start_index; i--) {
    hash_acl_unapply(am, lc_index, *vec_elt_at_index(*applied_acls, i));
  }
  for(i = start_index; i < vec_len(*applied_acls); i++) {
    hash_acl_apply(am, lc_index, *vec_elt_at_index(*applied_acls, i), i);
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
make_mask_and_match_from_rule(fa_5tuple_t *mask, acl_rule_t *r, hash_ace_info_t *hi)
{
  memset(mask, 0, sizeof(*mask));
  memset(&hi->match, 0, sizeof(hi->match));
  hi->action = r->is_permit;

  /* we will need to be matching based on lc_index and mask_type_index when applied */
  mask->pkt.lc_index = ~0;
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

int hash_acl_exists(acl_main_t *am, int acl_index)
{
  if (acl_index >= vec_len(am->hash_acl_infos))
    return 0;

  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  return ha->hash_acl_exists;
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
  ha->hash_acl_exists = 1;

  /* walk the newly added ACL entries and ensure that for each of them there
     is a mask type, increment a reference count for that mask type */
  for(i=0; i < a->count; i++) {
    hash_ace_info_t ace_info;
    fa_5tuple_t mask;
    memset(&ace_info, 0, sizeof(ace_info));
    ace_info.acl_index = acl_index;
    ace_info.ace_index = i;

    make_mask_and_match_from_rule(&mask, &a->rules[i], &ace_info);
    mask.pkt.flags_reserved = 0b000;
    ace_info.base_mask_type_index = assign_mask_type_index(am, &mask);
    /* assign the mask type index for matching itself */
    ace_info.match.pkt.mask_type_index_lsb = ace_info.base_mask_type_index;
    DBG("ACE: %d mask_type_index: %d", i, ace_info.base_mask_type_index);
    /* Ensure a given index is set in the mask type index bitmap for this ACL */
    ha->base_mask_type_index_bitmap = clib_bitmap_set(ha->base_mask_type_index_bitmap, ace_info.base_mask_type_index, 1);
    vec_add1(ha->rules, ace_info);
  }
  /*
   * if an ACL is applied somewhere, fill the corresponding lookup data structures.
   * We need to take care if the ACL is not the last one in the vector of ACLs applied to the interface.
   */
  if (acl_index < vec_len(am->lc_index_vec_by_acl)) {
    u32 *lc_index;
    vec_foreach(lc_index, am->lc_index_vec_by_acl[acl_index]) {
      hash_acl_reapply(am, *lc_index, acl_index);
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
  u32 *lc_list_copy = 0;
  {
    u32 *lc_index;
    lc_list_copy = vec_dup(ha->lc_index_list);
    vec_foreach(lc_index, lc_list_copy) {
      hash_acl_unapply(am, *lc_index, acl_index);
    }
    vec_free(lc_list_copy);
  }

  /* walk the mask types for the ACL about-to-be-deleted, and decrease
   * the reference count, possibly freeing up some of them */
  int i;
  for(i=0; i < vec_len(ha->rules); i++) {
    release_mask_type_index(am, ha->rules[i].base_mask_type_index);
  }
  clib_bitmap_free(ha->base_mask_type_index_bitmap);
  ha->hash_acl_exists = 0;
  vec_free(ha->rules);
  clib_mem_set_heap (oldheap);
}


void
show_hash_acl_hash (vlib_main_t * vm, acl_main_t *am, u32 verbose)
{
  vlib_cli_output(vm, "\nACL lookup hash table:\n%U\n",
                  BV (format_bihash), &am->acl_lookup_hash, verbose);
}

void
acl_plugin_show_tables_mask_type (void)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  ace_mask_type_entry_t *mte;

  vlib_cli_output (vm, "Mask-type entries:");
    /* *INDENT-OFF* */
    pool_foreach(mte, am->ace_mask_type_pool,
    ({
      vlib_cli_output(vm, "     %3d: %016llx %016llx %016llx %016llx %016llx %016llx  refcount %d",
		    mte - am->ace_mask_type_pool,
		    mte->mask.kv.key[0], mte->mask.kv.key[1], mte->mask.kv.key[2],
		    mte->mask.kv.key[3], mte->mask.kv.key[4], mte->mask.kv.value, mte->refcount);
    }));
    /* *INDENT-ON* */
}

void
acl_plugin_show_tables_acl_hash_info (u32 acl_index)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  u32 i, j;
  u64 *m;
  vlib_cli_output (vm, "Mask-ready ACL representations\n");
  for (i = 0; i < vec_len (am->hash_acl_infos); i++)
    {
      if ((acl_index != ~0) && (acl_index != i))
	{
	  continue;
	}
      hash_acl_info_t *ha = &am->hash_acl_infos[i];
      vlib_cli_output (vm, "acl-index %u bitmask-ready layout\n", i);
      vlib_cli_output (vm, "  applied lc_index list: %U\n",
		       format_vec32, ha->lc_index_list, "%d");
      vlib_cli_output (vm, "  mask type index bitmap: %U\n",
		       format_bitmap_hex, ha->base_mask_type_index_bitmap);
      for (j = 0; j < vec_len (ha->rules); j++)
	{
	  hash_ace_info_t *pa = &ha->rules[j];
	  m = (u64 *) & pa->match;
	  vlib_cli_output (vm,
			   "    %4d: %016llx %016llx %016llx %016llx %016llx %016llx mask index %d acl %d rule %d action %d src/dst portrange not ^2: %d,%d\n",
			   j, m[0], m[1], m[2], m[3], m[4], m[5],
			   pa->base_mask_type_index, pa->acl_index, pa->ace_index,
			   pa->action, pa->src_portrange_not_powerof2,
			   pa->dst_portrange_not_powerof2);
	}
    }
}

void
acl_plugin_print_pae (vlib_main_t * vm, int j, applied_hash_ace_entry_t * pae)
{
  vlib_cli_output (vm,
		   "    %4d: acl %d rule %d action %d bitmask-ready rule %d next %d prev %d tail %d hitcount %lld",
		   j, pae->acl_index, pae->ace_index, pae->action,
		   pae->hash_ace_info_index, pae->next_applied_entry_index,
		   pae->prev_applied_entry_index,
		   pae->tail_applied_entry_index, pae->hitcount);
}

void
acl_plugin_show_tables_applied_info (u32 lc_index)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  u32 lci, j;
  vlib_cli_output (vm, "Applied lookup entries for lookup contexts");
/*
  for (swi = 0;
       (swi < vec_len (am->input_lc_index_by_sw_if_index))
       || (swi < vec_len (am->output_lc_index_by_sw_if_index)); swi++)
    {
      if ((sw_if_index != ~0) && (sw_if_index != swi))
	{
	  continue;
	}

    }
*/
  for (lci = 0;
       (lci < vec_len(am->applied_hash_acl_info_by_lc_index)); lci++)
    {
      if ((lc_index != ~0) && (lc_index != lci))
	{
	  continue;
	}
      vlib_cli_output (vm, "lc_index %d:", lci);
      if (lci < vec_len (am->applied_hash_acl_info_by_lc_index))
	{
	  applied_hash_acl_info_t *pal =
	    &am->applied_hash_acl_info_by_lc_index[lci];
	  vlib_cli_output (vm, "  lookup mask_type_index_bitmap: %U",
			   format_bitmap_hex, pal->mask_type_index_bitmap);
	  vlib_cli_output (vm, "  applied acls: %U", format_vec32,
			   pal->applied_acls, "%d");
	}
      if (lci < vec_len (am->hash_entry_vec_by_lc_index))
	{
	  vlib_cli_output (vm, "  lookup applied entries:");
	  for (j = 0;
	       j < vec_len (am->hash_entry_vec_by_lc_index[lci]);
	       j++)
	    {
	      acl_plugin_print_pae (vm, j,
				    &am->hash_entry_vec_by_lc_index
				    [lci][j]);
	    }
	}
    }
}

void
acl_plugin_show_tables_bihash (u32 show_bihash_verbose)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  show_hash_acl_hash (vm, am, show_bihash_verbose);
}



/*==================================================================*/
/* TupleMerge section # Valerio */
/*==================================================================*/
/*
Code adapted by Valerio Bruschi (valerio.bruschi@telecom-paristech.fr) 
and based on the TupleMerge [1] simulator kindly made available
(at https://github.com/drjdaly/tuplemerge) by  James Daly 
(dalyjamese@gmail.com) and  Eric Torng (torng@cse.msu.edu)
( http://www.cse.msu.edu/~dalyjame/ or http://www.cse.msu.edu/~torng/ )

[1] James Daly, Eric Torng "TupleMerge: Building Online Packet Classifiers 
by Omitting Bits", In Proc. IEEE ICCCN 2017, pp. 1-10
*/
/*==================================================================*/

int
count_bits(u64 word){
        int counter = 0;
        while(word) {
                counter += word & 1;
                word >>= 1;
        }
	return counter;
}



void
print_mask(fa_5tuple_t *out_mask){
	vlib_main_t *vm = &vlib_global_main;
	u64 *pmask;
/*
	vlib_cli_output(vm, "Mask: %x %x  %x %x %x %x %x %x\n", out_mask->pkt.lc_index, out_mask->pkt.flags_reserved, 
			out_mask->pkt.is_ip6, out_mask->pkt.is_nonfirst_fragment, 
			out_mask->pkt.l4_valid, out_mask->pkt.is_input,
			out_mask->pkt.tcp_flags_valid, out_mask->pkt.tcp_flags);
*/
	pmask = (u64 *) out_mask;

	//DBG( "Mask: %lx", out_mask->addr[0].as_u64[1]);
	//ipv6 addr (mask1/2) || ipv4 addr (mask 2)
	//u64 mask1 = clib_net_to_host_u64 (((u64) *pmask));
	pmask++;

	u64 mask2 = clib_net_to_host_u64 (((u64) *pmask));
	pmask++;

	//ipv6 addr (mask3/4) || ipv4 addr (mask 4)
	//u64 mask3 = clib_net_to_host_u64 (((u64) *pmask));
	pmask++;

	u64 mask4 = clib_net_to_host_u64 (((u64) *pmask));
	pmask++;
	//port_s/d & proto & (?)
	u64 mask5 = clib_net_to_host_u64 (((u64) *pmask));
	pmask++;
	//flags: interface, type mask, tcp flag
	u64 mask6 = clib_net_to_host_u64 (((u64) *pmask));
	pmask++;
	vlib_cli_output(vm, "Mask: %08lx %08lx %016lx %016lx \n",
			mask2, mask4, mask5, mask6);

}

/* check if mask2 can be contained by mask1 */
u8 
compare_tuples(fa_5tuple_t *mask1, fa_5tuple_t *mask2){
	DBG( "TM-comparing tuple");
	//print_mask(mask1);
	//print_mask(mask2);
	//DBG( "TM-comparing tuple-end");

	int i=0;
	for(i=0;i<2;i++){
			//only for ipv4
		if ((mask1->addr[0].as_u64[i] & mask2->addr[0].as_u64[i]) != mask1->addr[0].as_u64[i]) return 1;
		if ((mask1->addr[1].as_u64[i] & mask2->addr[1].as_u64[i]) != mask1->addr[1].as_u64[i]) return 1;
	}

	/* take care if port are not exact-match  */
	if ((mask1->l4.as_u64 & mask2->l4.as_u64) != mask1->l4.as_u64) return 1;

	/* this part of the mask needs to be equal  */
	//if ((mask1->pkt.as_u64 != mask2->pkt.as_u64)) return 1;
	if ((mask1->pkt.as_u64 & mask2->pkt.as_u64) != mask1->pkt.as_u64) return 1;
	//DBG( "%lx %lx", mask1->pkt.as_u64, mask2->pkt.as_u64);


	return 0;
}


/*

Consider the situation when we have to create a new table
T for a given rule R. This occurs for the first rule inserted and
for later rules if it is incompatible with all existing tables.
In this event, we need to determine mT for a new table.
Setting mT = mR is not a good strategy; if another similar,
but slightly less specific, rule appears we will be unable to
add it to T and will thus have to create another new table. We
thus consider two factors: is the rule more strongly aligned
with source or destination addresses (usually the two most
important fields) and how much slack needs to be given to
allow for other rules. If the source and destination addresses
are close together (within 4 bits for our experiments), we use
both of them. Otherwise, we drop the smaller (less specific)
address and its associated port field from consideration; R is
predominantly aligned with one of the two fields and should
be grouped with other similar rules. This is similar to TSS
dropping port fields, but since it is based on observable rule
characteristics it is more likely to keep important fields and
discard less useful ones.
We then look at the absolute lengths of the addresses. If
the address is long, we are more likely to try to add shorter
lengths and likewise the reverse. We thus remove a few bits
from both address fields with more bits removed from longer
addresses. For 32 bit addresses, we remove 4 bits, 3 for more
than 24, 2 for more than 16, and so on (so 8 and fewer bits
don’t have any removed). We only do this for prefix fields like
addresses; both range fields (like ports) and exact match fields
(like protocol) should remain as they are.

*/
void 
relax_tuple2(fa_5tuple_t *mask){
	fa_5tuple_t *original_mask = malloc(sizeof(fa_5tuple_t));
	clib_memcpy(original_mask, mask, sizeof(fa_5tuple_t));

	DBG( "TM-relaxing");
	//print_mask(mask);

	u64 ip_sa = clib_net_to_host_u64(mask->addr[0].as_u64[1]);
	u64 ip_da = clib_net_to_host_u64(mask->addr[1].as_u64[1]);

	int counter1 = count_bits(ip_sa);
	int counter2 = count_bits(ip_da);
//se delta=0????
	const int deltaThreshold = 4;
	int delta = counter1 - counter2;
	if (-delta > deltaThreshold) {
		mask->addr[0].as_u64[1] = 0;
		mask->l4.port[0] = 0;
        } else if (delta > deltaThreshold) {
		mask->addr[1].as_u64[1] = 0;
		mask->l4.port[1] = 0;
        }
	////print_mask(mask);

			//only for ipv4
	if( ip_sa == 0xFFFFFFFF ) mask->addr[0].as_u64[1] = clib_host_to_net_u64((ip_sa << 2)&0xFFFFFFFF);
	else if( ip_sa > 0xFFFFFF00 ) mask->addr[0].as_u64[1] = clib_host_to_net_u64((ip_sa << 2)&0xFFFFFFFF);
	else if( ip_sa > 0xFFFF0000 ) mask->addr[0].as_u64[1] = clib_host_to_net_u64((ip_sa << 1)&0xFFFFFFFF);
	else if( ip_sa > 0xFF000000 ) mask->addr[0].as_u64[1] = clib_host_to_net_u64((ip_sa << 1)&0xFFFFFFFF);

	if( ip_da == 0xFFFFFFFF ) mask->addr[1].as_u64[1] = clib_host_to_net_u64((ip_da << 2)&0xFFFFFFFF);
	else if( ip_da > 0xFFFFFF00 ) mask->addr[1].as_u64[1] = clib_host_to_net_u64((ip_da << 2)&0xFFFFFFFF);
	else if( ip_da > 0xFFFF0000 ) mask->addr[1].as_u64[1] = clib_host_to_net_u64((ip_da << 1)&0xFFFFFFFF);
	else if( ip_da > 0xFF000000 ) mask->addr[1].as_u64[1] = clib_host_to_net_u64((ip_da << 1)&0xFFFFFFFF);


	mask->pkt.is_nonfirst_fragment = 0;
	mask->pkt.l4_valid = 0;
	//print_mask(mask);
	if(compare_tuples(mask, original_mask) != 0){
		DBG( "TM-relaxing-ERROR");
		clib_memcpy(mask, original_mask, sizeof(fa_5tuple_t));
	}
	DBG( "TM-relaxing-end");
}
void 
relax_tuple(fa_5tuple_t *mask){
	fa_5tuple_t *original_mask = malloc(sizeof(fa_5tuple_t));
	clib_memcpy(original_mask, mask, sizeof(fa_5tuple_t));

	DBG( "TM-relaxing");
	//print_mask(mask);

	u64 ip_sa = clib_net_to_host_u64(mask->addr[0].as_u64[1]);
	u64 ip_da = clib_net_to_host_u64(mask->addr[1].as_u64[1]);

	int counter1 = count_bits(ip_sa);
	int counter2 = count_bits(ip_da);
//se delta=0????
	const int deltaThreshold = 4;
	int delta = counter1 - counter2;
	if (-delta > deltaThreshold) {
		mask->addr[0].as_u64[1] = 0;
		mask->l4.port[0] = 0;
        } else if (delta > deltaThreshold) {
		mask->addr[1].as_u64[1] = 0;
		mask->l4.port[1] = 0;
        }
	////print_mask(mask);

			//only for ipv4
	if( ip_sa == 0xFFFFFFFF ) mask->addr[0].as_u64[1] = clib_host_to_net_u64((ip_sa << 6)&0xFFFFFFFF);
	else if( ip_sa > 0xFFFFFF00 ) mask->addr[0].as_u64[1] = clib_host_to_net_u64((ip_sa << 5)&0xFFFFFFFF);
	else if( ip_sa > 0xFFFF0000 ) mask->addr[0].as_u64[1] = clib_host_to_net_u64((ip_sa << 4)&0xFFFFFFFF);
	else if( ip_sa > 0xFF000000 ) mask->addr[0].as_u64[1] = clib_host_to_net_u64((ip_sa << 2)&0xFFFFFFFF);

	if( ip_da == 0xFFFFFFFF ) mask->addr[1].as_u64[1] = clib_host_to_net_u64((ip_da << 6)&0xFFFFFFFF);
	else if( ip_da > 0xFFFFFF00 ) mask->addr[1].as_u64[1] = clib_host_to_net_u64((ip_da << 5)&0xFFFFFFFF);
	else if( ip_da > 0xFFFF0000 ) mask->addr[1].as_u64[1] = clib_host_to_net_u64((ip_da << 4)&0xFFFFFFFF);
	else if( ip_da > 0xFF000000 ) mask->addr[1].as_u64[1] = clib_host_to_net_u64((ip_da << 2)&0xFFFFFFFF);


	mask->pkt.is_nonfirst_fragment = 0;
	mask->pkt.l4_valid = 0;
	//print_mask(mask);
	if(compare_tuples(mask, original_mask) != 0){
		DBG( "TM-relaxing-ERROR");
		clib_memcpy(mask, original_mask, sizeof(fa_5tuple_t));
	}
	DBG( "TM-relaxing-end");
}

static void
tm_hash_acl_build_applied_lookup_bitmap(acl_main_t *am, u32 lc_index)
{
  int i;
  uword *new_lookup_bitmap = 0;
  applied_hash_acl_info_t **applied_hash_acls = &am->applied_hash_acl_info_by_lc_index;
  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), lc_index);
  applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, lc_index);

  for(i=0; i < vec_len(pal->applied_acls); i++) {
    u32 ace_index=0;
    for(ace_index=0; ace_index < vec_len(*applied_hash_aces); ace_index++) {
	    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), ace_index);
	    new_lookup_bitmap =  clib_bitmap_set(new_lookup_bitmap, pae->mask_type_index, 1);

    }

  }
  uword *old_lookup_bitmap = pal->mask_type_index_bitmap;
  pal->mask_type_index_bitmap = new_lookup_bitmap;
  clib_bitmap_free(old_lookup_bitmap);
}

static void
tm_remake_mask_type_order_pool(acl_main_t *am,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 lc_index){

  hash_applied_mask_info_t *new_hash_applied_mask_pool = vec_new(hash_applied_mask_info_t,0);

  DBG( "remake mask type" ); 

  hash_applied_mask_info_t *minfo; 
  for(int i=0; i < vec_len((*applied_hash_aces)); i++) {
    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), i);

    u32 new_index = i;
    u32 new_pointer = vec_len(new_hash_applied_mask_pool);

    //search in order pool if mask_type_index is already there
    int search;
    for (search=0; search < vec_len(new_hash_applied_mask_pool); search++){
	    minfo = vec_elt_at_index(new_hash_applied_mask_pool, search);
	    if(minfo->mask_type_index == pae->mask_type_index)
		    break;
    }

    vec_validate((new_hash_applied_mask_pool), search);
    minfo = vec_elt_at_index((new_hash_applied_mask_pool), search);
    if(search == new_pointer){
	    //vlib_cli_output(&vlib_global_main, "search: %d, index: %d", search, pae->mask_type_index); 
	    minfo->mask_type_index = pae->mask_type_index;
	    minfo->num_entries = 0;
	    minfo->max_collisions = 0;
	    minfo->max_priority = ~0;
    }

    minfo->num_entries = minfo->num_entries + 1;

    if (pae->collision > minfo->max_collisions)
	    minfo->max_collisions = pae->collision; 

    if((minfo->max_priority > (new_index+1) ) | (minfo->max_priority == 0))
	    minfo->max_priority = (new_index+1);

  }

  hash_applied_mask_info_t **hash_applied_mask_pool = vec_elt_at_index(am->hash_applied_mask_pool_by_lc_index, lc_index);

  vec_free((*hash_applied_mask_pool));
  (*hash_applied_mask_pool) = vec_dup(new_hash_applied_mask_pool);
}


static u32
tm_assign_mask_type_index(acl_main_t *am, fa_5tuple_t *mask, u32 lc_index, applied_hash_acl_info_t **applied_hash_acls)
{
	DBG( "TM-assigning mask type index");
	//print_mask(mask);

	u32 mask_type_index = ~0;
	u32 for_mask_type_index = ~0;
	ace_mask_type_entry_t *mte;
	/* look for existing mask comparable with the one in input */
	//for(for_mask_type_index=0; for_mask_type_index < pool_len(am->ace_mask_type_pool); for_mask_type_index++) {
/*
	applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), lc_index);
	for(for_mask_type_index = pool_len(am->ace_mask_type_pool) -1; for_mask_type_index > 0 ; --for_mask_type_index) {
		if (!clib_bitmap_get(pal->mask_type_index_bitmap, for_mask_type_index)) {
			continue;
		}
*/
	hash_applied_mask_info_t **hash_applied_mask_pool = vec_elt_at_index(am->hash_applied_mask_pool_by_lc_index, lc_index);
	hash_applied_mask_info_t *minfo; 

//	for(int order_index = 0; order_index < vec_len((*hash_applied_mask_pool)); order_index++) {
	for(int order_index = vec_len((*hash_applied_mask_pool)) -1; order_index >= 0; order_index--) {
		minfo = vec_elt_at_index((*hash_applied_mask_pool), order_index);
		for_mask_type_index = minfo->mask_type_index;
		mte = vec_elt_at_index(am->ace_mask_type_pool, for_mask_type_index);
		if(compare_tuples(&mte->mask, mask) == 0){
			mask_type_index = (mte - am->ace_mask_type_pool);
			break;
		}
	}


	if(~0 == mask_type_index) {
		/* if no one mask is founded, then let use a relaxed version of the original one, in order to be used by new ace_entries */
		DBG( "TM-assigning mask type index-new one");
		pool_get_aligned (am->ace_mask_type_pool, mte, CLIB_CACHE_LINE_BYTES);
		mask_type_index = mte - am->ace_mask_type_pool;

		hash_applied_mask_info_t **hash_applied_mask_pool = vec_elt_at_index(am->hash_applied_mask_pool_by_lc_index, lc_index);

		int spot = vec_len((*hash_applied_mask_pool));
		vec_validate((*hash_applied_mask_pool), spot);
		minfo = vec_elt_at_index((*hash_applied_mask_pool), spot);
		minfo->mask_type_index = mask_type_index;
		minfo->num_entries = 0;
		minfo->max_collisions = 0;
		minfo->max_priority = ~0;

		clib_memcpy(&mte->mask, mask, sizeof(mte->mask));
		relax_tuple(&mte->mask);

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

	DBG( "TM-mask type index-assigned!! -> %d", mask_type_index);
	//print_mask(&mte->mask);
	return mask_type_index;
}


static void
tm_fill_applied_hash_ace_kv(acl_main_t *am,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 lc_index,
                            u32 new_index, clib_bihash_kv_48_8_t *kv, int is_new)
{
  DBG( "TM-filling ace key: %d (is_new: %d)", new_index, is_new);

  fa_5tuple_t *kv_key = (fa_5tuple_t *)kv->key;
  hash_acl_lookup_value_t *kv_val = (hash_acl_lookup_value_t *)&kv->value;
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), new_index);
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);
  hash_ace_info_t *ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
  applied_hash_acl_info_t **applied_hash_acls = &am->applied_hash_acl_info_by_lc_index;

  ace_mask_type_entry_t *mte; 
  fa_5tuple_t *mask; 
  if(is_new){
	  /* start taking base_mask associated to ace, and look if it is comparable with already existing masks */
	  mte = vec_elt_at_index(am->ace_mask_type_pool, ace_info->base_mask_type_index);
	  mask = &mte->mask; 
	  pae->mask_type_index = tm_assign_mask_type_index(am, mask, lc_index, applied_hash_acls);
  }

//aggiungere if is_base da poter utilizzare la funzione durante il lookup?
  /* apply founded mask to ace_key */
  fa_5tuple_t match = ace_info->match;
  mte = vec_elt_at_index(am->ace_mask_type_pool, pae->mask_type_index);

  u64 *pmatch =(u64 *) &match;
  u64 *pmask;
  u64 *pkey;

  pmatch =(u64 *) &match;
  pmask = (u64 *)&mte->mask;
  pkey = (u64 *)kv->key;


  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;


  //  memcpy(kv_key, &(vec_elt_at_index(ha->rules, pae->hash_ace_info_index)->match), sizeof(*kv_key));
  kv_key->pkt.mask_type_index_lsb = pae->mask_type_index;
  kv_key->pkt.lc_index = lc_index;
  kv_val->as_u64 = 0;
  kv_val->applied_entry_index = new_index;
  kv_val->need_portrange_check = vec_elt_at_index(ha->rules, pae->hash_ace_info_index)->src_portrange_not_powerof2 ||
                                   vec_elt_at_index(ha->rules, pae->hash_ace_info_index)->dst_portrange_not_powerof2;
  /* by default assume all values are shadowed -> check all mask types */
  kv_val->shadowed = 1;
  DBG( "TM-filling ace key: %d (is_new: %d) - END", new_index, is_new);
}


static void
tm_add_del_hashtable_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 index, int is_add)
{ 
  clib_bihash_kv_48_8_t kv;

  tm_fill_applied_hash_ace_kv(am, applied_hash_aces, lc_index, index, &kv, 0);
  hashtable_add_del(am, &kv, is_add);
}



static void
tm_deactivate_applied_ace_hash_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 index)
{
  DBG( "TM-deleting - applied_ace:%d", index);

  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), index);
  
  u32 mask_type_index = pae->mask_type_index;

  /* delete the old entry */
  if (pae->prev_applied_entry_index != ~0) {
    applied_hash_ace_entry_t *prev_pae = vec_elt_at_index((*applied_hash_aces), pae->prev_applied_entry_index);
    ASSERT(prev_pae->next_applied_entry_index == index);
    prev_pae->next_applied_entry_index = pae->next_applied_entry_index;

    u32 head_index = find_head_applied_ace_index(applied_hash_aces, index);
    ASSERT(head_index != ~0);
    applied_hash_ace_entry_t *head_pae = vec_elt_at_index((*applied_hash_aces), head_index);
    head_pae->collision = head_pae->collision - 1;

    if (pae->next_applied_entry_index == ~0) {
      /* it was a last entry we removed, update the pointer on the first one */
/*     u32 head_index = find_head_applied_ace_index(applied_hash_aces, index);
      ASSERT(head_index != ~0);
      applied_hash_ace_entry_t *head_pae = vec_elt_at_index((*applied_hash_aces), head_index);
*/
      ASSERT(head_pae->tail_applied_entry_index == index);
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
      next_pae->collision = pae->collision - 1;
      /* unlink from the next element */
      next_pae->prev_applied_entry_index = ~0;
      tm_add_del_hashtable_entry(am, lc_index,
                              applied_hash_aces, pae->next_applied_entry_index, 1);
    } else {
      /* no next entry, so just delete the entry in the hash table */
      tm_add_del_hashtable_entry(am, lc_index,
                              applied_hash_aces, index, 0);
    }
  }
  /* invalidate the old entry */
  pae->prev_applied_entry_index = ~0;
  pae->next_applied_entry_index = ~0;
  pae->tail_applied_entry_index = ~0;
  pae->collision = 0;

  /* releasing applied_mask_type and decrease
   * the reference count, possibly freeing up some of them */

  release_mask_type_index(am, mask_type_index);

  DBG( "TM-deleting - applied_ace:%d - END", index);
}

static void
tm_activate_applied_ace_hash_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 new_index, int is_new);
/*
this is a signal that we ignored too many bits in
mT and we need to split the table into two tables. We select
all of the colliding rules L and find their maximum common
tuple mL. Normally mL is specific enough to hash L with few
or no collisions. We then create a new table T2 with tuple mL
and transfer all compatible rules from T to T2. If mL is not
specific enough, we find the field with the biggest difference
between the minimum and maximum tuple lengths for all of
the rules in L and set that field to be the average of those two
values. We then transfer all compatible rules as before. This
guarantees that some rules from L will move and that T2 will
have a smaller number of collisions than T did.
*/
void
split_partition(acl_main_t *am, u32 first_index, 
                            u32 lc_index,
			    applied_hash_ace_entry_t **applied_hash_aces){

	DBG( "TM-split_partition - first_entry:%d", first_index);
	ace_mask_type_entry_t *mte;
	fa_5tuple_t *min_tuple = malloc(sizeof(fa_5tuple_t));
        fa_5tuple_t *max_tuple = malloc(sizeof(fa_5tuple_t));
	applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), first_index);
	hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);
	hash_ace_info_t *ace_info;
	u32 coll_mask_type_index = pae->mask_type_index;

	int i=0;
	u64 collisions = pae->collision;	
//	while(pae->next_applied_entry_index == ~0){
	for(i=0; i<collisions; i++){

		DBG( "TM-collision: base_ace:%d (ace_mask:%d, first_collision_mask:%d)", 
				pae->ace_index, pae->mask_type_index, coll_mask_type_index);

		ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
		mte = vec_elt_at_index(am->ace_mask_type_pool, ace_info->base_mask_type_index);
		fa_5tuple_t *mask = &mte->mask; 

		if(pae->mask_type_index != coll_mask_type_index) continue;
		//print_mask(mask);
		/* Computing min_mask and max_mask for colliding rules */
		if(i==0){
			clib_memcpy(min_tuple, mask, sizeof(fa_5tuple_t));
			clib_memcpy(max_tuple, mask, sizeof(fa_5tuple_t));
		}else{
			//only for ipv4
			if(clib_net_to_host_u64(mask->addr[0].as_u64[1]) < clib_net_to_host_u64(min_tuple->addr[0].as_u64[1]))
				min_tuple->addr[0].as_u64[1] = mask->addr[0].as_u64[1];
			if(clib_net_to_host_u64(mask->addr[1].as_u64[1]) < clib_net_to_host_u64(min_tuple->addr[1].as_u64[1]))
				min_tuple->addr[1].as_u64[1] = mask->addr[1].as_u64[1];
			
			if ((mask->l4.port[0] < min_tuple->l4.port[0]))
				min_tuple->l4.port[0] = mask->l4.port[0];
			if ((mask->l4.port[1] < min_tuple->l4.port[1]))
				min_tuple->l4.port[1] = mask->l4.port[1];

			if ((mask->l4.proto < min_tuple->l4.proto))
				min_tuple->l4.proto = mask->l4.proto;

			if(mask->pkt.as_u64 < min_tuple->pkt.as_u64)
				min_tuple->pkt.as_u64 = mask->pkt.as_u64;


			if(clib_net_to_host_u64(mask->addr[0].as_u64[1]) > clib_net_to_host_u64(max_tuple->addr[0].as_u64[1]))
				max_tuple->addr[0].as_u64[1] = mask->addr[0].as_u64[1];
			if(clib_net_to_host_u64(mask->addr[1].as_u64[1]) > clib_net_to_host_u64(max_tuple->addr[1].as_u64[1]))
				max_tuple->addr[1].as_u64[1] = mask->addr[1].as_u64[1];


			if ((mask->l4.port[0] > max_tuple->l4.port[0]))
				max_tuple->l4.port[0] = mask->l4.port[0];
			if ((mask->l4.port[1] > max_tuple->l4.port[1]))
				max_tuple->l4.port[1] = mask->l4.port[1];

			if ((mask->l4.proto < max_tuple->l4.proto))
				max_tuple->l4.proto = mask->l4.proto;

			if(mask->pkt.as_u64 > max_tuple->pkt.as_u64)
				max_tuple->pkt.as_u64 = mask->pkt.as_u64;
		}

		pae = vec_elt_at_index((*applied_hash_aces), pae->next_applied_entry_index);
	}

	DBG( "TM-split_partition - max/min_tuple");
	//print_mask(max_tuple);
	//print_mask(min_tuple);
	/* Computing field with max difference between (min/max)_mask */
	int best_dim=-1, best_delta=0, delta=0;
	delta = count_bits(max_tuple->addr[0].as_u64[1]) - count_bits(min_tuple->addr[0].as_u64[1]);
	if(delta > best_delta){
		best_delta = delta;
		best_dim = 0;
	}
	delta = count_bits(max_tuple->addr[1].as_u64[1]) - count_bits(min_tuple->addr[1].as_u64[1]);
	if(delta > best_delta){
		best_delta = delta;
		best_dim = 1;
	}
	delta = count_bits(max_tuple->l4.port[0]) - count_bits(min_tuple->l4.port[0]);
	if(delta > best_delta){
		best_delta = delta;
		best_dim = 2;
	}
	delta = count_bits(max_tuple->l4.port[1]) - count_bits(min_tuple->l4.port[1]);
	if(delta > best_delta){
		best_delta = delta;
		best_dim = 3;
	}
	delta = count_bits(max_tuple->l4.proto) - count_bits(min_tuple->l4.proto);
	if(delta > best_delta){
		best_delta = delta;
		best_dim = 4;
	}

	switch(best_dim){
		case 0: min_tuple->addr[0].as_u64[1] = 
			clib_host_to_net_u64((clib_net_to_host_u64(max_tuple->addr[0].as_u64[1]) << (best_delta)/2)&0xFFFFFFFF);
			break;
		case 1: min_tuple->addr[1].as_u64[1] = 
			clib_host_to_net_u64((clib_net_to_host_u64(max_tuple->addr[1].as_u64[1]) << (best_delta)/2)&0xFFFFFFFF);
			break;
		case 2: min_tuple->l4.port[0] = max_tuple->l4.port[0]  << (best_delta)/2;
			break;
		case 3: min_tuple->l4.port[1] = max_tuple->l4.port[1] << (best_delta)/2;
			break;
		case 4: min_tuple->l4.proto = max_tuple->l4.proto << (best_delta)/2;
			break;
		default: relax_tuple2(min_tuple);
			break;
	}

	//print_mask(max_tuple);
	//print_mask(min_tuple);

	min_tuple->pkt.is_nonfirst_fragment = 0;
        u32 new_mask_type_index = assign_mask_type_index(am, min_tuple);


	hash_applied_mask_info_t **hash_applied_mask_pool = vec_elt_at_index(am->hash_applied_mask_pool_by_lc_index, lc_index);

	hash_applied_mask_info_t *minfo; 
	//search in order pool if mask_type_index is already there
	int search;
	for (search=0; search < vec_len((*hash_applied_mask_pool)); search++){
		minfo = vec_elt_at_index((*hash_applied_mask_pool), search);
		if(minfo->mask_type_index == new_mask_type_index)
			break;
	}


	vec_validate((*hash_applied_mask_pool), search);
	minfo = vec_elt_at_index((*hash_applied_mask_pool), search);
	minfo->mask_type_index = new_mask_type_index;
	minfo->num_entries = 0;
	minfo->max_collisions = 0;
	minfo->max_priority = ~0;


	DBG( "TM-split_partition - mask type index-assigned!! -> %d", new_mask_type_index);

	if(coll_mask_type_index == new_mask_type_index){
		//vlib_cli_output(vm, "TM-There are collisions over threshold, but i'm not able to split! %d %d", coll_mask_type_index, new_mask_type_index);
		return;
	}


	/* populate new partition */
	DBG( "TM-Populate new partition");
	u32 r_ace_index = first_index;

//	for(i=0; i<collisions; i++){
	for(r_ace_index=0; r_ace_index < vec_len((*applied_hash_aces)); r_ace_index++) {

		applied_hash_ace_entry_t *pop_pae = vec_elt_at_index((*applied_hash_aces), r_ace_index);
		DBG( "TM-Population-collision: base_ace:%d (ace_mask:%d, first_collision_mask:%d)", 
				pop_pae->ace_index, pop_pae->mask_type_index, coll_mask_type_index);

		u32 next_index = pop_pae->next_applied_entry_index;
		if(pop_pae->mask_type_index != coll_mask_type_index) continue;

		ace_info = vec_elt_at_index(ha->rules, pop_pae->hash_ace_info_index);
		mte = vec_elt_at_index(am->ace_mask_type_pool, ace_info->base_mask_type_index);
		//can insert rule?
		//mte = vec_elt_at_index(am->ace_mask_type_pool, pop_pae->mask_type_index);
		fa_5tuple_t *pop_mask = &mte->mask;

		if(compare_tuples(min_tuple, pop_mask) != 0) continue;
		DBG( "TM-new partition can insert -> applied_ace:%d", r_ace_index);

		//delete and insert in new format
		tm_deactivate_applied_ace_hash_entry(am, lc_index, applied_hash_aces, r_ace_index);

		/* insert the new entry */
		pop_pae->mask_type_index = new_mask_type_index;

		//is_new avoid looping!
		tm_activate_applied_ace_hash_entry(am, lc_index, applied_hash_aces, r_ace_index, 0);

		r_ace_index = next_index;
	}

	/* After deletion we might not need some of the mask-types anymore... and add the new one!*/
	tm_hash_acl_build_applied_lookup_bitmap(am, lc_index);
	DBG( "TM-Populate new partition-END");
	DBG( "TM-split_partition - END");

}

static void
tm_activate_applied_ace_hash_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 new_index, int is_new)
{
  clib_bihash_kv_48_8_t kv;
  ASSERT(new_index != ~0);
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), new_index);
  DBG("activate_applied_ace_hash_entry lc_index %d new_index %d", lc_index, new_index);

  tm_fill_applied_hash_ace_kv(am, applied_hash_aces, lc_index, new_index, &kv, is_new);

  DBG("APPLY ADD KY: %016llx %016llx %016llx %016llx %016llx %016llx",
                        kv.key[0], kv.key[1], kv.key[2],
                        kv.key[3], kv.key[4], kv.key[5]);

  clib_bihash_kv_48_8_t result;
  hash_acl_lookup_value_t *result_val = (hash_acl_lookup_value_t *)&result.value;
  int res = BV (clib_bihash_search) (&am->acl_lookup_hash, &kv, &result);
  ASSERT(new_index != ~0);
  ASSERT(new_index < vec_len((*applied_hash_aces)));
  if (res == 0) {
    DBG( "TM-entry already exists: %d (base_ace: %d)", new_index, pae->ace_index);
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
    u64 collisions = first_pae->collision + 1;
    pae->collision = collisions;
    /* adjust the pointer to the new tail */
    first_pae->tail_applied_entry_index = new_index;
    /* adjust collision field in each entry on the same HT-spot */
    first_pae->collision = collisions;
    //applied_hash_ace_entry_t *next_pae = vec_elt_at_index((*applied_hash_aces), first_pae->next_applied_entry_index);

    //aggiornare contatore solo nell'head o su tutte le entry collidenti?
/*    while(next_pae->next_applied_entry_index == new_index){
	    next_pae->collision = collisions;
	    applied_hash_ace_entry_t *next_pae = vec_elt_at_index((*applied_hash_aces), next_pae->next_applied_entry_index);
    }
*/
    DBG( "TM-entry already exists, first entry: %d (%d %d)", first_index, new_index, collisions);
    if(collisions > TM_THRESHOLD && is_new){
	    /* create a new partition in order to replace collisions in a different mask_type */
	    split_partition(am, first_index, lc_index, applied_hash_aces);
    }
  } else {
    /* It's the very first entry */
    DBG( "TM-first entry in partition: %d (base_ace: %d)", new_index, pae->ace_index);
    hashtable_add_del(am, &kv, 1);
    ASSERT(new_index != ~0);
    pae->collision = 0;
    pae->tail_applied_entry_index = new_index;
  }
  DBG( "TM-activate applied ace entry: %d (is_new: %d) - END", new_index, is_new);

}

void
hash_acl_apply(acl_main_t *am, u32 lc_index, int acl_index, u32 acl_position)
{
  int i;

  DBG( "TM-APPLY");
  DBG0("HASH ACL apply: lc_index %d acl %d", lc_index, acl_index);
  if (!am->acl_lookup_hash_initialized) {
    BV (clib_bihash_init) (&am->acl_lookup_hash, "ACL plugin rule lookup bihash",
                           am->hash_lookup_hash_buckets, am->hash_lookup_hash_memory);
    clib_bihash_set_kvp_format_fn_48_8(&am->acl_lookup_hash, format_acl_plugin_5tuple_for_acl_hash);
    am->acl_lookup_hash_initialized = 1;
  }

  void *oldheap = hash_acl_set_heap(am);
  vec_validate(am->hash_entry_vec_by_lc_index, lc_index);
  vec_validate(am->hash_acl_infos, acl_index);
  applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, lc_index);

  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  u32 **hash_acl_applied_lc_index = &ha->lc_index_list;

  int base_offset = vec_len(*applied_hash_aces);

  /* Update the bitmap of the mask types with which the lookup
     needs to happen for the ACLs applied to this lc_index */
  applied_hash_acl_info_t **applied_hash_acls = &am->applied_hash_acl_info_by_lc_index;
  vec_validate((*applied_hash_acls), lc_index);

  vec_validate(am->hash_applied_mask_pool_by_lc_index, lc_index);

  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), lc_index);

  /* ensure the list of applied hash acls is initialized and add this acl# to it */
  u32 index = vec_search(pal->applied_acls, acl_index);
  if (index != ~0) {
    clib_warning("BUG: trying to apply twice acl_index %d on lc_index %d, according to lc",
                 acl_index, lc_index);
    goto done;
  }
  vec_add1(pal->applied_acls, acl_index);
  u32 index2 = vec_search((*hash_acl_applied_lc_index), lc_index);
  if (index2 != ~0) {
    clib_warning("BUG: trying to apply twice acl_index %d on lc_index %d, according to hash h-acl info",
                 acl_index, lc_index);
    goto done;
  }
  vec_add1((*hash_acl_applied_lc_index), lc_index);

  pal->mask_type_index_bitmap = clib_bitmap_or(pal->mask_type_index_bitmap,
                                     ha->base_mask_type_index_bitmap);
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
    pae->acl_position = acl_position;
    pae->action = ha->rules[i].action;
    pae->hitcount = 0;
    pae->hash_ace_info_index = i;
    /* we might link it in later */
    pae->next_applied_entry_index = ~0;
    pae->prev_applied_entry_index = ~0;
    pae->tail_applied_entry_index = ~0;
    tm_activate_applied_ace_hash_entry(am, lc_index, applied_hash_aces, new_index, 1);

    /* Update the applied_bitmap of the mask types with which the lookup
     needs to happen for the ACLs applied to this lc_index */
    pal->mask_type_index_bitmap = clib_bitmap_set(pal->mask_type_index_bitmap, pae->mask_type_index, 1);
  }
  DBG( "TM-APPLY-resetting bitmap");
  tm_remake_mask_type_order_pool(am, applied_hash_aces, lc_index);

done:
  clib_mem_set_heap (oldheap);
  DBG( "TM-APPLY-end");
}

