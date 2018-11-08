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


always_inline applied_hash_ace_entry_t **get_applied_hash_aces(acl_main_t *am, u32 lc_index)
{
  applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);

/*is_input ? vec_elt_at_index(am->input_hash_entry_vec_by_sw_if_index, sw_if_index)
                                                          : vec_elt_at_index(am->output_hash_entry_vec_by_sw_if_index, sw_if_index);
*/
  return applied_hash_aces;
}


static void
hashtable_add_del(acl_main_t *am, clib_bihash_kv_48_8_t *kv, int is_add)
{
    DBG("HASH ADD/DEL: %016llx %016llx %016llx %016llx %016llx %016llx %016llx add %d",
                        kv->key[0], kv->key[1], kv->key[2],
                        kv->key[3], kv->key[4], kv->key[5], kv->value, is_add);
    BV (clib_bihash_add_del) (&am->acl_lookup_hash, kv, is_add);
}

/*
 * TupleMerge
 *
 * Initial adaptation by Valerio Bruschi (valerio.bruschi@telecom-paristech.fr)
 * based on the TupleMerge [1] simulator kindly made available
 * by  James Daly (dalyjamese@gmail.com) and  Eric Torng (torng@cse.msu.edu)
 * ( http://www.cse.msu.edu/~dalyjame/ or http://www.cse.msu.edu/~torng/ ),
 * refactoring by Andrew Yourtchenko.
 *
 * [1] James Daly, Eric Torng "TupleMerge: Building Online Packet Classifiers
 * by Omitting Bits", In Proc. IEEE ICCCN 2017, pp. 1-10
 *
 */

static int
count_bits (u64 word)
{
  int counter = 0;
  while (word)
    {
      counter += word & 1;
      word >>= 1;
    }
  return counter;
}

/* check if mask2 can be contained by mask1 */
static u8
first_mask_contains_second_mask(int is_ip6, fa_5tuple_t * mask1, fa_5tuple_t * mask2)
{
  int i;
  if (is_ip6)
    {
      for (i = 0; i < 2; i++)
        {
          if ((mask1->ip6_addr[0].as_u64[i] & mask2->ip6_addr[0].as_u64[i]) !=
              mask1->ip6_addr[0].as_u64[i])
            return 0;
          if ((mask1->ip6_addr[1].as_u64[i] & mask2->ip6_addr[1].as_u64[i]) !=
              mask1->ip6_addr[1].as_u64[i])
            return 0;
        }
    }
  else
    {
      /* check the pads, both masks must have it 0 */
      u32 padcheck = 0;
      int i;
      for (i=0; i<6; i++) {
        padcheck |= mask1->l3_zero_pad[i];
        padcheck |= mask2->l3_zero_pad[i];
      }
      if (padcheck != 0)
        return 0;
      if ((mask1->ip4_addr[0].as_u32 & mask2->ip4_addr[0].as_u32) !=
          mask1->ip4_addr[0].as_u32)
        return 0;
      if ((mask1->ip4_addr[1].as_u32 & mask2->ip4_addr[1].as_u32) !=
          mask1->ip4_addr[1].as_u32)
        return 0;
    }

  /* take care if port are not exact-match  */
  if ((mask1->l4.as_u64 & mask2->l4.as_u64) != mask1->l4.as_u64)
    return 0;

  if ((mask1->pkt.as_u64 & mask2->pkt.as_u64) != mask1->pkt.as_u64)
    return 0;

  return 1;
}



/*
 * TupleMerge:
 *
 * Consider the situation when we have to create a new table
 * T for a given rule R. This occurs for the first rule inserted and
 * for later rules if it is incompatible with all existing tables.
 * In this event, we need to determine mT for a new table.
 * Setting mT = mR is not a good strategy; if another similar,
 * but slightly less specific, rule appears we will be unable to
 * add it to T and will thus have to create another new table. We
 * thus consider two factors: is the rule more strongly aligned
 * with source or destination addresses (usually the two most
 * important fields) and how much slack needs to be given to
 * allow for other rules. If the source and destination addresses
 * are close together (within 4 bits for our experiments), we use
 * both of them. Otherwise, we drop the smaller (less specific)
 * address and its associated port field from consideration; R is
 * predominantly aligned with one of the two fields and should
 * be grouped with other similar rules. This is similar to TSS
 * dropping port fields, but since it is based on observable rule
 * characteristics it is more likely to keep important fields and
 * discard less useful ones.
 * We then look at the absolute lengths of the addresses. If
 * the address is long, we are more likely to try to add shorter
 * lengths and likewise the reverse. We thus remove a few bits
 * from both address fields with more bits removed from longer
 * addresses. For 32 bit addresses, we remove 4 bits, 3 for more
 * than 24, 2 for more than 16, and so on (so 8 and fewer bits
 * don’t have any removed). We only do this for prefix fields like
 * addresses; both range fields (like ports) and exact match fields
 * (like protocol) should remain as they are.
 */


static u32
shift_ip4_if(u32 mask, u32 thresh, int numshifts, u32 else_val)
{
  if (mask > thresh)
     return clib_host_to_net_u32((clib_net_to_host_u32(mask) << numshifts) & 0xFFFFFFFF);
  else
     return else_val;
}

static void
relax_ip4_addr(ip4_address_t *ip4_mask, int relax2) {
  int shifts_per_relax[2][4] = { { 6, 5, 4, 2 }, { 3, 2, 1, 1 } };

  int *shifts = shifts_per_relax[relax2];
  if(ip4_mask->as_u32 == 0xffffffff)
    ip4_mask->as_u32 = clib_host_to_net_u32((clib_net_to_host_u32(ip4_mask->as_u32) << shifts[0])&0xFFFFFFFF);
  else
    ip4_mask->as_u32 = shift_ip4_if(ip4_mask->as_u32, 0xffffff00, shifts[1],
                        shift_ip4_if(ip4_mask->as_u32, 0xffff0000, shifts[2],
                          shift_ip4_if(ip4_mask->as_u32, 0xff000000, shifts[3], ip4_mask->as_u32)));
}

static void
relax_ip6_addr(ip6_address_t *ip6_mask, int relax2) {
  /*
   * This "better than nothing" relax logic is based on heuristics
   * from IPv6 knowledge, and may not be optimal.
   * Some further tuning may be needed in the future.
   */
  if (ip6_mask->as_u64[0] == 0xffffffffffffffffULL) {
    if (ip6_mask->as_u64[1] == 0xffffffffffffffffULL) {
      /* relax a /128 down to /64  - likely to have more hosts */
      ip6_mask->as_u64[1] = 0;
    } else if (ip6_mask->as_u64[1] == 0) {
      /* relax a /64 down to /56 - likely to have more subnets */
      ip6_mask->as_u64[0] = clib_host_to_net_u64(0xffffffffffffff00ULL);
    }
  }
}

static void
relax_tuple(fa_5tuple_t *mask, int is_ip6, int relax2){
	fa_5tuple_t save_mask = *mask;

	int counter_s = 0, counter_d = 0;
        if (is_ip6) {
	  int i;
	  for(i=0; i<2; i++){
		counter_s += count_bits(mask->ip6_addr[0].as_u64[i]);
		counter_d += count_bits(mask->ip6_addr[1].as_u64[i]);
	  }
        } else {
		counter_s += count_bits(mask->ip4_addr[0].as_u32);
		counter_d += count_bits(mask->ip4_addr[1].as_u32);
        }

/*
 * is the rule more strongly aligned with source or destination addresses
 * (usually the two most important fields) and how much slack needs to be
 * given to allow for other rules. If the source and destination addresses
 * are close together (within 4 bits for our experiments), we use both of them.
 * Otherwise, we drop the smaller (less specific) address and its associated
 * port field from consideration
 */
	const int deltaThreshold = 4;
	/* const int deltaThreshold = 8; if IPV6? */
	int delta = counter_s - counter_d;
	if (-delta > deltaThreshold) {
                if (is_ip6)
		  mask->ip6_addr[0].as_u64[1] = mask->ip6_addr[0].as_u64[0] = 0;
                else
		  mask->ip4_addr[0].as_u32 = 0;
		mask->l4.port[0] = 0;
        } else if (delta > deltaThreshold) {
                if (is_ip6)
		  mask->ip6_addr[1].as_u64[1] = mask->ip6_addr[1].as_u64[0] = 0;
                else
		  mask->ip4_addr[1].as_u32 = 0;
		mask->l4.port[1] = 0;
        }

        if (is_ip6) {
          relax_ip6_addr(&mask->ip6_addr[0], relax2);
          relax_ip6_addr(&mask->ip6_addr[1], relax2);
        } else {
          relax_ip4_addr(&mask->ip4_addr[0], relax2);
          relax_ip4_addr(&mask->ip4_addr[1], relax2);
        }
	mask->pkt.is_nonfirst_fragment = 0;
	mask->pkt.l4_valid = 0;
	if(!first_mask_contains_second_mask(is_ip6, mask, &save_mask)){
		DBG( "TM-relaxing-ERROR");
                *mask = save_mask;
	}
	DBG( "TM-relaxing-end");
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
  DBG0("ASSIGN MTE index %d new refcount %d", mask_type_index, mte->refcount);
  return mask_type_index;
}

static void
lock_mask_type_index(acl_main_t *am, u32 mask_type_index)
{
  DBG0("LOCK MTE index %d", mask_type_index);
  ace_mask_type_entry_t *mte = pool_elt_at_index(am->ace_mask_type_pool, mask_type_index);
  mte->refcount++;
  DBG0("LOCK MTE index %d new refcount %d", mask_type_index, mte->refcount);
}


static void
release_mask_type_index(acl_main_t *am, u32 mask_type_index)
{
  DBG0("RELEAS MTE index %d", mask_type_index);
  ace_mask_type_entry_t *mte = pool_elt_at_index(am->ace_mask_type_pool, mask_type_index);
  mte->refcount--;
  DBG0("RELEAS MTE index %d new refcount %d", mask_type_index, mte->refcount);
  if (mte->refcount == 0) {
    /* we are not using this entry anymore */
    clib_memset(mte, 0xae, sizeof(*mte));
    pool_put(am->ace_mask_type_pool, mte);
  }
}


static u32
tm_assign_mask_type_index(acl_main_t *am, fa_5tuple_t *mask, int is_ip6, u32 lc_index)
{
	u32 mask_type_index = ~0;
	u32 for_mask_type_index = ~0;
	ace_mask_type_entry_t *mte = 0;
	int order_index;
	/* look for existing mask comparable with the one in input */

	hash_applied_mask_info_t **hash_applied_mask_info_vec = vec_elt_at_index(am->hash_applied_mask_info_vec_by_lc_index, lc_index);
	hash_applied_mask_info_t *minfo;

        if (vec_len(*hash_applied_mask_info_vec) > 0) {
	    for(order_index = vec_len((*hash_applied_mask_info_vec)) -1; order_index >= 0; order_index--) {
		minfo = vec_elt_at_index((*hash_applied_mask_info_vec), order_index);
		for_mask_type_index = minfo->mask_type_index;
		mte = vec_elt_at_index(am->ace_mask_type_pool, for_mask_type_index);
		if(first_mask_contains_second_mask(is_ip6, &mte->mask, mask)){
			mask_type_index = (mte - am->ace_mask_type_pool);
			lock_mask_type_index(am, mask_type_index);
			break;
		}
            }
	}

	if(~0 == mask_type_index) {
		/* if no mask is found, then let's use a relaxed version of the original one, in order to be used by new ace_entries */
		DBG( "TM-assigning mask type index-new one");
		fa_5tuple_t relaxed_mask = *mask;
		relax_tuple(&relaxed_mask, is_ip6, 0);
		mask_type_index = assign_mask_type_index(am, &relaxed_mask);

		hash_applied_mask_info_t **hash_applied_mask_info_vec = vec_elt_at_index(am->hash_applied_mask_info_vec_by_lc_index, lc_index);

		int spot = vec_len((*hash_applied_mask_info_vec));
		vec_validate((*hash_applied_mask_info_vec), spot);
		minfo = vec_elt_at_index((*hash_applied_mask_info_vec), spot);
		minfo->mask_type_index = mask_type_index;
		minfo->num_entries = 0;
		minfo->max_collisions = 0;
		minfo->first_rule_index = ~0;

		/*
		 * We can use only 16 bits, since in the match there is only u16 field.
		 * Realistically, once you go to 64K of mask types, it is a huge
		 * problem anyway, so we might as well stop half way.
		 */
		ASSERT(mask_type_index < 32768);
	}
	mte = am->ace_mask_type_pool + mask_type_index;
	DBG0("TM-ASSIGN MTE index %d new refcount %d", mask_type_index, mte->refcount);
	return mask_type_index;
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

  /* apply the mask to ace key */
  hash_ace_info_t *ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
  ace_mask_type_entry_t *mte = vec_elt_at_index(am->ace_mask_type_pool, pae->mask_type_index);

  u64 *pmatch = (u64 *) &ace_info->match;
  u64 *pmask = (u64 *)&mte->mask;
  u64 *pkey = (u64 *)kv->key;

  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;

  kv_key->pkt.mask_type_index_lsb = pae->mask_type_index;
  kv_key->pkt.lc_index = lc_index;
  kv_val->as_u64 = 0;
  kv_val->applied_entry_index = new_index;
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
remake_hash_applied_mask_info_vec (acl_main_t * am,
                                   applied_hash_ace_entry_t **
                                   applied_hash_aces, u32 lc_index)
{
  DBG0("remake applied hash mask info lc_index %d", lc_index);
  hash_applied_mask_info_t *new_hash_applied_mask_info_vec =
    vec_new (hash_applied_mask_info_t, 0);

  hash_applied_mask_info_t *minfo;
  int i;
  for (i = 0; i < vec_len ((*applied_hash_aces)); i++)
    {
      applied_hash_ace_entry_t *pae =
        vec_elt_at_index ((*applied_hash_aces), i);

      /* check if mask_type_index is already there */
      u32 new_pointer = vec_len (new_hash_applied_mask_info_vec);
      int search;
      for (search = 0; search < vec_len (new_hash_applied_mask_info_vec);
           search++)
        {
          minfo = vec_elt_at_index (new_hash_applied_mask_info_vec, search);
          if (minfo->mask_type_index == pae->mask_type_index)
            break;
        }
       
      vec_validate ((new_hash_applied_mask_info_vec), search);
      minfo = vec_elt_at_index ((new_hash_applied_mask_info_vec), search);
      if (search == new_pointer)
        {
          DBG0("remaking index %d", search);
          minfo->mask_type_index = pae->mask_type_index;
          minfo->num_entries = 0;
          minfo->max_collisions = 0;
          minfo->first_rule_index = ~0;
        }

      minfo->num_entries = minfo->num_entries + 1;

      if (vec_len (pae->colliding_rules) > minfo->max_collisions)
        minfo->max_collisions = vec_len (pae->colliding_rules);

      if (minfo->first_rule_index > i)
        minfo->first_rule_index = i;
    }

  hash_applied_mask_info_t **hash_applied_mask_info_vec =
    vec_elt_at_index (am->hash_applied_mask_info_vec_by_lc_index, lc_index);

  vec_free ((*hash_applied_mask_info_vec));
  (*hash_applied_mask_info_vec) = new_hash_applied_mask_info_vec;
}

static void
vec_del_collision_rule (collision_match_rule_t ** pvec,
                        u32 applied_entry_index)
{
  u32 i = 0;
  u32 deleted = 0;
  while (i < _vec_len ((*pvec)))
    {
      collision_match_rule_t *cr = vec_elt_at_index ((*pvec), i);
      if (cr->applied_entry_index == applied_entry_index)
        {
          /* vec_del1 ((*pvec), i) would be more efficient but would reorder the elements. */
          vec_delete((*pvec), 1, i);
          deleted++;
          DBG0("vec_del_collision_rule deleting one at index %d", i);
        }
      else
        {
          i++;
        }
    }
  ASSERT(deleted > 0);
}

static void
acl_plugin_print_pae (vlib_main_t * vm, int j, applied_hash_ace_entry_t * pae);

static void
del_colliding_rule (applied_hash_ace_entry_t ** applied_hash_aces,
                    u32 head_index, u32 applied_entry_index)
{
  DBG0("DEL COLLIDING RULE: head_index %d applied index %d", head_index, applied_entry_index);


  applied_hash_ace_entry_t *head_pae =
    vec_elt_at_index ((*applied_hash_aces), head_index);
  if (ACL_HASH_LOOKUP_DEBUG > 0)
    acl_plugin_print_pae(acl_main.vlib_main, head_index, head_pae);
  vec_del_collision_rule (&head_pae->colliding_rules, applied_entry_index);
  if (vec_len(head_pae->colliding_rules) == 0) {
    vec_free(head_pae->colliding_rules);
  }
  if (ACL_HASH_LOOKUP_DEBUG > 0)
    acl_plugin_print_pae(acl_main.vlib_main, head_index, head_pae);
}

static void
add_colliding_rule (acl_main_t * am,
                    applied_hash_ace_entry_t ** applied_hash_aces,
                    u32 head_index, u32 applied_entry_index)
{
  applied_hash_ace_entry_t *head_pae =
    vec_elt_at_index ((*applied_hash_aces), head_index);
  applied_hash_ace_entry_t *pae =
    vec_elt_at_index ((*applied_hash_aces), applied_entry_index);
  DBG0("ADD COLLIDING RULE: head_index %d applied index %d", head_index, applied_entry_index);
  if (ACL_HASH_LOOKUP_DEBUG > 0)
    acl_plugin_print_pae(acl_main.vlib_main, head_index, head_pae);

  collision_match_rule_t cr;

  cr.acl_index = pae->acl_index;
  cr.ace_index = pae->ace_index;
  cr.acl_position = pae->acl_position;
  cr.applied_entry_index = applied_entry_index;
  cr.rule = am->acls[pae->acl_index].rules[pae->ace_index];
  vec_add1 (head_pae->colliding_rules, cr);
  if (ACL_HASH_LOOKUP_DEBUG > 0)
    acl_plugin_print_pae(acl_main.vlib_main, head_index, head_pae);
}

static u32
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
    /* link ourselves in */
    last_pae->next_applied_entry_index = new_index;
    pae->prev_applied_entry_index = last_index;
    /* adjust the pointer to the new tail */
    first_pae->tail_applied_entry_index = new_index;
    add_colliding_rule(am, applied_hash_aces, first_index, new_index);
    return first_index;
  } else {
    /* It's the very first entry */
    hashtable_add_del(am, &kv, 1);
    ASSERT(new_index != ~0);
    pae->tail_applied_entry_index = new_index;
    add_colliding_rule(am, applied_hash_aces, new_index, new_index);
    return new_index;
  }
}


static void *
hash_acl_set_heap(acl_main_t *am)
{
  if (0 == am->hash_lookup_mheap) {
    am->hash_lookup_mheap = mheap_alloc_with_lock (0 /* use VM */ , 
                                                   am->hash_lookup_mheap_size,
                                                   1 /* locked */);
    if (0 == am->hash_lookup_mheap) {
        clib_error("ACL plugin failed to allocate lookup heap of %U bytes", 
                   format_memory_size, am->hash_lookup_mheap_size);
    }
  }
  void *oldheap = clib_mem_set_heap(am->hash_lookup_mheap);
  return oldheap;
}

void
acl_plugin_hash_acl_set_validate_heap(int on)
{
  acl_main_t *am = &acl_main;
  clib_mem_set_heap(hash_acl_set_heap(am));
#if USE_DLMALLOC == 0
  mheap_t *h = mheap_header (am->hash_lookup_mheap);
  if (on) {
    h->flags |= MHEAP_FLAG_VALIDATE;
    h->flags &= ~MHEAP_FLAG_SMALL_OBJECT_CACHE;
    mheap_validate(h);
  } else {
    h->flags &= ~MHEAP_FLAG_VALIDATE;
    h->flags |= MHEAP_FLAG_SMALL_OBJECT_CACHE;
  }
#endif
}

void
acl_plugin_hash_acl_set_trace_heap(int on)
{
  acl_main_t *am = &acl_main;
  clib_mem_set_heap(hash_acl_set_heap(am));
#if USE_DLMALLOC == 0
  mheap_t *h = mheap_header (am->hash_lookup_mheap);
  if (on) {
    h->flags |= MHEAP_FLAG_TRACE;
  } else {
    h->flags &= ~MHEAP_FLAG_TRACE;
  }
#endif
}

static void
assign_mask_type_index_to_pae(acl_main_t *am, u32 lc_index, int is_ip6, applied_hash_ace_entry_t *pae)
{
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);
  hash_ace_info_t *ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);

  ace_mask_type_entry_t *mte;
  fa_5tuple_t mask;
  /*
   * Start taking base_mask associated to ace, and essentially copy it.
   * With TupleMerge we will assign a relaxed mask here.
   */
  mte = vec_elt_at_index(am->ace_mask_type_pool, ace_info->base_mask_type_index);
  mask = mte->mask;
  if (am->use_tuple_merge)
    pae->mask_type_index = tm_assign_mask_type_index(am, &mask, is_ip6, lc_index);
  else
    pae->mask_type_index = assign_mask_type_index(am, &mask);
}

static void
split_partition(acl_main_t *am, u32 first_index,
                            u32 lc_index, int is_ip6);


static void
check_collision_count_and_maybe_split(acl_main_t *am, u32 lc_index, int is_ip6, u32 first_index)
{
  applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, lc_index);
  applied_hash_ace_entry_t *first_pae = vec_elt_at_index((*applied_hash_aces), first_index);
  if (vec_len(first_pae->colliding_rules) > am->tuple_merge_split_threshold) {
    split_partition(am, first_index, lc_index, is_ip6);
  }
}

void
hash_acl_apply(acl_main_t *am, u32 lc_index, int acl_index, u32 acl_position)
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

  /*
   * if the applied ACL is empty, the current code will cause a
   * different behavior compared to current linear search: an empty ACL will
   * simply fallthrough to the next ACL, or the default deny in the end.
   *
   * This is not a problem, because after vpp-dev discussion,
   * the consensus was it should not be possible to apply the non-existent
   * ACL, so the change adding this code also takes care of that.
   */


  vec_validate(am->hash_applied_mask_info_vec_by_lc_index, lc_index);
  /* add the rules from the ACL to the hash table for lookup and append to the vector*/
  for(i=0; i < vec_len(ha->rules); i++) {
    /*
     * Expand the applied aces vector to fit a new entry.
     * One by one not to upset split_partition() if it is called.
     */
    vec_resize((*applied_hash_aces), 1);

    int is_ip6 = ha->rules[i].match.pkt.is_ip6;
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
    pae->colliding_rules = NULL;
    pae->mask_type_index = ~0;
    assign_mask_type_index_to_pae(am, lc_index, is_ip6, pae);
    u32 first_index = activate_applied_ace_hash_entry(am, lc_index, applied_hash_aces, new_index);
    if (am->use_tuple_merge)
      check_collision_count_and_maybe_split(am, lc_index, is_ip6, first_index);
  }
  remake_hash_applied_mask_info_vec(am, applied_hash_aces, lc_index);
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
  applied_hash_ace_entry_t *new_pae = vec_elt_at_index((*applied_hash_aces), new_index);

  if (ACL_HASH_LOOKUP_DEBUG > 0) {
    clib_warning("Moving pae from %d to %d", old_index, new_index);
    acl_plugin_print_pae(am->vlib_main, old_index, pae);
  }

  if (new_pae->tail_applied_entry_index == old_index) {
    /* fix-up the tail index if we are the tail and the start */
    new_pae->tail_applied_entry_index = new_index;
  }

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
  if (new_pae->colliding_rules) {
    /* update the information within the collision rule entry */
    ASSERT(vec_len(new_pae->colliding_rules) > 0);
    collision_match_rule_t *cr = vec_elt_at_index (new_pae->colliding_rules, 0);
    ASSERT(cr->applied_entry_index == old_index);
    cr->applied_entry_index = new_index;
  } else {
    /* find the index in the collision rule entry on the head element */
    u32 head_index = find_head_applied_ace_index(applied_hash_aces, new_index);
    ASSERT(head_index != ~0);
    applied_hash_ace_entry_t *head_pae = vec_elt_at_index((*applied_hash_aces), head_index);
    ASSERT(vec_len(head_pae->colliding_rules) > 0);
    u32 i;
    for (i=0; i<vec_len(head_pae->colliding_rules); i++) {
      collision_match_rule_t *cr = vec_elt_at_index (head_pae->colliding_rules, i);
      if (cr->applied_entry_index == old_index) {
        cr->applied_entry_index = new_index;
      }
    }
    if (ACL_HASH_LOOKUP_DEBUG > 0) {
      clib_warning("Head pae at index %d after adjustment", head_index);
      acl_plugin_print_pae(am->vlib_main, head_index, head_pae);
    }
  }
  /* invalidate the old entry */
  pae->prev_applied_entry_index = ~0;
  pae->next_applied_entry_index = ~0;
  pae->tail_applied_entry_index = ~0;
  pae->colliding_rules = NULL;
}

static void
deactivate_applied_ace_hash_entry(acl_main_t *am,
                            u32 lc_index,
                            applied_hash_ace_entry_t **applied_hash_aces,
                            u32 old_index)
{
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), old_index);
  DBG("UNAPPLY DEACTIVATE: lc_index %d applied index %d", lc_index, old_index);
  if (ACL_HASH_LOOKUP_DEBUG > 0) {
    clib_warning("Deactivating pae at index %d", old_index);
    acl_plugin_print_pae(am->vlib_main, old_index, pae);
  }

  if (pae->prev_applied_entry_index != ~0) {
    DBG("UNAPPLY = index %d has prev_applied_entry_index %d", old_index, pae->prev_applied_entry_index);
    applied_hash_ace_entry_t *prev_pae = vec_elt_at_index((*applied_hash_aces), pae->prev_applied_entry_index);
    ASSERT(prev_pae->next_applied_entry_index == old_index);
    prev_pae->next_applied_entry_index = pae->next_applied_entry_index;

    u32 head_index = find_head_applied_ace_index(applied_hash_aces, old_index);
    ASSERT(head_index != ~0);
    applied_hash_ace_entry_t *head_pae = vec_elt_at_index((*applied_hash_aces), head_index);
    del_colliding_rule(applied_hash_aces, head_index, old_index);

    if (pae->next_applied_entry_index == ~0) {
      /* it was a last entry we removed, update the pointer on the first one */
      ASSERT(head_pae->tail_applied_entry_index == old_index);
      head_pae->tail_applied_entry_index = pae->prev_applied_entry_index;
    } else {
      applied_hash_ace_entry_t *next_pae = vec_elt_at_index((*applied_hash_aces), pae->next_applied_entry_index);
      next_pae->prev_applied_entry_index = pae->prev_applied_entry_index;
    }
  } else {
    /* It was the first entry. We need either to reset the hash entry or delete it */
    /* delete our entry from the collision vector first */
    del_colliding_rule(applied_hash_aces, old_index, old_index);
    if (pae->next_applied_entry_index != ~0) {
      /* the next element becomes the new first one, so needs the tail pointer to be set */
      applied_hash_ace_entry_t *next_pae = vec_elt_at_index((*applied_hash_aces), pae->next_applied_entry_index);
      ASSERT(pae->tail_applied_entry_index != ~0);
      next_pae->tail_applied_entry_index = pae->tail_applied_entry_index;
      /* Remove ourselves and transfer the ownership of the colliding rules vector */
      next_pae->colliding_rules = pae->colliding_rules;
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
  DBG0("Releasing mask type index %d for pae index %d on lc_index %d", pae->mask_type_index, old_index, lc_index);
  release_mask_type_index(am, pae->mask_type_index);
  /* invalidate the old entry */
  pae->mask_type_index = ~0;
  pae->prev_applied_entry_index = ~0;
  pae->next_applied_entry_index = ~0;
  pae->tail_applied_entry_index = ~0;
  /* always has to be 0 */
  pae->colliding_rules = NULL;
}


void
hash_acl_unapply(acl_main_t *am, u32 lc_index, int acl_index)
{
  int i;

  DBG0("HASH ACL unapply: lc_index %d acl %d", lc_index, acl_index);
  applied_hash_acl_info_t **applied_hash_acls = &am->applied_hash_acl_info_by_lc_index;
  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), lc_index);

  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  u32 **hash_acl_applied_lc_index = &ha->lc_index_list;

  if (ACL_HASH_LOOKUP_DEBUG > 0) {
    clib_warning("unapplying acl %d", acl_index);
    acl_plugin_show_tables_mask_type();
    acl_plugin_show_tables_acl_hash_info(acl_index);
    acl_plugin_show_tables_applied_info(lc_index);
  }

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
    deactivate_applied_ace_hash_entry(am, lc_index,
                                      applied_hash_aces, base_offset + i);
  }
  for(i=0; i < tail_len; i ++) {
    /* move the entry at tail offset to base offset */
    /* that is, from (tail_offset+i) -> (base_offset+i) */
    DBG0("UNAPPLY MOVE: lc_index %d, applied index %d -> %d", lc_index, tail_offset+i, base_offset + i);
    move_applied_ace_hash_entry(am, lc_index, applied_hash_aces, tail_offset + i, base_offset + i);
  }
  /* trim the end of the vector */
  _vec_len((*applied_hash_aces)) -= vec_len(ha->rules);

  remake_hash_applied_mask_info_vec(am, applied_hash_aces, lc_index);

  if (vec_len((*applied_hash_aces)) == 0) {
    vec_free((*applied_hash_aces));
  }

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
make_ip6_address_mask(ip6_address_t *addr, u8 prefix_len)
{
  ip6_address_mask_from_width(addr, prefix_len);
}


/* Maybe should be moved into the core somewhere */
always_inline void
ip4_address_mask_from_width (ip4_address_t * a, u32 width)
{
  int i, byte, bit, bitnum;
  ASSERT (width <= 32);
  clib_memset (a, 0, sizeof (a[0]));
  for (i = 0; i < width; i++)
    {
      bitnum = (7 - (i & 7));
      byte = i / 8;
      bit = 1 << bitnum;
      a->as_u8[byte] |= bit;
    }
}


static void
make_ip4_address_mask(ip4_address_t *addr, u8 prefix_len)
{
  ip4_address_mask_from_width(addr, prefix_len);
}

static void
make_port_mask(u16 *portmask, u16 port_first, u16 port_last)
{
  if (port_first == port_last) {
    *portmask = 0xffff;
    /* single port is representable by masked value */
    return;
  }

  *portmask = 0;
  return;
}

static void
make_mask_and_match_from_rule(fa_5tuple_t *mask, acl_rule_t *r, hash_ace_info_t *hi)
{
  clib_memset(mask, 0, sizeof(*mask));
  clib_memset(&hi->match, 0, sizeof(hi->match));
  hi->action = r->is_permit;

  /* we will need to be matching based on lc_index and mask_type_index when applied */
  mask->pkt.lc_index = ~0;
  /* we will assign the match of mask_type_index later when we find it*/
  mask->pkt.mask_type_index_lsb = ~0;

  mask->pkt.is_ip6 = 1;
  hi->match.pkt.is_ip6 = r->is_ipv6;
  if (r->is_ipv6) {
    make_ip6_address_mask(&mask->ip6_addr[0], r->src_prefixlen);
    hi->match.ip6_addr[0] = r->src.ip6;
    make_ip6_address_mask(&mask->ip6_addr[1], r->dst_prefixlen);
    hi->match.ip6_addr[1] = r->dst.ip6;
  } else {
    clib_memset(hi->match.l3_zero_pad, 0, sizeof(hi->match.l3_zero_pad));
    make_ip4_address_mask(&mask->ip4_addr[0], r->src_prefixlen);
    hi->match.ip4_addr[0] = r->src.ip4;
    make_ip4_address_mask(&mask->ip4_addr[1], r->dst_prefixlen);
    hi->match.ip4_addr[1] = r->dst.ip4;
  }

  if (r->proto != 0) {
    mask->l4.proto = ~0; /* L4 proto needs to be matched */
    hi->match.l4.proto = r->proto;

    /* Calculate the src/dst port masks and make the src/dst port matches accordingly */
    make_port_mask(&mask->l4.port[0], r->src_port_or_type_first, r->src_port_or_type_last);
    hi->match.l4.port[0] = r->src_port_or_type_first & mask->l4.port[0];

    make_port_mask(&mask->l4.port[1], r->dst_port_or_code_first, r->dst_port_or_code_last);
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
  clib_memset(ha, 0, sizeof(*ha));
  ha->hash_acl_exists = 1;

  /* walk the newly added ACL entries and ensure that for each of them there
     is a mask type, increment a reference count for that mask type */
  for(i=0; i < a->count; i++) {
    hash_ace_info_t ace_info;
    fa_5tuple_t mask;
    clib_memset(&ace_info, 0, sizeof(ace_info));
    ace_info.acl_index = acl_index;
    ace_info.ace_index = i;

    make_mask_and_match_from_rule(&mask, &a->rules[i], &ace_info);
    mask.pkt.flags_reserved = 0b000;
    ace_info.base_mask_type_index = assign_mask_type_index(am, &mask);
    /* assign the mask type index for matching itself */
    ace_info.match.pkt.mask_type_index_lsb = ace_info.base_mask_type_index;
    DBG("ACE: %d mask_type_index: %d", i, ace_info.base_mask_type_index);
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
   * The part to remember is that this routine is called in process of reapplication
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
  vec_free(ha->lc_index_list);

  /* walk the mask types for the ACL about-to-be-deleted, and decrease
   * the reference count, possibly freeing up some of them */
  int i;
  for(i=0; i < vec_len(ha->rules); i++) {
    release_mask_type_index(am, ha->rules[i].base_mask_type_index);
  }
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
		    mte->mask.kv_40_8.key[0], mte->mask.kv_40_8.key[1], mte->mask.kv_40_8.key[2],
		    mte->mask.kv_40_8.key[3], mte->mask.kv_40_8.key[4], mte->mask.kv_40_8.value, mte->refcount);
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
      for (j = 0; j < vec_len (ha->rules); j++)
	{
	  hash_ace_info_t *pa = &ha->rules[j];
	  m = (u64 *) & pa->match;
	  vlib_cli_output (vm,
			   "    %4d: %016llx %016llx %016llx %016llx %016llx %016llx base mask index %d acl %d rule %d action %d\n",
			   j, m[0], m[1], m[2], m[3], m[4], m[5],
			   pa->base_mask_type_index, pa->acl_index, pa->ace_index,
			   pa->action);
	}
    }
}

static void
acl_plugin_print_colliding_rule (vlib_main_t * vm, int j, collision_match_rule_t *cr) {
  vlib_cli_output(vm,
                  "        %4d: acl %d ace %d acl pos %d pae index: %d",
                  j, cr->acl_index, cr->ace_index, cr->acl_position, cr->applied_entry_index);
}

static void
acl_plugin_print_pae (vlib_main_t * vm, int j, applied_hash_ace_entry_t * pae)
{
  vlib_cli_output (vm,
		   "    %4d: acl %d rule %d action %d bitmask-ready rule %d mask type index: %d colliding_rules: %d next %d prev %d tail %d hitcount %lld acl_pos: %d",
		   j, pae->acl_index, pae->ace_index, pae->action,
		   pae->hash_ace_info_index, pae->mask_type_index, vec_len(pae->colliding_rules), pae->next_applied_entry_index,
		   pae->prev_applied_entry_index,
		   pae->tail_applied_entry_index, pae->hitcount, pae->acl_position);
  int jj;
  for(jj=0; jj<vec_len(pae->colliding_rules); jj++)
    acl_plugin_print_colliding_rule(vm, jj, vec_elt_at_index(pae->colliding_rules, jj));
}

static void
acl_plugin_print_applied_mask_info (vlib_main_t * vm, int j, hash_applied_mask_info_t *mi)
{
  vlib_cli_output (vm,
		   "    %4d: mask type index %d first rule index %d num_entries %d max_collisions %d",
		   j, mi->mask_type_index, mi->first_rule_index, mi->num_entries, mi->max_collisions);
}

void
acl_plugin_show_tables_applied_info (u32 lc_index)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  u32 lci, j;
  vlib_cli_output (vm, "Applied lookup entries for lookup contexts");

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
	  vlib_cli_output (vm, "  applied acls: %U", format_vec32,
			   pal->applied_acls, "%d");
	}
      if (lci < vec_len (am->hash_applied_mask_info_vec_by_lc_index))
	{
	  vlib_cli_output (vm, "  applied mask info entries:");
	  for (j = 0;
	       j < vec_len (am->hash_applied_mask_info_vec_by_lc_index[lci]);
	       j++)
	    {
	      acl_plugin_print_applied_mask_info (vm, j,
				    &am->hash_applied_mask_info_vec_by_lc_index
				    [lci][j]);
	    }
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

/*
 * Split of the partition needs to happen when the collision count
 * goes over a specified threshold.
 *
 * This is a signal that we ignored too many bits in
 * mT and we need to split the table into two tables. We select
 * all of the colliding rules L and find their maximum common
 * tuple mL. Normally mL is specific enough to hash L with few
 * or no collisions. We then create a new table T2 with tuple mL
 * and transfer all compatible rules from T to T2. If mL is not
 * specific enough, we find the field with the biggest difference
 * between the minimum and maximum tuple lengths for all of
 * the rules in L and set that field to be the average of those two
 * values. We then transfer all compatible rules as before. This
 * guarantees that some rules from L will move and that T2 will
 * have a smaller number of collisions than T did.
 */


static void
ensure_ip6_min_addr (ip6_address_t * min_addr, ip6_address_t * mask_addr)
{
  int update =
    (clib_net_to_host_u64 (mask_addr->as_u64[0]) <
     clib_net_to_host_u64 (min_addr->as_u64[0]))
    ||
    ((clib_net_to_host_u64 (mask_addr->as_u64[0]) ==
      clib_net_to_host_u64 (min_addr->as_u64[0]))
     && (clib_net_to_host_u64 (mask_addr->as_u64[1]) <
	 clib_net_to_host_u64 (min_addr->as_u64[1])));
  if (update)
    {
      min_addr->as_u64[0] = mask_addr->as_u64[0];
      min_addr->as_u64[1] = mask_addr->as_u64[1];
    }
}

static void
ensure_ip6_max_addr (ip6_address_t * max_addr, ip6_address_t * mask_addr)
{
  int update =
    (clib_net_to_host_u64 (mask_addr->as_u64[0]) >
     clib_net_to_host_u64 (max_addr->as_u64[0]))
    ||
    ((clib_net_to_host_u64 (mask_addr->as_u64[0]) ==
      clib_net_to_host_u64 (max_addr->as_u64[0]))
     && (clib_net_to_host_u64 (mask_addr->as_u64[1]) >
	 clib_net_to_host_u64 (max_addr->as_u64[1])));
  if (update)
    {
      max_addr->as_u64[0] = mask_addr->as_u64[0];
      max_addr->as_u64[1] = mask_addr->as_u64[1];
    }
}

static void
ensure_ip4_min_addr (ip4_address_t * min_addr, ip4_address_t * mask_addr)
{
  int update =
    (clib_net_to_host_u32 (mask_addr->as_u32) <
     clib_net_to_host_u32 (min_addr->as_u32));
  if (update)
    min_addr->as_u32 = mask_addr->as_u32;
}

static void
ensure_ip4_max_addr (ip4_address_t * max_addr, ip4_address_t * mask_addr)
{
  int update =
    (clib_net_to_host_u32 (mask_addr->as_u32) >
     clib_net_to_host_u32 (max_addr->as_u32));
  if (update)
    max_addr->as_u32 = mask_addr->as_u32;
}

enum {
  DIM_SRC_ADDR = 0,
  DIM_DST_ADDR,
  DIM_SRC_PORT,
  DIM_DST_PORT,
  DIM_PROTO,
};



static void
split_partition(acl_main_t *am, u32 first_index,
                            u32 lc_index, int is_ip6){
	DBG( "TM-split_partition - first_entry:%d", first_index);
        applied_hash_ace_entry_t **applied_hash_aces = get_applied_hash_aces(am, lc_index);
	ace_mask_type_entry_t *mte;
	fa_5tuple_t the_min_tuple, *min_tuple = &the_min_tuple;
        fa_5tuple_t the_max_tuple, *max_tuple = &the_max_tuple;
	applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), first_index);
	hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);
	hash_ace_info_t *ace_info;
	u32 coll_mask_type_index = pae->mask_type_index;
        clib_memset(&the_min_tuple, 0, sizeof(the_min_tuple));
        clib_memset(&the_max_tuple, 0, sizeof(the_max_tuple));

	int i=0;
	u64 collisions = vec_len(pae->colliding_rules);
	for(i=0; i<collisions; i++){
                /* reload the hash acl info as it might be a different ACL# */
	        ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);

		DBG( "TM-collision: base_ace:%d (ace_mask:%d, first_collision_mask:%d)",
				pae->ace_index, pae->mask_type_index, coll_mask_type_index);

		ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
		mte = vec_elt_at_index(am->ace_mask_type_pool, ace_info->base_mask_type_index);
		fa_5tuple_t *mask = &mte->mask;

		if(pae->mask_type_index != coll_mask_type_index) continue;
		/* Computing min_mask and max_mask for colliding rules */
		if(i==0){
			clib_memcpy(min_tuple, mask, sizeof(fa_5tuple_t));
			clib_memcpy(max_tuple, mask, sizeof(fa_5tuple_t));
		}else{
			int j;
			for(j=0; j<2; j++){
                                if (is_ip6)
                                  ensure_ip6_min_addr(&min_tuple->ip6_addr[j], &mask->ip6_addr[j]);
                                else
                                  ensure_ip4_min_addr(&min_tuple->ip4_addr[j], &mask->ip4_addr[j]);

				if ((mask->l4.port[j] < min_tuple->l4.port[j]))
					min_tuple->l4.port[j] = mask->l4.port[j];
			}

			if ((mask->l4.proto < min_tuple->l4.proto))
				min_tuple->l4.proto = mask->l4.proto;

			if(mask->pkt.as_u64 < min_tuple->pkt.as_u64)
				min_tuple->pkt.as_u64 = mask->pkt.as_u64;


			for(j=0; j<2; j++){
                                if (is_ip6)
                                  ensure_ip6_max_addr(&max_tuple->ip6_addr[j], &mask->ip6_addr[j]);
                                else
                                  ensure_ip4_max_addr(&max_tuple->ip4_addr[j], &mask->ip4_addr[j]);

				if ((mask->l4.port[j] > max_tuple->l4.port[j]))
					max_tuple->l4.port[j] = mask->l4.port[j];
			}

			if ((mask->l4.proto < max_tuple->l4.proto))
				max_tuple->l4.proto = mask->l4.proto;

			if(mask->pkt.as_u64 > max_tuple->pkt.as_u64)
				max_tuple->pkt.as_u64 = mask->pkt.as_u64;
		}

		pae = pae->next_applied_entry_index == ~0 ? 0 : vec_elt_at_index((*applied_hash_aces), pae->next_applied_entry_index);
	}

	/* Computing field with max difference between (min/max)_mask */
	int best_dim=-1, best_delta=0, delta=0;

	/* SRC_addr dimension */
        if (is_ip6) {
	  int i;
	  for(i=0; i<2; i++){
		delta += count_bits(max_tuple->ip6_addr[0].as_u64[i]) - count_bits(min_tuple->ip6_addr[0].as_u64[i]);
	  }
        } else {
		delta += count_bits(max_tuple->ip4_addr[0].as_u32) - count_bits(min_tuple->ip4_addr[0].as_u32);
        }
	if(delta > best_delta){
		best_delta = delta;
		best_dim = DIM_SRC_ADDR;
	}

	/* DST_addr dimension */
	delta = 0;
        if (is_ip6) {
	  int i;
	  for(i=0; i<2; i++){
		delta += count_bits(max_tuple->ip6_addr[1].as_u64[i]) - count_bits(min_tuple->ip6_addr[1].as_u64[i]);
	  }
        } else {
		delta += count_bits(max_tuple->ip4_addr[1].as_u32) - count_bits(min_tuple->ip4_addr[1].as_u32);
        }
	if(delta > best_delta){
		best_delta = delta;
		best_dim = DIM_DST_ADDR;
	}

	/* SRC_port dimension */
	delta = count_bits(max_tuple->l4.port[0]) - count_bits(min_tuple->l4.port[0]);
	if(delta > best_delta){
		best_delta = delta;
		best_dim = DIM_SRC_PORT;
	}

	/* DST_port dimension */
	delta = count_bits(max_tuple->l4.port[1]) - count_bits(min_tuple->l4.port[1]);
	if(delta > best_delta){
		best_delta = delta;
		best_dim = DIM_DST_PORT;
	}

	/* Proto dimension */
	delta = count_bits(max_tuple->l4.proto) - count_bits(min_tuple->l4.proto);
	if(delta > best_delta){
		best_delta = delta;
		best_dim = DIM_PROTO;
	}

	int shifting = 0; //, ipv4_block = 0;
	switch(best_dim){
		case DIM_SRC_ADDR:
			shifting = (best_delta)/2; // FIXME IPV4-only
			// ipv4_block = count_bits(max_tuple->ip4_addr[0].as_u32);
			min_tuple->ip4_addr[0].as_u32 =
					clib_host_to_net_u32((clib_net_to_host_u32(max_tuple->ip4_addr[0].as_u32) << (shifting))&0xFFFFFFFF);

			break;
		case DIM_DST_ADDR:
			shifting = (best_delta)/2;
/*
			ipv4_block = count_bits(max_tuple->addr[1].as_u64[1]);
			if(ipv4_block > shifting)
				min_tuple->addr[1].as_u64[1] =
					clib_host_to_net_u64((clib_net_to_host_u64(max_tuple->addr[1].as_u64[1]) << (shifting))&0xFFFFFFFF);
			else{
				shifting = shifting - ipv4_block;
				min_tuple->addr[1].as_u64[1] = 0;
				min_tuple->addr[1].as_u64[0] =
					clib_host_to_net_u64((clib_net_to_host_u64(max_tuple->addr[1].as_u64[0]) << (shifting))&0xFFFFFFFF);
			}
*/
			min_tuple->ip4_addr[1].as_u32 =
					clib_host_to_net_u32((clib_net_to_host_u32(max_tuple->ip4_addr[1].as_u32) << (shifting))&0xFFFFFFFF);

			break;
		case DIM_SRC_PORT: min_tuple->l4.port[0] = max_tuple->l4.port[0]  << (best_delta)/2;
			break;
		case DIM_DST_PORT: min_tuple->l4.port[1] = max_tuple->l4.port[1] << (best_delta)/2;
			break;
		case DIM_PROTO: min_tuple->l4.proto = max_tuple->l4.proto << (best_delta)/2;
			break;
		default: relax_tuple(min_tuple, is_ip6, 1);
			break;
	}

	min_tuple->pkt.is_nonfirst_fragment = 0;
        u32 new_mask_type_index = assign_mask_type_index(am, min_tuple);

	hash_applied_mask_info_t **hash_applied_mask_info_vec = vec_elt_at_index(am->hash_applied_mask_info_vec_by_lc_index, lc_index);

	hash_applied_mask_info_t *minfo;
	//search in order pool if mask_type_index is already there
	int search;
	for (search=0; search < vec_len((*hash_applied_mask_info_vec)); search++){
		minfo = vec_elt_at_index((*hash_applied_mask_info_vec), search);
		if(minfo->mask_type_index == new_mask_type_index)
			break;
	}

	vec_validate((*hash_applied_mask_info_vec), search);
	minfo = vec_elt_at_index((*hash_applied_mask_info_vec), search);
	minfo->mask_type_index = new_mask_type_index;
	minfo->num_entries = 0;
	minfo->max_collisions = 0;
	minfo->first_rule_index = ~0;

	DBG( "TM-split_partition - mask type index-assigned!! -> %d", new_mask_type_index);

	if(coll_mask_type_index == new_mask_type_index){
		//vlib_cli_output(vm, "TM-There are collisions over threshold, but i'm not able to split! %d %d", coll_mask_type_index, new_mask_type_index);
		return;
	}


	/* populate new partition */
	DBG( "TM-Populate new partition");
	u32 r_ace_index = first_index;
        int repopulate_count = 0;

//	for(i=0; i<collisions; i++){
	for(r_ace_index=0; r_ace_index < vec_len((*applied_hash_aces)); r_ace_index++) {

		applied_hash_ace_entry_t *pop_pae = vec_elt_at_index((*applied_hash_aces), r_ace_index);
		DBG( "TM-Population-collision: base_ace:%d (ace_mask:%d, first_collision_mask:%d)",
				pop_pae->ace_index, pop_pae->mask_type_index, coll_mask_type_index);

		if(pop_pae->mask_type_index != coll_mask_type_index) continue;
		u32 next_index = pop_pae->next_applied_entry_index;

		ace_info = vec_elt_at_index(ha->rules, pop_pae->hash_ace_info_index);
		mte = vec_elt_at_index(am->ace_mask_type_pool, ace_info->base_mask_type_index);
		//can insert rule?
		//mte = vec_elt_at_index(am->ace_mask_type_pool, pop_pae->mask_type_index);
		fa_5tuple_t *pop_mask = &mte->mask;

		if(!first_mask_contains_second_mask(is_ip6, min_tuple, pop_mask)) continue;
		DBG( "TM-new partition can insert -> applied_ace:%d", r_ace_index);

		//delete and insert in new format
		deactivate_applied_ace_hash_entry(am, lc_index, applied_hash_aces, r_ace_index);

		/* insert the new entry */
		pop_pae->mask_type_index = new_mask_type_index;
                /* The very first repopulation gets the lock by virtue of a new mask being created above */
                if (++repopulate_count > 1)
                  lock_mask_type_index(am, new_mask_type_index);

		activate_applied_ace_hash_entry(am, lc_index, applied_hash_aces, r_ace_index);

		r_ace_index = next_index;
	}

	DBG( "TM-Populate new partition-END");
	DBG( "TM-split_partition - END");

}

