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
#include "bihash_48_8.h"

#include <vppinfra/bihash_template.h>
/*
included in fa_node.c
*/
#include <vppinfra/bihash_template.c>

#include "hash_lookup.h"

static u32
match_an_acl(acl_main_t *am, fa_5tuple_t *match)
{
  clib_bihash_kv_48_8_t kv;
  clib_bihash_kv_48_8_t result;
  hash_acl_lookup_value_t *result_val = (hash_acl_lookup_value_t *)&result.value;
  u64 *pmatch = (u64 *)match;
  u64 *pmask;
  int mask_type_index, i;
  u32 curr_match_index = ~0;

/*
  u32 sw_if_index = match->pkt.sw_if_index;
  applied_ace_hash_entry_t **applied_hash_aces = match->pkt.is_input ? &am->input_hash_entry_vec_by_sw_if_index[sw_if_index] :
                                                    &am->output_hash_entry_vec_by_sw_if_index[sw_if_index];
*/
  clib_warning("TRYING TO MATCH: %016llx %016llx %016llx %016llx %016llx %016llx",
	       pmatch[0], pmatch[1], pmatch[2], pmatch[3], pmatch[4], pmatch[5]);

  for(mask_type_index=0; mask_type_index < pool_len(am->ace_mask_type_pool); mask_type_index++) {
    ace_mask_type_entry_t *mte = &am->ace_mask_type_pool[mask_type_index];
    pmask = (u64 *)&mte->mask;
    for(i=0; i<6; i++) {
      kv.key[i] = pmatch[i] & pmask[i];
    }
    clib_warning("        KEY %3d: %016llx %016llx %016llx %016llx %016llx %016llx", mask_type_index,
		kv.key[0], kv.key[1], kv.key[2], kv.key[3], kv.key[4], kv.key[5]);
    int res = BV (clib_bihash_search) (&am->acl_lookup_hash, &kv, &result);
    if (res == 0) {
      clib_warning("ACL-MATCH! result_val: %016llx", result_val->as_u64);
      if (result_val->applied_entry_index < curr_match_index) {
	if (result_val->need_portrange_check) {
          /* FIXME: portrange checks here */
        }
        curr_match_index = result_val->applied_entry_index;
	if (!result_val->shadowed) {
          /* new result is known to not be shadowed, so no point to look up further */
          break;
	}
      }
    }
  }
  clib_warning("MATCH-RESULT: %d", curr_match_index);
  return curr_match_index;
}


void
hash_acl_apply(acl_main_t *am, u32 sw_if_index, u8 is_input, int acl_index)
{
  int i;
  clib_bihash_kv_48_8_t kv;
  applied_ace_hash_entry_t ae;
  fa_5tuple_t *kv_key = (fa_5tuple_t *)kv.key;
  hash_acl_lookup_value_t *kv_val = (hash_acl_lookup_value_t *)&kv.value;

  clib_warning("HASH ACL apply: sw_if_index %d is_input %d acl %d", sw_if_index, is_input, acl_index);
  u32 *acl_vec = is_input ? am->input_acl_vec_by_sw_if_index[sw_if_index] :
			    am->output_acl_vec_by_sw_if_index[sw_if_index];
  if (is_input) {
    vec_validate(am->input_hash_entry_vec_by_sw_if_index, sw_if_index);
  } else {
    vec_validate(am->output_hash_entry_vec_by_sw_if_index, sw_if_index);
  }
  applied_ace_hash_entry_t **applied_hash_aces = is_input ? &am->input_hash_entry_vec_by_sw_if_index[sw_if_index] :
                                                    &am->output_hash_entry_vec_by_sw_if_index[sw_if_index];
  u32 order_index = vec_search(acl_vec, acl_index);
  hash_acl_info_t *ha = &am->hash_acl_infos[acl_index];
  ASSERT(order_index != ~0);

  if (!am->acl_lookup_hash_initialized) {
    BV (clib_bihash_init) (&am->acl_lookup_hash, "ACL plugin rule lookup bihash",
                           65536, 2 << 25);
    am->acl_lookup_hash_initialized = 1;
  }
  int base_offset = vec_len(*applied_hash_aces);
  /* expand the applied aces vector by the necessary amount */
  vec_resize((*applied_hash_aces), vec_len(ha->rules));
  /* add the rules from the ACL to the hash table for lookup and append to the vector*/

  for(i=0; i < vec_len(ha->rules); i++) {
    ae.acl_index = acl_index;
    ae.ace_index = ha->rules[i].ace_index;
    ae.hash_ace_info_index = i;
    (*applied_hash_aces)[base_offset + i] = ae;

    memcpy(kv_key, &ha->rules[i].match, sizeof(*kv_key));
    /* initialize the sw_if_index and direction */
    kv_key->pkt.sw_if_index = sw_if_index;
    kv_key->pkt.is_input = is_input;
    kv_val->as_u64 = 0;
    kv_val->applied_entry_index = base_offset + i;
    kv_val->need_portrange_check = ha->rules[i].src_portrange_not_powerof2 ||
				   ha->rules[i].dst_portrange_not_powerof2;
    /* by default assume all values are shadowed -> check all mask types */
    kv_val->shadowed = 1;
    /* FIXME: there is a corner case with a portrange and a non-portrange ACEs in different ACLs,
       which this does not handle so far. */
    BV (clib_bihash_add_del) (&am->acl_lookup_hash, &kv, 1);
    //XXXXX clib_warning("APPLY SET MATCH: %016llx %016llx %016llx %016llx %016llx %016llx",
		
  }  
  /* 
   * FIXME: go over the rules and check which ones are shadowed and which aren't.
   * To do this, we must try to match the match value from every ACE as if it
   * was a live packet, and see if the resulting match happens earlier in the list.
   * if it does not match or it is later in the ACL - then the entry is not shadowed.
   */
}

void
hash_acl_unapply(acl_main_t *am, u32 sw_if_index, u8 is_input, int acl_index)
{
  int i;
  clib_bihash_kv_48_8_t kv;
  fa_5tuple_t *kv_key = (fa_5tuple_t *)kv.key;
  hash_acl_lookup_value_t *kv_val = (hash_acl_lookup_value_t *)&kv.value;

  clib_warning("HASH ACL unapply: sw_if_index %d is_input %d acl %d", sw_if_index, is_input, acl_index);
  hash_acl_info_t *ha = &am->hash_acl_infos[acl_index];  
  applied_ace_hash_entry_t **applied_hash_aces = is_input ? &am->input_hash_entry_vec_by_sw_if_index[sw_if_index] :
                                                    &am->output_hash_entry_vec_by_sw_if_index[sw_if_index];

  for(i=0; i < vec_len((*applied_hash_aces)); i++) {
    if ((*applied_hash_aces)[i].acl_index == acl_index) {
      break;
    }
  }
  if (vec_len((*applied_hash_aces)) <= i) {
    /* we went all the way without finding any entries. Probably a list was empty. */
    return;
  }
  int base_offset = i;
  int tail_offset = base_offset + vec_len(ha->rules);
  int tail_len = vec_len((*applied_hash_aces)) - tail_offset;
  for(i=0; i < tail_len; i ++) {
    if (i < vec_len(ha->rules)) {
      /* delete the old entry at base offset */
      memcpy(kv_key, &ha->rules[i].match, sizeof(*kv_key));
      kv_key->pkt.sw_if_index = sw_if_index;
      kv_key->pkt.is_input = is_input;
      kv_val->as_u64 = 0;
      BV (clib_bihash_add_del) (&am->acl_lookup_hash, &kv, 0);
    }
    /* move the entry at tail offset to base offset */
    applied_ace_hash_entry_t *pae = &((*applied_hash_aces)[tail_offset + i]);
    ha = &am->hash_acl_infos[pae->acl_index];
    memcpy(kv_key, &ha->rules[i].match, sizeof(*kv_key));
    /* sw_if_index and is_input remain the same from above */
    /* move the hash entry forward */
    (*applied_hash_aces)[base_offset + i] = (*applied_hash_aces)[tail_offset + i]; 
    kv_val->as_u64 = 0;
    /* the new applied entry index is base_offset + i, we will replace it */
    kv_val->applied_entry_index = base_offset + i;
    /* by default assume all values are shadowed -> check all mask types */
    kv_val->shadowed = 1;
    kv_val->need_portrange_check = ha->rules[i].src_portrange_not_powerof2 ||
				   ha->rules[i].dst_portrange_not_powerof2;
    BV (clib_bihash_add_del) (&am->acl_lookup_hash, &kv, 1);
  }
  /* trim the end of the vector */
  vec_resize((*applied_hash_aces), (-1) * vec_len(ha->rules));
  /* FIXME: fixup the shadowed flag, same as upon the addition */
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
   * FIXME: for now match all the ports, later
   * here would be a better optimization which would
   * pick out bitmaskable portranges.
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
  mask->pkt.is_input = ~0;
  /* we will assign the match of mask_type_index later when we find it*/
  mask->pkt.mask_type_index = ~0;

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
  }
  mte = am->ace_mask_type_pool + mask_type_index;
  mte->refcount++;
  return mask_type_index;
}

static void
release_mask_type_index(acl_main_t *am, u32 mask_type_index)
{
  ace_mask_type_entry_t *mte = &am->ace_mask_type_pool[mask_type_index];
  mte->refcount--;
  if (mte->refcount == 0) {
    /* we are not using this entry anymore */
    pool_put(am->ace_mask_type_pool, mte);
  }
}

void hash_acl_add(acl_main_t *am, int acl_index)
{
  clib_warning("HASH ACL add : %d", acl_index);
  int i;
  acl_list_t *a = &am->acls[acl_index];
  vec_validate(am->hash_acl_infos, acl_index);
  hash_acl_info_t *ha = &am->hash_acl_infos[acl_index];
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
    ace_info.match.pkt.mask_type_index = ace_info.mask_type_index;
    clib_warning("ACE: %d mask_type_index: %d", i, ace_info.mask_type_index);
    /* Ensure a given index is set in the mask type index bitmap for this ACL */
    ha->mask_type_index_bitmap = clib_bitmap_set(ha->mask_type_index_bitmap, ace_info.mask_type_index, 1);
    vec_add1(ha->rules, ace_info);
    if (am->l4_match_nonfirst_fragment) {
      /* add the second rule which matches the noninitial fragments with the respective mask */
      make_mask_and_match_from_rule(&mask, &a->rules[i], &ace_info, 1);
      ace_info.mask_type_index = assign_mask_type_index(am, &mask);
      ace_info.match.pkt.mask_type_index = ace_info.mask_type_index;
      clib_warning("ACE: %d (non-initial frags) mask_type_index: %d", i, ace_info.mask_type_index);
      /* Ensure a given index is set in the mask type index bitmap for this ACL */
      ha->mask_type_index_bitmap = clib_bitmap_set(ha->mask_type_index_bitmap, ace_info.mask_type_index, 1);
      vec_add1(ha->rules, ace_info);
    }
  }
  /* FIXME: if an ACL is applied somewhere, fill the corresponding lookup data structures (call hash_acl_apply) */
}

void hash_acl_delete(acl_main_t *am, int acl_index)
{
  clib_warning("HASH ACL delete : %d", acl_index);
  /* if the ACL is applied somewhere, remove the references of it (call hash_acl_unapply) */

  /* walk the mask types for the ACL about-to-be-deleted, and decrease
   * the reference count, possibly freeing up some of them */
  int i;
  hash_acl_info_t *ha = &am->hash_acl_infos[acl_index];
  for(i=0; i < vec_len(ha->rules); i++) {
    release_mask_type_index(am, ha->rules[i].mask_type_index);
  }
  clib_bitmap_free(ha->mask_type_index_bitmap);
  vec_free(ha->rules);
}

u8
hash_full_acl_match_5tuple (u32 sw_if_index, fa_5tuple_t * pkt_5tuple, int is_l2,
                       int is_ip6, int is_input, u32 * acl_match_p,
                       u32 * rule_match_p, u32 * trace_bitmap)
{
  acl_main_t *am = &acl_main;
  applied_ace_hash_entry_t **applied_hash_aces = is_input ? &am->input_hash_entry_vec_by_sw_if_index[sw_if_index] :
                                                    &am->output_hash_entry_vec_by_sw_if_index[sw_if_index];
  u32 match_index = match_an_acl(am, pkt_5tuple);
  if (match_index < vec_len((*applied_hash_aces))) {
    applied_ace_hash_entry_t *pae = &((*applied_hash_aces)[match_index]);
    hash_acl_info_t *ha = &am->hash_acl_infos[pae->acl_index];
    *acl_match_p = pae->acl_index; 
    *rule_match_p = pae->ace_index; 
    return ha->rules[pae->hash_ace_info_index].action;
  }
  return 0;
}
