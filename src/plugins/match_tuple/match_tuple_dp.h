always_inline u32
multi_acl_match_get_applied_ace_index (acl_main_t * am, int is_ip6, fa_5tuple_t * match)
{
  clib_bihash_kv_48_8_t kv;
  clib_bihash_kv_48_8_t result;
  fa_5tuple_t *kv_key = (fa_5tuple_t *) kv.key;
  hash_acl_lookup_value_t *result_val =
    (hash_acl_lookup_value_t *) & result.value;
  u64 *pmatch = (u64 *) match;
  u64 *pmask;
  u64 *pkey;
  int mask_type_index, order_index;
  u32 curr_match_index = (~0 - 1);



  u32 lc_index = match->pkt.lc_index;
  applied_hash_ace_entry_t **applied_hash_aces =
    vec_elt_at_index (am->hash_entry_vec_by_lc_index, lc_index);

  hash_applied_mask_info_t **hash_applied_mask_info_vec =
    vec_elt_at_index (am->hash_applied_mask_info_vec_by_lc_index, lc_index);

  hash_applied_mask_info_t *minfo;

  DBG ("TRYING TO MATCH: %016llx %016llx %016llx %016llx %016llx %016llx",
       pmatch[0], pmatch[1], pmatch[2], pmatch[3], pmatch[4], pmatch[5]);

  for (order_index = 0; order_index < vec_len ((*hash_applied_mask_info_vec));
       order_index++)
    {
      minfo = vec_elt_at_index ((*hash_applied_mask_info_vec), order_index);
      if (minfo->first_rule_index > curr_match_index)
	{
	  /* Index in this and following (by construction) partitions are greater than our candidate, Avoid trying to match! */
	  break;
	}

      mask_type_index = minfo->mask_type_index;
      ace_mask_type_entry_t *mte =
	vec_elt_at_index (am->ace_mask_type_pool, mask_type_index);
      pmatch = (u64 *) match;
      pmask = (u64 *) & mte->mask;
      pkey = (u64 *) kv.key;
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

      /*
       * The use of temporary variable convinces the compiler
       * to make a u64 write, avoiding the stall on crc32 operation
       * just a bit later.
       */
      fa_packet_info_t tmp_pkt = kv_key->pkt;
      tmp_pkt.mask_type_index_lsb = mask_type_index;
      kv_key->pkt.as_u64 = tmp_pkt.as_u64;

      int res =
	clib_bihash_search_inline_2_48_8 (&am->acl_lookup_hash, &kv, &result);

      if (res == 0)
	{
	  /* There is a hit in the hash, so check the collision vector */
	  u32 curr_index = result_val->applied_entry_index;
	  applied_hash_ace_entry_t *pae =
	    vec_elt_at_index ((*applied_hash_aces), curr_index);
	  collision_match_rule_t *crs = pae->colliding_rules;
	  int i;
	  for (i = 0; i < vec_len (crs); i++)
	    {
	      if (crs[i].applied_entry_index >= curr_match_index)
		{
		  continue;
		}
	      if (single_rule_match_5tuple (&crs[i].rule, is_ip6, match))
		{
		  curr_match_index = crs[i].applied_entry_index;
		}
	    }
	}
    }
  DBG ("MATCH-RESULT: %d", curr_match_index);
  return curr_match_index;
}

always_inline int
hash_multi_acl_match_5tuple (void *p_acl_main, u32 lc_index, fa_5tuple_t * pkt_5tuple,
                       int is_ip6, u8 *action, u32 *acl_pos_p, u32 * acl_match_p,
                       u32 * rule_match_p, u32 * trace_bitmap)
{
  acl_main_t *am = p_acl_main;
  applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);
  u32 match_index = multi_acl_match_get_applied_ace_index(am, is_ip6, pkt_5tuple);
  if (match_index < vec_len((*applied_hash_aces))) {
    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), match_index);
    pae->hitcount++;
    *acl_pos_p = pae->acl_position;
    *acl_match_p = pae->acl_index;
    *rule_match_p = pae->ace_index;
    *action = pae->action;
    return 1;
  }
  return 0;
}

