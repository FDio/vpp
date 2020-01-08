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

#include <vnet/match/engines/classifier/match_classifier.h>

u32
match_classifier_round_up_to_classifier_vector_size (u32 n_bytes)
{
  u32 d, m;
  /* round to size of u32x4 */
  d = n_bytes / VNET_CLASSIFY_VECTOR_SIZE;
  m = n_bytes % VNET_CLASSIFY_VECTOR_SIZE;
  if (m)
    d++;

  return ((d * VNET_CLASSIFY_VECTOR_SIZE) / VNET_CLASSIFY_VECTOR_SIZE);
}

u32
match_classifier_mk_table (void *mask,
			   u32 mask_len,
			   u32 n_sessions,
			   u32 next_table_index,
			   vnet_classify_flags_t flags,
			   i16 offset, uword user_ctx)
{
  vnet_classify_main_t *vcm = &vnet_classify_main;
  u32 memory_size = 2 << 22;
  u32 nbuckets = 32;
  u32 table_index = ~0;

  if (~0 != n_sessions)
    {
      memory_size = (n_sessions * 128 *
		     (sizeof (vnet_classify_entry_t) + mask_len));
      nbuckets = max_pow2 (n_sessions);
    }

  /* *INDENT-OFF* */
  if (vnet_classify_add_del_table (vcm, mask, nbuckets, memory_size,
                                   // no skip, the packet's current needs to be in the
                                   // correct location.
                                   0,
				   match_classifier_round_up_to_classifier_vector_size (mask_len),
                                   next_table_index,
				   // miss_next_index,
                                   0,
				   &table_index,
                                   flags,
                                   offset,
                                   // is_add,
				   1,
                                   // delete_chain
				   0))
    ASSERT (0);
  /* *INDENT-ON* */

  vnet_classify_table_t *vct;

  vct = pool_elt_at_index (vcm->tables, table_index);
  vct->user_ctx = user_ctx;

  return (table_index);
}

int
match_classifier_mk_session (u32 table_index,
			     void *match, u32 usr_context, u32 hit_next_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;

  /* *INDENT-OFF* */
  return (vnet_classify_add_del_session (cm, table_index, match,
                                         hit_next_index,
					 usr_context,
                                         0,	// advance,
					 CLASSIFY_ACTION_NONE,
					 0 /* metadata */ ,
					 1 /* is_add */ ));
  /* *INDENT-ON* */
}

vnet_classify_entry_t *
match_classifier_find_session (u32 table_index, void *match)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_classify_table_t *vct;
  vnet_classify_entry_t *e;
  u64 hash;

  vct = pool_elt_at_index (cm->tables, table_index);
  hash = vnet_classify_hash_packet_inline (vct, match);

  e = vnet_classify_find_entry_inline (vct, match, hash, 0);

  return (e);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
