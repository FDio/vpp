/*
 * trace_classify.h - Use the classifier to decide if a packet is traced
 *
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
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/classify/vnet_classify.h>

/** @file trace_classify.h
 * Use the vpp classifier to decide whether to trace packets
 */

/** @brief vnet_is_packet_traced
 * @param vlib_buffer_t *b - packet to classify
 * @param int func - 0 => use classifier w/ supplied table index
 * @param u32 classify_table_index - classifier table index
 * @return 0 => no trace, 1 => trace, -1 => error
 */

static inline int
vnet_is_packet_traced_inline (vlib_buffer_t * b,
			      u32 classify_table_index, int func)
{
  vnet_classify_main_t *vcm = &vnet_classify_main;
  vnet_classify_table_t *t;
  vnet_classify_entry_t *e;
  u64 hash;

  /*$$$ add custom classifiers here, if any */
  if (func != 0)
    return -1;

  /* This will happen... */
  if (pool_is_free_index (vcm->tables, classify_table_index))
    return -1;

  /* Get the table */
  t = pool_elt_at_index (vcm->tables, classify_table_index);

  /* Hash the packet */
  hash = vnet_classify_hash_packet (t, vlib_buffer_get_current (b));

  /* See if there's a matching entry */
  e = vnet_classify_find_entry (t, vlib_buffer_get_current (b), hash,
				0 /* time = 0, disables hit-counter */ );
  /* Hit means trace the packet... */
  if (e)
    {
      /* Manual hit accounting */
      e->hits++;
      return 1;
    }

  /*
   * Look for a hit in a less-specific table.
   * Performance hint: for this use-case, don't go there.
   */
  while (1)
    {
      /* Most likely, we're done right now */
      if (PREDICT_TRUE (t->next_table_index == ~0))
	return 0;
      t = pool_elt_at_index (vcm->tables, t->next_table_index);

      /* Compute hash for this table */
      hash = vnet_classify_hash_packet (t, vlib_buffer_get_current (b));

      /* See if there's a matching entry */
      e = vnet_classify_find_entry (t, vlib_buffer_get_current (b), hash,
				    0 /* time = 0, disables hit-counter */ );
      if (e)
	{
	  /* Manual hit accounting */
	  e->hits++;
	  return 1;
	}
    }
  /* NOTREACHED */
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
