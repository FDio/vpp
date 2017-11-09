/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __L3_SPAN_DPO_H__
#define __L3_SPAN_DPO_H__

#include <vnet/vnet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_types.h>

/**
 * Flags on the L3 Span DPO
 */
typedef enum l3_span_dpo_flags_t_
{
  L3_SPAN_DPO_FLAG_CLONE = (1 << 0),
} l3_span_dpo_flags_t;

/**
 * A representation of an L3 span in the data-path
 */
typedef struct l3_span_dpo_t
{
  /**
   * The index from which this DPO was cloned. ~0 if not a clone.
   */
  index_t l3sd_orig;

  /**
   * The replicate object built to perform the replication.
   * On the clones the first bucket[s] will be the span collector[s]
   * and the last bucket the DPO FIB provides.
   * On the original this is the replicate DPO the path-list of
   * span-collectros has contributed.
   */
  dpo_id_t l3sd_dpo;

  /**
   * Number of locks/users of the label
   */
  u16 l3sd_locks;

  /**
   * Flags on this span object
   */
  l3_span_dpo_flags_t l3sd_flags;
} l3_span_dpo_t;

/**
 * @brief Assert that the L3 span is less than a cache line in size.
 */
STATIC_ASSERT ((sizeof (l3_span_dpo_t) <= CLIB_CACHE_LINE_BYTES),
	       "L3 span label DPO is larger than one cache line.");

/**
 * @brief Create and lock an L3 Span DPO
 */
extern void l3_span_dpo_create_and_lock (dpo_proto_t payload_proto,
					 fib_node_index_t pl,
					 index_t counter, dpo_id_t * dpo);
extern void l3_span_dpo_update (index_t l3sdi, fib_node_index_t pl);
extern void l3_span_dpo_unlock (index_t l3sd);
extern u8 *format_l3_span_dpo (u8 * s, va_list * args);

extern void l3_span_dpo_module_init (void);

/*
 * Encapsulation violation for fast data-path access
 */
extern l3_span_dpo_t *l3_span_dpo_pool;

static inline l3_span_dpo_t *
l3_span_dpo_get (index_t index)
{
  return (pool_elt_at_index (l3_span_dpo_pool, index));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
