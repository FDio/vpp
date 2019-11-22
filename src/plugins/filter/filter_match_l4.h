/*
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

#ifndef __FILTER_MATCH_L4_H__
#define __FILTER_MATCH_L4_H__

#include <filter/filter_match.h>

#include <vnet/ip/ip.h>

/**
 * Match packets based on IP address
 */
typedef struct filter_match_l4_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * Base class first
   */
  filter_match_t fml_base;

  /**
   * src or dst IP
   */
  filter_match_dir_t fml_dir;

  /**
   * port to match
   */
  u16 fml_port;
  ip_protocol_t fml_iproto;

  /**
   * locks.
   */
  u32 fml_locks;
} filter_match_l4_t;

STATIC_ASSERT (sizeof (filter_match_l4_t) <= CLIB_CACHE_LINE_BYTES,
	       "Match L4 not in a cache line");

extern int filter_match_l4_add_and_lock (dpo_proto_t proto,
					 filter_match_dir_t dir,
					 ip_protocol_t ip_proto,
					 u16 port, dpo_id_t * dpo);

/**
 * Callback function invoked during a walk of all matches
 */
typedef int (*filter_match_l4_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the FILTER policies
 */
extern void filter_match_l4_walk (filter_match_walk_cb_t cb, void *ctx);


/**
 * Exposed DP types and function
 */
extern filter_match_l4_t *filter_match_l4_pool;

static inline filter_match_l4_t *
filter_match_l4_get (index_t fmli)
{
  return (pool_elt_at_index (filter_match_l4_pool, fmli));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
