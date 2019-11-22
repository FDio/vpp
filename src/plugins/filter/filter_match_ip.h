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

#ifndef __FILTER_MATCH_IP_H__
#define __FILTER_MATCH_IP_H__

#include <filter/filter_match.h>

#include <vnet/ip/ip.h>

/**
 * Match packets based on IP address
 */
typedef struct filter_match_ip_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * Base class first
   */
  filter_match_t fmi_base;

  /**
   * src or dst IP
   */
  filter_match_dir_t fmi_dir;

  /**
   * IP address to match
   */
  ip46_address_t fmi_ip;

  /**
   * locks.
   */
  u32 fmi_locks;
} filter_match_ip_t;

STATIC_ASSERT (sizeof (filter_match_ip_t) <= CLIB_CACHE_LINE_BYTES,
	       "Match IP not in a cache line");

extern int filter_match_ip_add_and_lock (dpo_proto_t proto,
					 filter_match_dir_t dir,
					 const ip46_address_t * ip,
					 dpo_id_t * dpo);

/**
 * Callback function invoked during a walk of all matches
 */
typedef int (*filter_match_ip_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the FILTER policies
 */
extern void filter_match_ip_walk (filter_match_walk_cb_t cb, void *ctx);


/**
 * Exposed DP types and function
 */
extern filter_match_ip_t *filter_match_ip_pool;

static inline filter_match_ip_t *
filter_match_ip_get (index_t fmii)
{
  return (pool_elt_at_index (filter_match_ip_pool, fmii));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
