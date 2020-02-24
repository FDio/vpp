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

#ifndef __MATCH_SET_DP_H__
#define __MATCH_SET_DP_H__

#include <vnet/match/match_set.h>

extern match_set_t *match_set_pool;
extern match_set_entry_t *match_set_entry_pool;

static_always_inline index_t
match_set_get_index (const match_set_t * ms)
{
  return (ms - match_set_pool);
}

static_always_inline match_set_t *
match_set_get (index_t msi)
{
  return (pool_elt_at_index (match_set_pool, msi));
}

static_always_inline match_set_entry_t *
match_set_entry_get (index_t msei)
{
  return (pool_elt_at_index (match_set_entry_pool, msei));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
