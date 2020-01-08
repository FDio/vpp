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

#ifndef _MATCH_ENGINE_HASH_H__
#define _MATCH_ENGINE_HASH_H__

#include <vnet/match/match_set.h>

/**
 * Engine Context.
 *  Per-set data that this hash engine stores
 */
typedef struct match_engine_hash_t_
{
  index_t mel_set;
  match_set_tag_flags_t mel_flags;

  uword *meh_hash;
} match_engine_hash_t;

extern match_engine_hash_t *match_engine_hash_pool;

/**
 * The types of tuples to match on
 *  - this is in sorted order of 'difficulty'
 */
#define foreach_match_hash_type                  \
  _(EXACT_IP,         "exact-ip")                \
  _(EXACT_IP_L4,      "exact-ip-l4")             \

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
