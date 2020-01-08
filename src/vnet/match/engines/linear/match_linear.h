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

#ifndef _MATCH_ENGINE_LINEAR_H__
#define _MATCH_ENGINE_LINEAR_H__

#include <vnet/match/match_set.h>
#include <vnet/classify/vnet_classify.h>


typedef struct match_engine_linear_set_t_
{
  index_t mels_set[MATCH_BOTH];
  match_set_app_t mels_app[MATCH_BOTH];
  match_result_t mels_res;
} match_engine_linear_set_t;

/**
 * Engine Context.
 *  Per-set data that this linear engine stores
 */
typedef struct match_engine_linear_t_
{
  index_t mel_set;
  match_set_tag_flags_t mel_flags;

  match_engine_linear_set_t *mel_sets;

  match_list_t mel_list;
} match_engine_linear_t;

extern match_engine_linear_t *match_engine_linear_pool;

/**
 * data cached during the data-plane search
 */
typedef struct match_engine_linear_per_thread_t_
{
  match_result_t *melptd_res[MATCH_BOTH];
  bool *melptd_match[MATCH_BOTH];
  clib_bitmap_t *melptd_bitmap[MATCH_BOTH];
} match_engine_linear_per_thread_t;

extern match_engine_linear_per_thread_t *match_engine_linear_per_thread;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
