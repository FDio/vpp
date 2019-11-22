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

#ifndef __FILTER_MATCH_H__
#define __FILTER_MATCH_H__

#include <filter/filter_types.h>

#define foreach_filter_match_dir \
  _(SRC, "src")                  \
  _(DST, "dst")

/**
 * Generic direction for packets
 */
typedef enum filter_match_dir_t_
{
#define _(s,v) FILTER_MATCH_##s,
  foreach_filter_match_dir
#undef _
} filter_match_dir_t;

extern u8 *format_filter_match_dir (u8 * s, va_list * args);
extern uword unformat_filter_match_dir (unformat_input_t * input,
					va_list * args);

#define foreach_filter_match_res \
  _(YES, "matched")                  \
  _(NO, "unmatched")

#define FILTER_MATCH_N_RES (FILTER_MATCH_NO+1)

/**
 * Generic resection for packets
 */
typedef enum filter_match_res_t_
{
#define _(s,v) FILTER_MATCH_##s,
  foreach_filter_match_res
#undef _
} filter_match_res_t;

extern u8 *format_filter_match_res (u8 * s, va_list * args);

/**
 * Base class for all match objects
 */
typedef struct filter_match_t_
{
  /**
   * did match branch
   */
  dpo_id_t fm_results[FILTER_MATCH_N_RES];

  /**
   * a descrption of this object
   */
  dpo_id_t fm_base;

  /**
   * The index of the rule for which this object is matching
   */
  index_t fm_rule;
} filter_match_t;

extern u8 *format_filter_match (u8 * s, va_list * args);
extern uword unformat_filter_match (unformat_input_t * input, va_list * args);

extern void filter_match_unstack (dpo_id_t * match);
extern void filter_match_stack (dpo_id_t * match,
				index_t rule,
				const dpo_id_t * pos, const dpo_id_t * neg);

/**
 * Virtual function table for a match object
 */
typedef filter_match_t *(*filter_match_base_get) (const dpo_id_t * dpo);

typedef struct filter_match_vft_t
{
  filter_match_base_get fmv_get_base;
  unformat_function_t *fmv_unformat;
} filter_match_vft_t;

extern void filter_match_register (dpo_type_t type,
				   const filter_match_vft_t * vft);

/**
 * Callback function invoked during a walk of all matches
 */
typedef int (*filter_match_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the FILTER policies
 */
extern void filter_match_walk (filter_match_walk_cb_t cb, void *ctx);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
