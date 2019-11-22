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

#ifndef __FILTER_TARGET_H__
#define __FILTER_TARGET_H__

#include <filter/filter_types.h>

/**
 * Base class for all target objects
 */
typedef struct filter_target_t_
{
} filter_target_t;

extern u8 *format_filter_target (u8 * s, va_list * args);
extern uword unformat_filter_target (unformat_input_t * input,
				     va_list * args);
extern void filter_target_rule_update (const dpo_id_t * ftg, index_t rule);

typedef void (*filter_target_rule_update_t) (const dpo_id_t * ftg,
					     index_t rule);

typedef struct filter_target_vft_t
{
  unformat_function_t *ftv_unformat;
  filter_target_rule_update_t ftv_rule_update;
} filter_target_vft_t;

extern void filter_target_register (dpo_type_t type,
				    const filter_target_vft_t * vft);

/**
 * Callback function invoked during a walk of all targetes
 */
typedef walk_rc_t (*filter_target_walk_cb_t) (index_t index, void *ctx);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
