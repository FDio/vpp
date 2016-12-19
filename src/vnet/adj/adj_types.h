/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef __ADJ_TYPES_H__
#define __ADJ_TYPES_H__

#include <vnet/vnet.h>

/**
 * @brief An index for adjacencies.
 * Alas 'C' is not typesafe enough to b0rk when a u32 is used instead of
 * an adi_index_t. However, for us humans, we can glean much more intent
 * from the declaration
 *  foo bar(adj_index_t t);
 * than we can from
 *  foo bar(u32 t);
 */
typedef u32 adj_index_t; 

/**
 * @brief Invalid ADJ index - used when no adj is known
 * likewise blazoned capitals INVALID speak volumes where ~0 does not.
 */
#define ADJ_INDEX_INVALID ((u32)~0)

/**
 * @brief return codes from a adjacency walker callback function
 */
typedef enum adj_walk_rc_t_
{
    ADJ_WALK_RC_STOP,
    ADJ_WALK_RC_CONTINUE,
} adj_walk_rc_t;

/**
 * @brief Call back function when walking adjacencies
 */
typedef adj_walk_rc_t (*adj_walk_cb_t)(adj_index_t ai,
				       void *ctx);

#endif
