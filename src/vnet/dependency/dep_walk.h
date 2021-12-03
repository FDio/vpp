/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Copyright (c) 2021 Graphiant  and/or its affiliates.
 *
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

#ifndef __DEP_WALK_H__
#define __DEP_WALK_H__

#include <vnet/dependency/dep.h>

/**
 * @brief Walk priorities.
 * Strict priorities. All walks a priority n are completed before n+1 is
 * started. Increasing numerical value implies decreasing priority.
 */
#define foreach_dep_walk_priority                                             \
  _ (HIGH, "high")                                                            \
  _ (LOW, "low")

typedef enum dep_walk_priority_t_
{
#define _(a, b) DEP_WALK_PRIORITY_##a,
  foreach_dep_walk_priority
#undef _
} dep_walk_priority_t;

#define DEP_WALK_PRIORITY_NUM                                                 \
  ((dep_walk_priority_t) (DEP_WALK_PRIORITY_LOW + 1))

extern u8 *format_dep_walk_priority (u8 *s, va_list *ap);

#define FOR_EACH_DEP_WALK_PRIORITY(_prio)                                     \
  for ((_prio) = DEP_WALK_PRIORITY_HIGH; (_prio) < DEP_WALK_PRIORITY_NUM;     \
       (_prio)++)

extern void dep_walk_async (dep_type_t parent_type, dep_index_t parent_index,
			    dep_walk_priority_t prio,
			    dep_back_walk_ctx_t *ctx);

extern void dep_walk_sync (dep_type_t parent_type, dep_index_t parent_index,
			   dep_back_walk_ctx_t *ctx);

extern u8 *format_dep_walk_priority (u8 *s, va_list *ap);

extern void dep_walk_process_enable (void);
extern void dep_walk_process_disable (void);

#endif
