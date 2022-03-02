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

#ifndef included_stat_segment_h
#define included_stat_segment_h

#include <vlib/vlib.h>
#include <vppinfra/socket.h>
#include <vlib/stats/stats.h>

/* clang-format off */
#define foreach_stat_segment_node_counter_name                                \
  _ (NODE_CLOCKS, COUNTER_VECTOR_SIMPLE, clocks, /sys/node)                   \
  _ (NODE_VECTORS, COUNTER_VECTOR_SIMPLE, vectors, /sys/node)                 \
  _ (NODE_CALLS, COUNTER_VECTOR_SIMPLE, calls, /sys/node)                     \
  _ (NODE_SUSPENDS, COUNTER_VECTOR_SIMPLE, suspends, /sys/node)

#define foreach_stat_segment_counter_name                                     \
  _ (NUM_WORKER_THREADS, SCALAR_INDEX, num_worker_threads, /sys)              \
  _ (LAST_STATS_CLEAR, SCALAR_INDEX, last_stats_clear, /sys)                  \
  _ (HEARTBEAT, SCALAR_INDEX, heartbeat, /sys)                                \
  _ (NODE_NAMES, NAME_VECTOR, names, /sys/node)                               \
  foreach_stat_segment_node_counter_name
/* clang-format on */

void vlib_stats_register_update_fn (u32 vector_index,
				    vlib_stats_update_fn update_fn,
				    u32 caller_index);

void vlib_stats_register_mem_heap (clib_mem_heap_t *heap);
void stat_provider_register_vector_rate (u32 num_workers);

#endif
