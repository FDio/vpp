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
#ifndef __included_stat_client_h__
#define __included_stat_client_h__

#include <vlib/vlib.h>
#include <vppinfra/socket.h>
#include <svm/ssvm.h>
#include <vpp/stats/stats.h>

typedef struct
{
  u64 current_epoch;

  /* Cached pointers to scalar quantities, these wont change */
  f64 *vector_rate_ptr;
  f64 *input_rate_ptr;
  f64 *last_runtime_ptr;
  f64 *last_runtime_stats_clear_ptr;

  volatile int segment_ready;

  /*
   * Cached pointers to vector quantities,
   * MUST invalidate when the epoch changes
   */
  vlib_counter_t **intfc_rx_counters;
  vlib_counter_t **intfc_tx_counters;
  u8 *serialized_nodes;

  u64 *thread_0_error_counts;
  u64 source_address_match_error_index;

  /* mapped stats segment object */
  ssvm_private_t stat_segment;

  /* Spinlock for the stats segment */
  clib_spinlock_t *stat_segment_lockp;

  u8 *socket_name;
} stat_client_main_t;

extern stat_client_main_t stat_client_main;

#endif /* __included_stat_client_h__ */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
