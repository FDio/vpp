/*
 * l2_learn.c : layer 2 learning using l2fib
 *
 * Copyright (c) 2014 Cisco and/or its affiliates.
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

#ifndef included_l2learn_h
#define included_l2learn_h

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>


typedef struct
{

  /* Hash table */
  BVT (clib_bihash) * mac_table;

  /* number of dynamically learned mac entries */
  u32 global_learn_count;

  /* maximum number of dynamically learned mac entries */
  u32 global_learn_limit;

  /* client waiting for L2 MAC events for learned and aged MACs */
  u32 client_pid;
  u32 client_index;

  /* Next nodes for each feature */
  u32 feat_next_node_index[32];

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2learn_main_t;

#define L2LEARN_DEFAULT_LIMIT (L2FIB_NUM_BUCKETS * 64)

extern l2learn_main_t l2learn_main;

extern vlib_node_registration_t l2fib_mac_age_scanner_process_node;

enum
{
  L2_MAC_AGE_PROCESS_EVENT_START = 1,
  L2_MAC_AGE_PROCESS_EVENT_STOP = 2,
  L2_MAC_AGE_PROCESS_EVENT_ONE_PASS = 3,
} l2_mac_age_process_event_t;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
