/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2014 Cisco and/or its affiliates.
 */

/* l2_learn.c : layer 2 learning using l2fib */

#ifndef included_l2learn_h
#define included_l2learn_h

#include <vlib/vlib.h>
#include <vppinfra/bihash_8_8.h>
#include <vnet/ethernet/ethernet.h>


typedef struct
{

  /* Hash table */
  BVT (clib_bihash) * mac_table;

  /* number of dynamically learned mac entries */
  u32 global_learn_count;

  /* maximum number of dynamically learned mac entries */
  u32 global_learn_limit;

  /* maximum number of dynamically learned mac entries per bridge domain */
  u32 bd_default_learn_limit;

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

typedef enum
{
  L2_MAC_AGE_PROCESS_EVENT_START = 1,
  L2_MAC_AGE_PROCESS_EVENT_STOP = 2,
  L2_MAC_AGE_PROCESS_EVENT_ONE_PASS = 3,
} l2_mac_age_process_event_t;

#endif
