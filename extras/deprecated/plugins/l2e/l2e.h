/*
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#ifndef included_vnet_l2_emulation_h
#define included_vnet_l2_emulation_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>

/**
 * Per-interface L2 configuration
 */
typedef struct l2_emulation_t_
{
  /**
   * Enabled or Disabled.
   *  this is required since one L3 protocl can be enabled, but others not
   */
  u8 enabled;
} l2_emulation_t;

/**
 * per-packet trace data
 */
typedef struct l2_emulation_trace_t_
{
  /* per-pkt trace data */
  u8 extracted;
} l2_emulation_trace_t;

/**
 * Grouping of global data for the L2 emulation feature
 */
typedef struct l2_emulation_main_t_
{
  u16 msg_id_base;

  u32 l2_emulation_node_index;

  /**
   * Per-interface vector of emulation configs
   */
  l2_emulation_t *l2_emulations;

  /**
   * Next nodes for L2 output features
   */
  u32 l2_input_feat_next[32];
} l2_emulation_main_t;

/**
 * L2 Emulation is a feautre that is applied to L2 ports to 'extract'
 * IP packets from the L2 path and inject them into the L3 path (i.e.
 * into the appropriate ip[4|6]_input node).
 * L3 routes in the table_id for that interface should then be configured
 * as DVR routes, therefore the forwarded packet has the L2 header
 * preserved and togehter the L3 routed system behaves like an L2 bridge.
 */
extern void l2_emulation_enable (u32 sw_if_index);
extern void l2_emulation_disable (u32 sw_if_index);

extern l2_emulation_main_t l2_emulation_main;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
