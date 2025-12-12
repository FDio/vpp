/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2013 Cisco and/or its affiliates.
 */

/* l2_input_vtr.h : layer 2 input vlan tag rewrite processing */

#ifndef included_vnet_l2_input_vtr_h
#define included_vnet_l2_input_vtr_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_vtr.h>


typedef struct
{

  /*
   *  The input vtr data is located in l2_output_config_t because
   * the same config data is used for the egress EFP Filter check.
   */

  /* Next nodes for each feature */
  u32 feat_next_node_index[32];

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2_invtr_main_t;

extern l2_invtr_main_t l2_invtr_main;

#endif /* included_vnet_l2_input_vtr_h */
