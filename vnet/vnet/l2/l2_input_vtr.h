/*
 * l2_input_vtr.h : layer 2 input vlan tag rewrite processing
 *
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


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
