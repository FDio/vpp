/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __portmirroring_h__
#define __portmirroring_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

enum {
    PM_FROM_CLASSSIFIER = 0,
    PM_FROM_FLOWTABLE = 1,
    PM_FROM_MAX
};

typedef enum {
    PM_IN_HIT_NEXT_ERROR,
    PM_IN_HIT_NEXT_ETHERNET_INPUT,
    PM_IN_HIT_NEXT_L2_LEARN,
    PM_IN_HIT_N_NEXT,
} pm_in_hit_next_t;

typedef struct
{
  /* mirror interface index */
  u32 sw_if_index;
  u32 from_node;

  /* Hit node index */
  u32 pm_in_hit_node_index;
  u32 pm_out_hit_node_index;

  u32 interface_output_node_index;

  /* depends on the previous node */
  u32 next_node_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /**
   * API dynamically registered base ID.
   */
  u16 msg_id_base;
} pm_main_t;

pm_main_t pm_main;

int pm_conf(u8 dst_interface, u8 from_node, u8 is_del);

extern vlib_node_registration_t pm_in_hit_node;
extern vlib_node_registration_t pm_out_hit_node;

#endif /* __portmirroring_h__ */
