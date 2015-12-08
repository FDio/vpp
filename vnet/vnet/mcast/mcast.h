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
#ifndef __included_vnet_mcast_h__
#define __included_vnet_mcast_h__

#include <vnet/vnet.h>
#include <vlib/buffer.h>
#include <vlib/buffer_funcs.h>

typedef struct {
  /* Arrange for both prep and recycle nodes to have identical
     next indices for a given output interface */
  u32 prep_and_recycle_node_next_index;

  /* Show command, etc. */
  u32 tx_sw_if_index;
} mcast_group_member_t;

typedef struct {
  /* vector of group members */
  mcast_group_member_t * members;
} mcast_group_t;

typedef struct {
  /* pool of multicast (interface) groups */
  mcast_group_t * groups;

  /* multicast "free" list, aka recycle list */
  u32 mcast_recycle_list_index;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} mcast_main_t;

mcast_main_t mcast_main;

#endif /* __included_vnet_mcast_h__ */
