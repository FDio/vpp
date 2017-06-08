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
#ifndef included_vnet_p2p_ethernet_h
#define included_vnet_p2p_ethernet_h

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>

int p2p_ethernet_add_del (vlib_main_t * vm, u32 parent_if_index, u8 * client_mac, int is_add);

#endif /* included_vnet_p2p_ethernet_h */
