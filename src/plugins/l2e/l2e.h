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
 * L2 Emulation is a feautre that is applied to L2 ports to 'extract'
 * IP packets from the L2 path and inject them into the L3 path (i.e.
 * into the appropriate ip[4|6]_input node).
 * L3 routes in the table_id for that interface should then be configured
 * as DVR routes, therefore the forwarded packet has the L2 header
 * preserved and togehter the L3 routed system behaves like an L2 bridge.
 */
extern void l2_emulation_enable (u32 sw_if_index);
extern void l2_emulation_disable (u32 sw_if_index);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
