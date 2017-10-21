/*
 * l2_l3_extract.h : Extract L3 packets from the L2 input and feed
 *                   them into the L3 path.
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

#ifndef included_vnet_l2_l3_extract_h
#define included_vnet_l2_l3_extract_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_types.h>

/**
 * Configure l3 extraction
 */
extern void l2_l3_extract_enable (fib_protocol_t l3_proto,
				  u32 sw_if_index,
				  u8 include_multicast, u8 include_broadcast);
extern void l2_l3_extract_disable (fib_protocol_t l3_proto,
				   u32 sw_if_index,
				   u8 include_multicast,
				   u8 include_broadcast);

#endif


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
