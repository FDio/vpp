/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

/**
 * @file
 * @brief IPv4 Reassembly.
 *
 * This file contains the source code for IPv4 reassembly.
 */

#ifndef __included_ip4_full_reass_h__
#define __included_ip4_full_reass_h__

#include <vnet/api_errno.h>
#include <vnet/vnet.h>

/**
 * @brief set ip4 reassembly configuration
 */
vnet_api_error_t ip4_full_reass_set (u32 timeout_ms, u32 max_reassemblies,
				     u32 max_reassembly_length,
				     u32 expire_walk_interval_ms);

/**
 * @brief get ip4 reassembly configuration
 */
vnet_api_error_t ip4_full_reass_get (u32 * timeout_ms, u32 * max_reassemblies,
				     u32 * max_reassembly_length,
				     u32 * expire_walk_interval_ms);

vnet_api_error_t ip4_full_reass_enable_disable (u32 sw_if_index,
						u8 enable_disable);

int ip4_full_reass_enable_disable_with_refcnt (u32 sw_if_index,
					       int is_enable);

uword ip4_full_reass_custom_register_next_node (uword node_index);
#endif /* __included_ip4_full_reass_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
