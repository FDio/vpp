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
 * @brief IPv4 shallow virtual reassembly.
 *
 * This file contains the source code for IPv4 shallow virtual reassembly.
 */

#ifndef __included_ip4_sv_reass_h__
#define __included_ip4_sv_reass_h__

#include <stdbool.h>
#include <vnet/api_errno.h>
#include <vnet/vnet.h>

/**
 * @brief set ip4 reassembly configuration
 */
vnet_api_error_t ip4_sv_reass_set (u32 timeout_ms, u32 max_reassemblies,
				   u32 max_reassembly_length,
				   u32 expire_walk_interval_ms);

/**
 * @brief get ip4 reassembly configuration
 */
vnet_api_error_t ip4_sv_reass_get (u32 * timeout_ms, u32 * max_reassemblies,
				   u32 * max_reassembly_length,
				   u32 * expire_walk_interval_ms);

vnet_api_error_t ip4_sv_reass_enable_disable (u32 sw_if_index,
					      u8 enable_disable);


int ip4_sv_reass_enable_disable_with_refcnt (u32 sw_if_index, int is_enable);
int ip4_sv_reass_output_enable_disable_with_refcnt (u32 sw_if_index,
						    int is_enable);

/*
 * Enable or disable extended reassembly.
 *
 * Extended reassembly means that fragments are cached until both first and
 * last fragments are seen. Furthermore, first fragment buffer will be cloned
 * and stored in reassembly context for later retrieval.
 */
void ip4_sv_reass_enable_disable_extended (bool is_enable);

struct ip4_sv_lock_unlock_args
{
  u32 *total_ip_payload_length;
  u32 *first_fragment_buffer_index;
  u32 *first_fragment_total_ip_header_length;
};

/*
 * Lock thread-level lock and fetch information from reassembly context.
 * Uses vnet_buffer2 data filled by extended reassembly.
 *
 * Returns 0 on success, -1 otherwise.
 */
int ip4_sv_reass_extended_lock (vlib_buffer_t *b,
				struct ip4_sv_lock_unlock_args *a);

void ip4_sv_reass_extended_unlock (vlib_buffer_t *b);

uword ip4_sv_reass_custom_register_next_node (uword node_index);
uword ip4_sv_reass_custom_context_register_next_node (uword node_index);

#endif /* __included_ip4_sv_reass_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
