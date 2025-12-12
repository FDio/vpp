/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

void ip4_local_full_reass_enable_disable (int enable);
int ip4_local_full_reass_enabled ();
#endif /* __included_ip4_full_reass_h__ */
