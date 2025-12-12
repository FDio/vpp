/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#ifndef included_ip_sas_h
#define included_ip_sas_h

#include <stdbool.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip4_packet.h>

bool ip6_sas_by_sw_if_index (u32 sw_if_index, const ip6_address_t *dst,
			     ip6_address_t *src);
bool ip4_sas_by_sw_if_index (u32 sw_if_index, const ip4_address_t *dst,
			     ip4_address_t *src);
bool ip6_sas (u32 table_id, u32 sw_if_index, const ip6_address_t *dst,
	      ip6_address_t *src);
bool ip4_sas (u32 table_id, u32 sw_if_index, const ip4_address_t *dst,
	      ip4_address_t *src);

#endif
