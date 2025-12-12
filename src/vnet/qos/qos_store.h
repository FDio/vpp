/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef __QOS_STORE_H__
#define __QOS_STORE_H__

#include <vnet/qos/qos_types.h>
#include <vnet/ip/ip_packet.h>

extern int qos_store_disable (u32 sw_if_index, qos_source_t input_source);
extern int qos_store_enable (u32 sw_if_index,
			     qos_source_t input_source, qos_bits_t value);

typedef walk_rc_t (*qos_store_walk_cb_t) (u32 sw_if_index,
					  qos_source_t input_source,
					  qos_bits_t value, void *ctx);
void qos_store_walk (qos_store_walk_cb_t fn, void *c);

#endif
