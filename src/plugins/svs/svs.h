/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/**
 * Source VRF Selection matches against a packet's source address to set
 * the VRF in which the subsequnet destination IP address lookup is done.
 * If no match for the source address is found, then the RX interface's
 * table/VRF is used.
 */
#ifndef __SVS_H__
#define __SVS_H__

#include <vnet/fib/fib_types.h>

#define SVS_PLUGIN_VERSION_MAJOR 1
#define SVS_PLUGIN_VERSION_MINOR 0

extern int svs_table_add (fib_protocol_t fproto, u32 table_id);
extern int svs_table_delete (fib_protocol_t fproto, u32 table_id);

extern int svs_route_add (u32 table_id,
			  const fib_prefix_t * pfx, u32 source_table_id);
extern int svs_route_delete (u32 table_id, const fib_prefix_t * pfx);

extern int svs_enable (fib_protocol_t fproto, u32 table_id, u32 sw_if_index);
extern int svs_disable (fib_protocol_t fproto, u32 table_id, u32 sw_if_index);

typedef walk_rc_t (*svs_walk_fn_t) (fib_protocol_t fproto, u32 table_id,
				    u32 sw_if_index, void *ctx);

extern void svs_walk (svs_walk_fn_t fn, void *ctx);
#endif
