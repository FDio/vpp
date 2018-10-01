/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
