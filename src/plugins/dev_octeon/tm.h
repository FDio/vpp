/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef _OCT_TM_H_
#define _OCT_TM_H_

#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/tm/tm.h>

#define NIX_TM_DFLT_RR_WT   71
#define OCT_TM_NODE_ID_NULL -1
#define OCT_TM_INVALID	    0

/* Internal mapping of flow_id to tm_node_id */
extern uword *flow_id_to_tm_node_id_hash;

void add_flow_id_to_tm_node_id_mapping (u32 flow_id, u32 tm_node_id);
u32 get_tm_node_id_from_flow_id (u32 flow_id);

#endif /* _OCT_TM_H_ */
