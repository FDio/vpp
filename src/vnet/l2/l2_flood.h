/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2013 Cisco and/or its affiliates.
 */

/* l2_flood.h : layer 2 flooding */

#ifndef included_l2flood_h
#define included_l2flood_h

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>

void
l2flood_register_input_type (vlib_main_t * vm,
			     ethernet_type_t type, u32 node_index);
#endif
