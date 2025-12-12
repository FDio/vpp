/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2013 Cisco and/or its affiliates.
 */

/* l2_fwd.c : layer 2 forwarding using l2fib */

#ifndef included_l2fwd_h
#define included_l2fwd_h

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>


void
l2fwd_register_input_type (vlib_main_t * vm,
			   ethernet_type_t type, u32 node_index);
#endif
