/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2010 Eliot Dresselhaus
 */

/* l3_types.h: layer 3 packet types */

#ifndef included_vnet_l3_types_h
#define included_vnet_l3_types_h

/* Inherit generic L3 packet types from ethernet. */
typedef enum
{
#define ethernet_type(n,f) VNET_L3_PACKET_TYPE_##f,
#include <vnet/ethernet/types.def>
#undef ethernet_type
} vnet_l3_packet_type_t;

#endif /* included_vnet_l3_types_h */
