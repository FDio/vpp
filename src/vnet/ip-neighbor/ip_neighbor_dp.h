/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/* ip_neighboor.h: ip neighbor generic services */

#ifndef __INCLUDE_IP_NEIGHBOR_DP_H__
#define __INCLUDE_IP_NEIGHBOR_DP_H__

#include <vnet/ip-neighbor/ip_neighbor_types.h>

/**
 * APIs invoked by neighbor implementation (i.s. ARP and ND) that can be
 * called from the DP when the protocol has resolved a neighbor
 */

extern void ip_neighbor_learn_dp (const ip_neighbor_learn_t * l);

#endif /* __INCLUDE_IP_NEIGHBOR_H__ */
