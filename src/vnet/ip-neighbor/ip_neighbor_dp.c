/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/* ip_neighboor.h: ip neighbor generic services */

#include <vlibmemory/api.h>

#include <vnet/ip-neighbor/ip_neighbor_dp.h>
#include <vnet/ip-neighbor/ip_neighbor.h>

/**
 * APIs invoked by neighbor implementation (i.s. ARP and ND) that can be
 * called from the DP when the protocol has resolved a neighbor
 */
void
ip_neighbor_learn_dp (const ip_neighbor_learn_t * l)
{
  vlib_rpc_call_main_thread (ip_neighbor_learn, (u8 *) l, sizeof (*l));
}
