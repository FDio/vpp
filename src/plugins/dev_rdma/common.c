/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <dev_rdma/bus.h>

#include <infiniband/verbs.h>

u32
rdma_port_speed (u8 speed)
{
  u32 speeds[] = {
    [1] = 2500000,   [2] = 5000000,   [4] = 10000000,  [8] = 10000000,
    [16] = 14000000, [32] = 25000000, [64] = 50000000, [128] = 100000000,
  };

  if (speed > ARRAY_LEN (speeds))
    return 0;
  return speeds[speed];
}

u16
rdma_port_mtu (u8 mtu)
{
  u16 mtus[] = {
    [IBV_MTU_256] = 256,   [IBV_MTU_512] = 512,	  [IBV_MTU_1024] = 1024,
    [IBV_MTU_2048] = 2048, [IBV_MTU_4096] = 4096,
  };

  if (mtu > ARRAY_LEN (mtus))
    return 0;
  return mtus[mtu];
}
