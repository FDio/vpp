/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>

#include <infiniband/verbs.h>
#include <common/common.h>

u32
mlx5_port_speed (u8 speed)
{
  return rdma_port_speed (speed);
}

u16
mlx5_port_mtu (u8 mtu)
{
  return rdma_port_mtu (mtu);
}
