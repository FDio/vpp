/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _DEV_RDMA_COMMON_H_
#define _DEV_RDMA_COMMON_H_

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <infiniband/verbs.h>

u32 rdma_port_speed (u8 speed);
u16 rdma_port_mtu (u8 mtu);

#endif /* _DEV_RDMA_COMMON_H_ */
