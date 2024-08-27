/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_BUS_PLATFORM_H_
#define _VNET_DEV_BUS_PLATFORM_H_

#include <vppinfra/clib.h>
#include <vppinfra/devicetree.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>

#define PLATFORM_BUS_NAME "platform"

extern clib_dt_main_t vnet_dev_bus_platform_dt_main;

typedef struct
{
  clib_dt_node_t *node;
} vnet_dev_bus_platform_device_info_t;

typedef struct
{
  clib_dt_node_t *node;
} vnet_dev_bus_platform_device_data_t;

#endif /* _VNET_DEV_BUS_PLATFORM_H_ */
