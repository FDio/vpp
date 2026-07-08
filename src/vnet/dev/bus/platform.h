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
  void *base;
  uword size;
} vnet_dev_bus_platform_mapping_t;

typedef struct
{
  clib_dt_node_t *node;
  vnet_dev_bus_platform_mapping_t *mappings;
} vnet_dev_bus_platform_device_data_t;

vnet_dev_rv_t vnet_dev_platform_map_uio_region (vnet_dev_t *, char *, void **);
void vnet_dev_platform_unmap_regions (vnet_dev_t *);

#endif /* _VNET_DEV_BUS_PLATFORM_H_ */
