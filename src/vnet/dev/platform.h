/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_DEVICETREE_H_
#define _VNET_DEV_DEVICETREE_H_

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>

#define PLATFORM_BUS_NAME "platform"

typedef struct
{
  char name[32];
  u32 size;
  u8 data[];
} vnet_dev_dt_property_t;

typedef struct vnet_bus_dt_node
{
  u8 *path;
  struct vnet_bus_dt_node *parent;
  struct vnet_bus_dt_node *prev;
  struct vnet_bus_dt_node *next;
  struct vnet_bus_dt_node **child_nodes;
  u8 depth;
  vnet_dev_dt_property_t *name;
  vnet_dev_dt_property_t *phandle;
  vnet_dev_dt_property_t **properties;
} vnet_dev_dt_node_t;

typedef struct
{
  vnet_dev_dt_node_t **nodes;
  vnet_dev_dt_node_t *root;
} vnet_dev_dt_main_t;

extern vnet_dev_dt_main_t vnet_dev_dt_main;

typedef struct
{
  vnet_dev_dt_node_t *node;
} vnet_dev_bus_platform_device_info_t;

typedef struct
{
  vnet_dev_dt_node_t *node;
} vnet_dev_bus_platform_device_data_t;

format_function_t format_vnet_dev_dt_desc;
format_function_t format_vnet_dev_dt_property_data;

#endif /* _VNET_DEV_DEVICETREE_H_ */
