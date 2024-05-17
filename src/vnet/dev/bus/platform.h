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
  vnet_dev_dt_property_t **properties;
} vnet_dev_dt_node_t;

typedef struct
{
  vnet_dev_dt_node_t **nodes;
  vnet_dev_dt_node_t *root;
  uword *node_by_path;
  uword *node_by_phandle;
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

vnet_dev_dt_property_t *
vnet_dev_dt_get_node_property_by_name (vnet_dev_dt_node_t *, char *);
int vnet_dev_dt_node_is_compatible (vnet_dev_dt_node_t *, char *);
vnet_dev_dt_node_t * vnet_dev_dt_deref_node (vnet_dev_dt_node_t *, char *);

format_function_t format_vnet_dev_dt_desc;
format_function_t format_vnet_dev_dt_property_data;

static_always_inline int
vnet_dev_dt_proprerty_is_u32 (vnet_dev_dt_property_t *p)
{
  if (p == 0 || p->size != 4)
    return 0;
  return 1;
}

static_always_inline u32
vnet_dev_dt_proprerty_get_u32 (vnet_dev_dt_property_t *p)
{
  return clib_net_to_host_u32 (*(u32u *) p->data);
}

#endif /* _VNET_DEV_DEVICETREE_H_ */
