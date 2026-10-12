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
#define VNET_DEV_PLATFORM_RESOURCE_NAME_LEN 64

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

typedef enum
{
  VNET_DEV_PLATFORM_RESOURCE_CLOCK,
  VNET_DEV_PLATFORM_RESOURCE_RESET,
  VNET_DEV_PLATFORM_RESOURCE_INTERCONNECT,
  VNET_DEV_PLATFORM_RESOURCE_ETHERNET_PHY,
} vnet_dev_platform_resource_type_t;

typedef struct
{
  vnet_dev_platform_resource_type_t type;
  int fd;
  char *node_name;
  char *resource_name;
} vnet_dev_platform_resource_handle_t;

typedef struct
{
  clib_dt_node_t *node;
  vnet_dev_bus_platform_mapping_t *mappings;
  vnet_dev_platform_resource_handle_t *resources;
  int kdi_fd;
} vnet_dev_bus_platform_device_data_t;

typedef struct
{
  u32 link;
  u32 speed_mbps;
  u8 full_duplex : 1;
  u8 autoneg : 1;
} vnet_dev_platform_ethernet_phy_state_t;

__clib_export vnet_dev_rv_t vnet_dev_platform_map_uio_region (vnet_dev_t *, char *, void **);
__clib_export void vnet_dev_platform_unmap_regions (vnet_dev_t *);
__clib_export int vnet_dev_platform_resource_open (vnet_dev_t *, vnet_dev_platform_resource_type_t,
						   char *);
__clib_export int vnet_dev_platform_resource_open_on_node (vnet_dev_t *,
							   vnet_dev_platform_resource_type_t,
							   char *, char *);
__clib_export void vnet_dev_platform_resource_close_fd (int);
__clib_export void vnet_dev_platform_resource_close (vnet_dev_t *);
__clib_export int vnet_dev_platform_clock_enable (vnet_dev_t *, char *, char *);
__clib_export int vnet_dev_platform_clock_disable (vnet_dev_t *, char *, char *);
__clib_export int vnet_dev_platform_clock_set_rate (vnet_dev_t *, char *, char *, u64);
__clib_export int vnet_dev_platform_reset_assert (vnet_dev_t *, char *, char *);
__clib_export int vnet_dev_platform_reset_deassert (vnet_dev_t *, char *, char *);
__clib_export int vnet_dev_platform_reset_pulse (vnet_dev_t *, char *, char *);
__clib_export int vnet_dev_platform_interconnect_set_bw (vnet_dev_t *, char *, char *, u64, u64);
__clib_export int vnet_dev_platform_ethernet_phy_start_aneg (int);
__clib_export int vnet_dev_platform_ethernet_phy_stop (int);
__clib_export int
vnet_dev_platform_ethernet_phy_get_state (int, vnet_dev_platform_ethernet_phy_state_t *);

#endif /* _VNET_DEV_BUS_PLATFORM_H_ */
