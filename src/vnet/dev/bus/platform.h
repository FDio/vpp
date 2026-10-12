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

typedef struct
{
  clib_dt_node_t *node;
  vnet_dev_bus_platform_mapping_t *mappings;
  int kdi_fd;
} vnet_dev_bus_platform_device_data_t;

typedef enum
{
  VNET_DEV_PLATFORM_RESOURCE_CLOCK,
  VNET_DEV_PLATFORM_RESOURCE_RESET,
  VNET_DEV_PLATFORM_RESOURCE_INTERCONNECT,
  VNET_DEV_PLATFORM_RESOURCE_PHY,
} vnet_dev_platform_resource_type_t;

typedef struct
{
  int fd;
  char name[VNET_DEV_PLATFORM_RESOURCE_NAME_LEN];
} vnet_dev_platform_clock_t;

typedef struct
{
  int fd;
  char name[VNET_DEV_PLATFORM_RESOURCE_NAME_LEN];
} vnet_dev_platform_reset_t;

typedef struct
{
  int fd;
  char name[VNET_DEV_PLATFORM_RESOURCE_NAME_LEN];
} vnet_dev_platform_interconnect_t;

typedef struct
{
  int fd;
  char name[VNET_DEV_PLATFORM_RESOURCE_NAME_LEN];
} vnet_dev_platform_phy_t;

__clib_export vnet_dev_rv_t vnet_dev_platform_map_uio_region (vnet_dev_t *, char *, void **);
__clib_export void vnet_dev_platform_unmap_regions (vnet_dev_t *);
__clib_export int vnet_dev_platform_resource_open (vnet_dev_t *, vnet_dev_platform_resource_type_t,
						   char *);
__clib_export int vnet_dev_platform_resource_open_on_node (vnet_dev_t *,
							   vnet_dev_platform_resource_type_t,
							   char *, char *);
__clib_export void vnet_dev_platform_resource_close_fd (int);
__clib_export void vnet_dev_platform_resource_close (vnet_dev_t *);
__clib_export int vnet_dev_platform_clock_enable (int);
__clib_export int vnet_dev_platform_clock_disable (int);
__clib_export int vnet_dev_platform_clock_set_rate (int, u64);
__clib_export int vnet_dev_platform_reset_assert (int);
__clib_export int vnet_dev_platform_reset_deassert (int);
__clib_export int vnet_dev_platform_reset_pulse (int);
__clib_export int vnet_dev_platform_interconnect_set_bw (int, u64, u64);
__clib_export int vnet_dev_platform_phy_power_on (int);
__clib_export int vnet_dev_platform_phy_power_off (int);

#endif /* _VNET_DEV_BUS_PLATFORM_H_ */
