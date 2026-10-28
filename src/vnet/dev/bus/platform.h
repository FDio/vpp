/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
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
  VNET_DEV_PLATFORM_RESOURCE_CLOCK_PROVIDER,
} vnet_dev_platform_resource_type_t;

/* A clock-provider resource registers kdi as the Linux clk-framework
 * provider for some other device_node's #clock-cells outputs, and lets
 * this process answer the prepare/unprepare/set_rate calls kernel
 * consumers make against it. See kdi's KDI_RESOURCE_CLOCK_PROVIDER. */
typedef enum
{
  VNET_DEV_PLATFORM_CLOCK_PROVIDER_OP_PREPARE,
  VNET_DEV_PLATFORM_CLOCK_PROVIDER_OP_UNPREPARE,
  VNET_DEV_PLATFORM_CLOCK_PROVIDER_OP_SET_RATE,
} vnet_dev_platform_clock_provider_op_t;

typedef struct
{
  u32 index;
  vnet_dev_platform_clock_provider_op_t op;
  u64 rate;
} vnet_dev_platform_clock_provider_request_t;

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
__clib_export void vnet_dev_platform_resource_close (vnet_dev_t *);
__clib_export vnet_dev_rv_t vnet_dev_platform_clock_enable (vnet_dev_t *, char *, char *);
__clib_export vnet_dev_rv_t vnet_dev_platform_clock_disable (vnet_dev_t *, char *, char *);
__clib_export vnet_dev_rv_t vnet_dev_platform_clock_set_rate (vnet_dev_t *, char *, char *, u64);
__clib_export vnet_dev_rv_t vnet_dev_platform_reset_assert (vnet_dev_t *, char *, char *);
__clib_export vnet_dev_rv_t vnet_dev_platform_reset_deassert (vnet_dev_t *, char *, char *);
__clib_export vnet_dev_rv_t vnet_dev_platform_reset_pulse (vnet_dev_t *, char *, char *);
__clib_export vnet_dev_rv_t vnet_dev_platform_interconnect_set_bw (vnet_dev_t *, char *, char *,
								   u64, u64);
__clib_export vnet_dev_rv_t vnet_dev_platform_ethernet_phy_open (vnet_dev_t *, char *, char *);
__clib_export vnet_dev_rv_t vnet_dev_platform_ethernet_phy_start_aneg (vnet_dev_t *, char *,
								       char *);
__clib_export vnet_dev_rv_t vnet_dev_platform_ethernet_phy_stop (vnet_dev_t *, char *, char *);
__clib_export vnet_dev_rv_t vnet_dev_platform_ethernet_phy_get_state (
  vnet_dev_t *, char *, char *, vnet_dev_platform_ethernet_phy_state_t *);

/* Sibling-device access: lets a driver address a platform device other
 * than the one it was probed against, e.g. a device sharing its parent
 * bus. node is any devicetree node; device_name comes back as the sysfs
 * platform device name kdi expects (freed by the caller). */
__clib_export vnet_dev_rv_t vnet_dev_platform_dt_node_device_name (clib_dt_node_t *node,
								   u8 **device_name);
__clib_export vnet_dev_rv_t vnet_dev_platform_open_resource_on_device (
  vnet_dev_t *dev, char *device_name, vnet_dev_platform_resource_type_t type, char *node_name,
  char *resource_name, u32 arg, int *fd);

/* Non-blocking: returns VNET_DEV_ERR_NOT_READY when there is nothing to
 * service, so it is safe to call from a periodic poll callback. */
__clib_export vnet_dev_rv_t
vnet_dev_platform_clock_provider_try_request (int fd, vnet_dev_platform_clock_provider_request_t *);
__clib_export vnet_dev_rv_t vnet_dev_platform_clock_provider_complete (int fd, i32 result,
								       u64 rate);
/* Pushes a rate into the kernel-registered provider clock on userspace's
 * own initiative and has it call clk_set_rate() on itself, rather than
 * only ever answering a consumer-initiated request - see kdi.h. */
__clib_export vnet_dev_rv_t vnet_dev_platform_clock_provider_notify_rate (vnet_dev_t *, int fd,
									  u32 index, u64 rate);

/* fd-based variants of the clock/reset consumer calls above, for a
 * resource fd obtained via vnet_dev_platform_open_resource_on_device() -
 * i.e. a sibling device's own clock/reset, rather than one of dev's own. */
__clib_export vnet_dev_rv_t vnet_dev_platform_clock_enable_fd (vnet_dev_t *, int fd);
__clib_export vnet_dev_rv_t vnet_dev_platform_clock_disable_fd (vnet_dev_t *, int fd);
__clib_export vnet_dev_rv_t vnet_dev_platform_clock_set_rate_fd (vnet_dev_t *, int fd, u64 rate);
__clib_export vnet_dev_rv_t vnet_dev_platform_reset_assert_fd (vnet_dev_t *, int fd);
__clib_export vnet_dev_rv_t vnet_dev_platform_reset_deassert_fd (vnet_dev_t *, int fd);
__clib_export vnet_dev_rv_t vnet_dev_platform_reset_pulse_fd (vnet_dev_t *, int fd);

#endif /* _VNET_DEV_BUS_PLATFORM_H_ */
