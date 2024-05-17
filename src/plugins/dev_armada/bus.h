/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_MVPP2_BUS_H_
#define _VNET_DEV_MVPP2_BUS_H_

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>

#define ARMADA_BUS_NAME "armada"

typedef enum
{
  ARMADA_DEVICE_TYPE_UNKNOWN,
  ARMADA_DEVICE_TYPE_PPIO,
  ARMADA_DEVICE_TYPE_SAM,
} vnet_dev_bus_armada_device_type_t;

typedef struct
{
  vnet_dev_bus_armada_device_type_t type : 8;
  u8 pp_id;
} vnet_dev_bus_armada_device_info_t;

typedef struct
{
  u8 pp_id;
} vnet_dev_bus_armada_device_data_t;

format_function_t format_vnet_dev_armada_desc;

#endif /* _VNET_DEV_MVPP2_BUS_H_ */
