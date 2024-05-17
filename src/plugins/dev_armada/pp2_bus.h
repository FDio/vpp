/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_MVPP2_BUS_H_
#define _VNET_DEV_MVPP2_BUS_H_

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>

typedef struct
{
  u8 pp_id;
  u8 ppio_id;
} vnet_dev_bus_mvpp2_device_info_t;

typedef struct
{
  u8 pp_id;
  u8 ppio_id;
} vnet_dev_bus_mvpp2_device_data_t;

format_function_t format_vnet_dev_mvpp2_desc;

#endif /* _VNET_DEV_MVPP2_BUS_H_ */
