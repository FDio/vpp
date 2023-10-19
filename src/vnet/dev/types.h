/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_TYPES_H_
#define _VNET_DEV_TYPES_H_

#include <vppinfra/types.h>
#include <vnet/dev/errors.h>

typedef char vnet_dev_device_id_t[32];
typedef char vnet_dev_if_name_t[32];
typedef char vnet_dev_driver_name_t[16];
typedef char vnet_dev_bus_name_t[6];
typedef u16 vnet_dev_port_id_t;
typedef struct vnet_dev vnet_dev_t;
typedef struct vnet_dev_port vnet_dev_port_t;
typedef struct vnet_dev_rx_queue vnet_dev_rx_queue_t;
typedef struct vnet_dev_tx_queue vnet_dev_tx_queue_t;

typedef enum
{
  VNET_DEV_MINUS_OK = 0,
#define _(n, d) VNET_DEV_ERR_MINUS_##n,
  foreach_vnet_dev_rv_type
#undef _
} vnet_dev_minus_rv_t;

typedef enum
{
  VNET_DEV_OK = 0,
#define _(n, d) VNET_DEV_ERR_##n = -(VNET_DEV_ERR_MINUS_##n),
  foreach_vnet_dev_rv_type
#undef _
} vnet_dev_rv_t;

#endif /* _VNET_DEV_TYPES_H_ */
