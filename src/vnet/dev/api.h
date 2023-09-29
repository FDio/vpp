/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_API_H_
#define _VNET_DEV_API_H_

#include <vppinfra/clib.h>
#include <vnet/vnet.h>
#include <vnet/dev/types.h>

typedef struct
{
  vnet_dev_device_id_t device_id;
  vnet_dev_driver_name_t driver_name;
  u8 *args;
} vnet_dev_api_attach_args_t;

vnet_dev_rv_t vnet_dev_api_attach (vlib_main_t *,
				   vnet_dev_api_attach_args_t *);

typedef struct
{
  vnet_dev_device_id_t device_id;
} vnet_dev_api_detach_args_t;
vnet_dev_rv_t vnet_dev_api_detach (vlib_main_t *,
				   vnet_dev_api_detach_args_t *);

typedef struct
{
  vnet_dev_device_id_t device_id;
} vnet_dev_api_reset_args_t;
vnet_dev_rv_t vnet_dev_api_reset (vlib_main_t *, vnet_dev_api_reset_args_t *);

typedef struct
{
  vnet_dev_device_id_t device_id;
  vnet_dev_if_name_t intf_name;
  u16 num_rx_queues;
  u16 num_tx_queues;
  u16 rx_queue_size;
  u16 tx_queue_size;
  vnet_dev_port_id_t port_id;
  u8 *args;
} vnet_dev_api_create_port_if_args_t;

vnet_dev_rv_t
vnet_dev_api_create_port_if (vlib_main_t *,
			     vnet_dev_api_create_port_if_args_t *);

typedef struct
{
  u32 sw_if_index;
} vnet_dev_api_remove_port_if_args_t;

vnet_dev_rv_t
vnet_dev_api_remove_port_if (vlib_main_t *,
			     vnet_dev_api_remove_port_if_args_t *);

#endif /* _VNET_DEV_API_H_ */
