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
  char driver_name[VNET_DEV_MAX_IF_NAME_LEN];
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
  char intf_name[VNET_DEV_MAX_IF_NAME_LEN];
  u16 num_rx_queues;
  u16 num_tx_queues;
  u16 rx_queue_size;
  u16 tx_queue_size;
  vnet_dev_port_id_t port_id;
} vnet_dev_api_create_port_if_args_t;

vnet_dev_rv_t
vnet_dev_api_create_port_if (vlib_main_t *,
			     vnet_dev_api_create_port_if_args_t *);

#endif /* _VNET_DEV_API_H_ */
