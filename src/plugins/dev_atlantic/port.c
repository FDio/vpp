/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_atlantic/atlantic.h>

vnet_dev_rv_t
atl_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  return VNET_DEV_OK;
}

vnet_dev_rv_t
atl_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  return VNET_DEV_OK;
}

void
atl_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
}

u8 *
atl_port_format_status (u8 *s, va_list *args)
{
  return s;
}

vnet_dev_rv_t
atl_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
			      vnet_dev_port_cfg_change_req_t *req)
{
  return VNET_DEV_OK;
}

vnet_dev_rv_t
atl_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		     vnet_dev_port_cfg_change_req_t *req)
{
  return VNET_DEV_OK;
}

vnet_dev_rv_t
atl_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  return VNET_DEV_OK;
}

void
atl_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
}

vnet_dev_rv_t
atl_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  return VNET_DEV_OK;
}

void
atl_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
}
