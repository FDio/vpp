/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#include <cadence.h>

VLIB_REGISTER_LOG_CLASS (cdn_port_log, static) = {
  .class_name = "cadence",
  .subclass_name = "port",
};

vnet_dev_rv_t
cdn_port_init (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  cdn_port_t *cp = vnet_dev_get_port_data (port);

  cp->link_up = 0;

  return VNET_DEV_OK;
}

vnet_dev_rv_t
cdn_port_start (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  cdn_port_t *cp = vnet_dev_get_port_data (port);

  cp->link_up = 1;

  return VNET_DEV_OK;
}

void
cdn_port_stop (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  cdn_port_t *cp = vnet_dev_get_port_data (port);

  cp->link_up = 0;
}

vnet_dev_rv_t
cdn_port_cfg_change_validate (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port __clib_unused,
			      vnet_dev_port_cfg_change_req_t *req __clib_unused)
{
  return VNET_DEV_OK;
}

vnet_dev_rv_t
cdn_port_cfg_change (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port __clib_unused,
		     vnet_dev_port_cfg_change_req_t *req __clib_unused)
{
  return VNET_DEV_OK;
}

vnet_dev_rv_t
cdn_rx_queue_alloc (vlib_main_t *vm __clib_unused, vnet_dev_rx_queue_t *rxq)
{
  cdn_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);

  crq->dummy = 0;

  return VNET_DEV_OK;
}

void
cdn_rx_queue_free (vlib_main_t *vm __clib_unused, vnet_dev_rx_queue_t *rxq)
{
  cdn_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);

  crq->dummy = 0;
}

vnet_dev_rv_t
cdn_tx_queue_alloc (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  cdn_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);

  ctq->dummy = 0;

  return VNET_DEV_OK;
}

void
cdn_tx_queue_free (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  cdn_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);

  ctq->dummy = 0;
}
