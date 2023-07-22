/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_FUNCS_H_
#define _VNET_DEV_FUNCS_H_

#include <vppinfra/clib.h>
#include <vnet/dev/dev.h>

static_always_inline void *
vnet_dev_get_data (vnet_dev_t *dev)
{
  return dev->data;
}

static_always_inline vnet_dev_t *
vnet_dev_from_data (void *p)
{
  return (void *) ((u8 *) p - STRUCT_OFFSET_OF (vnet_dev_t, data));
}

static_always_inline void *
vnet_dev_get_port_data (vnet_dev_port_t *port)
{
  return port->data;
}

static_always_inline void *
vnet_dev_get_rx_queue_data (vnet_dev_rx_queue_t *rxq)
{
  return rxq->data;
}

static_always_inline void *
vnet_dev_get_tx_queue_data (vnet_dev_tx_queue_t *txq)
{
  return txq->data;
}

static_always_inline vnet_dev_port_t *
vnet_dev_get_port_from_dev_instance (u32 dev_instance)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_if_t *intf = pool_elt_at_index (dm->interfaces, dev_instance);
  vnet_dev_driver_t *dr = pool_elt_at_index (dm->drivers, intf->driver_index);
  vnet_dev_t *dev = pool_elt_at_index (dr->devices, intf->dev_index)[0];
  return pool_elt_at_index (dev->ports, intf->port_index)[0];
}
#endif /* _VNET_DEV_FUNCS_H_ */
