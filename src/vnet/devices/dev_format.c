/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vlib/pci/pci.h"
#include "vppinfra/error.h"
#include <vnet/vnet.h>
#include <vnet/devices/dev.h>
#include <vnet/ethernet/ethernet.h>

u8 *
format_vnet_dev_addr (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);

  if (dev == 0)
    return 0;

  s = format (s, "%U", format_vlib_pci_addr, &dev->pci.addr);

  return s;
}

u8 *
format_vnet_dev_interface_name (u8 *s, va_list *args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  u32 i = va_arg (*args, u32);
  vnet_dev_if_t *intf = pool_elt_at_index (dm->interfaces, i);

  if (intf->name)
    return format (s, "%s", intf->name);

  s = format (s, "%s%u/%u", dm->drivers[intf->driver_index].registration->name,
	      intf->dev_index, intf->port_index);
  return s;
}

u8 *
format_vnet_dev_interface_info (u8 *s, va_list *args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  u32 i = va_arg (*args, u32);
  vnet_dev_if_t *intf = pool_elt_at_index (dm->interfaces, i);
  vnet_dev_driver_t *dr = pool_elt_at_index (dm->drivers, intf->driver_index);
  vnet_dev_t *dev = pool_elt_at_index (dr->devices, intf->dev_index)[0];
  vnet_dev_port_t *port = pool_elt_at_index (dev->ports, intf->port_index)[0];
  vnet_dev_rx_queue_t *rxq;
  vnet_dev_tx_queue_t *txq;
  u32 indent = format_get_indent (s);

  s = format (s, "Device:");
  s = format (s, "\n%UDriver is '%s'", format_white_space, indent + 2,
	      dr->registration->name);
  if (dev->description)
    s = format (s, ", description '%v'", dev->description);
  if (dev->bus_type == VNET_DEV_BUS_TYPE_PCIE)
    {
      vlib_pci_config_t cfg = {};
      clib_error_t *err;
      s = format (s, "\n%UPCIe address is %U", format_white_space, indent + 2,
		  format_vlib_pci_addr, &dev->pci.addr);

      err = vlib_pci_read_write_config (vlib_get_main (), dev->pci.handle,
					VLIB_READ, 0, &cfg, sizeof (cfg));
      if (!err)
	{
	  s = format (s, ", port is %U, speed is %U (max %U)",
		      format_vlib_pci_link_port, &cfg,
		      format_vlib_pci_link_speed, &cfg,
		      format_vlib_pci_link_speed_cap, &cfg);
	}
      else
	clib_error_free (err);
    }

  s = format (s, "\n%UPort %u:", format_white_space, indent, port->port_id);
  s = format (s, "\n%UHardware Address: %U", format_white_space, indent + 2,
	      format_ethernet_address, port->hw_addr);
  s = format (s, "\n%U%u RX queues (max %u), %u TX queues (max %u)",
	      format_white_space, indent + 2, pool_elts (port->rx_queues),
	      port->max_rx_queues, pool_elts (port->tx_queues),
	      port->max_tx_queues);

  pool_foreach_index (i, port->rx_queues)
    {
      rxq = pool_elt_at_index (port->rx_queues, i)[0];
      s = format (s, "\n%URX queue %u:", format_white_space, indent + 2,
		  rxq->queue_id);
      s = format (s, "\n%UNum descriptors is %u", format_white_space,
		  indent + 4, rxq->n_desc);
    }

  pool_foreach_index (i, port->tx_queues)
    {
      txq = pool_elt_at_index (port->tx_queues, i)[0];
      s = format (s, "\n%UTX queue %u:", format_white_space, indent + 2,
		  txq->queue_id);
      s = format (s, "\n%UNum descriptors is %u", format_white_space,
		  indent + 4, txq->n_desc);
    }
  return s;
}
