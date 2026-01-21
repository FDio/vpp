/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <driver.h>

VLIB_REGISTER_LOG_CLASS (vn_log, static) = {
  .class_name = "virtio-net",
  .subclass_name = "init",
};

vnet_dev_node_t vn_rx_node = {};
vnet_dev_node_t vn_tx_node = {};

static u8 *
vn_probe (vlib_main_t *vm, vnet_dev_probe_args_t *a)
{
  vnet_dev_bus_pci_device_info_t *di = a->device_info;

  if (di->vendor_id != 0x1af4)
    return 0;

  if (di->device_id == 0x1041)
    return format (0, "Virtio Network Device");

  return 0;
}

static vnet_dev_rv_t
vn_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vn_dev_t *vnd = vnet_dev_get_data (dev);
  virtio_pci_cap_t cap;
  u32 pos = 0;

  while ((pos = vnet_dev_pci_find_next_std_capa_offset (vm, dev, PCI_CAP_ID_VNDR, pos)))
    {
      if (vnet_dev_pci_config_read (vm, dev, pos, sizeof (cap), (u32 *) &cap) != VNET_DEV_OK)
	break;

      if (cap.cap_len < sizeof (virtio_pci_cap_t))
	{
	  log_debug (dev, "invalid virtio capability at offset 0x%x", pos);
	  continue;
	}

      log_debug (dev,
		 "found virtio capability: type %u, bar %u, offset 0x%x, length "
		 "0x%x",
		 cap.cfg_type, cap.bar, cap.offset, cap.length);

      if (cap.length == 0)
	continue;

      if (cap.bar >= 6)
	{
	  log_debug (dev, "invalid bar %u", cap.bar);
	  continue;
	}

      if (vnd->bar[cap.bar] == 0)
	{
	  if (vnet_dev_pci_map_region (vm, dev, cap.bar, &vnd->bar[cap.bar]) != VNET_DEV_OK)
	    {
	      log_debug (dev, "failed to map bar %u", cap.bar);
	      continue;
	    }
	}

      switch (cap.cfg_type)
	{
	case VIRTIO_PCI_CAP_COMMON_CFG:
	  vnd->common_cfg = (void *) (uword) (vnd->bar[cap.bar] + cap.offset);
	  break;
	case VIRTIO_PCI_CAP_NOTIFY_CFG:
	  if (cap.cap_len >= sizeof (virtio_pci_notify_cap_t))
	    {
	      vnd->notify_base = (void *) (uword) (vnd->bar[cap.bar] + cap.offset);
	      vnet_dev_pci_config_read (
		vm, dev, pos + offsetof (virtio_pci_notify_cap_t, notify_off_multiplier), 4,
		&vnd->notify_off_multiplier);
	    }
	  break;
	case VIRTIO_PCI_CAP_ISR_CFG:
	  vnd->isr = (void *) (uword) (vnd->bar[cap.bar] + cap.offset);
	  break;
	case VIRTIO_PCI_CAP_DEVICE_CFG:
	  vnd->device_cfg = (void *) (uword) (vnd->bar[cap.bar] + cap.offset);
	  break;
	default:
	  break;
	}
    }

  if (vnd->common_cfg == 0 || vnd->notify_base == 0 || vnd->isr == 0 || vnd->device_cfg == 0)
    {
      log_err (dev, "missing mandatory virtio capability");
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }

  log_debug (dev, "common config: %U", format_virtio_pci_cap_common_cfg, vnd->common_cfg);
  log_debug (dev, "notify config: %U", format_virtio_pci_notify_cfg, vnd);
  log_debug (dev, "isr config: %U", format_virtio_pci_isr, vnd->isr);
  log_debug (dev, "device config: %U", format_virtio_net_config, vnd->device_cfg);

  vnet_dev_port_add_args_t port_add_args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .max_rx_queues = vnd->common_cfg->num_queues,
        .max_tx_queues = vnd->common_cfg->num_queues,
        .max_supported_rx_frame_size = vnd->device_cfg->mtu,
        .caps = {
          .change_max_rx_frame_size = 1,
          .interrupt_mode = 1,
        },
        .rx_offloads = {
          .ip4_cksum = 1,
        },
        .tx_offloads = {
          .ip4_cksum = 1,
          .tcp_gso = 1,
        },
      },
      .ops = {
        .init = vn_port_init,
        .start = vn_port_start,
        .stop = vn_port_stop,
        .format_status = format_virtio_net_port_status,
      },
      .data_size = sizeof (vn_port_t),
    },
    .rx_node = &vn_rx_node,
    .tx_node = &vn_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (vn_rxq_t),
        .default_size = 256,
        .min_size = 32,
        .max_size = 4096,
        .size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = vn_rx_queue_alloc,
        .free = vn_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (vn_txq_t),
        .default_size = 256,
        .min_size = 32,
        .max_size = 4096,
        .size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = vn_tx_queue_alloc,
        .free = vn_tx_queue_free,
      },
    },
  };

  u8 mac[6];
  for (int i = 0; i < 6; i++)
    mac[i] = vnd->device_cfg->mac[i];

  vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr, mac);

  return vnet_dev_port_add (vm, dev, 0, &port_add_args);
}
VNET_DEV_REGISTER_DRIVER (virtio_net) = {
  .name = "virtio-net",
  .description = "Virtio Network Device",
  .bus = "pci",
  .device_data_sz = sizeof (vn_dev_t),
  .ops = {
    .init = vn_init,
    .probe = vn_probe,
    .format_info = format_virtio_net_device_info,
  },
};
