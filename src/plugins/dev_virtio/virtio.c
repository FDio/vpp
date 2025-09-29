/* SPDX-License-Identifier: Apache-2.0 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <dev_virtio/virtio.h>

extern vnet_dev_node_t virtio_rx_node;
extern vnet_dev_node_t virtio_tx_node;

VLIB_REGISTER_LOG_CLASS (dev_virtio_log, static) = {
  .class_name = "dev_virtio",
  .subclass_name = "driver",
};

dev_virtio_main_t dev_virtio_main;

#define dv_log_debug(dev, f, ...)                                             \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_virtio_log.class, "%U: " f,             \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define dv_log_info(dev, f, ...)                                              \
  vlib_log (VLIB_LOG_LEVEL_INFO, dev_virtio_log.class, "%U: " f,              \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define dv_log_warn(dev, f, ...)                                              \
  vlib_log (VLIB_LOG_LEVEL_WARNING, dev_virtio_log.class, "%U: " f,           \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)

static u8 *
virtio_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index,
              void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != 0x1af4)
    return 0;

  switch (di->device_id)
    {
    case 0x1000:
      return format (0, "Virtio PCI (transitional)");
    case 0x1041:
      return format (0, "Virtio PCI (modern)");
    default:
      break;
    }

  return 0;
}

static vnet_dev_rv_t
virtio_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  dev_virtio_device_t *vd = vnet_dev_get_data (dev);
  clib_memset (vd, 0, sizeof (*vd));
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
virtio_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  dev_virtio_device_t *vd = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;

  if ((rv = virtio_pci_map_caps (vm, dev, vd)))
    {
      dv_log_warn (dev, "failed to map PCI capabilities (%d)", rv);
      return rv;
    }

  vnet_dev_port_add_args_t port_args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .max_rx_queues = 1,
        .max_tx_queues = 1,
        .max_supported_rx_frame_size = ETHERNET_MAX_PACKET_BYTES,
      },
      .ops = {
        .init = virtio_port_init,
        .start = virtio_port_start,
        .stop = virtio_port_stop,
        .config_change = virtio_port_cfg_change,
        .config_change_validate = virtio_port_cfg_change_validate,
        .format_status = format_virtio_port_status,
      },
      .data_size = sizeof (dev_virtio_port_t),
    },
    .rx_node = &virtio_rx_node,
    .tx_node = &virtio_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (dev_virtio_rxq_t),
        .default_size = 256,
        .min_size = 32,
        .size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = virtio_rx_queue_alloc,
        .free = virtio_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (dev_virtio_txq_t),
        .default_size = 256,
        .min_size = 32,
        .size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = virtio_tx_queue_alloc,
        .free = virtio_tx_queue_free,
      },
    },
  };

  dv_log_info (dev, "registering placeholder port (modern=%u)", vd->modern);

  rv = vnet_dev_port_add (vm, dev, 0, &port_args);

  if (rv)
    dv_log_warn (dev, "port registration failed (%d)", rv);

  return rv;
}

static void
virtio_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  /* nothing yet */
}

static void
virtio_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  /* nothing yet */
}

VNET_DEV_REGISTER_DRIVER (virtio) = {
  .name = "dev_virtio",
  .bus = "pci",
  .device_data_sz = sizeof (dev_virtio_device_t),
  .ops = {
    .alloc = virtio_alloc,
    .init = virtio_init,
    .deinit = virtio_deinit,
    .free = virtio_free,
    .probe = virtio_probe,
  },
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Virtio PCI device driver (dev virtio skeleton)",
};
