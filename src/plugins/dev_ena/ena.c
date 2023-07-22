/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/error.h"
#include "vppinfra/format.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <dev_ena/ena.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "dev_ena",
  .subclass_name = "init",
};

#define log_debug(id, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ena_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_info(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_INFO, ena_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_notice(id, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, ena_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_warn(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ena_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_err(id, f, ...)                                                   \
  vlib_log (VLIB_LOG_LEVEL_ERR, ena_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)

vnet_dev_node_fn_t ena_rx_node_fn = {};
vnet_dev_node_fn_t ena_tx_node_fn = {};

static __clib_unused vnet_dev_rv_t
ena_err (ena_device_t *id, vnet_dev_rv_t rv, char *fmt, ...)
{
  va_list va;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);
  log_err (id, "%v", s);
  vec_free (s);
  return rv;
}

static vnet_dev_rv_t
ena_pci_err (ena_device_t *id, clib_error_t *err)
{
  log_err (id, "PCI error: %U", format_clib_error, err);
  clib_error_free (err);
  return VNET_DEV_ERR_BUS;
}

static vnet_dev_rv_t
ena_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ena_device_t *id = vnet_dev_get_data (port->dev);
  log_debug (id, "port init: port %u", port->port_id);

  return 0;
}

static_always_inline __clib_unused uword
vnet_dev_get_dma_addr (vlib_main_t *vm, vnet_dev_t *dev, void *p)
{
  return dev->va_dma ? pointer_to_uword (p) : vlib_physmem_get_pa (vm, p);
}

static vnet_dev_rv_t
ena_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ena_device_t *id = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (id, "port start: port %u", port->port_id);

  return rv;
}

static void
ena_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ena_device_t *id = vnet_dev_get_data (port->dev);
  log_debug (id, "port stop: port %u", port->port_id);
}

static vnet_dev_rv_t
ena_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ena_device_t *id = vnet_dev_get_data (dev);
  ena_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (id, "rx_queue_alloc:");

  if (id->avail_rxq_bmp == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  rxq->queue_id = get_lowest_set_bit_index (id->avail_rxq_bmp);
  id->avail_rxq_bmp ^= 1 << rxq->queue_id;

  iq->buffer_indices = clib_mem_alloc_aligned (
    rxq->size * sizeof (iq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);
  clib_memset_u32 (iq->buffer_indices, 0, rxq->size);

  // rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (ena_rx_desc_t) * rxq->size,
  // 0, (void **) &iq->descs);
  return rv;
}

static void
ena_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ena_device_t *id = vnet_dev_get_data (dev);

  log_debug (id, "rx_queue_free:");

  id->avail_rxq_bmp |= 1 << rxq->queue_id;
  // vnet_dev_dma_mem_free (vm, dev, iq->descs);
}

static vnet_dev_rv_t
ena_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ena_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "tx_queue_alloc:");
  if (id->avail_txq_bmp == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  txq->queue_id = get_lowest_set_bit_index (id->avail_txq_bmp);
  id->avail_txq_bmp ^= 1 << txq->queue_id;
  return VNET_DEV_OK;
}

static void
ena_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ena_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "tx_queue_free:");
  id->avail_txq_bmp |= 1 << txq->queue_id;
}

static vnet_dev_rv_t
ena_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *id = vnet_dev_get_data (dev);
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  /* map BAR0 */
  if (id->bar0 == 0)
    {
      if ((err = vlib_pci_map_region (vm, h, 0, &id->bar0)))
	return ena_pci_err (id, err);
    }

  vnet_dev_port_add_args_t port = {
    .type = VNET_DEV_PORT_TYPE_ETHERNET,
    .port = {
      .data_size = sizeof (ena_port_t),
      .max_rx_queues = 4,
      .max_tx_queues = 4,
      .max_frame_size = 9728,
    },
    .rx_queue = {
      .data_size = sizeof (ena_rxq_t),
      .default_size = 512,
      .multiplier = 8,
      .min_size = 32,
      .max_size = 32768,
    },
    .tx_queue = {
      .data_size = sizeof (ena_txq_t),
      .default_size = 512,
      .multiplier = 8,
      .min_size = 32,
      .max_size = 32768,
    },
    .ops = {
      .rx_node_fn = &ena_rx_node_fn,
      .tx_node_fn = &ena_tx_node_fn,
      .init = ena_port_init,
      .start = ena_port_start,
      .stop = ena_port_stop,
      .format_status = format_ena_port_status,
      .rx_queue_alloc = ena_rx_queue_alloc,
      .rx_queue_free = ena_rx_queue_free,
      .tx_queue_alloc = ena_tx_queue_alloc,
      .tx_queue_free = ena_tx_queue_free,
    },
  };

#if 0
  ena_reg_rd (id, ENA_REG_RAL0, &tmp);
  clib_memcpy (&port.port.hw_addr[0], &tmp, 4);
  ena_reg_rd (id, ENA_REG_RAH0, &tmp);
  clib_memcpy (&port.port.hw_addr[4], &tmp, 2);
  log_info (id, "device MAC address is %U", format_ethernet_address,
	    port.port.hw_addr);
#endif

  id->avail_rxq_bmp = pow2_mask (4);
  id->avail_txq_bmp = pow2_mask (4);
  vnet_dev_port_add (vm, dev, 0, &port);
  return 0;
}

static void
ena_free (vlib_main_t *vm, vnet_dev_t *dev)
{
}

static struct
{
  u16 device_id;
  char *description;
} ena_dev_types[] = {
  { .device_id = 0x15F2,
    .description = "Intel(R) Ethernet Controller I225-LM" },
  { .device_id = 0x15F3,
    .description = "Intel(R) Ethernet Controller I225-V" },
  { .device_id = 0x0d9f,
    .description = "Intel(R) Ethernet Controller (2) I225-IT" },
  { .device_id = 0x125b,
    .description = "Intel(R) Ethernet Controller I226-LM" },
  { .device_id = 0x125c,
    .description = "Intel(R) Ethernet Controller I226-V" },
  { .device_id = 0x125d,
    .description = "Intel(R) Ethernet Controller I226-IT" },
};

static u8 *
ena_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != 0x8086)
    return 0;

  FOREACH_ARRAY_ELT (dt, ena_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->description);
    }

  return 0;
}

VNET_DEV_REGISTER_DRIVER (ena) = {
  .name = "ena",
  .bus = "pci",
  .device_data_sz = sizeof (ena_device_t),
  .ops = { .device_init = ena_init,
	   .device_free = ena_free,
	   .probe = ena_probe,
  },
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_ena",
};
