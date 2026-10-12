/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <vlib/buffer_funcs.h>
#include <qppe.h>

#include <string.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "init",
};

typedef struct
{
  const char *name;
  u64 average_bw;
  u64 peak_bw;
} qppe_interconnect_bw_t;

static const qppe_interconnect_bw_t qppe_interconnect_bw[] = {
  {
    .name = "ppe",
    .average_bw = 353000,
    .peak_bw = 353000,
  },
  {
    .name = "ppe_cfg",
    .average_bw = 353000,
    .peak_bw = 353000,
  },
  {
    .name = "qos_gen",
    .average_bw = 6000,
    .peak_bw = 6000,
  },
  {
    .name = "timeout_ref",
    .average_bw = 6000,
    .peak_bw = 6000,
  },
  {
    .name = "nssnoc_memnoc",
    .average_bw = 533333,
    .peak_bw = 533333,
  },
  {
    .name = "memnoc_nssnoc",
    .average_bw = 533333,
    .peak_bw = 533333,
  },
  {
    .name = "memnoc_nssnoc_1",
    .average_bw = 533333,
    .peak_bw = 533333,
  },
};

#define _(f, n, s, d) { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },
static vlib_error_desc_t qppe_rx_node_counters[] = { foreach_qppe_rx_node_counter };
static vlib_error_desc_t qppe_tx_node_counters[] = { foreach_qppe_tx_node_counter };
#undef _

vnet_dev_node_t qppe_rx_node = {
  .error_counters = qppe_rx_node_counters,
  .n_error_counters = ARRAY_LEN (qppe_rx_node_counters),
  .format_trace = format_qppe_rx_trace,
};

vnet_dev_node_t qppe_tx_node = {
  .error_counters = qppe_tx_node_counters,
  .n_error_counters = ARRAY_LEN (qppe_tx_node_counters),
  .format_trace = format_qppe_tx_trace,
};

static vnet_dev_rv_t
qppe_open_clock (vnet_dev_t *dev, char *node_name, char *name)
{
  int rv;

  log_debug (dev, "opening clock '%s%s%s'", node_name, node_name[0] ? "/" : "", name);
  if ((!node_name[0] && strcmp (name, "ppe") == 0) ||
      (strcmp (node_name, "ethernet-dma") == 0 &&
       (strcmp (name, "sys") == 0 || strcmp (name, "apb") == 0)))
    {
      rv = vnet_dev_platform_clock_set_rate (dev, node_name, name, PPE_CLOCK_RATE);
      if (rv < 0)
	{
	  log_err (dev, "cannot set clock '%s%s%s' to %u Hz: %s", node_name,
		   node_name[0] ? "/" : "", name, PPE_CLOCK_RATE, strerror (-rv));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      log_debug (dev, "set clock '%s%s%s' to %u Hz", node_name, node_name[0] ? "/" : "", name,
		 PPE_CLOCK_RATE);
    }
  rv = vnet_dev_platform_clock_enable (dev, node_name, name);
  if (rv < 0)
    {
      log_err (dev, "cannot enable clock '%s%s%s': %s", node_name, node_name[0] ? "/" : "", name,
	       strerror (-rv));
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "enabled clock '%s%s%s'", node_name, node_name[0] ? "/" : "", name);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_open_reset (vlib_main_t *vm, vnet_dev_t *dev, char *node_name, char *name)
{
  int edma_reset = strcmp (node_name, "ethernet-dma") == 0 && strcmp (name, "edma") == 0;
  int port_reset = strncmp (node_name, "ethernet-ports/port@", 20) == 0;
  char *separator = node_name[0] ? "/" : "";
  int rv;

  if (port_reset)
    return VNET_DEV_OK;

  log_debug (dev, "handling reset '%s%s%s'", node_name, separator, name);

  if (edma_reset)
    {
      log_debug (dev, "asserting EDMA reset for %u us", EDMA_RESET_DELAY_US);
      rv = vnet_dev_platform_reset_assert (dev, node_name, name);
      if (rv < 0)
	{
	  log_err (dev, "cannot assert reset '%s/edma': %s", node_name, strerror (-rv));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      log_debug (dev, "asserted reset '%s/edma'", node_name);
      vlib_process_suspend (vm, EDMA_RESET_DELAY_US * 1e-6);
      rv = vnet_dev_platform_reset_deassert (dev, node_name, name);
      if (rv < 0)
	{
	  log_err (dev, "cannot deassert reset '%s/edma': %s", node_name, strerror (-rv));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      log_debug (dev, "deasserted reset '%s/edma'; waiting %u us for reset to settle", node_name,
		 EDMA_RESET_DELAY_US);
      vlib_process_suspend (vm, EDMA_RESET_DELAY_US * 1e-6);
      return VNET_DEV_OK;
    }

  rv = vnet_dev_platform_reset_pulse (dev, node_name, name);
  if (rv < 0)
    {
      log_err (dev, "cannot pulse reset '%s%s%s': %s", node_name, separator, name, strerror (-rv));
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "pulsed reset '%s%s%s'", node_name, separator, name);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_open_interconnect (vnet_dev_t *dev, char *node_name, char *name)
{
  u32 i;
  int rv;

  for (i = 0; i < ARRAY_LEN (qppe_interconnect_bw); i++)
    if (strcmp (name, qppe_interconnect_bw[i].name) == 0)
      break;

  if (i == ARRAY_LEN (qppe_interconnect_bw))
    {
      log_err (dev, "no bandwidth policy for interconnect '%s'", name);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  rv = vnet_dev_platform_interconnect_set_bw (
    dev, node_name, name, qppe_interconnect_bw[i].average_bw, qppe_interconnect_bw[i].peak_bw);
  if (rv < 0)
    {
      log_err (dev, "cannot set interconnect '%s' bandwidth to average %llu, peak %llu: %s", name,
	       qppe_interconnect_bw[i].average_bw, qppe_interconnect_bw[i].peak_bw, strerror (-rv));
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "configured interconnect '%s%s%s' with average/peak bandwidth %llu/%llu",
	     node_name, node_name[0] ? "/" : "", name, qppe_interconnect_bw[i].average_bw,
	     qppe_interconnect_bw[i].peak_bw);
  return VNET_DEV_OK;
}

static u8 *
qppe_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_platform_device_info_t *di = args->device_info;

  if (clib_dt_node_is_compatible (di->node, PPE_DT_COMPATIBLE))
    return format (0, "Qualcomm PPE (Packet Processing Engine)");
  return 0;
}

static vnet_dev_rv_t
qppe_port_reset (vlib_main_t *vm, vnet_dev_t *dev, clib_dt_node_t *node, char *node_name)
{
  clib_dt_property_t *names = clib_dt_get_node_property_by_name (node, "reset-names");
  u32 offset = 0;
  u32 n_resets = 0;
  int rv;

  while (names && offset < names->size)
    {
      char *name = (char *) names->data + offset;
      u32 remaining = names->size - offset;
      u32 name_len = strnlen (name, remaining);

      log_debug (dev, "asserting port reset '%s/%s'", node_name, name);
      rv = vnet_dev_platform_reset_assert (dev, node_name, name);
      if (rv < 0)
	{
	  log_err (dev, "cannot assert port reset '%s/%s': %s", node_name, name, strerror (-rv));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      n_resets++;
      offset += name_len + 1;
    }

  if (n_resets == 0)
    {
      log_err (dev, "port node '%s' has no opened resets", node_name);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev, "asserted %u port resets; waiting %u us", n_resets, PPE_PORT_RESET_DELAY_US);
  vlib_process_suspend (vm, PPE_PORT_RESET_DELAY_US * 1e-6);

  offset = 0;
  while (names && offset < names->size)
    {
      char *name = (char *) names->data + offset;
      u32 remaining = names->size - offset;
      u32 name_len = strnlen (name, remaining);

      rv = vnet_dev_platform_reset_deassert (dev, node_name, name);
      if (rv < 0)
	{
	  log_err (dev, "cannot deassert port reset '%s/%s': %s", node_name, name, strerror (-rv));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      log_debug (dev, "deasserted port reset '%s/%s'", node_name, name);
      offset += name_len + 1;
    }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_add_ports (vlib_main_t *vm, vnet_dev_t *dev, clib_dt_node_t *node)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  clib_dt_node_t *ports = clib_dt_get_child_node (node, "ethernet-ports");
  u8 buffer_pool_index = vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);
  vlib_buffer_pool_t *buffer_pool = vlib_get_buffer_pool (vm, buffer_pool_index);
  u16 max_supported_rx_frame_size =
    clib_min (buffer_pool->data_size * (QPPE_MAX_RX_CHAIN_LEN + 1), PPE_XGMAC_MAX_RX_FRAME_SIZE);
  u8 seen_ports = 0;
  vnet_dev_rv_t rv;

  if (ports == 0)
    {
      log_err (dev, "device tree has no ethernet-ports node");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  foreach_clib_dt_child_node (pn, ports)
    {
      clib_dt_property_t *p;
      clib_dt_property_t *names;
      vnet_dev_port_add_args_t args = {
	.port = {
	  .attr = {
	    .type = VNET_DEV_PORT_TYPE_ETHERNET,
	    .max_rx_queues = 1,
	    .max_tx_queues = 1,
	    .max_supported_rx_frame_size = max_supported_rx_frame_size,
	    .caps = {
	      .change_max_rx_frame_size = 1,
	    },
	  },
	  .ops = {
	    .init = qppe_port_init,
	    .deinit = qppe_port_deinit,
	    .start = qppe_port_start,
	    .stop = qppe_port_stop,
	    .config_change = qppe_port_cfg_change,
	    .config_change_validate = qppe_port_cfg_change_validate,
	    .format_status = format_qppe_port_status,
	  },
	  .data_size = sizeof (qppe_port_t),
	},
	.rx_node = &qppe_rx_node,
	.tx_node = &qppe_tx_node,
	.rx_queue = {
	  .config = {
	    .data_size = sizeof (qppe_rxq_t),
	    .default_size = 512,
	    .min_size = 32,
	    .max_size = 4096,
	    .size_is_power_of_two = 1,
	  },
	  .ops = {
	    .alloc = qppe_rxq_alloc,
	    .free = qppe_rxq_free,
	    .format_info = format_qppe_rxq_info,
	  },
	},
	.tx_queue = {
	  .config = {
	    .data_size = sizeof (qppe_txq_t),
	    .default_size = 512,
	    .min_size = 32,
	    .max_size = 4096,
	    .size_is_power_of_two = 1,
	  },
	  .ops = {
	    .alloc = qppe_txq_alloc,
	    .free = qppe_txq_free,
	    .format_info = format_qppe_txq_info,
	  },
	},
      };
      clib_dt_property_t *status;
      qppe_port_t port_data = {
	.ethernet_phy_fd = -1,
      };
      char *resource_node_name;
      char *ethernet_link_name;
      clib_dt_node_t *ethernet_link_node;
      clib_dt_node_t *phy_node;
      clib_dt_node_t *sfp_node;
      uword device_path_len;
      u32 offset;
      u32 remaining;
      u32 name_len;
      char *name;
      u32 port_id;
      int phy_fd = -1;

      status = clib_dt_get_node_property_by_name (pn, "status");
      if (status && strcmp (clib_dt_property_get_string (status), "disabled") == 0)
	{
	  log_debug (dev, "ignoring disabled port node %v", pn->path);
	  continue;
	}

      p = clib_dt_get_node_property_by_name (pn, "reg");
      if (!clib_dt_property_is_u32 (p))
	{
	  log_warn (dev, "skipping port node %v without a valid reg property", pn->path);
	  continue;
	}

      port_id = clib_dt_property_get_u32 (p);
      if (port_id >= PPE_MAX_PORTS)
	{
	  log_warn (dev, "skipping port %u: id exceeds maximum %u", port_id, PPE_MAX_PORTS - 1);
	  continue;
	}
      if (seen_ports & (1 << port_id))
	{
	  log_warn (dev, "skipping duplicate port id %u", port_id);
	  continue;
	}
      if (qd->n_ports >= EDMA_RX_RING_COUNT)
	{
	  log_err (dev, "cannot add more than %u Ethernet ports", EDMA_RX_RING_COUNT);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      seen_ports |= 1 << port_id;

      device_path_len = strlen ((char *) qd->dt_path);
      if (strncmp ((char *) pn->path, (char *) qd->dt_path, device_path_len) != 0 ||
	  pn->path[device_path_len] != '/')
	{
	  log_err (dev, "port device tree path %v is outside PPE node path %v", pn->path,
		   qd->dt_path);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      resource_node_name = (char *) pn->path + device_path_len + 1;
      port_data.clock_node_name = resource_node_name;
      log_debug (dev, "opening DT property 'clock-names' on node '%s'", resource_node_name);
      names = clib_dt_get_node_property_by_name (pn, "clock-names");
      offset = 0;
      while (names && offset < names->size)
	{
	  name = (char *) names->data + offset;
	  remaining = names->size - offset;
	  name_len = strnlen (name, remaining);
	  if (name_len == remaining || name_len >= VNET_DEV_PLATFORM_RESOURCE_NAME_LEN)
	    {
	      log_err (dev, "invalid resource name in device tree property 'clock-names'");
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	  rv = qppe_open_clock (dev, resource_node_name, name);
	  if (rv != VNET_DEV_OK)
	    return rv;
	  offset += name_len + 1;
	}

      log_debug (dev, "opening DT property 'reset-names' on node '%s'", resource_node_name);
      names = clib_dt_get_node_property_by_name (pn, "reset-names");
      offset = 0;
      while (names && offset < names->size)
	{
	  name = (char *) names->data + offset;
	  remaining = names->size - offset;
	  name_len = strnlen (name, remaining);
	  if (name_len == remaining || name_len >= VNET_DEV_PLATFORM_RESOURCE_NAME_LEN)
	    {
	      log_err (dev, "invalid resource name in device tree property 'reset-names'");
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	  rv = qppe_open_reset (vm, dev, resource_node_name, name);
	  if (rv != VNET_DEV_OK)
	    return rv;
	  offset += name_len + 1;
	}
      rv = qppe_port_reset (vm, dev, pn, resource_node_name);
      if (rv != VNET_DEV_OK)
	return rv;

      phy_node = clib_dt_dereference_node (pn, "phy-handle");
      sfp_node = clib_dt_dereference_node (pn, "sfp");
      if (phy_node || sfp_node)
	{
	  ethernet_link_name = phy_node ? "phy-handle" : "sfp";
	  ethernet_link_node = phy_node ? phy_node : sfp_node;
	  phy_fd = vnet_dev_platform_resource_open_on_node (
	    dev, VNET_DEV_PLATFORM_RESOURCE_ETHERNET_PHY, resource_node_name, ethernet_link_name);
	  if (phy_fd < 0)
	    {
	      log_err (dev, "cannot open Ethernet phylink for port %u via %s node %v: %s", port_id,
		       ethernet_link_name, ethernet_link_node->path, strerror (-phy_fd));
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	  port_data.ethernet_phy_fd = phy_fd;
	  vec_add1 (qd->ethernet_phy_fds, phy_fd);
	  log_debug (dev, "opened Ethernet phylink for port %u via %s node %v, fd %d", port_id,
		     ethernet_link_name, ethernet_link_node->path, phy_fd);
	}

      p = clib_dt_get_node_property_by_name (pn, "label");
      port_data.label = p ? clib_dt_property_get_string (p) : 0;
      p = clib_dt_get_node_property_by_name (pn, "phy-mode");
      port_data.phy_mode = p ? clib_dt_property_get_string (p) : 0;
      port_data.is_xgmac = port_data.phy_mode && (strcmp (port_data.phy_mode, "2500base-x") == 0 ||
						  strcmp (port_data.phy_mode, "usxgmii") == 0 ||
						  strcmp (port_data.phy_mode, "10gbase-r") == 0 ||
						  strcmp (port_data.phy_mode, "10g-qxgmii") == 0);
      p = clib_dt_get_node_property_by_name (pn, "managed");
      port_data.managed = p ? clib_dt_property_get_string (p) : 0;

      p = clib_dt_get_node_property_by_name (pn, "mac-address");
      if (!p || p->size != 6)
	p = clib_dt_get_node_property_by_name (pn, "local-mac-address");
      if (p && p->size == 6)
	vnet_dev_set_hw_addr_eth_mac (&args.port.attr.hw_addr, p->data);

      port_data.source_profile = qd->n_ports;
      args.port.initial_data = &port_data;
      if (vnet_dev_port_add (vm, dev, port_id, &args) != VNET_DEV_OK)
	{
	  log_err (dev, "failed to add PPE port %u from device tree node %v", port_id, pn->path);
	  return VNET_DEV_ERR_INIT_FAILED;
	}

      qd->n_ports++;
      log_debug (
	dev,
	"discovered port %u, node %v, source profile %u, label %s, phy-mode %s, managed %s, "
	"MAC %U",
	port_id, pn->path, port_data.source_profile, port_data.label ? port_data.label : "(none)",
	port_data.phy_mode ? port_data.phy_mode : "(unspecified)",
	port_data.managed ? port_data.managed : "(unspecified)", format_vnet_dev_hw_addr,
	&args.port.attr.hw_addr);
    }

  if (qd->n_ports == 0)
    {
      log_err (dev, "device tree contains no enabled Ethernet ports");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  return VNET_DEV_OK;
}

static void
qppe_close_resources (qppe_device_t *qd)
{
  int *ethernet_phy_fd;

  vec_foreach (ethernet_phy_fd, qd->ethernet_phy_fds)
    vnet_dev_platform_resource_close_fd (*ethernet_phy_fd);
  vec_free (qd->ethernet_phy_fds);
}

static vnet_dev_rv_t
qppe_check_buffer_pool_dma (vlib_main_t *vm, vnet_dev_t *dev)
{
  u8 buffer_pool_index = vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);
  vlib_buffer_pool_t *buffer_pool = vlib_get_buffer_pool (vm, buffer_pool_index);
  vlib_physmem_map_t *map = vlib_physmem_get_map (vm, buffer_pool->physmem_map_index);
  u64 dma_start;
  u64 dma_end;
  u32 i;

  if (dev->va_dma)
    {
      dma_start = pointer_to_uword (map->base);
      dma_end = dma_start + (((u64) map->n_pages << map->log2_page_size) - 1);
      if (dma_end > 0xffffffffULL)
	{
	  log_err (dev,
		   "VPP buffer pool %u physmem map %u DMA range 0x%llx-0x%llx exceeds the "
		   "32-bit EDMA address space",
		   buffer_pool_index, buffer_pool->physmem_map_index, dma_start, dma_end);
	  return VNET_DEV_ERR_NOT_SUPPORTED;
	}
    }
  else
    for (i = 0; i < vec_len (map->page_table); i++)
      {
	dma_start = map->page_table[i];
	dma_end = dma_start + ((1ULL << map->log2_page_size) - 1);
	if (dma_end > 0xffffffffULL)
	  {
	    log_err (dev,
		     "VPP buffer pool %u physmem map %u page %u DMA range 0x%llx-0x%llx exceeds "
		     "the 32-bit EDMA address space",
		     buffer_pool_index, buffer_pool->physmem_map_index, i, dma_start, dma_end);
	    return VNET_DEV_ERR_NOT_SUPPORTED;
	  }
      }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  clib_dt_node_t *edma_node;
  clib_dt_property_t *names;
  vnet_dev_rv_t rv;
  char *uio_region_name;
  char *last_separator;
  char *name;
  u32 offset;
  u32 remaining;
  u32 name_len;
  u32 ring_bmp = pow2_mask (EDMA_RX_RING_COUNT);

  qd->avail_rxfill_ring_bmp = ring_bmp;
  qd->avail_rxdesc_ring_bmp = ring_bmp;
  qd->avail_txdesc_ring_bmp = ring_bmp;
  qd->avail_txcmpl_ring_bmp = ring_bmp;
  qd->dt_path = dd->node->path;

  if (!clib_dt_node_is_compatible (dd->node, PPE_DT_COMPATIBLE))
    return VNET_DEV_ERR_NOT_SUPPORTED;

  rv = qppe_check_buffer_pool_dma (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  log_debug (dev, "initializing platform device %s from device tree node %v", dev->device_id,
	     qd->dt_path);

  log_debug (dev, "opening DT property 'interconnect-names' on device");
  names = clib_dt_get_node_property_by_name (dd->node, "interconnect-names");
  offset = 0;
  while (names && offset < names->size)
    {
      name = (char *) names->data + offset;
      remaining = names->size - offset;
      name_len = strnlen (name, remaining);
      if (name_len == remaining || name_len >= VNET_DEV_PLATFORM_RESOURCE_NAME_LEN)
	{
	  log_err (dev, "invalid resource name in device tree property 'interconnect-names'");
	  goto error;
	}
      rv = qppe_open_interconnect (dev, "", name);
      if (rv != VNET_DEV_OK)
	goto error;
      offset += name_len + 1;
    }

  log_debug (dev, "opening DT property 'clock-names' on device");
  names = clib_dt_get_node_property_by_name (dd->node, "clock-names");
  offset = 0;
  while (names && offset < names->size)
    {
      name = (char *) names->data + offset;
      remaining = names->size - offset;
      name_len = strnlen (name, remaining);
      if (name_len == remaining || name_len >= VNET_DEV_PLATFORM_RESOURCE_NAME_LEN)
	{
	  log_err (dev, "invalid resource name in device tree property 'clock-names'");
	  goto error;
	}
      rv = qppe_open_clock (dev, "", name);
      if (rv != VNET_DEV_OK)
	goto error;
      offset += name_len + 1;
    }

  log_debug (dev, "opening DT property 'reset-names' on device");
  names = clib_dt_get_node_property_by_name (dd->node, "reset-names");
  offset = 0;
  while (names && offset < names->size)
    {
      name = (char *) names->data + offset;
      remaining = names->size - offset;
      name_len = strnlen (name, remaining);
      if (name_len == remaining || name_len >= VNET_DEV_PLATFORM_RESOURCE_NAME_LEN)
	{
	  log_err (dev, "invalid resource name in device tree property 'reset-names'");
	  goto error;
	}
      rv = qppe_open_reset (vm, dev, "", name);
      if (rv != VNET_DEV_OK)
	goto error;
      offset += name_len + 1;
    }

  edma_node = clib_dt_get_child_node (dd->node, "ethernet-dma");
  if (!edma_node)
    {
      log_err (dev, "device tree has no ethernet-dma child node");
      goto error;
    }
  log_debug (dev, "opening DT property 'clock-names' on node '%s'", "ethernet-dma");
  names = clib_dt_get_node_property_by_name (edma_node, "clock-names");
  offset = 0;
  while (names && offset < names->size)
    {
      name = (char *) names->data + offset;
      remaining = names->size - offset;
      name_len = strnlen (name, remaining);
      if (name_len == remaining || name_len >= VNET_DEV_PLATFORM_RESOURCE_NAME_LEN)
	{
	  log_err (dev, "invalid resource name in device tree property 'clock-names'");
	  goto error;
	}
      rv = qppe_open_clock (dev, "ethernet-dma", name);
      if (rv != VNET_DEV_OK)
	goto error;
      offset += name_len + 1;
    }

  log_debug (dev, "opening DT property 'reset-names' on node '%s'", "ethernet-dma");
  names = clib_dt_get_node_property_by_name (edma_node, "reset-names");
  offset = 0;
  while (names && offset < names->size)
    {
      name = (char *) names->data + offset;
      remaining = names->size - offset;
      name_len = strnlen (name, remaining);
      if (name_len == remaining || name_len >= VNET_DEV_PLATFORM_RESOURCE_NAME_LEN)
	{
	  log_err (dev, "invalid resource name in device tree property 'reset-names'");
	  goto error;
	}
      rv = qppe_open_reset (vm, dev, "ethernet-dma", name);
      if (rv != VNET_DEV_OK)
	goto error;
      offset += name_len + 1;
    }

  last_separator = strrchr ((char *) qd->dt_path, '/');
  if (!last_separator)
    {
      log_err (dev, "device tree path '%v' has no node name", qd->dt_path);
      goto error;
    }
  uio_region_name = last_separator + 1;
  log_debug (dev, "mapping UIO region '%s' using the platform bus", uio_region_name);
  rv = vnet_dev_platform_map_uio_region (dev, uio_region_name, &qd->regs);
  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "cannot map UIO region '%s'", uio_region_name);
      goto error;
    }
  log_debug (dev, "mapped UIO region '%s' at %p", uio_region_name, qd->regs);

  rv = qppe_add_ports (vm, dev, dd->node);
  if (rv != VNET_DEV_OK)
    goto error;

  /* qppe_hw_init reads port registers into the port data created above. */
  rv = qppe_hw_init (dev);
  if (rv != VNET_DEV_OK)
    goto error;

  return VNET_DEV_OK;

error:
  return VNET_DEV_ERR_INIT_FAILED;
}

static void
qppe_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  qd->hw_initialized = 0;
  qd->regs = 0;
  qppe_close_resources (qd);
}

VNET_DEV_REGISTER_DRIVER (qppe) = {
  .name = "qppe",
  .description = "Qualcomm PPE (Packet Processing Engine)",
  .bus = PLATFORM_BUS_NAME,
  .device = {
    .data_sz = sizeof (qppe_device_t),
    .ops = {
      .init = qppe_init,
      .deinit = qppe_deinit,
      .probe = qppe_probe,
      .format_info = format_qppe_dev_info,
    },
  },
};
