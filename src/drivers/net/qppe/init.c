/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>
#include <vlib/buffer_funcs.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

#include <string.h>

#define QPPE_DT_COMPATIBLE "qcom,ipq9574-ppe"

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "init",
};

vnet_dev_rv_t
qppe_mmio_write_validate (vnet_dev_t *dev, const qppe_reg_val_t rv[], int n_rv)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  for (int i = 0; i < n_rv; i++)
    qppe_mmio_write32 (qd, rv[i].off, rv[i].val);

  for (int i = 0; i < n_rv; i++)
    {
      u32 val = qppe_mmio_read32 (qd, rv[i].off);
      u32 mask = rv[i].mask ? rv[i].mask : ~0u;

      if ((val & mask) != (rv[i].val & mask))
	{
	  log_err (
	    dev,
	    "register readback mismatch at offset 0x%x: expected 0x%08x, read 0x%08x, mask 0x%08x",
	    rv[i].off, rv[i].val, val, mask);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  return VNET_DEV_OK;
}

typedef struct
{
  char *name;
  u64 average_bw;
  u64 peak_bw;
} qppe_interconnect_t;

/* Bandwidth requests for the interconnects used by the PPE. */
static const qppe_interconnect_t qppe_interconnects[] = {
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
/* Register error descriptions and trace formatters for the PPE nodes. */
static vlib_error_desc_t qppe_rx_node_counters[] = { foreach_qppe_rx_node_counter };
static vlib_error_desc_t qppe_tx_node_counters[] = { foreach_qppe_tx_node_counter };
#undef _

vnet_dev_node_t qppe_rx_node = {
  .error_counters = qppe_rx_node_counters,
  .n_error_counters = ARRAY_LEN (qppe_rx_node_counters),
  .format_trace = format_qppe_edma_rx_trace,
};

vnet_dev_node_t qppe_tx_node = {
  .error_counters = qppe_tx_node_counters,
  .n_error_counters = ARRAY_LEN (qppe_tx_node_counters),
  .format_trace = format_qppe_edma_tx_trace,
};

/* Match this driver to supported PPE device-tree nodes. */
static u8 *
qppe_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_platform_device_info_t *di = args->device_info;

  if (clib_dt_node_is_compatible (di->node, QPPE_DT_COMPATIBLE))
    return format (0, "Qualcomm PPE (Packet Processing Engine)");
  return 0;
}

/* Discover enabled Ethernet ports and initialize their device-tree data. */
static vnet_dev_rv_t
qppe_add_ports (vlib_main_t *vm, vnet_dev_t *dev, clib_dt_node_t *node)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  clib_dt_node_t *ports = clib_dt_get_child_node (node, "ethernet-ports");
  u8 buffer_pool_index = vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);
  vlib_buffer_pool_t *buffer_pool = vlib_get_buffer_pool (vm, buffer_pool_index);
  u16 max_supported_rx_frame_size =
    clib_min (buffer_pool->data_size * (QPPE_MAX_RX_CHAIN_LEN + 1), HPPE_XGMAC_MAX_RX_FRAME_SIZE);
  u8 seen_ports = 0;
  u32 n_ports = 0;
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
	    .max_rx_queues = EDMA_RX_QUEUES_PER_PORT,
	    .max_tx_queues = EDMA_TX_QUEUES_PER_PORT,
	    .max_supported_rx_frame_size = max_supported_rx_frame_size,
	    .caps = {
	      .change_max_rx_frame_size = 1,
	    .rss = 1,
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
	    .format_info = format_qppe_edma_rxq_info,
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
	    .format_info = format_qppe_edma_txq_info,
	  },
	},
      };
      clib_dt_property_t *status;
      qppe_port_t port_data = {};
      char *resource_node_name;
      char *ethernet_link_name;
      clib_dt_node_t *ethernet_link_node;
      clib_dt_node_t *phy_node;
      clib_dt_node_t *sfp_node;
      uword device_path_len;
      char *name;
      u32 port_id;

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
      if (port_id >= QPPE_MAX_PORTS)
	{
	  log_warn (dev, "skipping port %u: id exceeds maximum %u", port_id, QPPE_MAX_PORTS - 1);
	  continue;
	}
      if (seen_ports & (1 << port_id))
	{
	  log_warn (dev, "skipping duplicate port id %u", port_id);
	  continue;
	}
      if (n_ports >= QPPE_RX_PROFILE_COUNT)
	{
	  log_err (dev, "cannot add more than %u Ethernet ports", QPPE_RX_PROFILE_COUNT);
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
      foreach_clib_dt_property_string (name, names)
	{
	  rv = vnet_dev_platform_clock_enable (dev, resource_node_name, name);
	  if (rv != VNET_DEV_OK)
	    return VNET_DEV_ERR_INIT_FAILED;
	}

      phy_node = clib_dt_dereference_node (pn, "phy-handle");
      sfp_node = clib_dt_dereference_node (pn, "sfp");
      if (phy_node || sfp_node)
	{
	  ethernet_link_name = phy_node ? "phy-handle" : "sfp";
	  ethernet_link_node = phy_node ? phy_node : sfp_node;
	  rv = vnet_dev_platform_ethernet_phy_open (dev, resource_node_name, ethernet_link_name);
	  if (rv != VNET_DEV_OK)
	    return VNET_DEV_ERR_INIT_FAILED;
	  port_data.ethernet_phy_node_name = resource_node_name;
	  port_data.ethernet_phy_name = ethernet_link_name;
	  log_debug (dev, "using Ethernet PHY for port %u via %s node %v", port_id,
		     ethernet_link_name, ethernet_link_node->path);
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

      rv = qppe_pcs_port_probe (dev, &port_data, pn);
      if (rv != VNET_DEV_OK)
	return rv;

      p = clib_dt_get_node_property_by_name (pn, "mac-address");
      if (!p || p->size != 6)
	p = clib_dt_get_node_property_by_name (pn, "local-mac-address");
      if (p && p->size == 6)
	vnet_dev_set_hw_addr_eth_mac (&args.port.attr.hw_addr, p->data);

      port_data.source_profile = n_ports;
      port_data.reset_names = clib_dt_get_node_property_by_name (pn, "reset-names");
      args.port.initial_data = &port_data;
      if (vnet_dev_port_add (vm, dev, port_id, &args) != VNET_DEV_OK)
	{
	  log_err (dev, "failed to add PPE port %u from device tree node %v", port_id, pn->path);
	  return VNET_DEV_ERR_INIT_FAILED;
	}

      n_ports++;
      log_debug (
	dev,
	"discovered port %u, node %v, source profile %u, label %s, phy-mode %s, managed %s, "
	"MAC %U",
	port_id, pn->path, port_data.source_profile, port_data.label ? port_data.label : "(none)",
	port_data.phy_mode ? port_data.phy_mode : "(unspecified)",
	port_data.managed ? port_data.managed : "(unspecified)", format_vnet_dev_hw_addr,
	&args.port.attr.hw_addr);
    }

  if (n_ports == 0)
    {
      log_err (dev, "device tree contains no enabled Ethernet ports");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  return VNET_DEV_OK;
}

/* Validate the device, enable resources, map registers, then initialize ports. */
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

  /* Reject devices that do not match the supported PPE binding. */
  if (!clib_dt_node_is_compatible (dd->node, QPPE_DT_COMPATIBLE))
    return VNET_DEV_ERR_NOT_SUPPORTED;

  /* Initialize ring availability and retain the PPE device-tree path. */
  qd->avail_rx_ring_bmp = pow2_mask (EDMA_RX_RING_COUNT);
  qd->avail_tx_ring_bmp = pow2_mask (EDMA_TX_RING_COUNT);
  qd->dt_path = dd->node->path;

  log_debug (dev, "initializing platform device %s from device tree node %v", dev->device_id,
	     qd->dt_path);

  /* Configure bandwidth for the interconnects */
  FOREACH_ARRAY_ELT (bw, qppe_interconnects)
    {
      rv = vnet_dev_platform_interconnect_set_bw (dev, "", bw->name, bw->average_bw, bw->peak_bw);
      if (rv != VNET_DEV_OK)
	goto error;
    }

  /* Enable device-level clocks listed in the device tree. */
  log_debug (dev, "opening DT property 'clock-names' on device");
  names = clib_dt_get_node_property_by_name (dd->node, "clock-names");
  foreach_clib_dt_property_string (name, names)
    {
      rv = vnet_dev_platform_clock_enable (dev, "", name);
      if (rv != VNET_DEV_OK)
	goto error;
    }

  /* Apply reset sequences for device-level resets listed in the device tree. */
  log_debug (dev, "opening DT property 'reset-names' on device");
  names = clib_dt_get_node_property_by_name (dd->node, "reset-names");
  foreach_clib_dt_property_string (name, names)
    {
      rv = vnet_dev_platform_reset_pulse (dev, "", name);
      if (rv != VNET_DEV_OK)
	goto error;
    }

  edma_node = clib_dt_get_child_node (dd->node, "ethernet-dma");
  if (!edma_node)
    {
      log_err (dev, "device tree has no ethernet-dma child node");
      goto error;
    }

  /* Enable EDMA resources and perform its reset sequence. */
  names = clib_dt_get_node_property_by_name (edma_node, "clock-names");
  foreach_clib_dt_property_string (name, names)
    {
      rv = vnet_dev_platform_clock_enable (dev, "ethernet-dma", name);
      if (rv != VNET_DEV_OK)
	goto error;
    }

  log_debug (dev, "asserting EDMA reset for %u us", EDMA_RESET_DELAY_US);
  rv = vnet_dev_platform_reset_assert (dev, "ethernet-dma", "edma");
  if (rv != VNET_DEV_OK)
    goto error;
  vlib_process_suspend (vm, EDMA_RESET_DELAY_US * 1e-6);
  rv = vnet_dev_platform_reset_deassert (dev, "ethernet-dma", "edma");
  if (rv != VNET_DEV_OK)
    goto error;
  log_debug (dev, "deasserted reset 'ethernet-dma/edma'; waiting %u us for reset to settle",
	     EDMA_RESET_DELAY_US);
  vlib_process_suspend (vm, EDMA_RESET_DELAY_US * 1e-6);

  last_separator = strrchr ((char *) qd->dt_path, '/');
  if (!last_separator)
    {
      log_err (dev, "device tree path '%v' has no node name", qd->dt_path);
      goto error;
    }
  uio_region_name = last_separator + 1;
  /* Map PPE registers and initialize hardware before adding ports. */
  log_debug (dev, "mapping UIO region '%s' using the platform bus", uio_region_name);
  rv = vnet_dev_platform_map_uio_region (dev, uio_region_name, &qd->regs);
  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "cannot map UIO region '%s'", uio_region_name);
      goto error;
    }
  log_debug (dev, "mapped UIO region '%s' at %p", uio_region_name, qd->regs);

  rv = qppe_bm_init (dev);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = qppe_qm_init (dev);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = qppe_sched_init (dev);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = qppe_edma_init (dev);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = qppe_rss_init (dev);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = qppe_acl_init (dev);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = qppe_acl_pre_ipo_init (dev);
  if (rv != VNET_DEV_OK)
    goto error;

  rv = qppe_add_ports (vm, dev, dd->node);
  if (rv != VNET_DEV_OK)
    goto error;

  return VNET_DEV_OK;

error:
  return VNET_DEV_ERR_INIT_FAILED;
}

static clib_arg_t qppe_dev_args[] = {
  {
    .name = "fill_ring_size",
    .desc = "RX fill ring size (power of two)",
    .type = CLIB_ARG_TYPE_UINT32,
    .min = 32,
    .max = 32768,
    .default_val.uint32 = 1024,
  },
  {
    .type = CLIB_ARG_END,
  },
};

VNET_DEV_REGISTER_DRIVER (qppe) = {
  .name = "qppe",
  .description = "Qualcomm PPE (Packet Processing Engine)",
  .bus = PLATFORM_BUS_NAME,
  .device = {
    .args = qppe_dev_args,
    .data_sz = sizeof (qppe_device_t),
    .dma_address_space_bits = 32,
    .ops = {
      .init = qppe_init,
      .probe = qppe_probe,
      .format_info = format_qppe_dev_info,
    },
  },
};
