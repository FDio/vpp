/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <vlib/buffer_funcs.h>
#include <qppe.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
qppe_open_clock (vnet_dev_t *dev, qppe_device_t *qd, char *node_name, char *name, int fd)
{
  int rv;

  vec_add1 (qd->clocks, ((vnet_dev_platform_clock_t) {
			  .fd = fd,
			}));
  snprintf (qd->clocks[vec_len (qd->clocks) - 1].name, sizeof (qd->clocks[0].name), "%s%s%s",
	    node_name, node_name[0] ? "/" : "", name);
  log_debug (dev, "opened clock '%s%s%s' with fd %d", node_name, node_name[0] ? "/" : "", name, fd);
  if ((!node_name[0] && strcmp (name, "ppe") == 0) ||
      (strcmp (node_name, "ethernet-dma") == 0 &&
       (strcmp (name, "sys") == 0 || strcmp (name, "apb") == 0)))
    {
      rv = vnet_dev_platform_clock_set_rate (fd, PPE_CLOCK_RATE);
      if (rv < 0)
	{
	  log_err (dev, "cannot set clock '%s%s%s' to %u Hz: %s", node_name,
		   node_name[0] ? "/" : "", name, PPE_CLOCK_RATE, strerror (-rv));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      log_debug (dev, "set clock '%s%s%s' to %u Hz", node_name, node_name[0] ? "/" : "", name,
		 PPE_CLOCK_RATE);
    }
  rv = vnet_dev_platform_clock_enable (fd);
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
qppe_open_reset (vnet_dev_t *dev, qppe_device_t *qd, char *node_name, char *name, int fd)
{
  int edma_reset = strcmp (node_name, "ethernet-dma") == 0 && strcmp (name, "edma") == 0;
  int port_reset = strncmp (node_name, "ethernet-ports/port@", 20) == 0;
  char *separator = node_name[0] ? "/" : "";
  int rv;

  vec_add1 (qd->resets, ((vnet_dev_platform_reset_t) {
			  .fd = fd,
			}));
  snprintf (qd->resets[vec_len (qd->resets) - 1].name, sizeof (qd->resets[0].name), "%s%s%s",
	    node_name, separator, name);
  log_debug (dev, "opened reset '%s%s%s' with fd %d", node_name, separator, name, fd);

  if (port_reset)
    return VNET_DEV_OK;

  if (edma_reset)
    {
      log_debug (dev, "asserting EDMA reset for %u us", EDMA_RESET_DELAY_US);
      rv = vnet_dev_platform_reset_assert (fd);
      if (rv < 0)
	{
	  log_err (dev, "cannot assert reset '%s/edma': %s", node_name, strerror (-rv));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      log_debug (dev, "asserted reset '%s/edma'", node_name);
      if (usleep (EDMA_RESET_DELAY_US) != 0)
	{
	  log_err (dev, "wait after asserting reset '%s/edma' failed: %s", node_name,
		   strerror (errno));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      rv = vnet_dev_platform_reset_deassert (fd);
      if (rv < 0)
	{
	  log_err (dev, "cannot deassert reset '%s/edma': %s", node_name, strerror (-rv));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      log_debug (dev, "deasserted reset '%s/edma'; waiting %u us for reset to settle", node_name,
		 EDMA_RESET_DELAY_US);
      if (usleep (EDMA_RESET_DELAY_US) != 0)
	{
	  log_err (dev, "wait after deasserting reset '%s/edma' failed: %s", node_name,
		   strerror (errno));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      return VNET_DEV_OK;
    }

  rv = vnet_dev_platform_reset_pulse (fd);
  if (rv < 0)
    {
      log_err (dev, "cannot pulse reset '%s%s%s': %s", node_name, separator, name, strerror (-rv));
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "pulsed reset '%s%s%s'", node_name, separator, name);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_open_interconnect (vnet_dev_t *dev, qppe_device_t *qd, char *node_name __clib_unused,
			char *name, int fd)
{
  u32 i;
  int rv;

  for (i = 0; i < ARRAY_LEN (qppe_interconnect_bw); i++)
    if (strcmp (name, qppe_interconnect_bw[i].name) == 0)
      break;

  if (i == ARRAY_LEN (qppe_interconnect_bw))
    {
      log_err (dev, "no bandwidth policy for interconnect '%s'", name);
      vnet_dev_platform_resource_close_fd (fd);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  vec_add1 (qd->interconnects, ((vnet_dev_platform_interconnect_t) {
				 .fd = fd,
			       }));
  snprintf (qd->interconnects[vec_len (qd->interconnects) - 1].name,
	    sizeof (qd->interconnects[0].name), "%s", name);
  rv = vnet_dev_platform_interconnect_set_bw (fd, qppe_interconnect_bw[i].average_bw,
					      qppe_interconnect_bw[i].peak_bw);
  if (rv < 0)
    {
      log_err (dev, "cannot set interconnect '%s' bandwidth to average %llu, peak %llu: %s", name,
	       qppe_interconnect_bw[i].average_bw, qppe_interconnect_bw[i].peak_bw, strerror (-rv));
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "opened interconnect '%s' with fd %d, average/peak bandwidth %llu/%llu", name, fd,
	     qppe_interconnect_bw[i].average_bw, qppe_interconnect_bw[i].peak_bw);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_open_phy (vnet_dev_t *dev, qppe_device_t *qd, char *node_name __clib_unused, char *name,
	       int fd)
{
  vec_add1 (qd->phys, ((vnet_dev_platform_phy_t) {
			.fd = fd,
		      }));
  snprintf (qd->phys[vec_len (qd->phys) - 1].name, sizeof (qd->phys[0].name), "%s", name);
  log_debug (dev, "opened PHY '%s' with fd %d", name, fd);
  return VNET_DEV_OK;
}

typedef vnet_dev_rv_t (qppe_resource_open_fn_t) (vnet_dev_t *, qppe_device_t *, char *, char *,
						 int);

static qppe_resource_open_fn_t *qppe_resource_open_handlers[] = {
  [VNET_DEV_PLATFORM_RESOURCE_CLOCK] = qppe_open_clock,
  [VNET_DEV_PLATFORM_RESOURCE_RESET] = qppe_open_reset,
  [VNET_DEV_PLATFORM_RESOURCE_INTERCONNECT] = qppe_open_interconnect,
  [VNET_DEV_PLATFORM_RESOURCE_PHY] = qppe_open_phy,
};

static u8 *
qppe_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_platform_device_info_t *di = args->device_info;

  if (clib_dt_node_is_compatible (di->node, PPE_DT_COMPATIBLE))
    return format (0, "Qualcomm PPE (Packet Processing Engine)");
  return 0;
}

static int
qppe_find_clock_fd (qppe_device_t *qd, char *name)
{
  vnet_dev_platform_clock_t *clock;

  vec_foreach (clock, qd->clocks)
    if (strcmp (clock->name, name) == 0)
      return clock->fd;
  return -1;
}

static vnet_dev_rv_t
qppe_port_reset (vnet_dev_t *dev, qppe_device_t *qd, char *node_name)
{
  vnet_dev_platform_reset_t *reset;
  uword node_name_len = strlen (node_name);
  u32 n_resets = 0;
  int rv;

  vec_foreach (reset, qd->resets)
    if (strncmp (reset->name, node_name, node_name_len) == 0 && reset->name[node_name_len] == '/')
      {
	log_debug (dev, "asserting port reset '%s'", reset->name);
	rv = vnet_dev_platform_reset_assert (reset->fd);
	if (rv < 0)
	  {
	    log_err (dev, "cannot assert port reset '%s': %s", reset->name, strerror (-rv));
	    return VNET_DEV_ERR_INIT_FAILED;
	  }
	n_resets++;
      }

  if (n_resets == 0)
    {
      log_err (dev, "port node '%s' has no opened resets", node_name);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev, "asserted %u port resets; waiting %u us", n_resets, PPE_PORT_RESET_DELAY_US);
  if (usleep (PPE_PORT_RESET_DELAY_US) != 0)
    {
      log_err (dev, "wait after asserting port resets for '%s' failed: %s", node_name,
	       strerror (errno));
      return VNET_DEV_ERR_INIT_FAILED;
    }

  vec_foreach (reset, qd->resets)
    if (strncmp (reset->name, node_name, node_name_len) == 0 && reset->name[node_name_len] == '/')
      {
	rv = vnet_dev_platform_reset_deassert (reset->fd);
	if (rv < 0)
	  {
	    log_err (dev, "cannot deassert port reset '%s': %s", reset->name, strerror (-rv));
	    return VNET_DEV_ERR_INIT_FAILED;
	  }
	log_debug (dev, "deasserted port reset '%s'", reset->name);
      }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_open_resources (vnet_dev_t *dev, qppe_device_t *qd, clib_dt_node_t *node, char *node_name,
		     char *property_name, vnet_dev_platform_resource_type_t type)
{
  clib_dt_property_t *names = clib_dt_get_node_property_by_name (node, property_name);
  u32 offset = 0;

  log_debug (dev, "opening DT property '%s' on node '%s'", property_name,
	     node_name[0] ? node_name : "(device)");

  while (names && offset < names->size)
    {
      char *name = (char *) names->data + offset;
      u32 remaining = names->size - offset;
      u32 name_len = strnlen (name, remaining);
      vnet_dev_rv_t rv;
      int fd;

      if (name_len == remaining || name_len >= VNET_DEV_PLATFORM_RESOURCE_NAME_LEN)
	{
	  log_err (dev, "invalid resource name in device tree property '%s'", property_name);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      if (type < VNET_DEV_PLATFORM_RESOURCE_CLOCK || type > VNET_DEV_PLATFORM_RESOURCE_PHY)
	return VNET_DEV_ERR_INIT_FAILED;
      fd = vnet_dev_platform_resource_open_on_node (dev, type, node_name, name);
      if (fd < 0)
	{
	  log_err (dev, "cannot open %s resource '%s%s%s': %s", property_name, node_name,
		   node_name[0] ? "/" : "", name, strerror (-fd));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      rv = qppe_resource_open_handlers[type](dev, qd, node_name, name, fd);
      if (rv != VNET_DEV_OK)
	return rv;
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
	.rx_clock_fd = -1,
	.tx_clock_fd = -1,
      };
      char *resource_node_name;
      char *ethernet_link_name;
      clib_dt_node_t *ethernet_link_node;
      clib_dt_node_t *phy_node;
      clib_dt_node_t *sfp_node;
      uword device_path_len;
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
      rv = qppe_open_resources (dev, qd, pn, resource_node_name, "clock-names",
				VNET_DEV_PLATFORM_RESOURCE_CLOCK);
      if (rv != VNET_DEV_OK)
	return rv;
      rv = qppe_open_resources (dev, qd, pn, resource_node_name, "reset-names",
				VNET_DEV_PLATFORM_RESOURCE_RESET);
      if (rv != VNET_DEV_OK)
	return rv;
      rv = qppe_port_reset (dev, qd, resource_node_name);
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
      {
	char clock_name[64];
	snprintf (clock_name, sizeof (clock_name), "%s/rx", resource_node_name);
	port_data.rx_clock_fd = qppe_find_clock_fd (qd, clock_name);
	snprintf (clock_name, sizeof (clock_name), "%s/tx", resource_node_name);
	port_data.tx_clock_fd = qppe_find_clock_fd (qd, clock_name);
      }
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
  vnet_dev_platform_clock_t *clock;
  vnet_dev_platform_reset_t *reset;
  vnet_dev_platform_interconnect_t *interconnect;
  vnet_dev_platform_phy_t *phy;
  int *ethernet_phy_fd;

  vec_foreach (clock, qd->clocks)
    vnet_dev_platform_resource_close_fd (clock->fd);
  vec_free (qd->clocks);
  vec_foreach (reset, qd->resets)
    vnet_dev_platform_resource_close_fd (reset->fd);
  vec_free (qd->resets);
  vec_foreach (interconnect, qd->interconnects)
    vnet_dev_platform_resource_close_fd (interconnect->fd);
  vec_free (qd->interconnects);
  vec_foreach (phy, qd->phys)
    vnet_dev_platform_resource_close_fd (phy->fd);
  vec_free (qd->phys);
  vec_foreach (ethernet_phy_fd, qd->ethernet_phy_fds)
    vnet_dev_platform_resource_close_fd (*ethernet_phy_fd);
  vec_free (qd->ethernet_phy_fds);
}

static vnet_dev_rv_t
qppe_check_buffer_pool_dma (vlib_main_t *vm, vnet_dev_t *dev)
{
  u8 buffer_pool_index = vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);
  vlib_buffer_pool_t *buffer_pool = vlib_get_buffer_pool (vm, buffer_pool_index);
  u32 i;

  for (i = 0; i < buffer_pool->n_buffers; i++)
    {
      u32 buffer_index = buffer_pool->buffers[i];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      uword buffer_dma = vnet_dev_get_dma_addr (vm, dev, buffer->data);

      if (buffer_dma > 0xffffffff - (buffer_pool->data_size - 1))
	{
	  log_err (dev,
		   "VPP buffer pool %u buffer %u DMA range 0x%lx-0x%lx exceeds the 32-bit EDMA "
		   "address space",
		   buffer_pool_index, buffer_index, buffer_dma,
		   buffer_dma + buffer_pool->data_size - 1);
	  return VNET_DEV_ERR_NOT_SUPPORTED;
	}
    }

  log_notice (dev, "validated DMA addresses for all %u buffers in VPP buffer pool %u",
	      buffer_pool->n_buffers, buffer_pool_index);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  clib_dt_node_t *edma_node;
  vnet_dev_rv_t rv;
  char *uio_region_name;
  char *last_separator;

  qd->avail_rxfill_ring_bmp = (1 << EDMA_RX_RING_COUNT) - 1;
  qd->avail_rxdesc_ring_bmp = (1 << EDMA_RX_RING_COUNT) - 1;
  qd->avail_txdesc_ring_bmp = (1 << EDMA_TX_RING_COUNT) - 1;
  qd->avail_txcmpl_ring_bmp = (1 << EDMA_TX_RING_COUNT) - 1;
  qd->dt_path = dd->node->path;

  if (!clib_dt_node_is_compatible (dd->node, PPE_DT_COMPATIBLE))
    return VNET_DEV_ERR_NOT_SUPPORTED;

  rv = qppe_check_buffer_pool_dma (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  log_debug (dev, "initializing platform device %s from device tree node %v", dev->device_id,
	     qd->dt_path);

  rv = qppe_open_resources (dev, qd, dd->node, "", "interconnect-names",
			    VNET_DEV_PLATFORM_RESOURCE_INTERCONNECT);
  if (rv != VNET_DEV_OK)
    goto error;
  rv = qppe_open_resources (dev, qd, dd->node, "", "clock-names", VNET_DEV_PLATFORM_RESOURCE_CLOCK);
  if (rv != VNET_DEV_OK)
    goto error;
  rv = qppe_open_resources (dev, qd, dd->node, "", "reset-names", VNET_DEV_PLATFORM_RESOURCE_RESET);
  if (rv != VNET_DEV_OK)
    goto error;
  rv = qppe_open_resources (dev, qd, dd->node, "", "phy-names", VNET_DEV_PLATFORM_RESOURCE_PHY);
  if (rv != VNET_DEV_OK)
    goto error;

  edma_node = clib_dt_get_child_node (dd->node, "ethernet-dma");
  if (!edma_node)
    {
      log_err (dev, "device tree has no ethernet-dma child node");
      goto error;
    }
  rv = qppe_open_resources (dev, qd, edma_node, "ethernet-dma", "clock-names",
			    VNET_DEV_PLATFORM_RESOURCE_CLOCK);
  if (rv != VNET_DEV_OK)
    goto error;
  rv = qppe_open_resources (dev, qd, edma_node, "ethernet-dma", "reset-names",
			    VNET_DEV_PLATFORM_RESOURCE_RESET);
  if (rv != VNET_DEV_OK)
    goto error;

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

  rv = qppe_hw_init (dev);
  if (rv != VNET_DEV_OK)
    goto error;

  return VNET_DEV_OK;

error:
  qppe_close_resources (qd);
  if (qd->regs)
    {
      vnet_dev_platform_unmap_regions (dev);
      qd->regs = 0;
    }
  return VNET_DEV_ERR_INIT_FAILED;
}

static void
qppe_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);

  qd->hw_initialized = 0;
  if (qd->regs)
    vnet_dev_platform_unmap_regions (dev);
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
