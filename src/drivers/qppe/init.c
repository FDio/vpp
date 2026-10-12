/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>
#include <qppe.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "init",
};

vnet_dev_node_t qppe_rx_node = {};
vnet_dev_node_t qppe_tx_node = {};

static u8 *
qppe_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_platform_device_info_t *di = args->device_info;

  if (clib_dt_node_is_compatible (di->node, QPPE_DT_COMPATIBLE))
    return format (0, "Qualcomm PPE (Packet Processing Engine)");
  return 0;
}

static vnet_dev_rv_t
qppe_add_ports (vlib_main_t *vm, vnet_dev_t *dev, clib_dt_node_t *node)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  clib_dt_node_t *ports = clib_dt_get_child_node (node, "ethernet-ports");
  u8 seen_ports = 0;

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
	    .max_supported_rx_frame_size = 1514,
	  },
	  .ops = {
	    .init = qppe_port_init,
	    .deinit = qppe_port_deinit,
	    .start = qppe_port_start,
	    .stop = qppe_port_stop,
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
	  },
	},
      };
      clib_dt_property_t *status;
      qppe_port_t port_data = {};
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
      seen_ports |= 1 << port_id;

      p = clib_dt_get_node_property_by_name (pn, "label");
      port_data.id = port_id;
      port_data.label = p ? clib_dt_property_get_string (p) : 0;
      p = clib_dt_get_node_property_by_name (pn, "phy-mode");
      port_data.phy_mode = p ? clib_dt_property_get_string (p) : 0;
      p = clib_dt_get_node_property_by_name (pn, "managed");
      port_data.managed = p ? clib_dt_property_get_string (p) : 0;

      p = clib_dt_get_node_property_by_name (pn, "mac-address");
      if (!p || p->size != 6)
	p = clib_dt_get_node_property_by_name (pn, "local-mac-address");
      if (p && p->size == 6)
	vnet_dev_set_hw_addr_eth_mac (&args.port.attr.hw_addr, p->data);

      args.port.initial_data = &port_data;
      if (vnet_dev_port_add (vm, dev, port_id, &args) != VNET_DEV_OK)
	{
	  log_err (dev, "failed to add PPE port %u from device tree node %v", port_id, pn->path);
	  return VNET_DEV_ERR_INIT_FAILED;
	}

      qd->n_ports++;
      log_debug (dev,
		 "discovered port %u, node %v, label %s, phy-mode %s, managed %s, "
		 "MAC %U",
		 port_id, pn->path, port_data.label ? port_data.label : "(none)",
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

static vnet_dev_rv_t
qppe_open_clock (vnet_dev_t *dev, qppe_device_t *qd, char *name, int fd)
{
  int rv;

  vec_add1 (qd->clocks, ((vnet_dev_platform_clock_t) {
			  .fd = fd,
			}));
  snprintf (qd->clocks[vec_len (qd->clocks) - 1].name, sizeof (qd->clocks[0].name), "%s", name);
  log_debug (dev, "opened clock '%s' with fd %d", name, fd);
  rv = vnet_dev_platform_clock_enable (fd);
  if (rv < 0)
    {
      log_err (dev, "cannot enable clock '%s': %s", name, strerror (-rv));
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "enabled clock '%s'", name);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_open_reset (vnet_dev_t *dev, qppe_device_t *qd, char *name, int fd)
{
  int rv;

  vec_add1 (qd->resets, ((vnet_dev_platform_reset_t) {
			  .fd = fd,
			}));
  snprintf (qd->resets[vec_len (qd->resets) - 1].name, sizeof (qd->resets[0].name), "%s", name);
  log_debug (dev, "opened reset '%s' with fd %d", name, fd);
  rv = vnet_dev_platform_reset_pulse (fd);
  if (rv < 0)
    {
      log_err (dev, "cannot pulse reset '%s': %s", name, strerror (-rv));
      return VNET_DEV_ERR_INIT_FAILED;
    }
  log_debug (dev, "pulsed reset '%s'", name);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_open_interconnect (vnet_dev_t *dev, qppe_device_t *qd, char *name, int fd)
{
  vec_add1 (qd->interconnects, ((vnet_dev_platform_interconnect_t) {
				 .fd = fd,
			       }));
  snprintf (qd->interconnects[vec_len (qd->interconnects) - 1].name,
	    sizeof (qd->interconnects[0].name), "%s", name);
  log_debug (dev, "opened interconnect '%s' with fd %d", name, fd);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_open_phy (vnet_dev_t *dev, qppe_device_t *qd, char *name, int fd)
{
  vec_add1 (qd->phys, ((vnet_dev_platform_phy_t) {
			.fd = fd,
		      }));
  snprintf (qd->phys[vec_len (qd->phys) - 1].name, sizeof (qd->phys[0].name), "%s", name);
  log_debug (dev, "opened PHY '%s' with fd %d", name, fd);
  return VNET_DEV_OK;
}

typedef vnet_dev_rv_t (qppe_resource_open_fn_t) (vnet_dev_t *, qppe_device_t *, char *, int);

static qppe_resource_open_fn_t *qppe_resource_open_handlers[] = {
  [VNET_DEV_PLATFORM_RESOURCE_CLOCK] = qppe_open_clock,
  [VNET_DEV_PLATFORM_RESOURCE_RESET] = qppe_open_reset,
  [VNET_DEV_PLATFORM_RESOURCE_INTERCONNECT] = qppe_open_interconnect,
  [VNET_DEV_PLATFORM_RESOURCE_PHY] = qppe_open_phy,
};

static vnet_dev_rv_t
qppe_open_resources (vnet_dev_t *dev, qppe_device_t *qd, clib_dt_node_t *node, char *property_name,
		     vnet_dev_platform_resource_type_t type)
{
  clib_dt_property_t *names = clib_dt_get_node_property_by_name (node, property_name);
  u32 offset = 0;

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
      fd = vnet_dev_platform_resource_open (dev, type, name);
      if (fd < 0)
	{
	  log_err (dev, "cannot open %s resource '%s': %s", property_name, name, strerror (-fd));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      rv = qppe_resource_open_handlers[type](dev, qd, name, fd);
      if (rv != VNET_DEV_OK)
	return rv;
      offset += name_len + 1;
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
}

static vnet_dev_rv_t
qppe_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  vnet_dev_rv_t rv;
  char *uio_region_name;
  char *last_separator;

  qd->dt_path = dd->node->path;

  if (!clib_dt_node_is_compatible (dd->node, QPPE_DT_COMPATIBLE))
    return VNET_DEV_ERR_NOT_SUPPORTED;

  log_debug (dev, "initializing platform device %s from device tree node %v", dev->device_id,
	     qd->dt_path);

  rv = qppe_open_resources (dev, qd, dd->node, "clock-names", VNET_DEV_PLATFORM_RESOURCE_CLOCK);
  if (rv != VNET_DEV_OK)
    goto error;
  rv = qppe_open_resources (dev, qd, dd->node, "reset-names", VNET_DEV_PLATFORM_RESOURCE_RESET);
  if (rv != VNET_DEV_OK)
    goto error;
  rv = qppe_open_resources (dev, qd, dd->node, "interconnect-names",
			    VNET_DEV_PLATFORM_RESOURCE_INTERCONNECT);
  if (rv != VNET_DEV_OK)
    goto error;
  rv = qppe_open_resources (dev, qd, dd->node, "phy-names", VNET_DEV_PLATFORM_RESOURCE_PHY);
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

  log_notice (dev,
	      "PPE registers mapped (%u DT ports); hardware data path "
	      "bring-up not implemented yet",
	      qd->n_ports);

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
