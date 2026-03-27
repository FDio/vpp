/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/bus/platform.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/mac_address.h>
#include <vppinfra/linux/sysfs.h>

#include <cadence.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CDN_UIO_SYSFS_ROOT "/sys/bus/platform/devices"
#define CDN_UIO_CLASS_ROOT "/sys/class/uio"
#define CDN_UIO_DEV_ROOT   "/dev"

VLIB_REGISTER_LOG_CLASS (cdn_log) = {
  .class_name = "cadence",
  .subclass_name = "init",
};

#define _(f, n, s, d) { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },
static vlib_error_desc_t cdn_rx_node_counters[] = { foreach_cdn_rx_node_counter };
static vlib_error_desc_t cdn_tx_node_counters[] = { foreach_cdn_tx_node_counter };
#undef _

vnet_dev_node_t cdn_rx_node = {
  .format_trace = format_cdn_rx_trace,
  .error_counters = cdn_rx_node_counters,
  .n_error_counters = ARRAY_LEN (cdn_rx_node_counters),
};

vnet_dev_node_t cdn_tx_node = {
  .format_trace = format_cdn_tx_trace,
  .error_counters = cdn_tx_node_counters,
  .n_error_counters = ARRAY_LEN (cdn_tx_node_counters),
};

static clib_error_t *
cdn_map_uio (vnet_dev_t *dev, cdn_device_t *cd)
{
  char path[PATH_MAX];
  char dev_path[PATH_MAX];
  DIR *dir = 0;
  struct dirent *de;
  int uio_num = -1;
  unsigned long long size = 0;
  clib_error_t *err = 0;
  char *device_name = dev->device_id + sizeof (PLATFORM_BUS_NAME);

  snprintf (path, sizeof (path), "%s/%s/uio", CDN_UIO_SYSFS_ROOT, device_name);
  dir = opendir (path);
  if (dir == 0)
    return clib_error_return_unix (0, "opendir %s", path);

  while ((de = readdir (dir)) != 0)
    {
      if (sscanf (de->d_name, "uio%d", &uio_num) == 1)
	break;
    }

  closedir (dir);

  if (uio_num < 0)
    return clib_error_return (0, "no UIO device under %s", path);

  snprintf (path, sizeof (path), "%s/uio%d/maps/map0/size", CDN_UIO_CLASS_ROOT, uio_num);
  err = clib_sysfs_read (path, "0x%llx", &size);
  if (err)
    return err;

  snprintf (dev_path, sizeof (dev_path), "%s/uio%d", CDN_UIO_DEV_ROOT, uio_num);
  cd->uio_fd = open (dev_path, O_RDWR);
  if (cd->uio_fd < 0)
    return clib_error_return_unix (0, "open %s", dev_path);

  cd->regs_size = round_pow2 (size, clib_max (getpagesize (), 4096));
  cd->regs = mmap (0, cd->regs_size, PROT_READ | PROT_WRITE, MAP_SHARED, cd->uio_fd, 0);
  if (cd->regs == MAP_FAILED)
    {
      err = clib_error_return_unix (0, "mmap %s", dev_path);
      close (cd->uio_fd);
      cd->uio_fd = -1;
      cd->regs = 0;
      return err;
    }

  log_debug (dev, "mapped %s size 0x%x to %p", dev_path, cd->regs_size, cd->regs);

  return 0;
}

static void
cdn_unmap_uio (cdn_device_t *cd)
{
  if (cd->regs)
    {
      munmap (cd->regs, cd->regs_size);
      cd->regs = 0;
    }

  if (cd->uio_fd >= 0)
    {
      close (cd->uio_fd);
      cd->uio_fd = -1;
    }
}

static u8 *
cdn_probe (vlib_main_t *vm __clib_unused, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_platform_device_info_t *di = args->device_info;

  if (clib_dt_node_is_compatible (di->node, "cisco,crayar-macb"))
    return format (0, "Cadence MACB/GEM");

  return 0;
}

static vnet_dev_rv_t
cdn_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  cdn_device_t *cd = vnet_dev_get_data (dev);
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  clib_dt_property_t *p;
  cdn_mid_t mid;
  cdn_dcfg6_t dcfg6;
  u8 mac[6];
  vnet_dev_port_add_args_t port_add_args = {
    .port = {
      .attr = {
	.type = VNET_DEV_PORT_TYPE_ETHERNET,
	.max_rx_queues = 8,
	.max_tx_queues = 8,
	.max_supported_rx_frame_size = 10240,
	.caps.change_max_rx_frame_size = 1,
      },
      .ops = {
	.init = cdn_port_init,
	.start = cdn_port_start,
	.stop = cdn_port_stop,
	.clear_counters = cdn_port_clear_counters,
	.config_change = cdn_port_cfg_change,
	.config_change_validate = cdn_port_cfg_change_validate,
      },
      .data_size = sizeof (cdn_port_t),
    },
    .rx_node = &cdn_rx_node,
    .tx_node = &cdn_tx_node,
    .rx_queue = {
      .config = {
	.data_size = sizeof (cdn_rxq_t),
	.default_size = 512,
	.size_is_power_of_two = 1,
	.min_size = 64,
	.max_size = 8192,
      },
      .ops = {
	.alloc = cdn_rx_queue_alloc,
	.free = cdn_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
	.data_size = sizeof (cdn_txq_t),
	.default_size = 512,
	.size_is_power_of_two = 1,
	.min_size = 64,
	.max_size = 4096,
      },
      .ops = {
	.alloc = cdn_tx_queue_alloc,
	.free = cdn_tx_queue_free,
      },
    },
  };
  clib_error_t *err;
  vnet_dev_rv_t rv;
  u32 mid_u32, mod_id_num, queue_mask;
  u32 n_queues;

  if (!clib_dt_node_is_compatible (dd->node, "cisco,crayar-macb"))
    return VNET_DEV_ERR_NOT_SUPPORTED;

  cd->uio_fd = -1;
  cd->phy_mode = CDN_PHY_MODE_UNKNOWN;

  p = clib_dt_get_node_property_by_name (dd->node, "phy-mode");
  if (p)
    {
      char *phy_mode;

      phy_mode = clib_dt_property_get_string (p);
      if (strcmp (phy_mode, "sgmii") == 0)
	cd->phy_mode = CDN_PHY_MODE_SGMII;
      else if (strcmp (phy_mode, "10gbase-r") == 0)
	cd->phy_mode = CDN_PHY_MODE_10GBASER;

      log_debug (dev, "phy-mode '%s' parsed as %u", phy_mode, cd->phy_mode);
    }
  else
    log_debug (dev, "phy-mode missing");

  err = cdn_map_uio (dev, cd);
  if (err)
    {
      log_err (dev, "%U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  mid_u32 = cdn_reg_rd (dev, cd, CDN_MID);
  mid.as_u32 = mid_u32;
  mod_id_num = mid.idnum;
  cd->is_gem = mod_id_num >= 0x2;
  if (!cd->is_gem)
    {
      log_err (dev, "only GEM with 64-bit DMA is supported");
      cdn_unmap_uio (cd);
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  dcfg6.as_u32 = cdn_reg_rd (dev, cd, CDN_DCFG6);
  if (!dcfg6.daw64)
    {
      log_err (dev, "64-bit DMA is required");
      cdn_unmap_uio (cd);
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  queue_mask = 1;
  queue_mask |= dcfg6.queue_mask;
  ASSERT (((1u << count_set_bits (queue_mask)) - 1) == queue_mask);

  cd->queue_mask = queue_mask;
  n_queues = count_set_bits (queue_mask);
  port_add_args.port.attr.max_rx_queues = n_queues;
  port_add_args.port.attr.max_tx_queues = n_queues;

  log_notice (dev, "MID 0x%08x idnum 0x%x ip %s queue-mask 0x%x", mid_u32, mod_id_num,
	      mod_id_num == CDN_MOD_ID_7021 ? "7021" :
	      mod_id_num == CDN_MOD_ID_7014 ? "7014" :
					      "unknown",
	      cd->queue_mask);

  /* Use a locally administered fallback MAC until burned-in address support is added. */
  ethernet_mac_address_generate (mac);
  vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr, mac);
  log_debug (dev, "fallback mac %U", format_ethernet_address, mac);

  rv = vnet_dev_port_add (vm, dev, 0, &port_add_args);
  if (rv != VNET_DEV_OK)
    cdn_unmap_uio (cd);

  return rv;
}

static void
cdn_deinit (vlib_main_t *vm __clib_unused, vnet_dev_t *dev)
{
  cdn_device_t *cd = vnet_dev_get_data (dev);

  cdn_unmap_uio (cd);
}

VNET_DEV_REGISTER_DRIVER (cdn) = {
  .name = "cadence",
  .description = "Cadence MACB/GEM",
  .bus = PLATFORM_BUS_NAME,
  .device = {
    .data_sz = sizeof (cdn_device_t),
    .ops = {
      .deinit = cdn_deinit,
      .init = cdn_init,
      .probe = cdn_probe,
      .format_info = format_cdn_dev_info,
    },
  },
};
