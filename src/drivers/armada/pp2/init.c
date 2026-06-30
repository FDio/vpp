/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <vppinfra/ring.h>
#include <vppinfra/linux/sysfs.h>
#include <pp2/pp2.h>
#include <vnet/ethernet/ethernet.h>

#include <net/if.h>
#include <netinet/in.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <unistd.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "init",
};

typedef struct
{
  char *phy_mode;
  u8 gop_index;
  u8 is_xlg : 1;
} mvpp2_mac_data_t;

static const mvpp2_mac_data_t mvpp2_mac_data[][3] = {
  {
    {
      .phy_mode = "KR",
      .is_xlg = 1,
    },
    {
      .phy_mode = "RGMII",
      .gop_index = 2,
    },
    {
      .phy_mode = "RGMII",
      .gop_index = 3,
    },
  },
  {
    {
      .phy_mode = "KR",
      .is_xlg = 1,
    },
    {
      .phy_mode = "RGMII",
      .gop_index = 2,
    },
    {
      .phy_mode = "RGMII",
      .gop_index = 3,
    },
  },
  {
    {
      .phy_mode = "KR",
      .is_xlg = 1,
    },
    {
      .phy_mode = "RGMII",
      .gop_index = 2,
    },
    {
      .phy_mode = "RGMII",
      .gop_index = 3,
    },
  },
  {
    {
      .phy_mode = "KR",
      .is_xlg = 1,
    },
    {
      .phy_mode = "RGMII",
      .gop_index = 2,
    },
    {
      .phy_mode = "RGMII",
      .gop_index = 3,
    },
  },
};

static clib_arg_t mvpp2_dev_args[] = {
  {
    .name = "force_bppe_addr",
    .desc = "Force the shared BPPE address window to the first VPP pool",
    .type = CLIB_ARG_TYPE_BOOL,
  },
  {
    .type = CLIB_ARG_END,
  },
};

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = (d), .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t mvpp2_rx_node_counters[] = { foreach_mvpp2_rx_node_counter };
vlib_error_desc_t mvpp2_tx_node_counters[] = { foreach_mvpp2_tx_node_counter };
#undef _

vnet_dev_node_t mvpp2_rx_node = {
  .error_counters = mvpp2_rx_node_counters,
  .n_error_counters = ARRAY_LEN (mvpp2_rx_node_counters),
  .format_trace = format_mvpp2_rx_trace,
};

vnet_dev_node_t mvpp2_tx_node = {
  .error_counters = mvpp2_tx_node_counters,
  .n_error_counters = ARRAY_LEN (mvpp2_tx_node_counters),
  .format_trace = format_mvpp2_tx_trace,
};

static u8 *
mvpp2_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_platform_device_info_t *di = args->device_info;

  if (clib_dt_node_is_compatible (di->node, "marvell,armada-7k-pp22"))
    return format (0, "Marvell Armada Packet Processor");
  return 0;
}
static void
mvpp2_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  log_debug (dev, "");

  mvpp2_loopback_deinit (vm, dev);
  for (u32 i = 0; i < ARRAY_LEN (md->threads); i++)
    if (md->threads[i].hif.descs)
      mvpp2_hif_free (vm, dev, i);

  vnet_dev_platform_unmap_regions (dev);
}

static u32
mvpp2_port_get_if_index (vnet_dev_t *dev, clib_dt_node_t *port_node)
{
  char net_path[PATH_MAX];
  char real_path[PATH_MAX];
  char path[PATH_MAX];
  u8 *port_node_path;
  struct dirent *e;
  DIR *dir;
  u32 if_index = 0;

  port_node_path = format (0, CLIB_DT_LINUX_PREFIX "%v%c", port_node->path, 0);
  snprintf (net_path, sizeof (net_path), "/sys/bus/platform/devices/%s/net",
	    dev->device_id + sizeof (PLATFORM_BUS_NAME));
  dir = opendir (net_path);
  if (!dir)
    {
      log_warn (dev, "cannot open %s: %s", net_path, strerror (errno));
      vec_free (port_node_path);
      return 0;
    }

  while ((e = readdir (dir)))
    {
      if (e->d_name[0] == '.')
	continue;

      snprintf (path, sizeof (path), "%s/%s/of_node", net_path, e->d_name);
      if (realpath (path, real_path) && strcmp (real_path, (char *) port_node_path) == 0)
	{
	  if_index = if_nametoindex (e->d_name);
	  if (if_index)
	    break;
	}
    }

  closedir (dir);
  vec_free (port_node_path);
  return if_index;
}

static vnet_dev_rv_t
mvpp2_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  vnet_dev_rv_t mrv;
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  clib_dt_node_t *sc;
  uintptr_t mem_base;
  int pp_id = -1;
  u32 i;
  u16 n_threads = vlib_get_n_threads ();

  if (!clib_dt_node_is_compatible (dd->node, "marvell,armada-7k-pp22"))
    return VNET_DEV_ERR_NOT_SUPPORTED;

  sc = clib_dt_dereference_node (dd->node, "marvell,system-controller");

  if (sc && vec_len (sc->path) > strlen ("/cpX/"))
    {
      if (strncmp ((char *) sc->path, "/cp0/", 4) == 0)
	pp_id = 0;
      else if (strncmp ((char *) sc->path, "/cp1/", 4) == 0)
	pp_id = 1;
    }

  if (pp_id < 0)
    return VNET_DEV_ERR_UNKNOWN_DEVICE;

  foreach_clib_dt_tree_node (n, clib_dt_get_root_node (sc))
    if (clib_dt_node_is_compatible (n, "marvell,mv88e6190") ||
	clib_dt_node_is_compatible (n, "marvell,mv88e6393x"))
      {
	clib_dt_node_t *ports;

	log_debug (dev, "found mv88e6190 compatible switch at %v", n->path);
	ports = clib_dt_get_child_node (n, "ports");
	foreach_clib_dt_child_node (pn, ports)
	  {
	    u32 reg = CLIB_U32_MAX;
	    char *label = "(no label)";
	    clib_dt_property_t *p;
	    clib_dt_node_t *ref;

	    p = clib_dt_get_node_property_by_name (pn, "reg");
	    if (p)
	      reg = clib_dt_property_get_u32 (p);
	    p = clib_dt_get_node_property_by_name (pn, "label");
	    if (p)
	      label = clib_dt_property_get_string (p);

	    log_debug (dev, "port %u label %s", reg, label);

	    ref = clib_dt_dereference_node (pn, "phy-handle");
	    if (ref)
	      log_debug (dev, "  phy is %v", ref->path);

	    ref = clib_dt_dereference_node (pn, "sfp");
	    if (ref)
	      log_debug (dev, "  sfp is %v", ref->path);

	    ref = clib_dt_dereference_node (pn, "ethernet");
	    if (ref)
	      log_debug (dev, "  connected to %v", ref->path);

	    p = clib_dt_get_node_property_by_name (pn, "phy-mode");
	    if (p)
	      log_debug (dev, "  phy mode is %s",
			 clib_dt_property_get_string (p));
	  }
      }

  md->pp_id = pp_id;
  md->hif_reserved_map = 0xf;
  md->bm_pool_reserved_map = 0x7;
  md->force_bppe_addr = clib_args_get_bool_val_by_name (dev->args, "force_bppe_addr");

  mrv = vnet_dev_platform_map_uio_region (dev, "pp", (void **) &mem_base);
  if (!mrv)
    {
      md->pp_base = mem_base;
      mrv = vnet_dev_platform_map_uio_region (dev, "mspg", (void **) &mem_base);
      if (!mrv)
	{
	  md->gop_hw_mspg = mem_base;
	  mrv = vnet_dev_platform_map_uio_region (dev, "cm3", (void **) &mem_base);
	  if (mrv)
	    {
	      log_warn (dev, "tx_pause not supported");
	      mrv = VNET_DEV_OK;
	    }
	  else
	    md->cm3_base = mem_base;
	}
    }

  if (mrv)
    {
      log_err (dev, "platform MMIO mapping failed, err %d", mrv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  md->version = mvpp2_dev_reg_rd (dev, MVPP2_VER_ID_REG);
  md->gop_hw_gmac = (mvpp2_mac_unit_desc_t) {
    .base = md->gop_hw_mspg + 0xE00,
    .obj_size = 0x1000,
  };
  md->gop_hw_xlg_mac = (mvpp2_mac_unit_desc_t) {
    .base = md->gop_hw_mspg + 0xF00,
    .obj_size = 0x1000,
  };

  mvpp2_bm_flush_pools (dev, md->bm_pool_reserved_map);
  rv = mvpp2_cls_mng_init (dev);
  if (rv != VNET_DEV_OK)
    goto done;
  md->free_bpools = pow2_mask (MVPP2_NUM_BPOOLS) ^ md->bm_pool_reserved_map;

  if (n_threads > MVPP2_MAX_THREADS ||
      n_threads > count_set_bits (pow2_mask (MVPP2_NUM_HIFS) ^ md->hif_reserved_map))
    {
      log_err (dev, "no enough HIFs (needed %u available %u)", n_threads,
	       count_set_bits (pow2_mask (MVPP2_NUM_HIFS) ^ md->hif_reserved_map));
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  for (i = 0; i < n_threads; i++)
    {
      mrv = mvpp2_hif_alloc (vm, dev, &md->threads[i].hif, 2048);
      if (mrv)
	{
	  log_err (dev, "HIF allocation failed for thread %u, err %d", i, mrv);
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto done;
	}
      log_debug (dev, "HIF %u allocated for thread %u", md->threads[i].hif.id, i);
    }

  mrv = mvpp2_loopback_init (vm, dev);
  if (mrv)
    {
      log_err (dev, "loopback initialization failed, err %d", mrv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  foreach_clib_dt_child_node (cn, dd->node)
    {
      clib_dt_property_t *p;
      const mvpp2_mac_data_t *mac;
      char netdev_name[IFNAMSIZ];
      struct ifreq s = {};
      u32 if_index;
      u8 port_id;
      int fd, srv;

      p = clib_dt_get_node_property_by_name (cn, "port-id");

      if (!clib_dt_property_is_u32 (p))
	continue;

      port_id = clib_dt_property_get_u32 (p);
      log_debug (dev, "found port with id %u", port_id);

      if (port_id >= ARRAY_LEN (mvpp2_mac_data[md->pp_id]))
	continue;
      mac = mvpp2_mac_data[md->pp_id] + port_id;

      p = clib_dt_get_node_property_by_name (cn, "status");
      if (p && strcmp (clib_dt_property_get_string (p), "disabled") == 0)
	continue;

      if_index = mvpp2_port_get_if_index (dev, cn);
      if (if_index == 0 || if_indextoname (if_index, netdev_name) == 0)
	{
	  log_warn (dev, "failed to get netdev for port %u, skipping", port_id);
	  continue;
	}

      srv = -1;
      if ((fd = socket (PF_INET, SOCK_DGRAM, IPPROTO_IP)) >= 0)
	{
	  strcpy (s.ifr_name, netdev_name);
	  srv = ioctl (fd, SIOCGIFHWADDR, &s);
	  close (fd);
	}

      if (srv < 0)
	{
	  log_warn (dev, "unable to get hw address, skipping port %u", port_id);
	  continue;
	}
      log_debug (dev, "adding port %u (netdev name %s, hwaddr %U)", port_id, netdev_name,
		 format_ethernet_address, s.ifr_addr.sa_data);

      mvpp2_port_t mvpp2_port = {
	.id = port_id,
	.if_index = if_index,
	.gop_index = mac->gop_index,
	.is_xlg = mac->is_xlg,
	.has_xlg = mac->gop_index == 0 || (mac->gop_index == 2 && md->version == MVPP2_VER_PP23),
	.phy_mode = mac->phy_mode,
      };

      vnet_dev_port_add_args_t port_add_args = {
        .port = {
          .attr = {
            .type = VNET_DEV_PORT_TYPE_ETHERNET,
            .max_rx_queues = MVPP2_PORT_MAX_RX_QUEUES,
            .max_tx_queues = MVPP2_PORT_MAX_TX_QUEUES,
            .max_supported_rx_frame_size = MVPP2_MAX_RX_FRAME_SIZE,
            .caps = {
              .change_max_rx_frame_size = 1,
            },
            .tx_offloads = {
              .ip4_cksum = 1,
            },
          },
	  .args = CLIB_ARGS ({
            .type = CLIB_ARG_TYPE_ENUM,
            .name = "rss_hash",
            .desc = "RSS Hash type (2-tuple, 5-tuple)",
            .default_val.enum_val = MVPP2_PORT_HASH_5_TUPLE,
            .enum_vals = CLIB_ARG_ENUM_VALS(
              { .val = MVPP2_PORT_HASH_2_TUPLE, .name = "2-tuple", },
              { .val = MVPP2_PORT_HASH_5_TUPLE, .name = "5-tuple", },
            ),
          }),
          .ops = {
            .init = mvpp2_port_init,
            .deinit = mvpp2_port_deinit,
            .start = mvpp2_port_start,
            .stop = mvpp2_port_stop,
            .config_change = mvpp2_port_cfg_change,
            .config_change_validate = mvpp2_port_cfg_change_validate,
            .format_status = format_mvpp2_port_status,
	    .clear_counters = mvpp2_port_clear_counters,
          },
          .data_size = sizeof (mvpp2_port_t),
          .initial_data = &mvpp2_port,
        },
    .rx_node = &mvpp2_rx_node,
    .tx_node = &mvpp2_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (mvpp2_rxq_t),
        .default_size = 512,
        .multiplier = 32,
        .min_size = 32,
        .max_size = 8192,
	.size_is_power_of_two = 1,
      },
      .ops = {
	  .clear_counters = mvpp2_rxq_clear_counters,
	  .format_info = format_mvpp2_rxq_info,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (mvpp2_txq_t),
        .default_size = 512,
        .multiplier = 32,
        .min_size = 32,
        .max_size = 8192,
	.size_is_power_of_two = 1,
          },
      .ops = {
	  .alloc = mvpp2_txq_alloc,
	  .free = mvpp2_txq_free,
	  .clear_counters = mvpp2_txq_clear_counters,
	  .format_info = format_mvpp2_txq_info,
      },
        },
      };

      vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr,
				    (u8 *) s.ifr_addr.sa_data);

      vnet_dev_port_add (vm, dev, port_id, &port_add_args);
    }

done:
  if (rv != VNET_DEV_OK)
    mvpp2_deinit (vm, dev);
  return rv;
}

VNET_DEV_REGISTER_DRIVER (pp2) = {
  .name = "mvpp2",
  .description = "Marvell Armada Packet Processor v2",
  .bus = PLATFORM_BUS_NAME,
  .device = {
    .data_sz = sizeof (mvpp2_device_t),
    .args = mvpp2_dev_args,
    .ops = {
      .init = mvpp2_init,
      .deinit = mvpp2_deinit,
      .probe = mvpp2_probe,
      .format_info = format_mvpp2_dev_info,
    },
  },
};
