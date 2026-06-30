/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <vppinfra/ring.h>
#include <vppinfra/linux/sysfs.h>
#include <musdk.h>
#include <pp2/pp2.h>
#include <vnet/ethernet/ethernet.h>

#include <net/if.h>
#include <netinet/in.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "init",
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
};

static u8 *
mvpp2_probe (vlib_main_t *vm, vnet_dev_probe_args_t *args)
{
  vnet_dev_bus_platform_device_info_t *di = args->device_info;

  if (clib_dt_node_is_compatible (di->node, "marvell,armada-7k-pp22"))
    return format (0, "Marvell Armada Packet Processor v2.2");
  return 0;
}
static void
mvpp2_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  log_debug (dev, "");
  if (!md->is_initialized)
    return;

  if (md->dummy_short_bpool.is_initialized)
    {
      pp2_bpool_deinit (vm, dev, &md->dummy_short_bpool);
    }

  for (u32 i = 0; i < ARRAY_LEN (md->threads); i++)
    if (md->threads[i].dm_if.desc_virt_arr)
      pp2_hif_deinit (vm, dev, i);

  pp2_loopback_deinit (md);
  if (md->pp_base)
    munmap ((void *) md->pp_base, md->pp_map_size);
  if (md->gop_hw_mspg)
    munmap ((void *) md->gop_hw_mspg, md->mspg_map_size);
  if (md->cm3_base)
    munmap ((void *) md->cm3_base, md->cm3_map_size);
  if (md->uio_fd >= 0)
    close (md->uio_fd);
  md->uio_fd = -1;
  md->is_initialized = 0;
}

static u32
mvpp2_port_get_if_index (vnet_dev_t *dev, clib_dt_node_t *port_node, u8 ppio_id)
{
  char net_path[PATH_MAX];
  char real_path[PATH_MAX];
  char path[PATH_MAX];
  u8 *port_node_path;
  struct dirent *e;
  clib_error_t *err;
  DIR *dir;
  u32 dev_port;
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

      snprintf (path, sizeof (path), "%s/%s/dev_port", net_path, e->d_name);
      err = clib_sysfs_read (path, "%u", &dev_port);

      if (!err && dev_port == ppio_id)
	if_index = if_nametoindex (e->d_name);
      if (err)
	{
	  clib_error_free (err);
	}
      if (if_index)
	break;

      snprintf (path, sizeof (path), "%s/%s/of_node", net_path, e->d_name);
      if (realpath (path, real_path) && strcmp (real_path, (char *) port_node_path) == 0)
	{
	  if_index = if_nametoindex (e->d_name);
	  break;
	}
    }

  closedir (dir);
  vec_free (port_node_path);
  return if_index;
}

vnet_dev_rv_t
mvpp2_device_lazy_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  vnet_dev_rv_t mrv;
  u8 index;
  u16 free_hifs;
  u16 n_threads = vlib_get_n_threads ();

  if (md->is_initialized)
    return rv;

  md->hif_reserved_map = 0xf;
  md->bm_pool_reserved_map = 0x7;

  if ((mrv = pp2_device_init (dev)))
    {
      log_err (dev, "pp2_device_init failed, err %d", mrv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  md->is_initialized = 1;
  log_debug (dev, "pp2_device_init() ok");

  free_hifs = pow2_mask (MVPP2_NUM_HIFS) ^ md->hif_reserved_map;
  md->free_bpools = pow2_mask (MVPP2_NUM_BPOOLS) ^ md->bm_pool_reserved_map;

  if (n_threads > MVPP2_MAX_THREADS || n_threads > count_set_bits (free_hifs))
    {
      log_err (dev, "no enough HIFs (needed %u available %u)", n_threads,
	       count_set_bits (free_hifs));
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  for (u32 i = 0; i < n_threads; i++)
    {
      index = get_lowest_set_bit_index (free_hifs);
      free_hifs ^= 1 << index;

      mrv = pp2_hif_init (vm, dev, i, index, 2048);
      if (mrv < 0)
	{
	  log_err (dev, "pp2_hif_init failed for hif %u thread %u, err %d",
		   index, i, mrv);
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto done;
	}
      log_debug (dev, "pp2_hif_init(hif %u, thread %u) ok", index, i);
    }

  index = get_lowest_set_bit_index (md->free_bpools);
  md->free_bpools ^= 1 << index;

  mrv = pp2_bpool_init (
    &(struct pp2_bpool_params) {
      .vm = vm,
      .dev = dev,
      .id = index,
      .buff_len = 64,
      .dummy_short_pool = 1,
    },
    &md->dummy_short_bpool);
  if (mrv < 0)
    {
      log_err (dev, "pp2_bpool_init failed for bpool %u:%u, err %d", md->pp_id, index, mrv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }
  log_debug (dev, "pp2_bpool_init(bpool %u:%u) ok", md->pp_id, index);
done:
  if (rv != VNET_DEV_OK)
    mvpp2_deinit (vm, dev);
  return rv;
}

static vnet_dev_rv_t
mvpp2_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  clib_dt_node_t *sc;
  clib_dt_node_t *sw = 0;
  int pp_id = -1;

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
	sw = n;
	log_debug (dev, "found mv88e6190 compatible switch at %v", n->path);
	ports = clib_dt_get_child_node (sw, "ports");
	foreach_clib_dt_child_node (pn, ports)
	  {
	    u32 reg = CLIB_U32_MAX;
	    char *label = "(no label)";
	    clib_dt_property_t *p;
	    clib_dt_node_t *n;

	    p = clib_dt_get_node_property_by_name (pn, "reg");
	    if (p)
	      reg = clib_dt_property_get_u32 (p);
	    p = clib_dt_get_node_property_by_name (pn, "label");
	    if (p)
	      label = clib_dt_property_get_string (p);

	    log_debug (dev, "port %u label %s", reg, label);

	    n = clib_dt_dereference_node (pn, "phy-handle");
	    if (n)
	      log_debug (dev, "  phy is %v", n->path);

	    n = clib_dt_dereference_node (pn, "sfp");
	    if (n)
	      log_debug (dev, "  sfp is %v", n->path);

	    n = clib_dt_dereference_node (pn, "ethernet");
	    if (n)
	      log_debug (dev, "  connected to %v", n->path);

	    p = clib_dt_get_node_property_by_name (pn, "phy-mode");
	    if (p)
	      log_debug (dev, "  phy mode is %s",
			 clib_dt_property_get_string (p));
	  }
      }

  md->pp_id = pp_id;

  foreach_clib_dt_child_node (cn, dd->node)
    {
      clib_dt_property_t *p;
      char netdev_name[IFNAMSIZ];
      struct ifreq s = {};
      u32 if_index;
      u8 ppio_id;
      int fd, srv;

      p = clib_dt_get_node_property_by_name (cn, "port-id");

      if (!clib_dt_property_is_u32 (p))
	continue;

      ppio_id = clib_dt_property_get_u32 (p);
      log_debug (dev, "found port with ppio id %u", ppio_id);

      if (ppio_id >= ARRAY_LEN (md->mac_data))
	continue;

      p = clib_dt_get_node_property_by_name (cn, "status");
      if (p && strcmp (clib_dt_property_get_string (p), "disabled") == 0)
	continue;

      if_index = mvpp2_port_get_if_index (dev, cn, ppio_id);
      if (if_index == 0 || if_indextoname (if_index, netdev_name) == 0)
	{
	  log_warn (dev, "failed to get netdev, skipping port %u ", ppio_id);
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
	  log_warn (dev, "unable to get hw address, skipping port %u",
		    ppio_id);
	  continue;
	}

      log_debug (dev, "adding ppio %u (netdev name %s, hwaddr %U)", ppio_id,
		 netdev_name, format_ethernet_address, s.ifr_addr.sa_data);

      mvpp2_port_t mvpp2_port = {
	.id = ppio_id,
	.if_index = if_index,
      };

      if (sw)
	{
	  clib_dt_node_t *ports = clib_dt_get_child_node (sw, "ports");
	  if (ports)
	    foreach_clib_dt_child_node (sp, ports)
	      {
		clib_dt_node_t *eth;

		eth = clib_dt_dereference_node (sp, "ethernet");

		if (cn != eth)
		  continue;

		mvpp2_port.is_dsa = 1;
		mvpp2_port.switch_node = sw;
		mvpp2_port.switch_port_node = sp;
		log_debug (dev, "port is connected to switch port %v",
			   sp->path);
		break;
	      }
	}

      vnet_dev_port_add_args_t port_add_args = {
        .port = {
          .attr = {
            .type = VNET_DEV_PORT_TYPE_ETHERNET,
            .max_rx_queues = PP2_PPIO_MAX_NUM_INQS,
            .max_tx_queues = PP2_PPIO_MAX_NUM_OUTQS,
            .max_supported_rx_frame_size = 9216,
	    .caps.secondary_interfaces = mvpp2_port.is_dsa != 0,
          },
	  .args = CLIB_ARGS ({
            .type = CLIB_ARG_TYPE_ENUM,
            .name = "rss_hash",
            .desc = "RSS Hash type (2-tuple, 5-tuple)",
            .default_val.enum_val = PP2_PPIO_HASH_T_5_TUPLE,
            .enum_vals = CLIB_ARG_ENUM_VALS(
              { .val = PP2_PPIO_HASH_T_2_TUPLE, .name = "2-tuple", },
              { .val = PP2_PPIO_HASH_T_5_TUPLE , .name = "5-tuple", },
            ),
          },{
            .type = CLIB_ARG_TYPE_ENUM,
            .name = "dsa_enable",
            .desc = "DSA header parsing (on, off, auto)",
            .default_val.enum_val = MVPP2_PORT_DSA_ENABLED_AUTO,
            .enum_vals = CLIB_ARG_ENUM_VALS(
              { .val = MVPP2_PORT_DSA_ENABLED_OFF, .name = "off", },
              { .val = MVPP2_PORT_DSA_ENABLED_ON, .name = "on", },
              { .val = MVPP2_PORT_DSA_ENABLED_AUTO, .name = "auto", },
            ),
          }),
          .ops = {
            .init = mvpp2_port_init,
            .deinit = mvpp2_port_deinit,
            .start = mvpp2_port_start,
            .stop = mvpp2_port_stop,
	    .add_sec_if = mvpp2_port_add_sec_if,
	    .del_sec_if = mvpp2_port_del_sec_if,
            .config_change = mvpp2_port_cfg_change,
            .config_change_validate = mvpp2_port_cfg_change_validate,
            .format_status = format_mvpp2_port_status,
	    .clear_counters = mvpp2_port_clear_counters,
          },
          .data_size = sizeof (mvpp2_port_t),
          .initial_data = &mvpp2_port,
	  .sec_if_args = CLIB_ARGS (
	    CLIB_ARG_UINT32 (0, "dsa_switch", "DSA source switch ID", .max= 31),
	    CLIB_ARG_UINT32 (0, "dsa_port", "DSA source switch port ID", .max = 31)
	  ),
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
      },
        },
      };

      vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr,
				    (u8 *) s.ifr_addr.sa_data);

      vnet_dev_port_add (vm, dev, ppio_id, &port_add_args);
    }

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
    .ops = {
      .init = mvpp2_init,
      .deinit = mvpp2_deinit,
      .probe = mvpp2_probe,
      .format_info = format_mvpp2_dev_info,
    },
  },
};
