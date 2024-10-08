/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <vppinfra/ring.h>
#include <dev_armada/musdk.h>
#include <dev_armada/pp2/pp2.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <linux/if.h>
#include <sys/ioctl.h>

#define MV_SYS_DMA_MEM_SZ (2 << 20)

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "init",
};

static int num_pp2_in_use = 0;
static int dma_mem_initialized = 0;
static int global_pp2_initialized = 0;

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

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
mvpp2_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_platform_device_info_t *di = dev_info;

  if (clib_dt_node_is_compatible (di->node, "marvell,armada-7k-pp22"))
    return format (0, "Marvell Armada Packet Processor v2.2");
  return 0;
}
static void
mvpp2_global_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  log_debug (dev, "");
  if (--num_pp2_in_use == 0)
    {
      if (global_pp2_initialized)
	{
	  for (u32 i = 0; i < ARRAY_LEN (md->thread); i++)
	    if (md->thread[i].bpool)
	      {
		pp2_bpool_deinit (md->thread[i].bpool);
		md->thread[i].bpool = 0;
	      }
	  for (u32 i = 0; i < ARRAY_LEN (md->hif); i++)
	    if (md->hif[i])
	      {
		pp2_hif_deinit (md->hif[i]);
		md->hif[i] = 0;
	      }

	  pp2_deinit ();
	  global_pp2_initialized = 0;
	}
      if (dma_mem_initialized)
	{
	  mv_sys_dma_mem_destroy ();
	  log_debug (0, "mv_sys_dma_mem_destroy()");
	  dma_mem_initialized = 0;
	}
    }
}

static void
mvpp2_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  log_debug (dev, "");
  mvpp2_global_deinit (vm, dev);
}

static vnet_dev_rv_t
mvpp2_global_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  int mrv;
  u16 free_hifs, free_bpools;
  u16 n_threads = vlib_get_n_threads ();

  struct pp2_init_params init_params = {
    .hif_reserved_map = 0xf,
    .bm_pool_reserved_map = 0x7,
  };

  if (num_pp2_in_use++)
    return rv;

  mrv = mv_sys_dma_mem_init (MV_SYS_DMA_MEM_SZ);
  if (mrv < 0)
    {
      log_err (0, "mv_sys_dma_mem_init failed, err %d", mrv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  dma_mem_initialized = 1;
  log_debug (0, "mv_sys_dma_mem_init(%u) ok", MV_SYS_DMA_MEM_SZ);

  if ((mrv = pp2_init (&init_params)))
    {
      log_err (dev, "pp2_init failed, err %d", mrv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  log_debug (dev, "pp2_init() ok");

  free_hifs = pow2_mask (MVPP2_NUM_HIFS) ^ init_params.hif_reserved_map;
  free_bpools =
    pow2_mask (MVPP2_NUM_BPOOLS) ^ init_params.bm_pool_reserved_map;

  if (n_threads > count_set_bits (free_hifs))
    {
      log_err (dev, "no enough HIFs (needed %u available %u)", n_threads,
	       count_set_bits (free_hifs));
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  for (u32 i = 0; i < n_threads; i++)
    {
      char match[16];
      u8 index;
      struct pp2_hif_params hif_params = {
	.match = match,
	.out_size = 2048,
      };
      struct pp2_bpool_params bpool_params = {
	.match = match,
	.buff_len = vlib_buffer_get_default_data_size (vm),
      };

      index = get_lowest_set_bit_index (free_hifs);
      free_hifs ^= 1 << index;
      snprintf (match, sizeof (match), "hif-%u", index);

      mrv = pp2_hif_init (&hif_params, md->hif + i);
      if (mrv < 0)
	{
	  log_err (dev, "pp2_hif_init failed for hif %u thread %u, err %d",
		   index, i, mrv);
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto done;
	}
      log_debug (dev, "pp2_hif_init(hif %u, thread %u) ok", index, i);

      index = get_lowest_set_bit_index (free_bpools);
      free_bpools ^= 1 << index;
      snprintf (match, sizeof (match), "pool-%u:%u", md->pp_id, index);

      mrv = pp2_bpool_init (&bpool_params, &md->thread[i].bpool);
      if (mrv < 0)
	{
	  log_err (dev, "pp2_bpool_init failed for bpool %u thread %u, err %d",
		   index, i, mrv);
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto done;
	}
      log_debug (dev, "pp2_bpool_init(bpool %u, thread %u) pool-%u:%u ok",
		 index, i, md->thread[i].bpool->pp2_id,
		 md->thread[i].bpool->id);
      for (u32 j = 0; j < ARRAY_LEN (md->thread[0].bre); j++)
	md->thread[i].bre[j].bpool = md->thread[i].bpool;
    }

done:
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

  if ((mvpp2_global_init (vm, dev)) != VNET_DEV_OK)
    return rv;

  md->pp_id = pp_id;

  foreach_clib_dt_child_node (cn, dd->node)
    {
      clib_dt_property_t *p;
      char netdev_name[IFNAMSIZ];
      struct ifreq s = {};
      u8 ppio_id;
      int fd, srv;

      p = clib_dt_get_node_property_by_name (cn, "port-id");

      if (!clib_dt_property_is_u32 (p))
	continue;

      ppio_id = clib_dt_property_get_u32 (p);
      log_debug (dev, "found port with ppio id %u", ppio_id);

      if (pp2_ppio_available (md->pp_id, ppio_id) == 0)
	continue;

      if (pp2_netdev_get_ifname (md->pp_id, ppio_id, netdev_name) < 0)
	{
	  log_warn (dev, "failed to get ifname, skipping port %u ", ppio_id);
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
	.ppio_id = ppio_id,
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
        .max_size = 4096,
	.size_is_power_of_two = 1,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (mvpp2_txq_t),
        .default_size = 512,
        .multiplier = 32,
        .min_size = 32,
        .max_size = 4096,
	.size_is_power_of_two = 1,
          },
      .ops = {
	  .alloc = mvpp2_txq_alloc,
	  .free = mvpp2_txq_free,
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
  .bus = PLATFORM_BUS_NAME,
  .device_data_sz = sizeof (mvpp2_device_t),
  .ops = {
    .init = mvpp2_init,
    .deinit = mvpp2_deinit,
    .probe = mvpp2_probe,
    .format_info = format_mvpp2_dev_info,
  },
};
