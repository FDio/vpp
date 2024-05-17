/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vppinfra/ring.h>
#include <dev_armada/musdk.h>
#include <dev_armada/bus.h>
#include <dev_armada/pp2.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <linux/if.h>
#include <sys/ioctl.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "init",
};

static int num_pp2_in_use = 0;
static int global_pp2_initialized = 0;

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t mvpp2_rx_node_counters[] = { foreach_mvpp2_rx_node_counter };
vlib_error_desc_t mvpp2_tx_node_counters[] = { foreach_mvpp2_tx_node_counter };
#undef _

vnet_dev_node_t mvpp2_rx_node = {
  .error_counters = mvpp2_rx_node_counters,
  .n_error_counters = ARRAY_LEN (mvpp2_rx_node_counters),
  //  .format_trace = format_mvpp2_rx_trace,
};

vnet_dev_node_t mvpp2_tx_node = {
  .error_counters = mvpp2_tx_node_counters,
  .n_error_counters = ARRAY_LEN (mvpp2_tx_node_counters),
};

static u8 *
mvpp2_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_armada_device_info_t *di = dev_info;

  return format (0, "Packet Processor %u", di->pp_id);
}

static void
mvpp2_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  log_debug (dev, "deinit");
  if (--num_pp2_in_use == 0 && global_pp2_initialized)
    {
      for (u32 i = 0; i < ARRAY_LEN (md->bpool); i++)
	if (md->bpool[i])
	  {
	    pp2_bpool_deinit (md->bpool[i]);
	    md->bpool[i] = 0;
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
}

static vnet_dev_rv_t
mvpp2_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_bus_armada_device_data_t *d = vnet_dev_get_bus_data (dev);
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;

  if (num_pp2_in_use++ == 0)
    {
      int mrv;
      u16 free_hifs, free_bpools;
      u16 n_threads = vlib_get_n_threads ();

      struct pp2_init_params init_params = {
	.hif_reserved_map = 0xf,
	.bm_pool_reserved_map = 0x7,
      };

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
	  snprintf (match, sizeof (match), "pool-%u:%u", d->pp_id, index);

	  mrv = pp2_bpool_init (&bpool_params, md->bpool + i);
	  if (mrv < 0)
	    {
	      log_err (dev,
		       "pp2_bpool_init failed for bpool %u thread %u, err %d",
		       index, i, mrv);
	      rv = VNET_DEV_ERR_INIT_FAILED;
	      goto done;
	    }
	  log_debug (dev, "pp2_bpool_init(bpool %u, thread %u) pool-%u:%u ok",
		     index, i, md->bpool[i]->pp2_id, md->bpool[i]->id);
	}
    }

  for (u8 ppio_id = 0; ppio_id < PP2_NUM_ETH_PPIO; ppio_id++)
    {
      char netdev_name[IFNAMSIZ];
      struct ifreq s = {};
      int fd, srv;

      if (pp2_ppio_available (d->pp_id, ppio_id) == 0)
	continue;

      if (pp2_netdev_get_ifname (d->pp_id, ppio_id, netdev_name) < 0)
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

      vnet_dev_port_add_args_t port_add_args = {
        .port = {
          .attr = {
            .type = VNET_DEV_PORT_TYPE_ETHERNET,
            .max_rx_queues = PP2_PPIO_MAX_NUM_INQS,
            .max_tx_queues = PP2_PPIO_MAX_NUM_OUTQS,
            .max_supported_rx_frame_size = 9216,
          },
          .ops = {
            .init = mvpp2_port_init,
            .deinit = mvpp2_port_deinit,
            .start = mvpp2_port_start,
            .stop = mvpp2_port_stop,
#if 0
        .format_status = format_mvpp2_port_status,
#endif
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
#if 0
      .ops = {
        .alloc = mvpp2_rx_queue_alloc,
        .free = mvpp2_rx_queue_free,
      },
#endif
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
#if 0
      .ops = {
        .alloc = mvpp2_tx_queue_alloc,
        .free = mvpp2_tx_queue_free,
      },
#endif
        },
      };

      vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr,
				    (u8 *) s.ifr_addr.sa_data);

      vnet_dev_port_add (vm, dev, ppio_id, &port_add_args);
    }

done:
  if (rv != VNET_DEV_OK)
    mvpp2_deinit (vm, dev);
  return rv;
}

VNET_DEV_REGISTER_DRIVER (pp2) = {
  .name = "mvpp2",
  .bus = ARMADA_BUS_NAME,
  .device_data_sz = sizeof (mvpp2_device_t),
  .ops = {
    .init = mvpp2_init,
    .deinit = mvpp2_deinit,
    .probe = mvpp2_probe,
  },
};
