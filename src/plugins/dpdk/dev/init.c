/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dpdk/dev/dpdk.h>

VLIB_REGISTER_LOG_CLASS (dpdk_log, static) = {
  .class_name = "dev_dpdk",
  .subclass_name = "init",
};

static vnet_dev_arg_t all_port_args[] = {
#define _(type, id, name, desc, ...)                                                               \
  [DEV_DPDK_PORT_ARG_##id] = VNET_DEV_ARG_##type (DEV_DPDK_PORT_ARG_##id, name, desc, __VA_ARGS__),
  foreach_dev_dpdk_port_arg
#undef _
};

vnet_dev_node_t dev_dpdk_rx_node = {};
vnet_dev_node_t dev_dpdk_tx_node = {};

typedef struct
{
  u16 port_id;
} dpdk_device_t;

static u8 *
dev_dpdk_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != 0x8086)
    return 0;

  return format (0, "Intel NIC");
}

struct rte_device *
dev_dpdk_init_find_dev (u8 *devstr)
{
  struct rte_device *dd = 0;
  struct rte_dev_iterator it;
  RTE_DEV_FOREACH (dd, (char *) devstr, &it)
  if (rte_dev_driver (dd))
    break;
  return dd;
}

static vnet_dev_rv_t
dev_dpdk_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  struct rte_device *dd = 0;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  int rte_rv;
  u8 *devstr = format (0, "bus=pci,addr=%U%c", format_vnet_dev_pci_device_addr, dev, 0);
  char *bfd = (char *) format (0, "%U%c", format_vnet_dev_pci_device_addr, dev, 0);
  uint16_t port_id = CLIB_U16_MAX;
  vnet_dev_port_id_t next_vnet_dev_port = 0;
  vnet_dev_arg_t *port_args = 0;

  if (dev_dpdk_init_find_dev (devstr))
    {
      rv = VNET_DEV_ERR_ALREADY_IN_USE;
      goto done;
    }

  rte_rv = rte_eal_hotplug_add ("pci", bfd, "");
  if (rte_rv != 0)
    {
      rv = VNET_DEV_ERR_NOT_FOUND;
      log_err (dev, "rte_eal_hotplug_add failed, rv = %d", bfd, rte_rv);
      goto done;
    }

  dd = dev_dpdk_init_find_dev (devstr);

  if (!dd)
    {
      rv = VNET_DEV_ERR_NOT_FOUND;
      log_err (dev, "device not found");
      goto done;
    }

  RTE_ETH_FOREACH_DEV_OF (port_id, dd)
    {
      struct rte_eth_dev_info info;
      const struct rte_bus *bus;
      u16 rx_default_size = 2 * VLIB_FRAME_SIZE;
      u16 tx_default_size = 2 * VLIB_FRAME_SIZE;
      u16 max_rx_frame_size;
      u16 rss_key_size = sizeof (((vnet_dev_rss_key_t *) 0)->key);
      vnet_dev_hw_addr_t hw_addr = {};
      dev_dpdk_port_t port_data;

      rte_rv = rte_eth_dev_info_get (port_id, &info);
      if (rte_rv)
	{
	  log_err (dev, "rte_eth_dev_info_get failed for port %u", port_id);
	  continue;
	}

      bus = rte_dev_bus (info.device);

      log_notice (dev, "port %u: name=%s driver=%s bus=%s\n", port_id,
		  info.device ? rte_dev_name (info.device) : "unknown",
		  info.driver_name ? info.driver_name : "unknown",
		  bus ? rte_bus_name (bus) : "unknown");

      max_rx_frame_size =
	info.max_rx_pktlen ? clib_min (info.max_rx_pktlen, (u32) 0xffff) : RTE_ETHER_MAX_LEN;
      rte_eth_macaddr_get (port_id, (struct rte_ether_addr *) &hw_addr);

      rx_default_size = clib_max (rx_default_size, info.rx_desc_lim.nb_min);
      rx_default_size = clib_min (rx_default_size, info.rx_desc_lim.nb_max);
      tx_default_size = clib_max (tx_default_size, info.tx_desc_lim.nb_min);
      tx_default_size = clib_min (tx_default_size, info.tx_desc_lim.nb_max);

      port_data = (dev_dpdk_port_t){
	.port_id = port_id,
	.rx_offload_capa = info.rx_offload_capa,
	.tx_offload_capa = info.tx_offload_capa,
      };

      vec_reset_length (port_args);

      if (info.rx_offload_capa & dev_dpdk_rx_ip4_csum_flags)
	port_data.rx_ip4_csum = 1;

      if (info.rx_offload_capa & dev_dpdk_rx_lro_flags)
	vec_add1 (port_args, all_port_args[DEV_DPDK_PORT_ARG_LRO]);

      if (info.rx_offload_capa & dev_dpdk_rx_scatter_flags)
	{
	  vec_add1 (port_args, all_port_args[DEV_DPDK_PORT_ARG_RX_SCATTER]);
	  port_data.rx_scatter = 1;
	}

      if (info.tx_offload_capa & dev_dpdk_tx_tcp_tso_flags)
	vec_add1 (port_args, all_port_args[DEV_DPDK_PORT_ARG_TCP_TSO]);

      if (info.tx_offload_capa & dev_dpdk_tx_udp_tso_flags)
	vec_add1 (port_args, all_port_args[DEV_DPDK_PORT_ARG_UDP_TSO]);

      if (info.tx_offload_capa & dev_dpdk_tx_tcp_csum_flags)
	{
	  vec_add1 (port_args, all_port_args[DEV_DPDK_PORT_ARG_TX_TCP_CSUM]);
	  port_data.tx_tcp_csum = 1;
	}
      if (info.tx_offload_capa & dev_dpdk_tx_udp_csum_flags)
	{
	  vec_add1 (port_args, all_port_args[DEV_DPDK_PORT_ARG_TX_UDP_CSUM]);
	  port_data.tx_udp_csum = 1;
	}
      if (info.tx_offload_capa & dev_dpdk_tx_ip4_csum_flags)
	{
	  vec_add1 (port_args, all_port_args[DEV_DPDK_PORT_ARG_TX_IP4_CSUM]);
	  port_data.tx_ip4_csum = 1;
	}
      if (info.tx_offload_capa & dev_dpdk_tx_outer_ip4_csum_flags)
	vec_add1 (port_args, all_port_args[DEV_DPDK_PORT_ARG_TX_OUTER_IP4_CSUM]);
      if (info.tx_offload_capa & dev_dpdk_tx_outer_udp_csum_flags)
	vec_add1 (port_args, all_port_args[DEV_DPDK_PORT_ARG_TX_OUTER_UDP_CSUM]);

      vec_add1 (port_args, VNET_DEV_ARG_END ());

      vnet_dev_port_add (
      vm, dev, next_vnet_dev_port++,
      &(vnet_dev_port_add_args_t){
	.port = {
	  .data_size = sizeof (dev_dpdk_port_t),
	  .args = port_args,
	  .ops = {
		  .alloc = dev_dpdk_port_alloc,
		  .start = dev_dpdk_port_start,
		  .stop = dev_dpdk_port_stop,
		},
	  .initial_data = &port_data,
	  .attr = {
	    .hw_addr = hw_addr,
	    .type = VNET_DEV_PORT_TYPE_ETHERNET,
	    .max_rx_queues = info.max_rx_queues,
	    .max_tx_queues = info.max_tx_queues,
	    .max_supported_rx_frame_size = max_rx_frame_size,
	    .caps = {
	      .change_max_rx_frame_size = info.max_rx_pktlen != 0,
	      .mac_filter = info.max_mac_addrs > 0,
	      .rss = (info.reta_size && info.hash_key_size >= rss_key_size),
	    },
	    .rx_offloads = {
	      .ip4_cksum = port_data.rx_ip4_csum,
	    },
	    .tx_offloads = {
	      .ip4_cksum = port_data.tx_ip4_csum,
	      .tcp_gso = port_data.tcp_tso,
	      .udp_gso = port_data.udp_tso,
	    },
	  },
	},
	.rx_node = &dev_dpdk_rx_node,
	.tx_node = &dev_dpdk_tx_node,
	.rx_queue = {
	  .config = {
	    .min_size = info.rx_desc_lim.nb_min,
	    .max_size = info.rx_desc_lim.nb_max,
	    .default_size = rx_default_size,
	    .multiplier =
	      info.rx_desc_lim.nb_align ? info.rx_desc_lim.nb_align : 1,
	  },
	},
	.tx_queue = {
	  .config = {
	    .min_size = info.tx_desc_lim.nb_min,
	    .max_size = info.tx_desc_lim.nb_max,
	    .default_size = tx_default_size,
	    .multiplier =
	      info.tx_desc_lim.nb_align ? info.tx_desc_lim.nb_align : 1,
	  },
	},
      });
      vec_reset_length (port_args);
    }

  vec_free (port_args);

  const struct rte_driver *drv = rte_dev_driver (dd);
  log_debug (dev, "device attached, driver is %s", drv ? rte_driver_name (drv) : "unknown");

done:
  if (port_id != CLIB_U16_MAX)
    rte_eth_dev_close (port_id);
  vec_free (devstr);
  vec_free (bfd);
  return rv;
}

VNET_DEV_REGISTER_DRIVER (dpdk) = {
  .name = "dpdk",
  .bus = "pci",
  .priority = -100,
  .device_data_sz = sizeof (dpdk_device_t),
  .ops = {
    .init = dev_dpdk_init,
    .probe = dev_dpdk_probe,
  },
};
