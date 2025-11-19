/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <dpdk/dev/dpdk.h>
#include <dpdk/buffer.h>

VLIB_REGISTER_LOG_CLASS (dpdk_log, static) = {
  .class_name = "dev_dpdk",
  .subclass_name = "port",
};

vnet_dev_rv_t
dev_dpdk_port_alloc (vlib_main_t *vm, vnet_dev_port_t *port)
{
  dev_dpdk_port_t *dp = vnet_dev_get_port_data (port);
  vnet_dev_t *dev = port->dev;
  u64 rxc = 0, txc = 0, rxs = dp->rx_offload_capa, txs = dp->tx_offload_capa;

  foreach_vnet_dev_args (a, port)
  {
    switch (a->id)
      {
      case DEV_DPDK_PORT_ARG_TCP_TSO:
	dp->tcp_tso = vnet_dev_arg_get_bool (a);
	break;
      case DEV_DPDK_PORT_ARG_UDP_TSO:
	dp->udp_tso = vnet_dev_arg_get_bool (a);
	break;
      case DEV_DPDK_PORT_ARG_LRO:
	dp->lro = vnet_dev_arg_get_bool (a);
	break;
      case DEV_DPDK_PORT_ARG_RX_SCATTER:
	dp->rx_scatter = vnet_dev_arg_get_bool (a);
	break;
      case DEV_DPDK_PORT_ARG_TX_TCP_CSUM:
	dp->tx_tcp_csum = vnet_dev_arg_get_bool (a);
	break;
      case DEV_DPDK_PORT_ARG_TX_UDP_CSUM:
	dp->tx_udp_csum = vnet_dev_arg_get_bool (a);
	break;
      case DEV_DPDK_PORT_ARG_TX_IP4_CSUM:
	dp->tx_ip4_csum = vnet_dev_arg_get_bool (a);
	break;
      case DEV_DPDK_PORT_ARG_TX_OUTER_IP4_CSUM:
	dp->tx_outer_ip4_csum = vnet_dev_arg_get_bool (a);
	break;
      case DEV_DPDK_PORT_ARG_TX_OUTER_UDP_CSUM:
	dp->tx_outer_udp_csum = vnet_dev_arg_get_bool (a);
	break;
      default:
	break;
      }
  }

  rxc |= dp->rx_ip4_csum ? dev_dpdk_rx_ip4_csum_flags : 0;
  rxc |= dp->lro ? dev_dpdk_rx_lro_flags : 0;
  rxc |= dp->rx_scatter ? dev_dpdk_rx_scatter_flags : 0;
  dp->rx_offload_config = rxc;

  txc |= dp->tcp_tso ? dev_dpdk_tx_tcp_tso_flags : 0;
  txc |= dp->udp_tso ? dev_dpdk_tx_udp_tso_flags : 0;
  txc |= dp->tx_tcp_csum ? dev_dpdk_tx_tcp_csum_flags : 0;
  txc |= dp->tx_udp_csum ? dev_dpdk_tx_udp_csum_flags : 0;
  txc |= dp->tx_ip4_csum ? dev_dpdk_tx_ip4_csum_flags : 0;
  txc |= dp->tx_outer_ip4_csum ? dev_dpdk_tx_outer_ip4_csum_flags : 0;
  txc |= dp->tx_outer_udp_csum ? dev_dpdk_tx_outer_udp_csum_flags : 0;
  dp->tx_offload_config = txc;

  log_debug (dev, "supported RX offloads: %U", format_dpdk_rx_offload_caps, rxs);
  log_debug (dev, "supported TX offloads: %U", format_dpdk_tx_offload_caps, txs);
  log_debug (dev, "configured RX offloads: %U", format_dpdk_rx_offload_caps, rxc);
  log_debug (dev, "configured TX offloads: %U", format_dpdk_tx_offload_caps, txc);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
dev_dpdk_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  dev_dpdk_port_t *dp = vnet_dev_get_port_data (port);
  clib_numa_node_index_t nn = dev->numa_node;
  u16 n_rxq = vnet_dev_port_get_num_rx_queues (port);
  u16 n_txq = vnet_dev_port_get_num_tx_queues (port);
  u16 port_id = dp->port_id;
  u8 bpidx = vlib_buffer_pool_get_default_for_numa (vm, nn);
  struct rte_mempool *mp = dpdk_mempool_by_buffer_pool_index[bpidx];
  int rv;

  struct rte_eth_conf cfg = {
    .rxmode.offloads = dp->rx_offload_config,
    .txmode.offloads = dp->tx_offload_config,
  };

  rv = rte_eth_dev_configure (port_id, n_rxq, n_txq, &cfg);
  if (rv)
    {
      log_err (dev, "rte_eth_dev_configure failed, rv=%d", rv);
      goto error;
    }

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      rv = rte_eth_rx_queue_setup (port_id, q->queue_id, q->size, nn, 0, mp);
      if (rv)
	{
	  log_err (dev, "rte_eth_rx_queue_setup failed for queue %u, rv=%d", q->queue_id, rv);
	  goto error;
	}
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      rv = rte_eth_tx_queue_setup (port_id, q->queue_id, q->size, nn, 0);
      if (rv)
	{
	  log_err (dev, "rte_eth_tx_queue_setup failed for queue %u, rv=%d", q->queue_id, rv);
	  goto error;
	}
    }

  rv = rte_eth_dev_start (dp->port_id);
  if (rv)
    {
      log_err (dev, "rte_eth_dev_start failed, rv=%d", rv);
      goto error;
    }

  log_debug (dev, "port %u", dp->port_id);
  return VNET_DEV_OK;

error:
  rte_eth_dev_stop (dp->port_id);
  rte_eth_dev_close (dp->port_id);
  return VNET_DEV_ERR_INIT_FAILED;
}

void
dev_dpdk_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  dev_dpdk_port_t *dp = vnet_dev_get_port_data (port);
  rte_eth_dev_stop (dp->port_id);
  rte_eth_dev_close (dp->port_id);
  log_debug (dev, "port %u", dp->port_id);
}
