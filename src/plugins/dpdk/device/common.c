/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vlib/unix/cj.h>
#include <assert.h>

#include <vnet/ethernet/ethernet.h>
#include <dpdk/device/dpdk.h>

#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>

clib_error_t *
dpdk_error_return (clib_error_t * error, char *str, dpdk_device_t * xd,
		   int rv)
{
  return clib_error_return (error, "%s[%d]: %s(%d)", str, xd->device_index,
			    rte_strerror (rv), rv);
}

clib_error_t *
dpdk_device_setup (dpdk_device_t * xd)
{
  dpdk_main_t *dm = &dpdk_main;
  clib_error_t *err = 0;
  int rv;
  int j;

  ASSERT (vlib_get_thread_index () == 0);

  if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
    {
      vnet_hw_interface_set_flags (dm->vnet_main, xd->hw_if_index, 0);
      dpdk_device_stop (xd);
    }

  rv = rte_eth_dev_configure (xd->device_index, xd->rx_q_used,
			      xd->tx_q_used, &xd->port_conf);

  if (rv < 0)
    return dpdk_error_return (err, "rte_eth_dev_configure", xd, rv);

  /* Set up one TX-queue per worker thread */
  for (j = 0; j < xd->tx_q_used; j++)
    {
      rv = rte_eth_tx_queue_setup (xd->device_index, j, xd->nb_tx_desc,
				   xd->cpu_socket, &xd->tx_conf);

      /* retry with any other CPU socket */
      if (rv < 0)
	rv = rte_eth_tx_queue_setup (xd->device_index, j, xd->nb_tx_desc,
				     SOCKET_ID_ANY, &xd->tx_conf);
      if (rv < 0)
	err = dpdk_error_return (err, "rte_eth_tx_queue_setup", xd, rv);
    }

  for (j = 0; j < xd->rx_q_used; j++)
    {
      uword tidx = vnet_get_device_input_thread_index (dm->vnet_main,
						       xd->hw_if_index, j);
      unsigned lcore = vlib_worker_threads[tidx].lcore_id;
      u16 socket_id = rte_lcore_to_socket_id (lcore);

      rv = rte_eth_rx_queue_setup (xd->device_index, j, xd->nb_rx_desc,
				   xd->cpu_socket, 0,
				   dm->pktmbuf_pools[socket_id]);

      /* retry with any other CPU socket */
      if (rv < 0)
	rv = rte_eth_rx_queue_setup (xd->device_index, j, xd->nb_rx_desc,
				     SOCKET_ID_ANY, 0,
				     dm->pktmbuf_pools[socket_id]);

      if (rv < 0)
	err = dpdk_error_return (err, "rte_eth_rx_queue_setup", xd, rv);
    }

  if (err)
    return err;

  if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
    err = dpdk_device_start (xd);

  return err;
}

clib_error_t *
dpdk_device_start (dpdk_device_t * xd)
{
  int rv;
  clib_error_t *err = 0;

  rv = rte_eth_dev_start (xd->device_index);

  if (rv)
    return dpdk_error_return (err, "rte_eth_dev_start", xd, rv);

  if (xd->default_mac_address)
    rv =
      rte_eth_dev_default_mac_addr_set (xd->device_index,
					(struct ether_addr *)
					xd->default_mac_address);

  if (rv)
    err = dpdk_error_return (err, "rte_eth_dev_default_mac_addr_set", xd, rv);

  if (xd->flags & DPDK_DEVICE_FLAG_PROMISC)
    rte_eth_promiscuous_enable (xd->device_index);
  else
    rte_eth_promiscuous_disable (xd->device_index);

  rte_eth_allmulticast_enable (xd->device_index);

  if (xd->pmd == VNET_DPDK_PMD_BOND)
    {
      u8 slink[16];
      int nlink = rte_eth_bond_slaves_get (xd->device_index, slink, 16);
      while (nlink >= 1)
	{
	  u8 dpdk_port = slink[--nlink];
	  rte_eth_allmulticast_enable (dpdk_port);
	}
    }

  return err;
}

clib_error_t *
dpdk_device_stop (dpdk_device_t * xd)
{
  rte_eth_dev_stop (xd->device_index);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
