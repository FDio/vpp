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

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>
#include <dpdk/device/dpdk.h>

#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>

void
dpdk_device_error (dpdk_device_t * xd, char *str, int rv)
{
  xd->errors = clib_error_return (xd->errors, "%s[port:%d, errno:%d]: %s",
				  str, xd->device_index, rv,
				  rte_strerror (rv));
}

void
dpdk_device_setup (dpdk_device_t * xd)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, xd->vlib_sw_if_index);
  int rv;
  int j;

  ASSERT (vlib_get_thread_index () == 0);

  clib_error_free (xd->errors);
  sw->flags &= ~VNET_SW_INTERFACE_FLAG_ERROR;

  if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
    {
      vnet_hw_interface_set_flags (dm->vnet_main, xd->hw_if_index, 0);
      dpdk_device_stop (xd);
    }

  rv = rte_eth_dev_configure (xd->device_index, xd->rx_q_used,
			      xd->tx_q_used, &xd->port_conf);

  if (rv < 0)
    {
      dpdk_device_error (xd, "rte_eth_dev_configure", rv);
      goto error;
    }

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
	dpdk_device_error (xd, "rte_eth_tx_queue_setup", rv);
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
	dpdk_device_error (xd, "rte_eth_rx_queue_setup", rv);
    }

  if (vec_len (xd->errors))
    goto error;

  if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
    dpdk_device_start (xd);

  if (vec_len (xd->errors))
    goto error;

  return;

error:
  xd->flags |= DPDK_DEVICE_FLAG_PMD_INIT_FAIL;
  sw->flags |= VNET_SW_INTERFACE_FLAG_ERROR;
}

void
dpdk_device_start (dpdk_device_t * xd)
{
  int rv;

  if (xd->flags & DPDK_DEVICE_FLAG_PMD_INIT_FAIL)
    return;

  rv = rte_eth_dev_start (xd->device_index);

  if (rv)
    {
      dpdk_device_error (xd, "rte_eth_dev_start", rv);
      return;
    }

  if (xd->default_mac_address)
    rv =
      rte_eth_dev_default_mac_addr_set (xd->device_index,
					(struct ether_addr *)
					xd->default_mac_address);

  if (rv)
    dpdk_device_error (xd, "rte_eth_dev_default_mac_addr_set", rv);

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
}

void
dpdk_device_stop (dpdk_device_t * xd)
{
  if (xd->flags & DPDK_DEVICE_FLAG_PMD_INIT_FAIL)
    return;

  rte_eth_allmulticast_disable (xd->device_index);
  rte_eth_dev_stop (xd->device_index);

  /* For bonded interface, stop slave links */
  if (xd->pmd == VNET_DPDK_PMD_BOND)
    {
      u8 slink[16];
      int nlink = rte_eth_bond_slaves_get (xd->device_index, slink, 16);
      while (nlink >= 1)
	{
	  u8 dpdk_port = slink[--nlink];
	  rte_eth_dev_stop (dpdk_port);
	}
    }
}

void
dpdk_port_state_callback (uint8_t port_id,
			  enum rte_eth_event_type type, void *param)
{
  struct rte_eth_link link;
  vlib_main_t *vm = vlib_get_main ();
  dpdk_device_t *xd = &dpdk_main.devices[port_id];

  RTE_SET_USED (param);
  if (type != RTE_ETH_EVENT_INTR_LSC)
    {
      clib_warning ("Unknown event %d received for port %d", type, port_id);
      return;
    }

  rte_eth_link_get_nowait (port_id, &link);
  u8 link_up = link.link_status;

  if (xd->flags & DPDK_DEVICE_FLAG_BOND_SLAVE)
    {
      u8 bd_port = xd->bond_port;
      int bd_mode = rte_eth_bond_mode_get (bd_port);

      if ((link_up && !(xd->flags & DPDK_DEVICE_FLAG_BOND_SLAVE_UP)) ||
	  (!link_up && (xd->flags & DPDK_DEVICE_FLAG_BOND_SLAVE_UP)))
	{
	  clib_warning ("Port %d state to %s, "
			"slave of port %d BondEthernet%d in mode %d",
			port_id, (link_up) ? "UP" : "DOWN",
			bd_port, xd->port_id, bd_mode);
	  if (bd_mode == BONDING_MODE_ACTIVE_BACKUP)
	    {
	      rte_eth_link_get_nowait (bd_port, &link);
	      if (link.link_status)	/* bonded interface up */
		{
		  u32 hw_if_index = dpdk_main.devices[bd_port].hw_if_index;
		  vlib_process_signal_event
		    (vm, send_garp_na_process_node_index, SEND_GARP_NA,
		     hw_if_index);
		}
	    }
	}
      if (link_up)		/* Update slave link status */
	xd->flags |= DPDK_DEVICE_FLAG_BOND_SLAVE_UP;
      else
	xd->flags &= ~DPDK_DEVICE_FLAG_BOND_SLAVE_UP;
    }
  else				/* Should not happen as callback not setup for "normal" links */
    {
      if (link_up)
	clib_warning ("Port %d Link Up - speed %u Mbps - %s",
		      port_id, (unsigned) link.link_speed,
		      (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
		      "full-duplex" : "half-duplex");
      else
	clib_warning ("Port %d Link Down\n\n", port_id);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
