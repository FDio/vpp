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

  vec_validate_aligned (xd->buffer_pool_for_queue, xd->rx_q_used - 1,
			CLIB_CACHE_LINE_BYTES);
  for (j = 0; j < xd->rx_q_used; j++)
    {
      dpdk_mempool_private_t *privp;
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

      privp = rte_mempool_get_priv (dm->pktmbuf_pools[socket_id]);
      xd->buffer_pool_for_queue[j] = privp->buffer_pool_index;

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

/* Even type for send_garp_na_process */
enum
{
  SEND_GARP_NA = 1,
} dpdk_send_garp_na_process_event_t;

static vlib_node_registration_t send_garp_na_proc_node;

static uword
send_garp_na_process (vlib_main_t * vm,
		      vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword event_type, *event_data = 0;

  while (1)
    {
      u32 i;
      uword dpdk_port;
      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &event_data);
      ASSERT (event_type == SEND_GARP_NA);
      for (i = 0; i < vec_len (event_data); i++)
	{
	  dpdk_port = event_data[i];
	  if (i < 5)		/* wait 0.2 sec for link to settle, max total 1 sec */
	    vlib_process_suspend (vm, 0.2);
	  dpdk_device_t *xd = &dpdk_main.devices[dpdk_port];
	  u32 hw_if_index = xd->hw_if_index;
	  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
	  dpdk_update_link_state (xd, vlib_time_now (vm));
	  send_ip4_garp (vm, hi);
	  send_ip6_na (vm, hi);
	}
      vec_reset_length (event_data);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (send_garp_na_proc_node, static) = {
    .function = send_garp_na_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "send-garp-na-process",
};
/* *INDENT-ON* */

void vl_api_force_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);

static void
garp_na_proc_callback (uword * dpdk_port)
{
  vlib_main_t *vm = vlib_get_main ();
  ASSERT (vlib_get_thread_index () == 0);
  vlib_process_signal_event
    (vm, send_garp_na_proc_node.index, SEND_GARP_NA, *dpdk_port);
}

always_inline int
dpdk_port_state_callback_inline (uint8_t port_id,
				 enum rte_eth_event_type type, void *param)
{
  struct rte_eth_link link;
  dpdk_device_t *xd = &dpdk_main.devices[port_id];

  RTE_SET_USED (param);
  if (type != RTE_ETH_EVENT_INTR_LSC)
    {
      clib_warning ("Unknown event %d received for port %d", type, port_id);
      return -1;
    }

  rte_eth_link_get_nowait (port_id, &link);
  u8 link_up = link.link_status;

  if (xd->flags & DPDK_DEVICE_FLAG_BOND_SLAVE)
    {
      uword bd_port = xd->bond_port;
      int bd_mode = rte_eth_bond_mode_get (bd_port);
#if 0
      clib_warning ("Port %d state to %s, "
		    "slave of port %d BondEthernet%d in mode %d",
		    port_id, (link_up) ? "UP" : "DOWN",
		    bd_port, xd->port_id, bd_mode);
#endif
      if (bd_mode == BONDING_MODE_ACTIVE_BACKUP)
	{
	  vl_api_force_rpc_call_main_thread
	    (garp_na_proc_callback, (u8 *) & bd_port, sizeof (uword));
	}
      xd->flags |= link_up ?
	DPDK_DEVICE_FLAG_BOND_SLAVE_UP : ~DPDK_DEVICE_FLAG_BOND_SLAVE_UP;
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

  return 0;
}

#if DPDK_VOID_CALLBACK
void
dpdk_port_state_callback (uint8_t port_id,
			  enum rte_eth_event_type type, void *param)
{
  dpdk_port_state_callback_inline (port_id, type, param);
}

#else
int
dpdk_port_state_callback (uint8_t port_id,
			  enum rte_eth_event_type type,
			  void *param,
			  void *ret_param __attribute__ ((unused)))
{
  return dpdk_port_state_callback_inline (port_id, type, param);
}
#endif
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
