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
#include <assert.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>

void
dpdk_device_error (dpdk_device_t * xd, char *str, int rv)
{
  dpdk_log_err ("Interface %U error %d: %s",
		format_dpdk_device_name, xd->port_id, rv, rte_strerror (rv));
  xd->errors = clib_error_return (xd->errors, "%s[port:%d, errno:%d]: %s",
				  str, xd->port_id, rv, rte_strerror (rv));
}

void
dpdk_device_setup (dpdk_device_t * xd)
{
  dpdk_main_t *dm = &dpdk_main;
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, xd->sw_if_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, xd->hw_if_index);
  struct rte_eth_dev_info dev_info;
  u64 bitmap;
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

  /* Enable flow director when flows exist */
  if (xd->pmd == VNET_DPDK_PMD_I40E)
    {
      if ((xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) != 0)
	xd->port_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;
      else
	xd->port_conf.fdir_conf.mode = RTE_FDIR_MODE_NONE;
    }

  rte_eth_dev_info_get (xd->port_id, &dev_info);

  bitmap = xd->port_conf.txmode.offloads & ~dev_info.tx_offload_capa;
  if (bitmap)
    {
      dpdk_log_warn ("unsupported tx offloads requested on port %u: %U",
		     xd->port_id, format_dpdk_tx_offload_caps, bitmap);
      xd->port_conf.txmode.offloads ^= bitmap;
    }

  bitmap = xd->port_conf.rxmode.offloads & ~dev_info.rx_offload_capa;
  if (bitmap)
    {
      dpdk_log_warn ("unsupported rx offloads requested on port %u: %U",
		     xd->port_id, format_dpdk_rx_offload_caps, bitmap);
      xd->port_conf.rxmode.offloads ^= bitmap;
    }

  rv = rte_eth_dev_configure (xd->port_id, xd->rx_q_used,
			      xd->tx_q_used, &xd->port_conf);

  if (rv < 0)
    {
      dpdk_device_error (xd, "rte_eth_dev_configure", rv);
      goto error;
    }

  vec_validate_aligned (xd->tx_queues, xd->tx_q_used - 1,
			CLIB_CACHE_LINE_BYTES);
  for (j = 0; j < xd->tx_q_used; j++)
    {
      rv =
	rte_eth_tx_queue_setup (xd->port_id, j, xd->nb_tx_desc,
				xd->cpu_socket, &xd->tx_conf);

      /* retry with any other CPU socket */
      if (rv < 0)
	rv =
	  rte_eth_tx_queue_setup (xd->port_id, j,
				  xd->nb_tx_desc, SOCKET_ID_ANY,
				  &xd->tx_conf);
      if (rv < 0)
	dpdk_device_error (xd, "rte_eth_tx_queue_setup", rv);

      if (xd->tx_q_used < tm->n_vlib_mains)
	clib_spinlock_init (&vec_elt (xd->tx_queues, j).lock);
    }

  vec_validate_aligned (xd->rx_queues, xd->rx_q_used - 1,
			CLIB_CACHE_LINE_BYTES);
  for (j = 0; j < xd->rx_q_used; j++)
    {
      dpdk_rx_queue_t *rxq = vec_elt_at_index (xd->rx_queues, j);
      u8 bpidx = vlib_buffer_pool_get_default_for_numa
	(vm, vnet_hw_if_get_rx_queue_numa_node (vnm, rxq->queue_index));
      vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, bpidx);
      struct rte_mempool *mp = dpdk_mempool_by_buffer_pool_index[bpidx];

      rv = rte_eth_rx_queue_setup (xd->port_id, j, xd->nb_rx_desc,
				   xd->cpu_socket, 0, mp);

      /* retry with any other CPU socket */
      if (rv < 0)
	rv = rte_eth_rx_queue_setup (xd->port_id, j, xd->nb_rx_desc,
				     SOCKET_ID_ANY, 0, mp);

      rxq->buffer_pool_index = bp->index;

      if (rv < 0)
	dpdk_device_error (xd, "rte_eth_rx_queue_setup", rv);
    }

  if (vec_len (xd->errors))
    goto error;

  rte_eth_dev_set_mtu (xd->port_id, hi->max_packet_bytes);

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

  rv = rte_eth_dev_start (xd->port_id);

  if (rv)
    {
      dpdk_device_error (xd, "rte_eth_dev_start", rv);
      return;
    }

  if (xd->default_mac_address)
    rv = rte_eth_dev_default_mac_addr_set (xd->port_id,
					   (void *) xd->default_mac_address);

  if (rv)
    dpdk_device_error (xd, "rte_eth_dev_default_mac_addr_set", rv);

  if (xd->flags & DPDK_DEVICE_FLAG_PROMISC)
    rte_eth_promiscuous_enable (xd->port_id);
  else
    rte_eth_promiscuous_disable (xd->port_id);

  rte_eth_allmulticast_enable (xd->port_id);

  dpdk_log_info ("Interface %U started",
		 format_dpdk_device_name, xd->port_id);
}

void
dpdk_device_stop (dpdk_device_t * xd)
{
  if (xd->flags & DPDK_DEVICE_FLAG_PMD_INIT_FAIL)
    return;

  rte_eth_allmulticast_disable (xd->port_id);
  rte_eth_dev_stop (xd->port_id);
  clib_memset (&xd->link, 0, sizeof (struct rte_eth_link));

  dpdk_log_info ("Interface %U stopped",
		 format_dpdk_device_name, xd->port_id);
}

void vl_api_force_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);

always_inline int
dpdk_port_state_callback_inline (dpdk_portid_t port_id,
				 enum rte_eth_event_type type, void *param)
{
  struct rte_eth_link link;

  RTE_SET_USED (param);
  if (type != RTE_ETH_EVENT_INTR_LSC)
    {
      dpdk_log_info ("Unknown event %d received for port %d", type, port_id);
      return -1;
    }

  rte_eth_link_get_nowait (port_id, &link);
  u8 link_up = link.link_status;
  if (link_up)
    dpdk_log_info ("Port %d Link Up - speed %u Mbps - %s",
		   port_id, (unsigned) link.link_speed,
		   (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
		   "full-duplex" : "half-duplex");
  else
    dpdk_log_info ("Port %d Link Down\n\n", port_id);

  return 0;
}

int
dpdk_port_state_callback (dpdk_portid_t port_id,
			  enum rte_eth_event_type type,
			  void *param,
			  void *ret_param __attribute__ ((unused)))
{
  return dpdk_port_state_callback_inline (port_id, type, param);
}

/* If this device is PCI return pointer to info, otherwise NULL */
struct rte_pci_device *
dpdk_get_pci_device (const struct rte_eth_dev_info *info)
{
  const struct rte_bus *bus;

  bus = rte_bus_find_by_device (info->device);
  if (bus && !strcmp (bus->name, "pci"))
    return RTE_DEV_TO_PCI (info->device);
  else
    return NULL;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
