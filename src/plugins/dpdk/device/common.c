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
#include <vppinfra/file.h>
#include <vlib/unix/unix.h>
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

static inline void
dpdk_device_flag_set (dpdk_device_t *xd, __typeof__ (xd->flags) flag,
		      uword val)
{
  if (val)
    xd->flags |= flag;
  else
    xd->flags &= ~flag;
}

static inline void
dpdk_dev_hi_caps_set (vnet_hw_interface_t *hi, __typeof__ (hi->caps) caps,
		      uword val)
{
  if (val)
    hi->caps |= caps;
  else
    hi->caps &= ~caps;
}

void
dpdk_device_setup (dpdk_device_t * xd)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, xd->sw_if_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, xd->hw_if_index);
  dpdk_driver_t *dr = xd->driver;
  struct rte_eth_dev_info di;
  struct rte_eth_conf conf = {};
  u64 rxo, txo;
  u16 mtu;
  int rv;
  int j;

  ASSERT (vlib_get_thread_index () == 0);

  clib_error_free (xd->errors);
  sw->flags &= ~VNET_SW_INTERFACE_FLAG_ERROR;

  if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
    {
      vnet_hw_interface_set_flags (vnm, xd->hw_if_index, 0);
      dpdk_device_stop (xd);
    }

  rte_eth_dev_info_get (xd->port_id, &di);

  /* create rx and tx offload wishlist */
  rxo = DEV_RX_OFFLOAD_IPV4_CKSUM;
  txo = 0;

  if (xd->conf.enable_tcp_udp_checksum)
    rxo |= DEV_RX_OFFLOAD_UDP_CKSUM | DEV_RX_OFFLOAD_TCP_CKSUM |
	   DEV_TX_OFFLOAD_IPV4_CKSUM;

  if (xd->conf.enable_tcp_udp_checksum &&
      xd->conf.enable_outer_checksum_offload)
    txo |= DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM | DEV_TX_OFFLOAD_OUTER_UDP_CKSUM;

  if (xd->conf.no_tx_checksum_offload == 0)
    txo |= DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM;

  if (xd->conf.no_multi_seg == 0)
    {
      txo |= DEV_TX_OFFLOAD_MULTI_SEGS;
      rxo |= DEV_RX_OFFLOAD_JUMBO_FRAME | DEV_RX_OFFLOAD_SCATTER;
    }

  if (xd->conf.enable_lro)
    rxo |= DEV_RX_OFFLOAD_TCP_LRO;

  /* per-device offload config */
  if (xd->conf.enable_tso)
    txo |= DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_TCP_TSO |
	   DEV_TX_OFFLOAD_VXLAN_TNL_TSO;

  if (dr && dr->disable_rx_scatter)
    rxo &= ~DEV_RX_OFFLOAD_SCATTER;

  /* mask unsupported offloads */
  rxo &= xd->supported_rx_off;
  txo &= xd->supported_tx_off;

  dpdk_log_debug ("[%u] Configured RX offloads: %U", xd->port_id,
		  format_dpdk_rx_offload_caps, rxo);
  dpdk_log_debug ("[%u] Configured TX offloads: %U", xd->port_id,
		  format_dpdk_tx_offload_caps, txo);

  /* Enable flow director when flows exist */
  if (xd->supported_flow_actions &&
      (xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) != 0)
    conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;

  /* finalize configuration */
  conf.rxmode.offloads = rxo;
  conf.txmode.offloads = txo;
  if (rxo & DEV_RX_OFFLOAD_TCP_LRO)
    conf.rxmode.max_lro_pkt_size = xd->conf.max_lro_pkt_size;

  if (xd->conf.enable_lsc_int)
    conf.intr_conf.lsc = 1;
  if (xd->conf.enable_rxq_int)
    conf.intr_conf.rxq = 1;

  conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
  if (xd->conf.n_rx_queues > 1)
    {
      if (dr == 0 || dr->mq_mode_none == 0)
	conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    }

  conf.rx_adv_conf.rss_conf.rss_hf = xd->conf.rss_hf;
  if (rxo & DEV_RX_OFFLOAD_JUMBO_FRAME)
    conf.rxmode.max_rx_pkt_len =
      clib_min (ETHERNET_MAX_PACKET_BYTES, di.max_rx_pktlen);

  rv = rte_eth_dev_configure (xd->port_id, xd->conf.n_rx_queues,
			      xd->conf.n_tx_queues, &conf);

  if (rv < 0)
    {
      dpdk_device_error (xd, "rte_eth_dev_configure", rv);
      goto error;
    }

  rte_eth_dev_get_mtu (xd->port_id, &mtu);
  dpdk_log_debug ("[%u] mtu %u hi->max_packet_bytes %u", xd->port_id, mtu,
		  hi->max_packet_bytes);
  hi->max_packet_bytes = mtu;
  hi->max_supported_packet_bytes = mtu;

  xd->enabled_rx_off = rxo;
  xd->enabled_tx_off = txo;

  vec_validate_aligned (xd->tx_queues, xd->conf.n_tx_queues - 1,
			CLIB_CACHE_LINE_BYTES);
  for (j = 0; j < xd->conf.n_tx_queues; j++)
    {
      rv = rte_eth_tx_queue_setup (xd->port_id, j, xd->conf.n_tx_desc,
				   xd->cpu_socket, &xd->tx_conf);

      /* retry with any other CPU socket */
      if (rv < 0)
	rv = rte_eth_tx_queue_setup (xd->port_id, j, xd->conf.n_tx_desc,
				     SOCKET_ID_ANY, &xd->tx_conf);
      if (rv < 0)
	dpdk_device_error (xd, "rte_eth_tx_queue_setup", rv);

      if (xd->conf.n_tx_queues < tm->n_vlib_mains)
	clib_spinlock_init (&vec_elt (xd->tx_queues, j).lock);
    }

  vec_validate_aligned (xd->rx_queues, xd->conf.n_rx_queues - 1,
			CLIB_CACHE_LINE_BYTES);

  for (j = 0; j < xd->conf.n_rx_queues; j++)
    {
      dpdk_rx_queue_t *rxq = vec_elt_at_index (xd->rx_queues, j);
      u8 bpidx = vlib_buffer_pool_get_default_for_numa (
	vm, vnet_hw_if_get_rx_queue_numa_node (vnm, rxq->queue_index));
      vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, bpidx);
      struct rte_mempool *mp = dpdk_mempool_by_buffer_pool_index[bpidx];

      rv = rte_eth_rx_queue_setup (xd->port_id, j, xd->conf.n_rx_desc,
				   xd->cpu_socket, 0, mp);

      /* retry with any other CPU socket */
      if (rv < 0)
	rv = rte_eth_rx_queue_setup (xd->port_id, j, xd->conf.n_rx_desc,
				     SOCKET_ID_ANY, 0, mp);

      rxq->buffer_pool_index = bp->index;

      if (rv < 0)
	dpdk_device_error (xd, "rte_eth_rx_queue_setup", rv);
    }

  if (vec_len (xd->errors))
    goto error;

  rte_eth_dev_set_mtu (xd->port_id, hi->max_packet_bytes);

  dpdk_device_flag_set (xd, DPDK_DEVICE_FLAG_RX_IP4_CKSUM,
			rxo & DEV_RX_OFFLOAD_IPV4_CKSUM);
  dpdk_device_flag_set (xd, DPDK_DEVICE_FLAG_MAYBE_MULTISEG,
			rxo & DEV_RX_OFFLOAD_SCATTER);
  dpdk_device_flag_set (
    xd, DPDK_DEVICE_FLAG_TX_OFFLOAD,
    (txo & (DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM)) ==
      (DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM));

  dpdk_dev_hi_caps_set (hi, VNET_HW_INTERFACE_CAP_SUPPORTS_TX_IP4_CKSUM,
			txo & DEV_TX_OFFLOAD_IPV4_CKSUM);
  dpdk_dev_hi_caps_set (hi, VNET_HW_INTERFACE_CAP_SUPPORTS_TX_TCP_CKSUM,
			txo & DEV_TX_OFFLOAD_TCP_CKSUM);
  dpdk_dev_hi_caps_set (hi, VNET_HW_INTERFACE_CAP_SUPPORTS_TX_UDP_CKSUM,
			txo & DEV_TX_OFFLOAD_UDP_CKSUM);
  dpdk_dev_hi_caps_set (hi, VNET_HW_INTERFACE_CAP_SUPPORTS_TX_IP4_OUTER_CKSUM,
			txo & DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM);
  dpdk_dev_hi_caps_set (hi, VNET_HW_INTERFACE_CAP_SUPPORTS_TX_UDP_OUTER_CKSUM,
			txo & DEV_TX_OFFLOAD_OUTER_UDP_CKSUM);
  dpdk_dev_hi_caps_set (hi, VNET_HW_INTERFACE_CAP_SUPPORTS_TCP_GSO,
			txo & DEV_TX_OFFLOAD_TCP_TSO);
  dpdk_dev_hi_caps_set (hi, VNET_HW_INTERFACE_CAP_SUPPORTS_VXLAN_TNL_GSO,
			txo & DEV_TX_OFFLOAD_VXLAN_TNL_TSO);

  if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
    dpdk_device_start (xd);

  if (vec_len (xd->errors))
    goto error;

  return;

error:
  xd->flags |= DPDK_DEVICE_FLAG_PMD_INIT_FAIL;
  sw->flags |= VNET_SW_INTERFACE_FLAG_ERROR;
}

static clib_error_t *
dpdk_rx_read_ready (clib_file_t *uf)
{
  vnet_main_t *vnm = vnet_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  u32 qidx = uf->private_data;
  vnet_hw_if_rx_queue_t *rxq = vnet_hw_if_get_rx_queue (vnm, qidx);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, rxq->dev_instance);

  u64 b;
  CLIB_UNUSED (ssize_t size) = read (uf->file_descriptor, &b, sizeof (b));
  if (rxq->mode != VNET_HW_IF_RX_MODE_POLLING)
    {
      vnet_hw_if_rx_queue_set_int_pending (vnm, uf->private_data);
      rte_eth_dev_rx_intr_enable (xd->port_id, rxq->queue_id);
    }

  return 0;
}

static void
dpdk_setup_interrupts (dpdk_device_t *xd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, xd->hw_if_index);
  if (!hi)
    return;

  if (!xd->conf.enable_rxq_int)
    return;

  /* Probe for interrupt support */
  if (rte_eth_dev_rx_intr_enable (xd->port_id, 0))
    {
      dpdk_log_info ("probe for interrupt mode for device %U. Failed.\n",
		     format_dpdk_device_name, xd->port_id);
    }
  else
    {
      xd->flags |= DPDK_DEVICE_FLAG_INT_SUPPORTED;
      if (!(xd->flags & DPDK_DEVICE_FLAG_INT_UNMASKABLE))
	rte_eth_dev_rx_intr_disable (xd->port_id, 0);
      dpdk_log_info ("Probe for interrupt mode for device %U. Success.\n",
		     format_dpdk_device_name, xd->port_id);
    }

  if (xd->flags & DPDK_DEVICE_FLAG_INT_SUPPORTED)
    {
      hi->caps |= VNET_HW_INTERFACE_CAP_SUPPORTS_INT_MODE;
      for (int q = 0; q < xd->conf.n_rx_queues; q++)
	{
	  dpdk_rx_queue_t *rxq = vec_elt_at_index (xd->rx_queues, q);
	  clib_file_t f = { 0 };
	  rxq->efd = rte_eth_dev_rx_intr_ctl_q_get_fd (xd->port_id, q);
	  if (rxq->efd < 0)
	    {
	      xd->flags &= ~DPDK_DEVICE_FLAG_INT_SUPPORTED;
	      hi->caps &= ~VNET_HW_INTERFACE_CAP_SUPPORTS_INT_MODE;
	      break;
	    }
	  f.read_function = dpdk_rx_read_ready;
	  f.flags = UNIX_FILE_EVENT_EDGE_TRIGGERED;
	  f.file_descriptor = rxq->efd;
	  f.private_data = rxq->queue_index;
	  f.description =
	    format (0, "%U queue %u", format_dpdk_device_name, xd->port_id, q);
	  rxq->clib_file_index = clib_file_add (&file_main, &f);
	  vnet_hw_if_set_rx_queue_file_index (vnm, rxq->queue_index,
					      rxq->clib_file_index);
	  if (xd->flags & DPDK_DEVICE_FLAG_INT_UNMASKABLE)
	    {
	      clib_file_main_t *fm = &file_main;
	      clib_file_t *f =
		pool_elt_at_index (fm->file_pool, rxq->clib_file_index);
	      fm->file_update (f, UNIX_FILE_UPDATE_DELETE);
	    }
	}
    }
  vnet_hw_if_update_runtime_data (vnm, xd->hw_if_index);
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

  dpdk_setup_interrupts (xd);

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

/* If this device is VMBUS return pointer to info, otherwise NULL */
struct rte_vmbus_device *
dpdk_get_vmbus_device (const struct rte_eth_dev_info *info)
{
  const struct rte_bus *bus;

  bus = rte_bus_find_by_device (info->device);
  if (bus && !strcmp (bus->name, "vmbus"))
    return container_of (info->device, struct rte_vmbus_device, device);
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
