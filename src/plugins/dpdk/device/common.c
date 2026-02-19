/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/file.h>
#include <vlib/file.h>
#include <assert.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>

/* DPDK TX offload to vnet hw interface caps mapppings */
static struct
{
  u64 offload;
  vnet_hw_if_caps_t caps;
} tx_off_caps_map[] = {
  { RTE_ETH_TX_OFFLOAD_IPV4_CKSUM, VNET_HW_IF_CAP_TX_IP4_CKSUM },
  { RTE_ETH_TX_OFFLOAD_TCP_CKSUM, VNET_HW_IF_CAP_TX_TCP_CKSUM },
  { RTE_ETH_TX_OFFLOAD_UDP_CKSUM, VNET_HW_IF_CAP_TX_UDP_CKSUM },
  { RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM, VNET_HW_IF_CAP_TX_IP4_OUTER_CKSUM },
  { RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM, VNET_HW_IF_CAP_TX_UDP_OUTER_CKSUM },
  { RTE_ETH_TX_OFFLOAD_TCP_TSO, VNET_HW_IF_CAP_TCP_GSO },
  { RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO, VNET_HW_IF_CAP_VXLAN_TNL_GSO },
  { RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO, VNET_HW_IF_CAP_IPIP_TNL_GSO }
};

void
dpdk_device_error (dpdk_device_t * xd, char *str, int rv)
{
  dpdk_log_err ("Interface %U error %d: %s", format_dpdk_device_name,
		xd->device_index, rv, rte_strerror (rv));
  xd->errors = clib_error_return (xd->errors, "%s[port:%d, errno:%d]: %s",
				  str, xd->port_id, rv, rte_strerror (rv));
}

void
dpdk_device_flow_error (dpdk_device_t *xd, char *str)
{
  dpdk_log_err ("Interface %U error %d: %s", format_dpdk_device_name, xd->device_index, rte_errno,
		rte_strerror (rte_errno));
  dpdk_log_err ("[%d] %s - type: %d, cause: %s, message: %s", xd->port_id, str,
		xd->last_flow_error.type, xd->last_flow_error.cause, xd->last_flow_error.message);
  xd->errors = clib_error_return (xd->errors, "%s[port:%d, errno:%d]: %s", str, xd->port_id,
				  rte_errno, rte_strerror (rte_errno));
}

/*
 * Check for async flow offload support.
 * The only way to tell, is to check if rte_flow_info_get and rte_flow_configure does not return
 * -ENOTSUP.
 */
void
dpdk_device_configure_flow_offload (dpdk_device_t *xd)
{
  struct rte_flow_port_info flow_port_info = {};
  struct rte_flow_queue_info flow_queue_info = {};
  // dummy values to configure devices for flow offload
  struct rte_flow_port_attr port_attr = {};
  struct rte_flow_queue_attr queue_attr = {
    .size = DPDK_DEFAULT_ASYNC_FLOW_QUEUE_SIZE,
  };
  const struct rte_flow_queue_attr *queue_attr_list[] = { &queue_attr };
  int rv;

  rv = rte_flow_info_get (xd->port_id, &flow_port_info, &flow_queue_info, &xd->last_flow_error);
  if (rv == -ENOTSUP)
    {
      return;
    }
  else if (rv)
    {
      dpdk_device_flow_error (xd, "rte_flow_info_get");
      xd->supported_flow_actions = 0;
      return;
    }

  // at least one queue is need, of size DPDK_DEFAULT_ASYNC_FLOW_QUEUE_SIZE for now
  rv = rte_flow_configure (xd->port_id, &port_attr, DPDK_DEFAULT_ASYNC_FLOW_N_QUEUES,
			   queue_attr_list, &xd->last_flow_error);
  if (rv == -ENOTSUP)
    {
      return;
    }
  else if (rv)
    {
      dpdk_device_flow_error (xd, "rte_flow_configure");
      xd->supported_flow_actions = 0;
      return;
    }

  dpdk_log_debug ("[%u] Async flow port info: %U", xd->port_id, format_dpdk_flow_port_info,
		  &flow_port_info);
  dpdk_log_debug ("[%u] Async flow queue info: %U", xd->port_id, format_dpdk_flow_queue_info,
		  &flow_queue_info);
}

void
dpdk_device_setup (dpdk_device_t *xd)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, xd->sw_if_index);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, xd->hw_if_index);
  u16 buf_sz = vlib_buffer_get_default_data_size (vm);
  vnet_hw_if_caps_change_t caps = {};
  struct rte_eth_dev_info dev_info;
  struct rte_eth_conf conf = {};
  u64 rxo, txo;
  u32 max_frame_size;
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

  rv = rte_eth_dev_info_get (xd->port_id, &dev_info);
  if (rv)
    dpdk_device_error (xd, "rte_eth_dev_info_get", rv);

  dpdk_log_debug ("[%u] configuring device %U", xd->port_id,
		  format_dpdk_rte_device, dev_info.device);

  /* create rx and tx offload wishlist */
  rxo = RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
  txo = 0;

  if (xd->conf.enable_tcp_udp_checksum)
    rxo |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM | RTE_ETH_RX_OFFLOAD_TCP_CKSUM;

  if (xd->conf.disable_tx_checksum_offload == 0 &&
      xd->conf.enable_outer_checksum_offload)
    txo |=
      RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM;

  if (xd->conf.disable_tx_checksum_offload == 0)
    txo |= RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM |
	   RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
	   RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

  if (xd->conf.disable_multi_seg == 0)
    {
      txo |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
      rxo |= RTE_ETH_RX_OFFLOAD_SCATTER;
#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
      rxo |= DEV_RX_OFFLOAD_JUMBO_FRAME;
#endif
    }

  if (xd->conf.enable_lro)
    rxo |= RTE_ETH_RX_OFFLOAD_TCP_LRO;

  /* per-device offload config */
  if (xd->conf.enable_tso)
    txo |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_TSO |
	   RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO | RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO;

  if (xd->conf.disable_rx_scatter)
    rxo &= ~RTE_ETH_RX_OFFLOAD_SCATTER;

  /* mask unsupported offloads */
  rxo &= dev_info.rx_offload_capa;
  txo &= dev_info.tx_offload_capa;

  dpdk_log_debug ("[%u] Supported RX offloads: %U", xd->port_id,
		  format_dpdk_rx_offload_caps, dev_info.rx_offload_capa);
  dpdk_log_debug ("[%u] Configured RX offloads: %U", xd->port_id,
		  format_dpdk_rx_offload_caps, rxo);
  dpdk_log_debug ("[%u] Supported TX offloads: %U", xd->port_id,
		  format_dpdk_tx_offload_caps, dev_info.tx_offload_capa);
  dpdk_log_debug ("[%u] Configured TX offloads: %U", xd->port_id,
		  format_dpdk_tx_offload_caps, txo);

  /* finalize configuration */
  conf.rxmode.offloads = rxo;
  conf.txmode.offloads = txo;
  if (rxo & RTE_ETH_RX_OFFLOAD_TCP_LRO)
    conf.rxmode.max_lro_pkt_size = xd->conf.max_lro_pkt_size;

  if (xd->conf.enable_lsc_int)
    conf.intr_conf.lsc = 1;
  if (xd->conf.enable_rxq_int)
    conf.intr_conf.rxq = 1;

  conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
  if (xd->conf.n_rx_queues > 1)
    {
      if (xd->conf.disable_rss == 0)
	{
	  conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	  conf.rx_adv_conf.rss_conf.rss_hf = xd->conf.rss_hf;
	}
    }

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
  if (rxo & DEV_RX_OFFLOAD_JUMBO_FRAME)
    {
      conf.rxmode.max_rx_pkt_len = dev_info.max_rx_pktlen;
      xd->max_supported_frame_size = dev_info.max_rx_pktlen;
    }
  else
    {
      xd->max_supported_frame_size =
	clib_min (1500 + xd->driver_frame_overhead, buf_sz);
    }
#else
  if (xd->conf.disable_multi_seg)
    xd->max_supported_frame_size = clib_min (dev_info.max_rx_pktlen, buf_sz);
  else
    xd->max_supported_frame_size = dev_info.max_rx_pktlen;
#endif

  max_frame_size = clib_min (xd->max_supported_frame_size,
			     ethernet_main.default_mtu + hi->frame_overhead);

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)
  conf.rxmode.mtu = max_frame_size - xd->driver_frame_overhead;
#endif

retry:
  rv = rte_eth_dev_configure (xd->port_id, xd->conf.n_rx_queues,
			      xd->conf.n_tx_queues, &conf);
  if (rv < 0 && conf.intr_conf.rxq)
    {
      conf.intr_conf.rxq = 0;
      goto retry;
    }

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
  rte_eth_dev_set_mtu (xd->port_id,
		       max_frame_size - xd->driver_frame_overhead);
#endif

  hi->max_frame_size = 0;
  vnet_hw_interface_set_max_frame_size (vnm, xd->hw_if_index, max_frame_size);
  dpdk_log_debug ("[%u] max_frame_size %u max max_frame_size %u "
		  "driver_frame_overhead %u",
		  xd->port_id, hi->max_frame_size,
		  xd->max_supported_frame_size, xd->driver_frame_overhead);

  vec_validate_aligned (xd->tx_queues, xd->conf.n_tx_queues - 1,
			CLIB_CACHE_LINE_BYTES);
  for (j = 0; j < xd->conf.n_tx_queues; j++)
    {
      rv = rte_eth_tx_queue_setup (xd->port_id, j, xd->conf.n_tx_desc,
				   xd->cpu_socket, 0);

      /* retry with any other CPU socket */
      if (rv < 0)
	rv = rte_eth_tx_queue_setup (xd->port_id, j, xd->conf.n_tx_desc,
				     SOCKET_ID_ANY, 0);
      if (rv < 0)
	dpdk_device_error (xd, "rte_eth_tx_queue_setup", rv);

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

  if (xd->supported_flow_actions != 0)
    dpdk_device_configure_flow_offload (xd);

  xd->buffer_flags =
    (VLIB_BUFFER_TOTAL_LENGTH_VALID | VLIB_BUFFER_EXT_HDR_VALID);

  if ((rxo & (RTE_ETH_RX_OFFLOAD_TCP_CKSUM | RTE_ETH_RX_OFFLOAD_UDP_CKSUM)) ==
      (RTE_ETH_RX_OFFLOAD_TCP_CKSUM | RTE_ETH_RX_OFFLOAD_UDP_CKSUM))
    xd->buffer_flags |=
      (VNET_BUFFER_F_L4_CHECKSUM_COMPUTED | VNET_BUFFER_F_L4_CHECKSUM_CORRECT);

  dpdk_device_flag_set (xd, DPDK_DEVICE_FLAG_RX_IP4_CKSUM,
			rxo & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM);
  dpdk_device_flag_set (xd, DPDK_DEVICE_FLAG_MAYBE_MULTISEG,
			rxo & RTE_ETH_RX_OFFLOAD_SCATTER);
  dpdk_device_flag_set (
    xd, DPDK_DEVICE_FLAG_TX_OFFLOAD,
    (txo & (RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM)) ==
      (RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM));

  /* unconditionally set mac filtering cap */
  caps.val = caps.mask = VNET_HW_IF_CAP_MAC_FILTER;

  ethernet_set_flags (vnm, xd->hw_if_index,
		      ETHERNET_INTERFACE_FLAG_DEFAULT_L3);

  for (int i = 0; i < ARRAY_LEN (tx_off_caps_map); i++)
    {
      __typeof__ (tx_off_caps_map[0]) *v = tx_off_caps_map + i;
      caps.mask |= v->caps;
      if ((v->offload & txo) == v->offload)
	caps.val |= v->caps;
    }

  vnet_hw_if_change_caps (vnm, xd->hw_if_index, &caps);
  xd->enabled_rx_off = rxo;
  xd->enabled_tx_off = txo;

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
  int int_mode = 0;
  if (!hi)
    return;

  if (!xd->conf.enable_rxq_int)
    return;

  /* Probe for interrupt support */
  if (rte_eth_dev_rx_intr_enable (xd->port_id, 0))
    {
      dpdk_log_info ("probe for interrupt mode for device %U. Failed.\n",
		     format_dpdk_device_name, xd->device_index);
    }
  else
    {
      xd->flags |= DPDK_DEVICE_FLAG_INT_SUPPORTED;
      if (!(xd->flags & DPDK_DEVICE_FLAG_INT_UNMASKABLE))
	rte_eth_dev_rx_intr_disable (xd->port_id, 0);
      dpdk_log_info ("Probe for interrupt mode for device %U. Success.\n",
		     format_dpdk_device_name, xd->device_index);
    }

  if (xd->flags & DPDK_DEVICE_FLAG_INT_SUPPORTED)
    {
      int_mode = 1;
      for (int q = 0; q < xd->conf.n_rx_queues; q++)
	{
	  dpdk_rx_queue_t *rxq = vec_elt_at_index (xd->rx_queues, q);
	  clib_file_t f = { 0 };
	  rxq->efd = rte_eth_dev_rx_intr_ctl_q_get_fd (xd->port_id, q);
	  if (rxq->efd < 0)
	    {
	      xd->flags &= ~DPDK_DEVICE_FLAG_INT_SUPPORTED;
	      int_mode = 0;
	      break;
	    }
	  f.read_function = dpdk_rx_read_ready;
	  f.flags = UNIX_FILE_EVENT_EDGE_TRIGGERED;
	  f.file_descriptor = rxq->efd;
	  f.private_data = rxq->queue_index;
	  f.description = format (0, "%U queue %u", format_dpdk_device_name,
				  xd->device_index, q);
	  rxq->clib_file_index = clib_file_add (&file_main, &f);
	  vnet_hw_if_set_rx_queue_file_index (vnm, rxq->queue_index,
					      rxq->clib_file_index);
	  if (xd->flags & DPDK_DEVICE_FLAG_INT_UNMASKABLE)
	    {
	      clib_file_main_t *fm = &file_main;
	      clib_file_t *f = clib_file_get (fm, rxq->clib_file_index);
	      fm->file_update (f, UNIX_FILE_UPDATE_DELETE);
	    }
	}
    }

  if (int_mode)
    vnet_hw_if_set_caps (vnm, hi->hw_if_index, VNET_HW_IF_CAP_INT_MODE);
  else
    vnet_hw_if_unset_caps (vnm, hi->hw_if_index, VNET_HW_IF_CAP_INT_MODE);
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

  dpdk_log_debug ("[%u] RX burst function: %U", xd->port_id,
		  format_dpdk_burst_fn, xd, VLIB_RX);
  dpdk_log_debug ("[%u] TX burst function: %U", xd->port_id,
		  format_dpdk_burst_fn, xd, VLIB_TX);

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

  dpdk_log_info ("Interface %U started", format_dpdk_device_name,
		 xd->device_index);
}

void
dpdk_device_stop (dpdk_device_t * xd)
{
  if (xd->flags & DPDK_DEVICE_FLAG_PMD_INIT_FAIL)
    return;

  rte_eth_allmulticast_disable (xd->port_id);
  rte_eth_dev_stop (xd->port_id);
  clib_memset (&xd->link, 0, sizeof (struct rte_eth_link));

  dpdk_log_info ("Interface %U stopped", format_dpdk_device_name,
		 xd->device_index);
}

always_inline int
dpdk_port_state_callback_inline (dpdk_portid_t port_id,
				 enum rte_eth_event_type type, void *param)
{
  struct rte_eth_link link;
  CLIB_UNUSED (int rv);

  RTE_SET_USED (param);
  if (type != RTE_ETH_EVENT_INTR_LSC)
    {
      dpdk_log_info ("Unknown event %d received for port %d", type, port_id);
      return -1;
    }

  rv = rte_eth_link_get_nowait (port_id, &link);
  ASSERT (rv == 0);
  u8 link_up = link.link_status;
  if (link_up)
    dpdk_log_info ("Port %d Link Up - speed %u Mbps - %s", port_id,
		   (unsigned) link.link_speed,
		   (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
			   "full-duplex" :
			   "half-duplex");
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
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
  if (bus && !strcmp (rte_bus_name (bus), "pci"))
#else
  if (bus && !strcmp (bus->name, "pci"))
#endif
    return RTE_DEV_TO_PCI (info->device);
  else
    return NULL;
}

#ifdef __linux__
/* If this device is VMBUS return pointer to info, otherwise NULL */
struct rte_vmbus_device *
dpdk_get_vmbus_device (const struct rte_eth_dev_info *info)
{
  const struct rte_bus *bus;

  bus = rte_bus_find_by_device (info->device);
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
  if (bus && !strcmp (rte_bus_name (bus), "vmbus"))
#else
  if (bus && !strcmp (bus->name, "vmbus"))
#endif
    return container_of (info->device, struct rte_vmbus_device, device);
  else
    return NULL;
}
#endif /* __linux__ */

clib_error_t *
dpdk_read_eeprom (vnet_main_t *vnm, vnet_hw_interface_t *hi,
		  vnet_interface_eeprom_t **eeprom)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  dpdk_device_t *xd;
  vnet_device_class_t *dc;
  struct rte_eth_dev_module_info mi = { 0 };
  struct rte_dev_eeprom_info ei = { 0 };

  dc = vec_elt_at_index (im->device_classes, hi->dev_class_index);
  *eeprom = NULL;

  if (dc->index != dpdk_device_class.index)
    {
      return clib_error_return (0, "Interface %v is not a DPDK interface",
				hi->name);
    }

  if (hi->dev_instance >= vec_len (dm->devices))
    {
      return clib_error_return (0, "Invalid device instance %u",
				hi->dev_instance);
    }

  xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  /* Get module info */
  if (rte_eth_dev_get_module_info (xd->port_id, &mi) != 0)
    {
      return clib_error_return (
	0, "Module info not available for interface %v", hi->name);
    }
  if (mi.eeprom_len > 1024)
    {
      return clib_error_return (0, "EEPROM invalid length: %u bytes",
				mi.eeprom_len);
    }

  /* Allocate EEPROM structure */
  *eeprom = clib_mem_alloc (sizeof (vnet_interface_eeprom_t));
  if (!*eeprom)
    {
      return clib_error_return (0, "Memory allocation failed");
    }

  /* Get EEPROM data */
  ei.length = mi.eeprom_len;
  ei.data = (*eeprom)->eeprom_raw;

  if (rte_eth_dev_get_module_eeprom (xd->port_id, &ei) != 0)
    {
      clib_mem_free (*eeprom);
      *eeprom = NULL;
      return clib_error_return (0, "EEPROM read error for interface %v",
				hi->name);
    }

  (*eeprom)->eeprom_len = mi.eeprom_len;
  (*eeprom)->eeprom_type = mi.type;
  return 0;
}
