/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <vppinfra/ring.h>
#include <dev_avf/avf.h>
#include <dev_avf/virtchnl.h>
#include <dev_avf/virtchnl_funcs.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (avf_log, static) = {
  .class_name = "dev_avf",
  .subclass_name = "init",
};

static const u32 driver_cap_flags =
  /**/ VIRTCHNL_VF_OFFLOAD_L2 |
  /**/ VIRTCHNL_VF_OFFLOAD_RSS_PF |
  /**/ VIRTCHNL_VF_OFFLOAD_WB_ON_ITR |
  /**/ VIRTCHNL_VF_OFFLOAD_VLAN |
  /**/ VIRTCHNL_VF_OFFLOAD_VLAN_V2 |
  /**/ VIRTCHNL_VF_OFFLOAD_RX_POLLING |
  /**/ VIRTCHNL_VF_CAP_ADV_LINK_SPEED |
  /**/ VIRTCHNL_VF_OFFLOAD_FDIR_PF |
  /**/ VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF;

static const virtchnl_version_info_t driver_virtchnl_version = {
  .major = VIRTCHNL_VERSION_MAJOR,
  .minor = VIRTCHNL_VERSION_MINOR,
};

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t avf_rx_node_counters[] = { foreach_avf_rx_node_counter };
vlib_error_desc_t avf_tx_node_counters[] = { foreach_avf_tx_node_counter };
#undef _

vnet_dev_node_t avf_rx_node = {
  .error_counters = avf_rx_node_counters,
  .n_error_counters = ARRAY_LEN (avf_rx_node_counters),
  .format_trace = format_avf_rx_trace,
};

vnet_dev_node_t avf_tx_node = {
  .error_counters = avf_tx_node_counters,
  .n_error_counters = ARRAY_LEN (avf_tx_node_counters),
};

avf_main_t avf_main;

static struct
{
  u16 device_id;
  char *desc;
} avf_dev_types[] = {

#define _(id, d)                                                              \
  {                                                                           \
    .device_id = (id), .desc = (d)                                            \
  }

  _ (0x1889, "Intel(R) Adaptive Virtual Function"),
  _ (0x154c, "Intel(R) X710 Virtual Function"),
  _ (0x37cd, "Intel(R) X722 Virtual Function"),
#undef _
};

static vnet_dev_rv_t
avf_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  avf_port_t *ap = vnet_dev_get_port_data (port);
  avf_rxq_t *arq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv;

  if (ap->avail_rxq_bmp == 0)
    {
      log_err (dev, "rx_queue_alloc: no available queues");
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  rxq->queue_id = get_lowest_set_bit_index (ap->avail_rxq_bmp);
  ap->avail_rxq_bmp ^= 1 << rxq->queue_id;

  arq->buffer_indices = clib_mem_alloc_aligned (
    rxq->size * sizeof (arq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (avf_rx_desc_t) * rxq->size, 0,
			       (void **) &arq->descs);
  if (rv != VNET_DEV_OK)
    return rv;

  arq->qrx_tail = ad->bar0 + AVF_QTX_TAIL (rxq->queue_id);

  log_debug (dev, "rx_queue_alloc: queue %u alocated", rxq->queue_id);
  return rv;
}

static void
avf_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  avf_port_t *ap = vnet_dev_get_port_data (rxq->port);
  avf_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);

  log_debug (dev, "rx_queue_free: queue %u", rxq->queue_id);

  ap->avail_rxq_bmp |= 1 << rxq->queue_id;
  vnet_dev_dma_mem_free (vm, dev, aq->descs);
}

static vnet_dev_rv_t
avf_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  avf_port_t *ap = vnet_dev_get_port_data (txq->port);
  avf_txq_t *atq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_rv_t rv;

  if (ap->avail_txq_bmp == 0)
    {
      log_err (dev, "tx_queue_alloc: no available queues");
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  txq->queue_id = get_lowest_set_bit_index (ap->avail_txq_bmp);
  ap->avail_txq_bmp ^= 1 << txq->queue_id;

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (avf_tx_desc_t) * txq->size, 0,
			       (void **) &atq->descs);
  if (rv != VNET_DEV_OK)
    return rv;

  clib_ring_new_aligned (atq->rs_slots, 32, CLIB_CACHE_LINE_BYTES);
  atq->buffer_indices = clib_mem_alloc_aligned (
    txq->size * sizeof (atq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);
  atq->tmp_descs = clib_mem_alloc_aligned (
    sizeof (atq->tmp_descs[0]) * txq->size, CLIB_CACHE_LINE_BYTES);
  atq->tmp_bufs = clib_mem_alloc_aligned (
    sizeof (atq->tmp_bufs[0]) * txq->size, CLIB_CACHE_LINE_BYTES);

  atq->qtx_tail = ad->bar0 + AVF_QTX_TAIL (txq->queue_id);

  log_debug (dev, "tx_queue_alloc: queue %u alocated", txq->queue_id);
  return VNET_DEV_OK;
}

static void
avf_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  avf_txq_t *atq = vnet_dev_get_tx_queue_data (txq);
  avf_port_t *ap = vnet_dev_get_port_data (txq->port);
  avf_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
  log_debug (dev, "tx_queue_free: queue %u", txq->queue_id);
  ap->avail_txq_bmp |= 1 << txq->queue_id;
  vnet_dev_dma_mem_free (vm, dev, aq->descs);
  clib_ring_free (atq->rs_slots);

  foreach_ptr (p, aq->tmp_descs, aq->tmp_bufs, aq->buffer_indices)
    if (p)
      clib_mem_free (p);
}

static u8 *
avf_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != 0x8086)
    return 0;

  FOREACH_ARRAY_ELT (dt, avf_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->desc);
    }

  return 0;
}

static vnet_dev_rv_t
avf_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  return avf_aq_init (vm, dev);
}

static vnet_dev_rv_t
avf_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  virtchnl_version_info_t ver;
  virtchnl_vf_resource_t res;
  vnet_dev_rv_t rv;

  log_debug (dev, "init");

  rv = vnet_dev_pci_map_region (vm, dev, 0, &ad->bar0);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_aq_alloc (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = vnet_dev_pci_bus_master_enable (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_reset (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_vc_op_version (vm, dev, &driver_virtchnl_version, &ver);
  if (rv != VNET_DEV_OK)
    return rv;

  if (ver.major != driver_virtchnl_version.major ||
      ver.minor != driver_virtchnl_version.minor)
    return VNET_DEV_ERR_UNSUPPORTED_DEV_VER;

  avf_vc_op_get_vf_resources (vm, dev, &driver_cap_flags, &res);
  if (rv != VNET_DEV_OK)
    return rv;

  if (res.num_vsis != 1 || res.vsi_res[0].vsi_type != VIRTCHNL_VSI_SRIOV)
    return VNET_DEV_ERR_UNSUPPORTED_DEV;

  if (res.vf_cap_flags & VIRTCHNL_VF_OFFLOAD_VLAN_V2)
    {
      virtchnl_vlan_caps_t caps;
      avf_vc_op_get_offload_vlan_v2_caps (vm, dev, &caps);
    }

  vnet_dev_port_add_args_t port_add_args = {
    .port = {
      .config = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .max_rx_queues = res.num_queue_pairs,
        .max_tx_queues = res.num_queue_pairs,
        .max_supported_frame_size = res.max_mtu,
      },
      .ops = {
        .init = avf_port_init,
        .start = avf_port_start,
        .stop = avf_port_stop,
        .format_status = format_avf_port_status,
      },
      .data_size = sizeof (avf_port_t),
    },
    .rx_node = &avf_rx_node,
    .tx_node = &avf_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (avf_rxq_t),
        .default_size = 512,
        .multiplier = 8,
        .min_size = 32,
        .max_size = 32768,
      },
      .ops = {
        .alloc = avf_rx_queue_alloc,
        .free = avf_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (avf_txq_t),
        .default_size = 512,
        .multiplier = 8,
        .min_size = 32,
        .max_size = 32768,
      },
      .ops = {
        .alloc = avf_tx_queue_alloc,
        .free = avf_tx_queue_free,
      },
    },
  };

  vnet_dev_set_hw_addr (&port_add_args.port.config.hw_addr, 6,
			res.vsi_res[0].default_mac_addr);

  log_info (dev, "MAC address is %U", format_ethernet_address,
	    res.vsi_res[0].default_mac_addr);

  port_add_args.port.initial_data = &(avf_port_t){
    .vf_cap_flags = res.vf_cap_flags,
    .rss_key_size = res.rss_key_size,
    .rss_lut_size = res.rss_lut_size,
    .max_vectors = res.max_vectors,
    .vsi_id = res.vsi_res[0].vsi_id,
    .num_qp = res.vsi_res[0].num_queue_pairs,
    .avail_rxq_bmp = pow2_mask (res.num_queue_pairs),
    .avail_txq_bmp = pow2_mask (res.num_queue_pairs),
  };

  if (vlib_get_n_threads () <= vnet_dev_get_pci_n_msix_interrupts (dev) - 1)
    port_add_args.port.config.caps.interrupt_mode = 1;
  else
    log_notice (dev,
		"number of threads (%u) bigger than number of interrupt lines "
		"(%u), interrupt mode disabled",
		vlib_get_n_threads (), res.max_vectors);

  vnet_dev_port_add (vm, dev, 0, &port_add_args);

  return rv;
}

static void
avf_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  log_debug (dev, "deinit");
  avf_aq_deinit (vm, dev);
  avf_aq_free (vm, dev);
}

VNET_DEV_REGISTER_DRIVER (avf) = {
  .name = "avf",
  .bus = "pci",
  .device_data_sz = sizeof (avf_device_t),
  .ops = {
    .device_init = avf_init,
    .device_deinit = avf_deinit,
    .probe = avf_probe,
  },
};

clib_error_t *
avf_num_workers_change (vlib_main_t *vm)
{
  avf_main_t *am = &avf_main;

  vec_validate_aligned (am->per_thread_data, vlib_get_n_threads () - 1,
			CLIB_CACHE_LINE_BYTES);

  return 0;
}

VLIB_NUM_WORKERS_CHANGE_FN (avf_num_workers_change);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_avf",
};
