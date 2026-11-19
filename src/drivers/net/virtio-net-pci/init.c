/* SPDX-License-Identifier: Apache-2.0 */
#include <inline_funcs.h>

#define _(n, s, v, d)                                                                              \
  {                                                                                                \
    .name = s,                                                                                     \
    .desc = d,                                                                                     \
    .severity = VL_COUNTER_SEVERITY_##v,                                                           \
  },
static vlib_error_desc_t vnp_rx_counters[] = { foreach_vnp_rx_node_counter };
static vlib_error_desc_t vnp_tx_counters[] = { foreach_vnp_tx_node_counter };
#undef _

vnet_dev_node_t vnp_rx_node = {
  .format_trace = format_vnp_rx_trace,
  .error_counters = vnp_rx_counters,
  .n_error_counters = ARRAY_LEN (vnp_rx_counters),
};

vnet_dev_node_t vnp_tx_node = {
  .format_trace = format_vnp_tx_trace,
  .error_counters = vnp_tx_counters,
  .n_error_counters = ARRAY_LEN (vnp_tx_counters),
};

static u8 *
vnp_probe (vlib_main_t *vm __clib_unused, vnet_dev_probe_args_t *a)
{
  vnet_dev_bus_pci_device_info_t *di = a->device_info;

  if (di->vendor_id == 0x1af4 && (di->device_id == 0x1041 || di->device_id == 0x1000))
    return format (0, "Virtio network device");

  return 0;
}

vnet_dev_rv_t
vnp_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  f64 deadline = vlib_time_now (vm) + 1;

  vnp_reg_wr8 (&vd->common->status, 0);

  while (vnp_reg_rd8 (&vd->common->status))
    {
      if (vlib_time_now (vm) > deadline)
	return VNET_DEV_ERR_TIMEOUT;

      vlib_process_suspend (vm, 1e-3);
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnp_negotiate (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  virtio_pci_common_cfg_t *c = vd->common;
  u64 offered;
  vnet_dev_rv_t rv = vnp_reset (vm, dev);

  if (rv != VNET_DEV_OK)
    return rv;

  vnp_reg_wr8 (&c->status, VIRTIO_CONFIG_STATUS_ACK);
  vnp_reg_wr8 (&c->status, VIRTIO_CONFIG_STATUS_ACK | VIRTIO_CONFIG_STATUS_DRIVER);
  vnp_reg_wr32 (&c->device_feature_select, 0);
  offered = vnp_reg_rd32 (&c->device_feature);
  vnp_reg_wr32 (&c->device_feature_select, 1);
  offered |= (u64) vnp_reg_rd32 (&c->device_feature) << 32;
  vd->offered = offered;

  if ((offered & (VIRTIO_F_VERSION_1_BIT | VIRTIO_NET_F_MAC_BIT)) !=
      (VIRTIO_F_VERSION_1_BIT | VIRTIO_NET_F_MAC_BIT))
    goto unsupported;

  vd->features =
    offered &
    (VIRTIO_F_VERSION_1_BIT | VIRTIO_NET_F_MAC_BIT | VIRTIO_NET_F_STATUS_BIT |
     VIRTIO_F_ACCESS_PLATFORM_BIT | VIRTIO_NET_F_MRG_RXBUF_BIT | VIRTIO_RING_F_INDIRECT_DESC_BIT |
     VIRTIO_NET_F_CTRL_VQ_BIT | VIRTIO_NET_F_CTRL_RX_BIT | VIRTIO_NET_F_MQ_BIT |
     VIRTIO_NET_F_CTRL_MAC_ADDR_BIT | VIRTIO_NET_F_RSS_BIT | VIRTIO_F_RING_PACKED_BIT |
     VIRTIO_NET_F_MTU_BIT | VIRTIO_NET_F_CSUM_BIT | VIRTIO_NET_F_GUEST_CSUM_BIT |
     VIRTIO_NET_F_HOST_TSO4_BIT | VIRTIO_NET_F_HOST_TSO6_BIT | VIRTIO_NET_F_GUEST_TSO4_BIT |
     VIRTIO_NET_F_GUEST_TSO6_BIT);

  if (!(vd->features & VIRTIO_NET_F_CTRL_VQ_BIT))
    vd->features &= ~(VIRTIO_NET_F_CTRL_RX_BIT | VIRTIO_NET_F_MQ_BIT |
		      VIRTIO_NET_F_CTRL_MAC_ADDR_BIT | VIRTIO_NET_F_RSS_BIT);

  if (vd->config_length < 12 || vd->config->mtu < 68)
    vd->features &= ~VIRTIO_NET_F_MTU_BIT;

  if (vd->config_length < 8)
    vd->features &= ~VIRTIO_NET_F_STATUS_BIT;

  if (vd->config_length < 24 || vd->config->rss_max_key_size < 40)
    vd->features &= ~VIRTIO_NET_F_RSS_BIT;

  if (!(vd->features & VIRTIO_NET_F_CSUM_BIT))
    vd->features &= ~(VIRTIO_NET_F_HOST_TSO4_BIT | VIRTIO_NET_F_HOST_TSO6_BIT);
  /* without mergeable buffers a received GSO packet does not fit one RX buffer */
  if (!(vd->features & VIRTIO_NET_F_GUEST_CSUM_BIT) || !(vd->features & VIRTIO_NET_F_MRG_RXBUF_BIT))
    vd->features &= ~(VIRTIO_NET_F_GUEST_TSO4_BIT | VIRTIO_NET_F_GUEST_TSO6_BIT);

  if (!clib_args_get_bool_val_by_name (dev->args, "packed"))
    vd->features &= ~VIRTIO_F_RING_PACKED_BIT;

  if (!clib_args_get_bool_val_by_name (dev->args, "indirect"))
    vd->features &= ~VIRTIO_RING_F_INDIRECT_DESC_BIT;

  if (!clib_args_get_bool_val_by_name (dev->args, "rss"))
    vd->features &= ~VIRTIO_NET_F_RSS_BIT;

  if (!clib_args_get_bool_val_by_name (dev->args, "gso"))
    vd->features &= ~(VIRTIO_NET_F_HOST_TSO4_BIT | VIRTIO_NET_F_HOST_TSO6_BIT |
		      VIRTIO_NET_F_GUEST_TSO4_BIT | VIRTIO_NET_F_GUEST_TSO6_BIT);

  if (!clib_args_get_bool_val_by_name (dev->args, "checksum_offload"))
    vd->features &=
      ~(VIRTIO_NET_F_CSUM_BIT | VIRTIO_NET_F_GUEST_CSUM_BIT | VIRTIO_NET_F_HOST_TSO4_BIT |
	VIRTIO_NET_F_HOST_TSO6_BIT | VIRTIO_NET_F_GUEST_TSO4_BIT | VIRTIO_NET_F_GUEST_TSO6_BIT);

  /* Without ACCESS_PLATFORM virtio bypasses the IOMMU, even under VFIO. */
  dev->va_dma = (vd->features & VIRTIO_F_ACCESS_PLATFORM_BIT) &&
		vlib_pci_supports_virtual_addr_dma (vm, vnet_dev_get_pci_handle (dev));
  vnp_reg_wr32 (&c->driver_feature_select, 0);
  vnp_reg_wr32 (&c->driver_feature, vd->features);
  vnp_reg_wr32 (&c->driver_feature_select, 1);
  vnp_reg_wr32 (&c->driver_feature, vd->features >> 32);
  vnp_reg_wr8 (&c->status, vnp_reg_rd8 (&c->status) | VIRTIO_CONFIG_STATUS_FEATURES_OK);

  if (!(vnp_reg_rd8 (&c->status) & VIRTIO_CONFIG_STATUS_FEATURES_OK))
    goto unsupported;

  vnp_reg_wr16 (&c->msix_config, 0xffff);
  return VNET_DEV_OK;

unsupported:
  vnp_reg_wr8 (&c->status, vnp_reg_rd8 (&c->status) | VIRTIO_CONFIG_STATUS_FAILED);
  return VNET_DEV_ERR_NOT_SUPPORTED;
}

static vnet_dev_rv_t
vnp_read_config (vlib_main_t *vm, vnet_dev_t *dev, u32 off, void *p, u32 size)
{
  clib_error_t *err =
    vlib_pci_read_write_config (vm, vnet_dev_get_pci_handle (dev), VLIB_READ, off, p, size);

  if (!err)
    return VNET_DEV_OK;

  clib_error_free (err);
  return VNET_DEV_ERR_BUS;
}

static vnet_dev_rv_t
vnp_map_caps (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  void *bars[6] = {};
  u8 pos, seen[256] = {};
  vnet_dev_rv_t rv;

  rv = vnp_read_config (vm, dev, 0x34, &pos, sizeof (pos));
  if (rv)
    return rv;

  while (pos)
    {
      virtio_pci_cap_t cap;
      u32 offset, length;
      uword bar_size;
      clib_error_t *err;
      void *base;
      u8 cap_pos = pos;

      if (pos < 0x40 || (pos & 3) || seen[pos] || pos > 256 - sizeof (cap))
	return VNET_DEV_ERR_INVALID_DATA;

      seen[pos] = 1;
      rv = vnp_read_config (vm, dev, pos, &cap, sizeof (cap));
      if (rv)
	return rv;

      pos = cap.next;

      if (cap.vendor != 9 || cap.type < 1 || cap.type > 4)
	continue;

      if (cap.length < sizeof (cap) || cap.bar >= ARRAY_LEN (bars))
	return VNET_DEV_ERR_INVALID_DATA;

      offset = cap.offset;
      length = cap.region_length;
      err = vlib_pci_get_region_size (vm, vnet_dev_get_pci_handle (dev), cap.bar, &bar_size);
      if (err)
	{
	  clib_error_free (err);
	  return VNET_DEV_ERR_BUS;
	}

      if (!length || offset > bar_size || length > bar_size - offset)
	return VNET_DEV_ERR_INVALID_DATA;

      if (!bars[cap.bar])
	{
	  rv = vnet_dev_pci_map_region (vm, dev, cap.bar, &bars[cap.bar]);
	  if (rv)
	    return rv;
	}

      base = bars[cap.bar] + offset;

      switch (cap.type)
	{
	case 1:
	  if (length < sizeof (virtio_pci_common_cfg_t) || (offset & 3))
	    return VNET_DEV_ERR_INVALID_DATA;

	  vd->common = base;
	  break;
	case 2:
	  if (cap.length < sizeof (virtio_pci_notify_cap_t) || cap_pos > 236 || (offset & 1))
	    return VNET_DEV_ERR_INVALID_DATA;

	  rv = vnp_read_config (
	    vm, dev, cap_pos + STRUCT_OFFSET_OF (virtio_pci_notify_cap_t, notify_off_multiplier),
	    &vd->notify_multiplier, 4);
	  if (rv)
	    return rv;

	  vd->notify_multiplier = vd->notify_multiplier;
	  vd->notify = base;
	  vd->notify_length = length;
	  break;
	case 3:
	  vd->isr = base;
	  break;
	case 4:
	  if (length < 6)
	    return VNET_DEV_ERR_INVALID_DATA;

	  vd->config = base;
	  vd->config_length = length;
	  break;
	}
    }

  return vd->common && vd->notify && vd->config ? VNET_DEV_OK : VNET_DEV_ERR_NOT_SUPPORTED;
}

static vnet_dev_rv_t
vnp_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = vnp_map_caps (vm, dev);
  u32 max_frame_size = CLIB_U16_MAX, rx_chain_length = 1;
  u16 queue_sizes[2], max_pairs = 1;
  vnet_dev_port_add_args_t args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .max_rx_queues = 1,
        .max_tx_queues = 1,
        .caps.change_max_rx_frame_size = 1,
      },
      .ops = { .init = vnp_port_init, .deinit = vnp_port_deinit, .start = vnp_port_start, .stop = vnp_port_stop, .config_change_validate = vnp_port_cfg_validate,
        .config_change = vnp_port_cfg_change, .format_status = format_vnp_port_status, },
      .data_size = sizeof (vnp_port_t),
    },
    .rx_node = &vnp_rx_node,
    .tx_node = &vnp_tx_node,
    .rx_queue = {
      .config = { .data_size = sizeof (vnp_rxq_t), .default_size = 256,
                  .min_size = 64, .max_size = 256, .size_is_power_of_two = 1, },
      .ops = { .alloc = vnp_rxq_alloc, .free = vnp_rxq_free, .format_info = format_vnp_rx_queue, },
    },
    .tx_queue = {
      .config = { .data_size = sizeof (vnp_txq_t), .default_size = 256,
                  .min_size = 64, .max_size = 256, .size_is_power_of_two = 1, },
      .ops = { .alloc = vnp_txq_alloc, .free = vnp_txq_free, .format_info = format_vnp_tx_queue, },
    },
  };

  if (rv)
    return rv;

  rv = vnet_dev_pci_bus_master_enable (vm, dev);
  if (rv)
    return rv;

  rv = vnp_negotiate (vm, dev);
  if (rv)
    return rv;

  for (u16 i = 0; i < 2; i++)
    {
      vnp_reg_wr16 (&vd->common->queue_select, i);
      queue_sizes[i] = vnp_reg_rd16 (&vd->common->queue_size);

      if (queue_sizes[i] < 64)
	return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  if ((vd->features & VIRTIO_NET_F_MQ_BIT) && vd->config_length >= 10)
    max_pairs = vd->config->max_virtqueue_pairs;

  if (!max_pairs || max_pairs > 32767 ||
      2 * max_pairs + ((vd->features & VIRTIO_NET_F_CTRL_VQ_BIT) != 0) >
	vnp_reg_rd16 (&vd->common->num_queues))
    return VNET_DEV_ERR_INVALID_DATA;

  if (vd->features & VIRTIO_NET_F_MTU_BIT)
    max_frame_size = vd->config->mtu + sizeof (ethernet_header_t) + VNET_DEV_ETH_FCS_LEN;

  if (vd->features & VIRTIO_NET_F_MRG_RXBUF_BIT)
    rx_chain_length = VNP_MAX_SEGS;

  max_frame_size =
    clib_min (max_frame_size,
	      rx_chain_length * vlib_buffer_get_default_data_size (vm) + VNET_DEV_ETH_FCS_LEN);
  args.port.attr.max_supported_rx_frame_size = max_frame_size;

  args.port.attr.max_rx_queues = args.port.attr.max_tx_queues = max_pairs;
  args.port.attr.tx_offloads.tcp_cksum = (vd->features & VIRTIO_NET_F_CSUM_BIT) != 0;
  args.port.attr.tx_offloads.udp_cksum = (vd->features & VIRTIO_NET_F_CSUM_BIT) != 0;
  args.port.attr.tx_offloads.tcp_gso =
    (vd->features & (VIRTIO_NET_F_HOST_TSO4_BIT | VIRTIO_NET_F_HOST_TSO6_BIT)) ==
    (VIRTIO_NET_F_HOST_TSO4_BIT | VIRTIO_NET_F_HOST_TSO6_BIT);
  args.port.attr.caps.interrupt_mode =
    vnet_dev_get_pci_n_msix_interrupts (dev) >= vlib_get_n_threads () + 1 || vd->isr;
  args.port.attr.caps.mac_filter = clib_args_get_bool_val_by_name (dev->args, "mac_filter") &&
				   (vd->features & VIRTIO_NET_F_CTRL_RX_BIT) != 0;
  args.port.attr.caps.rss = (vd->features & VIRTIO_NET_F_RSS_BIT) != 0;

  if (vd->features & VIRTIO_NET_F_CTRL_VQ_BIT)
    {
      rv = vnp_ctlq_alloc (vm, dev, &vd->control, 64, 2 * max_pairs);
      if (rv)
	return rv;
    }

  args.rx_queue.config.max_size = clib_min (4096, queue_sizes[0]);
  args.rx_queue.config.default_size = clib_min (256, args.rx_queue.config.max_size);
  args.tx_queue.config.max_size = clib_min (4096, queue_sizes[1]);
  args.tx_queue.config.default_size = clib_min (256, args.tx_queue.config.max_size);

  for (u32 i = 0; i < 6; i++)
    args.port.attr.hw_addr.eth_mac[i] = vd->config->mac[i];

  return vnet_dev_port_add (vm, dev, 0, &args);
}

static void
vnp_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnp_dev_t *vd = vnet_dev_get_data (dev);

  if (vd->common)
    vnp_reset (vm, dev);

  if (vd->control.size)
    vnp_ctlq_free (vm, dev, &vd->control);
}

static clib_arg_t vnp_device_args[] = {
  {
    .name = "packed",
    .desc = "Use packed rings when offered",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 1,
  },
  {
    .name = "indirect",
    .desc = "Use indirect TX descriptors when offered",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 1,
  },
  {
    .name = "rss",
    .desc = "Enable RSS when offered",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 1,
  },
  {
    .name = "gso",
    .desc = "Enable TCP segmentation offload when offered",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 1,
  },
  {
    .name = "checksum_offload",
    .desc = "Enable transport checksum offloads when offered",
    .type = CLIB_ARG_TYPE_BOOL,
    .default_val.boolean = 1,
  },
  {
    .name = "mac_filter",
    .desc = "Rely on the device to filter on the destination MAC address",
    .type = CLIB_ARG_TYPE_BOOL,
  },
  {
    .type = CLIB_ARG_END,
  },
};

VNET_DEV_REGISTER_DRIVER (virtio_net_pci) = {
  .name = "virtio-net-pci",
  .description = "Modern Virtio PCI Ethernet",
  .bus = "pci",
  .device = {
    .data_sz = sizeof (vnp_dev_t),
    .args = vnp_device_args,
    .ops = { .probe = vnp_probe, .init = vnp_init, .deinit = vnp_deinit, .format_info = format_vnp_dev_info, },
  },
};
