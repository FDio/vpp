/* SPDX-License-Identifier: Apache-2.0 */
#include <inline_funcs.h>

VLIB_REGISTER_LOG_CLASS (vnp_log, static) = {
  .class_name = "virtio-net-pci",
  .subclass_name = "control",
};

vnet_dev_rv_t
vnp_ctlq_alloc (vlib_main_t *vm, vnet_dev_t *dev, vnp_ctlq_t *q, u16 size, u16 id)
{
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  u8 packed = (vd->features & VIRTIO_F_RING_PACKED_BIT) != 0;
  u32 ring_size;
  void *mem;
  vnet_dev_rv_t rv;

  if (packed)
    ring_size = round_pow2 (size * sizeof (pvirtq_desc_t) + 8, 64);
  else
    ring_size = vnp_ring_size (size);

  rv = vnet_dev_dma_mem_alloc (vm, dev, ring_size + size * 16, 4096, &mem, "virtio control queue");
  if (rv)
    return rv;

  q->desc = mem;
  q->size = size;
  q->id = id;
  q->packed = packed;
  return VNET_DEV_OK;
}

void
vnp_ctlq_free (vlib_main_t *vm, vnet_dev_t *dev, vnp_ctlq_t *q)
{
  vnet_dev_dma_mem_free (vm, dev, q->desc);
  *q = (vnp_ctlq_t) {};
}

vnet_dev_rv_t
vnp_ctlq_start (vlib_main_t *vm, vnet_dev_t *dev, vnp_ctlq_t *q)
{
  virtq_avail_t *avail = (void *) (q->desc + q->size);
  virtq_used_t *used = (void *) ((u8 *) q->desc + vnp_used_offset (q->size));
  void *desc_area, *driver_area, *device_area;

  q->index = 0;
  q->failed = 0;

  if (q->packed)
    {
      pvirtq_event_suppress_t *driver_event = (void *) (q->pdesc + q->size);

      clib_memset (q->pdesc, 0, q->size * sizeof (q->pdesc[0]) + 8);
      driver_event->flags = VRING_EVENT_F_DISABLE;
      desc_area = q->pdesc;
      driver_area = driver_event;
      device_area = driver_event + 1;
    }
  else
    {
      clib_memset (avail, 0, 6 + 2 * q->size);
      clib_memset (used, 0, 6 + 8 * q->size);
      avail->flags = VRING_AVAIL_F_NO_INTERRUPT;
      desc_area = q->desc;
      driver_area = avail;
      device_area = used;
    }

  return vnp_queue_enable (vm, dev, q->id, q->size, desc_area, driver_area, device_area,
			   &q->notify);
}

vnet_dev_rv_t
vnp_control (vlib_main_t *vm, vnet_dev_t *dev, u8 class, u8 command, void *data, u32 length)
{
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  vnp_ctlq_t *q = &vd->control;
  virtq_avail_t *avail = (void *) (q->desc + q->size);
  virtq_used_t *used = (void *) ((u8 *) q->desc + vnp_used_offset (q->size));
  u32 ring_size;
  u8 *p;
  u64 addr[3];
  u32 len[3] = { 2, length, 1 };
  u16 flags[3] = { VRING_DESC_F_NEXT, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE };
  u16 first = 0;
  u8 first_wrap = 0;
  f64 deadline;

  if (!q->size || q->failed)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  if (length > q->size * 16 - 3)
    return VNET_DEV_ERR_INVALID_VALUE;

  if (q->packed)
    ring_size = round_pow2 (q->size * sizeof (pvirtq_desc_t) + 8, 64);
  else
    ring_size = vnp_ring_size (q->size);

  p = (u8 *) q->desc + ring_size;

  log_debug (dev, "%U length %u", format_vnp_ctrl_cmd, class, command, length);

  *(virtio_net_ctrl_hdr_t *) p = (virtio_net_ctrl_hdr_t) {
    .class = class,
    .command = command,
  };
  clib_memcpy_fast (p + 2, data, length);
  p[length + 2] = 0xff;
  addr[0] = vnet_dev_get_dma_addr (vm, dev, p);
  addr[1] = vnet_dev_get_dma_addr (vm, dev, p + 2);
  addr[2] = vnet_dev_get_dma_addr (vm, dev, p + length + 2);

  if (q->packed)
    {
      u16 pos = q->index, first_flags = 0;
      u8 wrap = !(__atomic_load_n (&q->pdesc[pos].flags, __ATOMIC_ACQUIRE) & VRING_DESC_F_AVAIL);

      first = pos;
      first_wrap = wrap;

      for (u32 i = 0; i < 3; i++)
	{
	  u16 f = flags[i] | (wrap ? VRING_DESC_F_AVAIL : VRING_DESC_F_USED);

	  q->pdesc[pos].addr = addr[i];
	  q->pdesc[pos].len = len[i];
	  q->pdesc[pos].id = 0;

	  if (i == 0)
	    first_flags = f;
	  else
	    __atomic_store_n (&q->pdesc[pos].flags, f, __ATOMIC_RELEASE);

	  if (++pos == q->size)
	    {
	      pos = 0;
	      wrap ^= 1;
	    }
	}

      __atomic_store_n (&q->pdesc[first].flags, first_flags, __ATOMIC_RELEASE);
      q->index = pos;
    }
  else
    {
      for (u32 i = 0; i < 3; i++)
	q->desc[i] = (virtq_desc_t) {
	  .addr = addr[i],
	  .len = len[i],
	  .flags = flags[i],
	  .next = i + 1,
	};

      avail->ring[q->index++ & (q->size - 1)] = 0;
      __atomic_store_n (&avail->idx, q->index, __ATOMIC_RELEASE);
    }

  vnp_reg_wr16 (q->notify, q->id);
  deadline = vlib_time_now (vm) + 1;

  while (1)
    {
      if (q->packed)
	{
	  u16 f = __atomic_load_n (&q->pdesc[first].flags, __ATOMIC_ACQUIRE);

	  if (((f & VRING_DESC_F_AVAIL) != 0) == first_wrap &&
	      ((f & VRING_DESC_F_USED) != 0) == first_wrap)
	    break;
	}
      else if (__atomic_load_n (&used->idx, __ATOMIC_ACQUIRE) == q->index)
	break;

      if (vlib_time_now (vm) > deadline)
	{
	  log_err (dev, "control queue %u timeout, %U", q->id, format_vnp_ctrl_cmd, class, command);
	  q->failed = 1;
	  return VNET_DEV_ERR_TIMEOUT;
	}

      vlib_process_suspend (vm, 1e-4);
    }

  log_debug (dev, "%U ack %U", format_vnp_ctrl_cmd, class, command, format_vnp_ctrl_ack,
	     p[length + 2]);

  return p[length + 2] == VIRTIO_NET_OK ? VNET_DEV_OK : VNET_DEV_ERR_NOT_SUPPORTED;
}

vnet_dev_rv_t
vnp_filters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnp_dev_t *vd = vnet_dev_get_data (port->dev);
  vnp_port_t *vp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;
  u8 enabled = 1, differs = 0;
  u8 payload[8 + 64 * 6] = {};
  u32 n_unicast = 0, n_multicast = 0, offset = 4, multicast_offset, count;

  if (!(vd->features & VIRTIO_NET_F_CTRL_RX_BIT))
    return VNET_DEV_OK;

  if (!port->attr.caps.mac_filter)
    {
      rv = vnp_control (vm, port->dev, VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_PROMISC, &enabled, 1);
      if (rv)
	return rv;

      if (vd->features & VIRTIO_NET_F_MAC_BIT)
	for (u32 i = 0; i < 6; i++)
	  differs |= port->primary_hw_addr.eth_mac[i] != vd->config->mac[i];
      else
	differs = 1;

      if (differs && (vd->features & VIRTIO_NET_F_CTRL_MAC_ADDR_BIT))
	return vnp_control (vm, port->dev, VIRTIO_NET_CTRL_MAC, VIRTIO_NET_CTRL_MAC_ADDR_SET,
			    port->primary_hw_addr.eth_mac, 6);

      return VNET_DEV_OK;
    }

  rv = vnp_control (vm, port->dev, VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_ALLMULTI, &enabled, 1);
  if (rv)
    return rv;

  enabled = port->promisc;
  rv = vnp_control (vm, port->dev, VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_PROMISC, &enabled, 1);
  if (rv)
    return rv;

  if (vd->features & VIRTIO_NET_F_CTRL_MAC_ADDR_BIT)
    {
      rv = vnp_control (vm, port->dev, VIRTIO_NET_CTRL_MAC, VIRTIO_NET_CTRL_MAC_ADDR_SET,
			port->primary_hw_addr.eth_mac, 6);
      if (rv)
	return rv;
    }

  for (u32 i = 0; i < vp->n_macs; i++)
    if (!ethernet_address_cast (vp->macs[i]))
      {
	clib_memcpy_fast (payload + offset, vp->macs[i], 6);
	offset += 6;
	n_unicast++;
      }

  ((virtio_net_ctrl_mac_t *) payload)->entries = n_unicast;
  multicast_offset = offset;
  offset += 4;

  for (u32 i = 0; i < vp->n_macs; i++)
    if (ethernet_address_cast (vp->macs[i]))
      {
	clib_memcpy_fast (payload + offset, vp->macs[i], 6);
	offset += 6;
	n_multicast++;
      }

  count = n_multicast;
  ((virtio_net_ctrl_mac_t *) (payload + multicast_offset))->entries = count;
  return vnp_control (vm, port->dev, VIRTIO_NET_CTRL_MAC, VIRTIO_NET_CTRL_MAC_TABLE_SET, payload,
		      offset);
}

vnet_dev_rv_t
vnp_rss (vlib_main_t *vm, vnet_dev_port_t *port, const vnet_dev_rss_config_t *config)
{
  vnp_dev_t *vd = vnet_dev_get_data (port->dev);
  u8 payload[512] = {};
  u16 n_queues = 0, lut_size = 128;
  virtio_net_rss_config_t *rss = (void *) payload;
  u16 *lut = rss->indirection_table;
  vnp_rss_tail_t *tail;
  u32 supported;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    n_queues++;

  if (!(vd->features & VIRTIO_NET_F_RSS_BIT))
    {
      u16 pairs = n_queues;
      return vnp_control (vm, port->dev, VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET,
			  &pairs, sizeof (pairs));
    }

  lut_size = clib_min (lut_size, vd->config->rss_max_indirection_table_length);

  if (config->set_lut)
    lut_size = config->lut_len;

  supported = vd->config->supported_hash_types;
  rss->hash_types = (supported & 0x3ff);
  rss->indirection_table_mask = (lut_size - 1);

  for (u32 i = 0; i < lut_size; i++)
    lut[i] = (config->set_lut ? config->lut[i] : i % n_queues);

  tail = (void *) (lut + lut_size);
  tail->max_tx_vq = n_queues;
  tail->hash_key_length = 40;

  for (u32 i = 0; i < 40; i++)
    tail->hash_key_data[i] = config->set_key ? config->key[i] : 0x6d + i;

  return vnp_control (vm, port->dev, VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_RSS_CONFIG, payload,
		      sizeof (*rss) + 2 * lut_size + sizeof (*tail) + tail->hash_key_length);
}
