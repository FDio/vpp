/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vppinfra/types.h>
#include <vlib/pci/pci.h>
#include <dev_virtio/virtio.h>
#include <dev_virtio/pci.h>

VLIB_REGISTER_LOG_CLASS (virtio_log, static) = {
  .class_name = "virtio",
  .subclass_name = "pci",
};

#define PCI_CAPABILITY_LIST 0x34
#define PCI_CAP_ID_VNDR	    0x09
#define PCI_CAP_ID_MSIX	    0x11

#define PCI_MSIX_ENABLE 0x8000

static const u8 virtio_rss_key[VIRTIO_NET_RSS_MAX_KEY_SIZE] = {
  0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67,
  0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb,
  0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
  0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

clib_error_t *
virtio_pci_init_max_virtqueue_pairs (vlib_main_t *vm, virtio_if_t *vif)
{
  clib_error_t *error = 0;
  u16 max_queue_pairs = 1;

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MQ))
    {
      max_queue_pairs = virtio_pci_get_max_virtqueue_pairs (vm, vif);
    }

  log_debug (vnet_dev_get_by_index (vif->dev_index), "max queue pair is %x",
	     max_queue_pairs);
  if (max_queue_pairs < 1 || max_queue_pairs > 0x8000)
    return clib_error_return (error,
			      "max queue pair is %x,"
			      " should be in range [1, 0x8000]",
			      max_queue_pairs);

  vif->max_queue_pairs = max_queue_pairs;
  return error;
}

u16
virtio_pci_is_link_up (vlib_main_t *vm, virtio_if_t *vif)
{
  /*
   * Minimal driver: assumes link is up
   */
  u16 status = 1;
  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_STATUS))
    status = virtio_pci_get_device_status (vm, vif);
  return status;
}

static int
virtio_pci_send_ctrl_msg_packed (vlib_main_t *vm, virtio_if_t *vif,
				 virtio_ctrl_msg_t *data, u32 len)
{
  vnet_virtio_vring_t *vring = vif->cxq_vring;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;
  virtio_ctrl_msg_t result;
  u32 buffer_index;
  vlib_buffer_t *b;
  u16 used, next;
  u16 sz = vring->queue_size;
  u16 flags = 0, first_desc_flags = 0;

  used = vring->desc_in_use;
  next = vring->desc_next;
  vnet_virtio_vring_packed_desc_t *d = &vring->packed_desc[next];

  if (vlib_buffer_alloc (vm, &buffer_index, 1))
    b = vlib_get_buffer (vm, buffer_index);
  else
    return VIRTIO_NET_ERR;
  /*
   * current_data may not be initialized with 0 and may contain
   * previous offset.
   */
  b->current_data = 0;
  clib_memcpy (vlib_buffer_get_current (b), data, sizeof (virtio_ctrl_msg_t));

  first_desc_flags = VRING_DESC_F_NEXT;
  if (vring->avail_wrap_counter)
    {
      first_desc_flags |= VRING_DESC_F_AVAIL;
      first_desc_flags &= ~VRING_DESC_F_USED;
    }
  else
    {
      first_desc_flags &= ~VRING_DESC_F_AVAIL;
      first_desc_flags |= VRING_DESC_F_USED;
    }
  d->addr = vlib_buffer_get_current_pa (vm, b);
  d->len = sizeof (virtio_net_ctrl_hdr_t);
  d->id = next;

  next++;
  if (next >= sz)
    {
      next = 0;
      vring->avail_wrap_counter ^= 1;
    }
  used++;

  d = &vring->packed_desc[next];
  flags = VRING_DESC_F_NEXT;
  if (vring->avail_wrap_counter)
    {
      flags |= VRING_DESC_F_AVAIL;
      flags &= ~VRING_DESC_F_USED;
    }
  else
    {
      flags &= ~VRING_DESC_F_AVAIL;
      flags |= VRING_DESC_F_USED;
    }
  d->addr = vlib_buffer_get_current_pa (vm, b) +
	    STRUCT_OFFSET_OF (virtio_ctrl_msg_t, data);
  d->len = len;
  d->id = next;
  d->flags = flags;

  next++;
  if (next >= sz)
    {
      next = 0;
      vring->avail_wrap_counter ^= 1;
    }
  used++;

  d = &vring->packed_desc[next];
  flags = VRING_DESC_F_WRITE;
  if (vring->avail_wrap_counter)
    {
      flags |= VRING_DESC_F_AVAIL;
      flags &= ~VRING_DESC_F_USED;
    }
  else
    {
      flags &= ~VRING_DESC_F_AVAIL;
      flags |= VRING_DESC_F_USED;
    }
  d->addr = vlib_buffer_get_current_pa (vm, b) +
	    STRUCT_OFFSET_OF (virtio_ctrl_msg_t, status);
  d->len = sizeof (data->status);
  d->id = next;
  d->flags = flags;

  next++;
  if (next >= sz)
    {
      next = 0;
      vring->avail_wrap_counter ^= 1;
    }
  used++;

  CLIB_MEMORY_STORE_BARRIER ();
  vring->packed_desc[vring->desc_next].flags = first_desc_flags;
  vring->desc_next = next;
  vring->desc_in_use = used;
  CLIB_MEMORY_BARRIER ();
  if (vring->device_event->flags != VRING_EVENT_F_DISABLE)
    {
      virtio_kick (vm, vring, vif);
    }

  u16 last = vring->last_used_idx;
  d = &vring->packed_desc[last];
  do
    {
      flags = d->flags;
    }
  while ((flags & VRING_DESC_F_AVAIL) != (vring->used_wrap_counter << 7) ||
	 (flags & VRING_DESC_F_USED) != (vring->used_wrap_counter << 15));

  last += 3;
  if (last >= vring->queue_size)
    {
      last = last - vring->queue_size;
      vring->used_wrap_counter ^= 1;
    }
  vring->desc_in_use -= 3;
  vring->last_used_idx = last;

  CLIB_MEMORY_BARRIER ();
  clib_memcpy (&result, vlib_buffer_get_current (b),
	       sizeof (virtio_ctrl_msg_t));
  log_debug (vnet_dev_get_by_index (vif->dev_index), "ctrl-queue: status %u",
	     result.status);
  status = result.status;
  vlib_buffer_free (vm, &buffer_index, 1);
  return status;
}

static int
virtio_pci_send_ctrl_msg_split (vlib_main_t *vm, virtio_if_t *vif,
				virtio_ctrl_msg_t *data, u32 len)
{
  vnet_virtio_vring_t *vring = vif->cxq_vring;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;
  virtio_ctrl_msg_t result;
  u32 buffer_index;
  vlib_buffer_t *b;
  u16 used, next, avail;
  u16 sz = vring->queue_size;
  u16 mask = sz - 1;

  used = vring->desc_in_use;
  next = vring->desc_next;
  avail = vring->avail->idx;
  vnet_virtio_vring_desc_t *d = &vring->desc[next];

  if (vlib_buffer_alloc (vm, &buffer_index, 1))
    b = vlib_get_buffer (vm, buffer_index);
  else
    return VIRTIO_NET_ERR;
  /*
   * current_data may not be initialized with 0 and may contain
   * previous offset.
   */
  b->current_data = 0;
  clib_memcpy (vlib_buffer_get_current (b), data, sizeof (virtio_ctrl_msg_t));
  d->flags = VRING_DESC_F_NEXT;
  d->addr = vlib_buffer_get_current_pa (vm, b);
  d->len = sizeof (virtio_net_ctrl_hdr_t);
  vring->avail->ring[avail & mask] = next;
  avail++;
  next = (next + 1) & mask;
  d->next = next;
  used++;

  d = &vring->desc[next];
  d->flags = VRING_DESC_F_NEXT;
  d->addr = vlib_buffer_get_current_pa (vm, b) +
	    STRUCT_OFFSET_OF (virtio_ctrl_msg_t, data);
  d->len = len;
  next = (next + 1) & mask;
  d->next = next;
  used++;

  d = &vring->desc[next];
  d->flags = VRING_DESC_F_WRITE;
  d->addr = vlib_buffer_get_current_pa (vm, b) +
	    STRUCT_OFFSET_OF (virtio_ctrl_msg_t, status);
  d->len = sizeof (data->status);
  next = (next + 1) & mask;
  used++;

  CLIB_MEMORY_STORE_BARRIER ();
  vring->avail->idx = avail;
  vring->desc_next = next;
  vring->desc_in_use = used;

  if ((vring->used->flags & VRING_AVAIL_F_NO_INTERRUPT) == 0)
    {
      virtio_kick (vm, vring, vif);
    }

  u16 last = vring->last_used_idx, n_left = 0;
  n_left = vring->used->idx - last;

  while (n_left)
    {
      vnet_virtio_vring_used_elem_t *e = &vring->used->ring[last & mask];
      u16 slot = e->id;

      d = &vring->desc[slot];
      while (d->flags & VRING_DESC_F_NEXT)
	{
	  used--;
	  slot = d->next;
	  d = &vring->desc[slot];
	}
      used--;
      last++;
      n_left--;
    }
  vring->desc_in_use = used;
  vring->last_used_idx = last;

  CLIB_MEMORY_BARRIER ();
  clib_memcpy (&result, vlib_buffer_get_current (b),
	       sizeof (virtio_ctrl_msg_t));
  log_debug (vnet_dev_get_by_index (vif->dev_index), "ctrl-queue: status %u",
	     result.status);
  status = result.status;
  vlib_buffer_free (vm, &buffer_index, 1);
  return status;
}

static int
virtio_pci_send_ctrl_msg (vlib_main_t *vm, virtio_if_t *vif,
			  virtio_ctrl_msg_t *data, u32 len)
{
  if (vif->is_packed)
    return virtio_pci_send_ctrl_msg_packed (vm, vif, data, len);
  else
    return virtio_pci_send_ctrl_msg_split (vm, vif, data, len);
}

static int
virtio_pci_disable_offload (vlib_main_t *vm, virtio_if_t *vif)
{
  virtio_ctrl_msg_t offload_hdr;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;

  offload_hdr.ctrl.class = VIRTIO_NET_CTRL_GUEST_OFFLOADS;
  offload_hdr.ctrl.cmd = VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET;
  offload_hdr.status = VIRTIO_NET_ERR;
  u64 offloads = 0ULL;
  clib_memcpy (offload_hdr.data, &offloads, sizeof (offloads));

  status = virtio_pci_send_ctrl_msg (vm, vif, &offload_hdr, sizeof (offloads));
  log_debug (vnet_dev_get_by_index (vif->dev_index), "disable offloads");
  vif->remote_features = virtio_pci_get_device_features (vm, vif);
  virtio_pci_get_driver_features (vm, vif);
  return status;
}

static int
virtio_pci_enable_checksum_offload (vlib_main_t *vm, virtio_if_t *vif)
{
  virtio_ctrl_msg_t csum_offload_hdr;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;

  csum_offload_hdr.ctrl.class = VIRTIO_NET_CTRL_GUEST_OFFLOADS;
  csum_offload_hdr.ctrl.cmd = VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET;
  csum_offload_hdr.status = VIRTIO_NET_ERR;
  u64 offloads = 0ULL;
  offloads |= VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM);
  clib_memcpy (csum_offload_hdr.data, &offloads, sizeof (offloads));

  status =
    virtio_pci_send_ctrl_msg (vm, vif, &csum_offload_hdr, sizeof (offloads));
  log_debug (vnet_dev_get_by_index (vif->dev_index),
	     "enable checksum offload");
  vif->remote_features = virtio_pci_get_device_features (vm, vif);
  vif->features = virtio_pci_get_driver_features (vm, vif);
  return status;
}

static int
virtio_pci_enable_gso (vlib_main_t *vm, virtio_if_t *vif)
{
  virtio_ctrl_msg_t gso_hdr;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;

  gso_hdr.ctrl.class = VIRTIO_NET_CTRL_GUEST_OFFLOADS;
  gso_hdr.ctrl.cmd = VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET;
  gso_hdr.status = VIRTIO_NET_ERR;
  u64 offloads = VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM) |
		 VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO4) |
		 VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO6);
  clib_memcpy (gso_hdr.data, &offloads, sizeof (offloads));

  status = virtio_pci_send_ctrl_msg (vm, vif, &gso_hdr, sizeof (offloads));
  log_debug (vnet_dev_get_by_index (vif->dev_index), "enable gso");
  vif->remote_features = virtio_pci_get_device_features (vm, vif);
  virtio_pci_get_driver_features (vm, vif);
  return status;
}

int
virtio_pci_offloads (vlib_main_t *vm, virtio_if_t *vif, int gso_enabled,
		     int csum_offload_enabled)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_if_caps_change_t cc = {};

  if ((vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ)) &&
      (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_GUEST_OFFLOADS)))
    {
      if (gso_enabled &&
	  (vif->features & (VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO4) |
			    VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO6))))
	{
	  if (virtio_pci_enable_gso (vm, vif))
	    {
	      log_warning (vnet_dev_get_by_index (vif->dev_index),
			   "gso is not enabled");
	    }
	  else
	    {
	      vif->gso_enabled = 1;
	      vif->csum_offload_enabled = 1;
	      cc.val = cc.mask =
		VNET_HW_IF_CAP_TCP_GSO | VNET_HW_IF_CAP_TX_TCP_CKSUM |
		VNET_HW_IF_CAP_TX_UDP_CKSUM | VNET_HW_IF_CAP_TX_FIXED_OFFSET;
	    }
	}
      else if (csum_offload_enabled &&
	       (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CSUM)))
	{
	  if (virtio_pci_enable_checksum_offload (vm, vif))
	    {
	      log_warning (vnet_dev_get_by_index (vif->dev_index),
			   "checksum offload is not enabled");
	    }
	  else
	    {
	      vif->csum_offload_enabled = 1;
	      vif->gso_enabled = 0;
	      cc.val = VNET_HW_IF_CAP_TX_TCP_CKSUM |
		       VNET_HW_IF_CAP_TX_UDP_CKSUM |
		       VNET_HW_IF_CAP_TX_FIXED_OFFSET;
	      cc.mask = VNET_HW_IF_CAP_TCP_GSO | VNET_HW_IF_CAP_TX_TCP_CKSUM |
			VNET_HW_IF_CAP_TX_UDP_CKSUM |
			VNET_HW_IF_CAP_TX_FIXED_OFFSET;
	    }
	}
      else
	{
	  if (virtio_pci_disable_offload (vm, vif))
	    {
	      log_warning (vnet_dev_get_by_index (vif->dev_index),
			   "offloads are not disabled");
	    }
	  else
	    {
	      vif->csum_offload_enabled = 0;
	      vif->gso_enabled = 0;
	      cc.val = 0;
	      cc.mask = VNET_HW_IF_CAP_TX_CKSUM | VNET_HW_IF_CAP_TCP_GSO |
			VNET_HW_IF_CAP_TX_FIXED_OFFSET;
	    }
	}
    }

  if (cc.mask)
    vnet_hw_if_change_caps (vnm, vif->hw_if_index, &cc);

  return 0;
}

int
virtio_pci_enable_multiqueue (vlib_main_t *vm, virtio_if_t *vif,
			      u16 num_queues)
{
  virtio_ctrl_msg_t mq_hdr;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;

  mq_hdr.ctrl.class = VIRTIO_NET_CTRL_MQ;
  mq_hdr.ctrl.cmd = VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET;
  mq_hdr.status = VIRTIO_NET_ERR;
  clib_memcpy (mq_hdr.data, &num_queues, sizeof (num_queues));

  status = virtio_pci_send_ctrl_msg (vm, vif, &mq_hdr, sizeof (num_queues));
  log_debug (vnet_dev_get_by_index (vif->dev_index),
	     "multi-queue enable %u queues", num_queues);
  return status;
}

int
virtio_pci_enable_multiqueue_rss (vlib_main_t *vm, virtio_if_t *vif,
				  u16 num_queues)
{
  virtio_ctrl_msg_t mq_hdr;
  virtio_net_rss_config *rss = (virtio_net_rss_config *) mq_hdr.data;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;

  STATIC_ASSERT (sizeof (*rss) <= sizeof (mq_hdr.data),
		 "virtio_net_rss_config size too big");
  mq_hdr.ctrl.class = VIRTIO_NET_CTRL_MQ;
  mq_hdr.ctrl.cmd = VIRTIO_NET_CTRL_MQ_RSS_CONFIG;
  mq_hdr.status = VIRTIO_NET_ERR;

  rss->hash_types = VIRTIO_NET_HASH_TYPE_SUPPORTED;
  rss->indirection_table_mask = VIRTIO_NET_RSS_MAX_TABLE_LEN - 1;
  rss->unclassified_queue = 0;
  for (int i = 0; i < VIRTIO_NET_RSS_MAX_TABLE_LEN; i++)
    rss->indirection_table[i] = i % num_queues;
  rss->max_tx_vq = num_queues;
  rss->hash_key_length = VIRTIO_NET_RSS_MAX_KEY_SIZE;
  clib_memcpy (rss->hash_key_data, virtio_rss_key,
	       VIRTIO_NET_RSS_MAX_KEY_SIZE);

  status = virtio_pci_send_ctrl_msg (vm, vif, &mq_hdr, sizeof (*rss));
  log_debug (vnet_dev_get_by_index (vif->dev_index),
	     "multi-queue with rss enable %u queues", num_queues);
  return status;
}

static u8
virtio_pci_queue_size_valid (u16 qsz)
{
  if (qsz < 64 || qsz > 4096)
    return 0;
  if ((qsz % 64) != 0)
    return 0;
  return 1;
}

clib_error_t *
virtio_pci_control_vring_packed_init (vlib_main_t *vm, virtio_if_t *vif,
				      u16 queue_num)
{
  clib_error_t *error = 0;
  u16 queue_size = 0;
  vnet_virtio_vring_t *vring;
  u32 i = 0;
  void *ptr = NULL;

  queue_size = virtio_pci_get_queue_size (vm, vif, queue_num);

  if (queue_size > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (queue_size == 0)
    queue_size = 256;

  vec_validate_aligned (vif->cxq_vring, 0, CLIB_CACHE_LINE_BYTES);
  vring = vec_elt_at_index (vif->cxq_vring, 0);

  i = (((queue_size * sizeof (vnet_virtio_vring_packed_desc_t)) +
	sizeof (vnet_virtio_vring_desc_event_t) + VNET_VIRTIO_PCI_VRING_ALIGN -
	1) &
       ~(VNET_VIRTIO_PCI_VRING_ALIGN - 1)) +
      sizeof (vnet_virtio_vring_desc_event_t);

  ptr = vlib_physmem_alloc_aligned_on_numa (vm, i, VNET_VIRTIO_PCI_VRING_ALIGN,
					    vif->numa_node);
  if (!ptr)
    return vlib_physmem_last_error (vm);
  clib_memset (ptr, 0, i);

  vring->packed_desc = ptr;

  vring->driver_event =
    ptr + (queue_size * sizeof (vnet_virtio_vring_packed_desc_t));
  vring->driver_event->off_wrap = 0;
  vring->driver_event->flags = VRING_EVENT_F_DISABLE;

  vring->device_event =
    ptr + (((queue_size * sizeof (vnet_virtio_vring_packed_desc_t)) +
	    sizeof (vnet_virtio_vring_desc_event_t) +
	    VNET_VIRTIO_PCI_VRING_ALIGN - 1) &
	   ~(VNET_VIRTIO_PCI_VRING_ALIGN - 1));
  vring->device_event->off_wrap = 0;
  vring->device_event->flags = 0;

  vring->total_packets = 0;
  vring->queue_id = queue_num;
  vring->queue_size = queue_size;
  vring->avail_wrap_counter = 1;
  vring->used_wrap_counter = 1;

  ASSERT (vring->buffers == 0);

  log_debug (vnet_dev_get_by_index (vif->dev_index),
	     "control-queue: number %u, size %u", queue_num, queue_size);
  virtio_pci_setup_queue (vm, vif, queue_num, vring);
  vring->queue_notify_offset =
    vif->notify_off_multiplier *
    virtio_pci_get_queue_notify_off (vm, vif, queue_num);
  log_debug (vnet_dev_get_by_index (vif->dev_index),
	     "queue-notify-offset: number %u, offset %u", queue_num,
	     vring->queue_notify_offset);
  return error;
}

clib_error_t *
virtio_pci_control_vring_split_init (vlib_main_t *vm, virtio_if_t *vif,
				     u16 queue_num)
{
  clib_error_t *error = 0;
  u16 queue_size = 0;
  vnet_virtio_vring_t *vring;
  u32 i = 0;
  void *ptr = NULL;

  queue_size = virtio_pci_get_queue_size (vm, vif, queue_num);
  if (!virtio_pci_queue_size_valid (queue_size))
    clib_warning ("queue size is not valid");

  if (!is_pow2 (queue_size))
    return clib_error_return (0, "ring size must be power of 2");

  if (queue_size > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (queue_size == 0)
    queue_size = 256;

  vec_validate_aligned (vif->cxq_vring, 0, CLIB_CACHE_LINE_BYTES);
  vring = vec_elt_at_index (vif->cxq_vring, 0);
  i = vnet_virtio_vring_size (queue_size, VNET_VIRTIO_PCI_VRING_ALIGN);
  i = round_pow2 (i, VNET_VIRTIO_PCI_VRING_ALIGN);
  ptr = vlib_physmem_alloc_aligned_on_numa (vm, i, VNET_VIRTIO_PCI_VRING_ALIGN,
					    vif->numa_node);
  if (!ptr)
    return vlib_physmem_last_error (vm);
  clib_memset (ptr, 0, i);
  vnet_virtio_vring_init (vring, queue_size, ptr, VNET_VIRTIO_PCI_VRING_ALIGN);
  vring->queue_id = queue_num;
  vring->total_packets = 0;

  ASSERT (vring->buffers == 0);
  log_debug (vnet_dev_get_by_index (vif->dev_index),
	     "control-queue: number %u, size %u", queue_num, queue_size);
  virtio_pci_setup_queue (vm, vif, queue_num, vring);
  vring->queue_notify_offset =
    vif->notify_off_multiplier *
    virtio_pci_get_queue_notify_off (vm, vif, queue_num);
  log_debug (vnet_dev_get_by_index (vif->dev_index),
	     "queue-notify-offset: number %u, offset %u", queue_num,
	     vring->queue_notify_offset);

  return error;
}

clib_error_t *
virtio_pci_control_vring_init (vlib_main_t *vm, virtio_if_t *vif,
			       u16 queue_num)
{
  if (vif->is_packed)
    return virtio_pci_control_vring_packed_init (vm, vif, queue_num);
  else
    return virtio_pci_control_vring_split_init (vm, vif, queue_num);
}

clib_error_t *
virtio_pci_vring_split_init (vlib_main_t *vm, virtio_if_t *vif, u16 queue_num,
			     u16 queue_size, vnet_virtio_vring_t *vring)
{
  clib_error_t *error = 0;
  u32 i = 0;
  void *ptr = NULL;

  i = vnet_virtio_vring_size (queue_size, VNET_VIRTIO_PCI_VRING_ALIGN);
  i = round_pow2 (i, VNET_VIRTIO_PCI_VRING_ALIGN);
  ptr = vlib_physmem_alloc_aligned_on_numa (vm, i, VNET_VIRTIO_PCI_VRING_ALIGN,
					    vif->numa_node);
  if (!ptr)
    return vlib_physmem_last_error (vm);
  clib_memset (ptr, 0, i);
  vnet_virtio_vring_init (vring, queue_size, ptr, VNET_VIRTIO_PCI_VRING_ALIGN);
  vring->queue_id = queue_num;
  vring->total_packets = 0;

  ASSERT (vring->buffers == 0);
  vec_validate_aligned (vring->buffers, queue_size, CLIB_CACHE_LINE_BYTES);
  if (queue_num % 2)
    {
      clib_spinlock_init (&vring->lockp);
      log_debug (vnet_dev_get_by_index (vif->dev_index),
		 "tx-queue: number %u, size %u", queue_num, queue_size);
      clib_memset_u32 (vring->buffers, ~0, queue_size);
    }
  else
    {
      log_debug (vnet_dev_get_by_index (vif->dev_index),
		 "rx-queue: number %u, size %u", queue_num, queue_size);
    }
  vring->queue_size = queue_size;
  if (virtio_pci_setup_queue (vm, vif, queue_num, vring))
    return clib_error_return (0, "error in queue address setup");

  vring->queue_notify_offset =
    vif->notify_off_multiplier *
    virtio_pci_get_queue_notify_off (vm, vif, queue_num);
  log_debug (vnet_dev_get_by_index (vif->dev_index),
	     "queue-notify-offset: number %u, offset %u", queue_num,
	     vring->queue_notify_offset);
  return error;
}

clib_error_t *
virtio_pci_vring_packed_init (vlib_main_t *vm, virtio_if_t *vif, u16 queue_num,
			      u16 queue_size, vnet_virtio_vring_t *vring)
{
  clib_error_t *error = 0;
  u32 i = 0;
  void *ptr = NULL;

  i = (((queue_size * sizeof (vnet_virtio_vring_packed_desc_t)) +
	sizeof (vnet_virtio_vring_desc_event_t) + VNET_VIRTIO_PCI_VRING_ALIGN -
	1) &
       ~(VNET_VIRTIO_PCI_VRING_ALIGN - 1)) +
      sizeof (vnet_virtio_vring_desc_event_t);

  ptr = vlib_physmem_alloc_aligned_on_numa (vm, i, VNET_VIRTIO_PCI_VRING_ALIGN,
					    vif->numa_node);
  if (!ptr)
    return vlib_physmem_last_error (vm);

  clib_memset (ptr, 0, i);
  vring->packed_desc = ptr;

  vring->driver_event =
    ptr + (queue_size * sizeof (vnet_virtio_vring_packed_desc_t));
  vring->driver_event->off_wrap = 0;
  vring->driver_event->flags = VRING_EVENT_F_DISABLE;

  vring->device_event =
    ptr + (((queue_size * sizeof (vnet_virtio_vring_packed_desc_t)) +
	    sizeof (vnet_virtio_vring_desc_event_t) +
	    VNET_VIRTIO_PCI_VRING_ALIGN - 1) &
	   ~(VNET_VIRTIO_PCI_VRING_ALIGN - 1));
  vring->device_event->off_wrap = 0;
  vring->device_event->flags = 0;

  vring->queue_id = queue_num;

  vring->avail_wrap_counter = 1;
  vring->used_wrap_counter = 1;
  vring->total_packets = 0;

  ASSERT (vring->buffers == 0);
  vec_validate_aligned (vring->buffers, queue_size, CLIB_CACHE_LINE_BYTES);
  if (queue_num % 2)
    {
      log_debug (vnet_dev_get_by_index (vif->dev_index),
		 "tx-queue: number %u, size %u", queue_num, queue_size);
      clib_memset_u32 (vring->buffers, ~0, queue_size);
    }
  else
    {
      log_debug (vnet_dev_get_by_index (vif->dev_index),
		 "rx-queue: number %u, size %u", queue_num, queue_size);
    }
  vring->queue_size = queue_size;
  if (virtio_pci_setup_queue (vm, vif, queue_num, vring))
    return clib_error_return (0, "error in queue address setup");

  vring->queue_notify_offset =
    vif->notify_off_multiplier *
    virtio_pci_get_queue_notify_off (vm, vif, queue_num);
  log_debug (vnet_dev_get_by_index (vif->dev_index),
	     "queue-notify-offset: number %u, offset %u", queue_num,
	     vring->queue_notify_offset);

  return error;
}

clib_error_t *
virtio_pci_vring_init (vlib_main_t *vm, virtio_if_t *vif, u16 queue_num,
		       u16 queue_size, vnet_virtio_vring_t *vring)
{
  if (vif->is_packed)
    return virtio_pci_vring_packed_init (vm, vif, queue_num, queue_size,
					 vring);
  else
    return virtio_pci_vring_split_init (vm, vif, queue_num, queue_size, vring);
}

static void
virtio_negotiate_features (vlib_main_t *vm, virtio_if_t *vif)
{
  /*
   * if features are not requested
   * default: all supported features
   */
  u64 supported_features =
    VIRTIO_FEATURE (VIRTIO_NET_F_CSUM) |
    VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM) |
    VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_GUEST_OFFLOADS) |
    VIRTIO_FEATURE (VIRTIO_NET_F_MTU) | VIRTIO_FEATURE (VIRTIO_NET_F_MAC) |
    VIRTIO_FEATURE (VIRTIO_NET_F_GSO) |
    VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO4) |
    VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO6) |
    VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_UFO) |
    VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO4) |
    VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO6) |
    VIRTIO_FEATURE (VIRTIO_NET_F_HOST_UFO) |
    VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF) |
    VIRTIO_FEATURE (VIRTIO_NET_F_STATUS) |
    VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ) | VIRTIO_FEATURE (VIRTIO_NET_F_MQ) |
    VIRTIO_FEATURE (VIRTIO_F_NOTIFY_ON_EMPTY) |
    VIRTIO_FEATURE (VIRTIO_F_ANY_LAYOUT) |
    VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC) |
    VIRTIO_FEATURE (VIRTIO_F_VERSION_1);

  if (vif->rss_enabled)
    supported_features |= VIRTIO_FEATURE (VIRTIO_NET_F_RSS);

  if (vif->is_packed)
    {
      supported_features |= (VIRTIO_FEATURE (VIRTIO_F_RING_PACKED) |
			     VIRTIO_FEATURE (VIRTIO_F_IN_ORDER));
    }

  vif->features = vif->remote_features & supported_features;

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MTU))
    {
      u16 mtu = 0;
      mtu = virtio_pci_get_mtu (vm, vif);

      if (mtu < 64)
	vif->features &= ~VIRTIO_FEATURE (VIRTIO_NET_F_MTU);
    }

    // XXX Don't want to silently turn off the packed if it is configured
#if (0)
  if ((vif->features & (VIRTIO_FEATURE (VIRTIO_F_RING_PACKED))) == 0)
    vif->is_packed = 0;
#endif

  virtio_pci_set_driver_features (vm, vif, vif->features);
  vif->features = virtio_pci_get_driver_features (vm, vif);
}

void
virtio_pci_read_device_feature (vlib_main_t *vm, virtio_if_t *vif)
{
  vif->remote_features = virtio_pci_get_device_features (vm, vif);
}

int
virtio_pci_reset_device (vlib_main_t *vm, virtio_if_t *vif)
{
  u8 status = 0;

  /*
   * Reset the device
   */
  status = virtio_pci_device_reset (vm, vif);

  /*
   * Set the Acknowledge status bit
   */
  virtio_pci_set_status (vm, vif, VIRTIO_CONFIG_STATUS_ACK);

  /*
   * Set the Driver status bit
   */
  virtio_pci_set_status (vm, vif, VIRTIO_CONFIG_STATUS_DRIVER);

  /*
   * Read the status and verify it
   */
  status = virtio_pci_get_status (vm, vif);
  if ((status & VIRTIO_CONFIG_STATUS_ACK) &&
      (status & VIRTIO_CONFIG_STATUS_DRIVER))
    vif->status = status;
  else
    return -1;

  return 0;
}

clib_error_t *
virtio_pci_read_caps (vlib_main_t *vm, virtio_if_t *vif, void **bar)
{
  clib_error_t *error = 0;
  virtio_pci_cap_t cap;
  u8 pos, common_cfg = 0, notify = 0, dev_cfg = 0, isr = 0, pci_cfg = 0;
  vlib_pci_dev_handle_t h = vif->pci_dev_handle;

  if ((error = vlib_pci_read_config_u8 (vm, h, PCI_CAPABILITY_LIST, &pos)))
    {
      log_error (vnet_dev_get_by_index (vif->dev_index),
		 "error in reading capabilty list position");
      return clib_error_return (error,
				"error in reading capabilty list position");
    }
  while (pos)
    {
      if ((error = vlib_pci_read_write_config (vm, h, VLIB_READ, pos, &cap,
					       sizeof (cap))))
	{
	  log_error (vnet_dev_get_by_index (vif->dev_index), "%s [%2x]",
		     "error in reading the capability at", pos);
	  return clib_error_return (
	    error, "error in reading the capability at [%2x]", pos);
	}
      if (cap.cap_vndr != PCI_CAP_ID_VNDR)
	{
	  log_debug (vnet_dev_get_by_index (vif->dev_index), "[%2x] %s %2x ",
		     pos, "skipping non VNDR cap id:", cap.cap_vndr);
	  goto next;
	}

      log_debug (vnet_dev_get_by_index (vif->dev_index),
		 "[%4x] cfg type: %u, bar: %u, offset: %04x, len: %u", pos,
		 cap.cfg_type, cap.bar, cap.offset, cap.length);

      if (cap.bar >= 0 && cap.bar <= 5)
	{
	  vif->bar = bar[cap.bar];
	  vif->bar_id = cap.bar;
	}
      else
	return clib_error_return (error, "invalid bar %u", cap.bar);

      switch (cap.cfg_type)
	{
	case VIRTIO_PCI_CAP_COMMON_CFG:
	  vif->common_offset = cap.offset;
	  common_cfg = 1;
	  break;
	case VIRTIO_PCI_CAP_NOTIFY_CFG:
	  if ((error = vlib_pci_read_write_config (
		 vm, h, VLIB_READ, pos + sizeof (cap),
		 &vif->notify_off_multiplier,
		 sizeof (vif->notify_off_multiplier))))
	    {
	      log_error (vnet_dev_get_by_index (vif->dev_index),
			 "notify off multiplier is not given");
	    }
	  else
	    {
	      log_debug (vnet_dev_get_by_index (vif->dev_index),
			 "notify off multiplier is %u",
			 vif->notify_off_multiplier);
	      vif->notify_offset = cap.offset;
	      notify = 1;
	    }
	  break;
	case VIRTIO_PCI_CAP_DEVICE_CFG:
	  vif->device_offset = cap.offset;
	  dev_cfg = 1;
	  break;
	case VIRTIO_PCI_CAP_ISR_CFG:
	  vif->isr_offset = cap.offset;
	  isr = 1;
	  break;
	case VIRTIO_PCI_CAP_PCI_CFG:
	  if (cap.bar == 0)
	    pci_cfg = 1;
	  break;
	}
    next:
      pos = cap.cap_next;
    }

  if (common_cfg == 0 || notify == 0 || dev_cfg == 0 || isr == 0)
    {
      return clib_error_return (0, "modern virtio pci capabilities missing");
    }

  if (!pci_cfg)
    {
      log_debug (vnet_dev_get_by_index (vif->dev_index),
		 "modern virtio pci device found");
    }
  else
    {
      log_debug (vnet_dev_get_by_index (vif->dev_index),
		 "transitional virtio pci device found");
    }

  return error;
}

clib_error_t *
virtio_pci_device_init (vlib_main_t *vm, virtio_if_t *vif)
{
  clib_error_t *error = 0;
  u8 status = 0;

  if (virtio_pci_reset_device (vm, vif) < 0)
    {
      log_error (vnet_dev_get_by_index (vif->dev_index),
		 "Failed to reset the device");
      return clib_error_return (error, "Failed to reset the device");
    }
  /*
   * read device features and negotiate (user) requested features
   */
  virtio_pci_read_device_feature (vm, vif);
  if ((vif->remote_features & VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC)) ==
      0)
    {
      log_warning (vnet_dev_get_by_index (vif->dev_index),
		   "error encountered: vhost-net backend doesn't "
		   "support VIRTIO_RING_F_INDIRECT_DESC features");
    }
  if ((vif->remote_features & VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF)) == 0)
    {
      log_warning (vnet_dev_get_by_index (vif->dev_index),
		   "error encountered: vhost-net backend doesn't "
		   "support VIRTIO_NET_F_MRG_RXBUF features");
    }
  virtio_negotiate_features (vm, vif);

  if ((vif->is_packed) &&
      ((vif->features & (VIRTIO_FEATURE (VIRTIO_F_RING_PACKED))) == 0))
    {
      log_error (vnet_dev_get_by_index (vif->dev_index),
		 "error encountered: Device doesn't support packed ring");
      return clib_error_return (error, "Device doesn't support packed ring");
    }

  /*
   * After FEATURE_OK, driver should not accept new feature bits
   */
  virtio_pci_set_status (vm, vif, VIRTIO_CONFIG_STATUS_FEATURES_OK);
  status = virtio_pci_get_status (vm, vif);
  if (!(status & VIRTIO_CONFIG_STATUS_FEATURES_OK))
    {
      log_error (
	vnet_dev_get_by_index (vif->dev_index),
	"error encountered: Device doesn't support requested features");
      return clib_error_return (error,
				"Device doesn't support requested features");
    }
  vif->status = status;

  /*
   * get or set the mac address
   */
  if (virtio_pci_get_mac (vm, vif))
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (vif->mac_addr + 2, &rnd, sizeof (rnd));
      vif->mac_addr[0] = 2;
      vif->mac_addr[1] = 0xfe;
      virtio_pci_set_mac (vm, vif);
    }

  virtio_set_net_hdr_size (vif);

  /*
   * Initialize the virtqueues
   */
  return (virtio_pci_init_max_virtqueue_pairs (vm, vif));
}

clib_error_t *
virtio_pci_port_start (vlib_main_t *vm, virtio_if_t *vif,
		       vnet_dev_port_t *port)
{
  clib_error_t *error;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      virtio_rxq_t *vrq = vnet_dev_get_rx_queue_data (rxq);
      if ((error = virtio_pci_vring_init (vm, vif, RX_QUEUE (rxq->queue_id),
					  rxq->size, &vrq->vring)))
	{
	  log_error (vnet_dev_get_by_index (vif->dev_index),
		     "error encountered: failed to init rx vring");
	  return error;
	}
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      virtio_rxq_t *vtq = vnet_dev_get_tx_queue_data (txq);
      if ((error = virtio_pci_vring_init (vm, vif, TX_QUEUE (txq->queue_id),
					  txq->size, &vtq->vring)))
	{
	  log_error (vnet_dev_get_by_index (vif->dev_index),
		     "error encountered: failed to init tx vring");
	  return error;
	}
    }

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ))
    {
      if ((error = virtio_pci_control_vring_init (vm, vif,
						  vif->max_queue_pairs * 2)))
	{
	  log_warning (vnet_dev_get_by_index (vif->dev_index), "%s (%u) %s",
		       "error in control-queue", vif->max_queue_pairs * 2,
		       "initialization");
	  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MQ))
	    vif->features &= ~VIRTIO_FEATURE (VIRTIO_NET_F_MQ);
	}
    }
  else
    {
      log_debug (vnet_dev_get_by_index (vif->dev_index),
		 "control queue is not available");
      vif->cxq_vring = NULL;
    }

  /*
   * set the msix interrupts
   */
  if (vif->msix_enabled == VIRTIO_MSIX_ENABLED)
    {
      int i, j;
      if (virtio_pci_set_config_irq (vm, vif, 0) == VIRTIO_MSI_NO_VECTOR)
	{
	  log_warning (vnet_dev_get_by_index (vif->dev_index),
		       "config vector 0 is not set");
	}
      else
	{
	  log_debug (vnet_dev_get_by_index (vif->dev_index),
		     "config msix vector is set at 0");
	}
      for (i = 0, j = 1; i < vif->max_queue_pairs; i++, j++)
	{
	  if (virtio_pci_set_queue_irq (vm, vif, j, RX_QUEUE (i)) ==
	      VIRTIO_MSI_NO_VECTOR)
	    {
	      log_warning (vnet_dev_get_by_index (vif->dev_index),
			   "queue (%u) vector is not set at %u", RX_QUEUE (i),
			   j);
	    }
	  else
	    {
	      log_debug (vnet_dev_get_by_index (vif->dev_index),
			 "%s (%u) %s %u", "queue", RX_QUEUE (i),
			 "msix vector is set at", j);
	    }
	}
    }

  return 0;
}

int
virtio_pci_enable_disable_offloads (vlib_main_t *vm, virtio_if_t *vif,
				    int gso_enabled,
				    int checksum_offload_enabled,
				    int offloads_disabled)
{
  if (gso_enabled)
    virtio_pci_offloads (vm, vif, 1, 0);
  else if (checksum_offload_enabled)
    virtio_pci_offloads (vm, vif, 0, 1);
  else if (offloads_disabled)
    virtio_pci_offloads (vm, vif, 0, 0);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
