/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_virtio/virtio.h>
#include <dev_virtio/pci.h>

u8 *
format_virtio_rx_queue_format_info (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  virtio_rxq_t *vrq = vnet_dev_get_rx_queue_data (rxq);
  vnet_virtio_vring_t *vring = &vrq->vring;
  u32 indent = format_get_indent (s);

  s = format (s, "last_used_idx %d, desc_next %d, desc_in_use %d\n",
	      vring->last_used_idx, vring->desc_next, vring->desc_in_use);
  s = format (s, "%Uavail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d",
	      format_white_space, indent, vring->avail->flags,
	      vring->avail->idx, vring->used->flags, vring->used->idx);

  return s;
}

u8 *
format_virtio_tx_queue_format_info (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  vnet_dev_tx_queue_t *txq = va_arg (*args, vnet_dev_tx_queue_t *);
  virtio_txq_t *vtq = vnet_dev_get_tx_queue_data (txq);
  vnet_virtio_vring_t *vring = &vtq->vring;
  virtio_vring_buffering_t *buffering = vring->buffering;
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;
  virtio_if_t *vif = virtio_vnet_dev_get_if (dev);
  u32 indent = format_get_indent (s);

  s = format (s, "last_used_idx %d, desc_next %d, desc_in_use %d\n",
	      vring->last_used_idx, vring->desc_next, vring->desc_in_use);
  s =
    format (s, "%Uavail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d\n",
	    format_white_space, indent, vring->avail->flags, vring->avail->idx,
	    vring->used->flags, vring->used->idx);

  if (buffering)
    {
      s = format (s, "%Upacket-buffering: %s\n", format_white_space, indent,
		  buffering->is_enable ? "enable" : "disable");
      s = format (s, "%Usize %u n_buffers %u front %u back %u\n",
		  format_white_space, indent, buffering->size,
		  virtio_vring_n_buffers (buffering), buffering->front,
		  buffering->back);
    }

  /* Print the control queue when the last TX queue is printed */
  if (((TX_QUEUE_ACCESS (vring->queue_id) + 1) ==
       port->interfaces->num_tx_queues) &&
      vif->cxq_vring &&
      (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ)))
    {
      s = format (s, "%UControl queue %d:\n", format_white_space, indent - 2,
		  vring->queue_id);
      s = format (s,
		  "%Uqsz %d, last_used_idx %d, desc_next %d, desc_in_use %d\n",
		  format_white_space, indent, vring->queue_size,
		  vring->last_used_idx, vring->desc_next, vring->desc_in_use);
      if (vif->is_packed)
	{
	  s =
	    format (s,
		    "%Udriver_event.flags 0x%x driver_event.off_wrap %d "
		    "device_event.flags 0x%x device_event.off_wrap %d\n",
		    format_white_space, indent, vring->driver_event->flags,
		    vring->driver_event->off_wrap, vring->device_event->flags,
		    vring->device_event->off_wrap);
	  s = format (s, "%Uavail wrap counter %d, used wrap counter %d",
		      format_white_space, indent, vring->avail_wrap_counter,
		      vring->used_wrap_counter);
	}
      else
	{
	  s = format (
	    s, "%Uavail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d",
	    format_white_space, indent, vring->avail->flags, vring->avail->idx,
	    vring->used->flags, vring->used->idx);
	}
    }

  return s;
}

u8 *
format_virtio_tx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  virtio_tx_trace_t *t = va_arg (*args, virtio_tx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%Ubuffer 0x%x: %U\n", format_white_space, indent,
	      t->buffer_index, format_vnet_buffer_no_chain, &t->buffer);
  s = format (s, "%U%U\n", format_white_space, indent,
	      format_generic_header_offset, &t->gho);
  s = format (s, "%U%U", format_white_space, indent,
	      format_ethernet_header_with_length, t->buffer.pre_data,
	      sizeof (t->buffer.pre_data));

  return s;
}

u8 *
format_virtio_rx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  virtio_input_trace_t *t = va_arg (*args, virtio_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "virtio: hw_if_index %d next-index %d vring %u len %u",
	      t->hw_if_index, t->next_index, t->ring, t->len);
  s = format (s,
	      "\n%Uhdr: flags 0x%02x gso_type 0x%02x hdr_len %u "
	      "gso_size %u csum_start %u csum_offset %u num_buffers %u",
	      format_white_space, indent + 2, t->hdr.flags, t->hdr.gso_type,
	      t->hdr.hdr_len, t->hdr.gso_size, t->hdr.csum_start,
	      t->hdr.csum_offset, t->hdr.num_buffers);
  return s;
}

static u8 *
format_virtio_device_status (u8 *s, virtio_if_t *vif)
{
  struct status_struct
  {
    u8 bit;
    char *str;
  };
  struct status_struct *status_entry;
  struct status_struct status_array[] = {
#define _(s, b)                                                               \
  {                                                                           \
    .str = #s,                                                                \
    .bit = b,                                                                 \
  },
    foreach_virtio_config_status_flags
#undef _
    { .str = NULL }
  };
  u32 indent = format_get_indent (s);

  s = format (s, "status 0x%x\n", vif->status);

  status_entry = (struct status_struct *) &status_array;
  while (status_entry->str)
    {
      if (vif->status & status_entry->bit)
	s = format (s, "%U%s (%x)\n", format_white_space, indent,
		    status_entry->str, status_entry->bit);
      status_entry++;
    }
  return s;
}

u8 *
format_virtio_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  vnet_dev_t *dev = port->dev;
  virtio_if_t *vif = virtio_vnet_dev_get_if (dev);
  struct feat_struct
  {
    u8 bit;
    char *str;
  };
  struct feat_struct *feat_entry;
  u32 indent = format_get_indent (s);

  struct feat_struct feat_array[] = {
#define _(s, b)                                                               \
  {                                                                           \
    .str = #s,                                                                \
    .bit = b,                                                                 \
  },
    foreach_virtio_net_features
#undef _
    { .str = NULL }
  };

  s = format_virtio_device_status (s, vif);
  s = format (s, "%Ufeatures 0x%lx\n", format_white_space, indent - 2,
	      vif->features);
  feat_entry = (struct feat_struct *) &feat_array;
  while (feat_entry->str)
    {
      if (vif->features & (1ULL << feat_entry->bit))
	s = format (s, "%U%s (%d)\n", format_white_space, indent,
		    feat_entry->str, feat_entry->bit);
      feat_entry++;
    }
  s = format (s, "%Uremote-features 0x%lx\n", format_white_space, indent - 2,
	      vif->remote_features);
  feat_entry = (struct feat_struct *) &feat_array;
  while (feat_entry->str)
    {
      if (vif->remote_features & (1ULL << feat_entry->bit))
	s = format (s, "%U%s (%d)\n", format_white_space, indent,
		    feat_entry->str, feat_entry->bit);
      feat_entry++;
    }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
