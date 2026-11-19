/* SPDX-License-Identifier: Apache-2.0 */
#include <inline_funcs.h>

static char *
vnp_feature_name (u32 bit)
{
  switch (bit)
    {
#define _(f, b)                                                                                    \
  case b:                                                                                          \
    return #f;
    foreach_virtio_net_features foreach_virtio_config_features
#undef _
      case 28:
      return "INDIRECT_DESC";
    }

  return 0;
}

static u8 *
format_vnp_features (u8 *s, va_list *args)
{
  u64 features = va_arg (*args, u64);
  u32 n = 0;

  for (u32 bit = 0; bit < 64; bit++)
    {
      char *name = vnp_feature_name (bit);

      if ((features & (1ULL << bit)) == 0)
	continue;

      if (n++)
	s = format (s, " ");

      if (name)
	s = format (s, "%s", name);
      else
	s = format (s, "bit%u", bit);
    }

  return n ? s : format (s, "none");
}

static u8 *
format_vnp_status (u8 *s, va_list *args)
{
  u8 status = va_arg (*args, u32);

  static struct
  {
    u8 bit;
    char *name;
  } flags[] = {
    { VIRTIO_CONFIG_STATUS_ACK, "ACK" },
    { VIRTIO_CONFIG_STATUS_DRIVER, "DRIVER" },
    { VIRTIO_CONFIG_STATUS_DRIVER_OK, "DRIVER_OK" },
    { VIRTIO_CONFIG_STATUS_FEATURES_OK, "FEATURES_OK" },
    { VIRTIO_CONFIG_STATUS_NEEDS_RESET, "NEEDS_RESET" },
    { VIRTIO_CONFIG_STATUS_FAILED, "FAILED" },
  };

  s = format (s, "0x%02x", status);

  for (u32 i = 0; i < ARRAY_LEN (flags); i++)
    if (status & flags[i].bit)
      s = format (s, "%s%s", status & (flags[i].bit - 1) ? " " : " (", flags[i].name);

  return status ? format (s, ")") : s;
}

u8 *
format_vnp_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);

  s = format (s, "Features offered and not negotiated: %U", format_vnp_features,
	      vd->offered & ~vd->features);
  s = format_word_wrap_last_line_with_indent (s, 100, 2);
  s = format (format_newline (s, indent), "Features offered and negotiated: %U",
	      format_vnp_features, vd->offered & vd->features);
  s = format_word_wrap_last_line_with_indent (s, 100, 2);
  s = format (format_newline (s, indent), "device status %U, %u virtqueues", format_vnp_status,
	      vnp_reg_rd8 (&vd->common->status), vnp_reg_rd16 (&vd->common->num_queues));
  s = format (format_newline (s, indent), "%s ring, indirect descriptors %s, control queue %s",
	      vd->features & VIRTIO_F_RING_PACKED_BIT ? "packed" : "split",
	      vd->features & VIRTIO_RING_F_INDIRECT_DESC_BIT ? "on" : "off",
	      vd->control.size ? vd->control.failed ? "failed" : "on" : "off");

  if (vd->features & VIRTIO_NET_F_MTU_BIT)
    s = format (format_newline (s, indent), "device MTU %u", vd->config->mtu);

  return s;
}

u8 *
format_vnp_port_status (u8 *s, va_list *args)
{
  va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  vnp_dev_t *vd = vnet_dev_get_data (port->dev);
  vnp_port_t *vp = vnet_dev_get_port_data (port);
  u32 indent = format_get_indent (s);

  if (!vp->irq_registered)
    s = format (s, "interrupts not available");
  else if (vp->use_intx)
    s = format (s, "interrupts INTx");
  else
    s = format (s, "interrupts MSI-X");

  if (port->attr.caps.mac_filter)
    s = format (format_newline (s, indent),
		"RX filter: all-multicast, promiscuous %s, %u secondary MAC%s",
		port->promisc ? "on" : "off", vp->n_macs, vp->n_macs == 1 ? "" : "s");
  else
    s = format (format_newline (s, indent), "RX filter: none, destination MAC checked by VPP");

  if (vd->features & VIRTIO_NET_F_RSS_BIT)
    s = format (format_newline (s, indent), "RSS hash types 0x%x, max indirection table length %u",
		vd->config->supported_hash_types, vd->config->rss_max_indirection_table_length);

  return s;
}

u8 *
format_vnp_rx_queue (u8 *s, va_list *args)
{
  va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  vnp_rxq_t *q = vnet_dev_get_rx_queue_data (rxq);

  if (q->packed)
    return format (s, "packed avail %u used %u free %u", q->packed_avail, q->packed_used,
		   q->n_free);

  return format (s, "avail %u used %u last-used %u free %u", q->avail->idx, q->used->idx,
		 q->last_used, q->n_free);
}

u8 *
format_vnp_tx_queue (u8 *s, va_list *args)
{
  va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_tx_queue_t *txq = va_arg (*args, vnet_dev_tx_queue_t *);
  vnp_txq_t *q = vnet_dev_get_tx_queue_data (txq);
  u32 outstanding = 0;

  for (u32 i = 0; i < txq->size; i++)
    outstanding += q->buffer_indices[i] != VLIB_BUFFER_INVALID_INDEX;

  return format (s, "%u free descriptors, %u outstanding packets", q->n_free, outstanding);
}

u8 *
format_vnp_rx_trace (u8 *s, va_list *args)
{
  va_arg (*args, vlib_main_t *);
  va_arg (*args, vlib_node_t *);
  vnp_rx_trace_t *tr = va_arg (*args, vnp_rx_trace_t *);
  return format (s,
		 "virtio-net-pci RX queue %u length %u flags %u gso-type %u gso-size %u buffers %u",
		 tr->queue_id, tr->length, tr->hdr.flags, tr->hdr.gso_type, tr->hdr.gso_size,
		 tr->hdr.num_buffers);
}

static u8 *
format_vnp_desc_flags (u8 *s, va_list *args)
{
  u32 flags = va_arg (*args, u32);
  u32 n = 0;

#define _(b_, n_)                                                                                  \
  if (flags & VRING_DESC_F_##n_)                                                                   \
    s = format (s, "%s%s", n++ ? "|" : "", #n_);
  foreach_virtq_desc_flag
#undef _

    if (n == 0) s = format (s, "none");

  return s;
}

static u8 *
format_vnp_desc (u8 *s, va_list *args)
{
  virtq_desc_t *d = va_arg (*args, virtq_desc_t *);
  u32 packed = va_arg (*args, u32);

  if (packed)
    {
      pvirtq_desc_t *p = (pvirtq_desc_t *) d;

      return format (s, "addr 0x%lx len %u id %u flags %U", p->addr, p->len, p->id,
		     format_vnp_desc_flags, p->flags);
    }

  return format (s, "addr 0x%lx len %u flags %U next %u", d->addr, d->len, format_vnp_desc_flags,
		 d->flags, d->next);
}

u8 *
format_vnp_tx_trace (u8 *s, va_list *args)
{
  va_arg (*args, vlib_main_t *);
  va_arg (*args, vlib_node_t *);
  vnp_tx_trace_t *tr = va_arg (*args, vnp_tx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "virtio-net-pci TX queue %u submitted length %u flags %u gso-type %u gso-size %u",
	      tr->queue_id, tr->length, tr->hdr.flags, tr->hdr.gso_type, tr->hdr.gso_size);

  if (tr->length == 0)
    return s;

  s = format (format_newline (s, indent + 2), "head descriptor: %U", format_vnp_desc, &tr->head, 0);

  if (tr->n_descs == 0)
    return s;

  s = format (format_newline (s, indent + 2),
	      "%s descriptors:", tr->indirect ? "indirect table" : "chained");

  for (u32 i = 0; i < tr->n_descs; i++)
    s = format (format_newline (s, indent + 4), "[%u] %U", i, format_vnp_desc, &tr->descs[i],
		tr->indirect && tr->packed);

  return s;
}

u8 *
format_vnp_ctrl_cmd (u8 *s, va_list *args)
{
  u32 class = va_arg (*args, u32);
  u32 command = va_arg (*args, u32);
  char *class_name = 0, *command_name = 0;

  switch (class)
    {
#define _(n, v)                                                                                    \
  case VIRTIO_NET_CTRL_##n:                                                                        \
    class_name = #n;                                                                               \
    break;
      foreach_virtio_net_ctrl_class
#undef _
    }

  if (class == VIRTIO_NET_CTRL_RX)
    switch (command)
      {
#define _(n, v)                                                                                    \
  case VIRTIO_NET_CTRL_RX_##n:                                                                     \
    command_name = #n;                                                                             \
    break;
	foreach_virtio_net_ctrl_rx_cmd
#undef _
      }
  else if (class == VIRTIO_NET_CTRL_MAC)
    switch (command)
      {
#define _(n, v)                                                                                    \
  case VIRTIO_NET_CTRL_MAC_##n:                                                                    \
    command_name = #n;                                                                             \
    break;
	foreach_virtio_net_ctrl_mac_cmd
#undef _
      }
  else if (class == VIRTIO_NET_CTRL_MQ)
    switch (command)
      {
#define _(n, v)                                                                                    \
  case VIRTIO_NET_CTRL_MQ_##n:                                                                     \
    command_name = #n;                                                                             \
    break;
	foreach_virtio_net_ctrl_mq_cmd
#undef _
      }

  if (class_name)
    s = format (s, "%s", class_name);
  else
    s = format (s, "class %u", class);

  if (command_name)
    return format (s, " %s", command_name);

  return format (s, " command %u", command);
}

u8 *
format_vnp_ctrl_ack (u8 *s, va_list *args)
{
  u32 ack = va_arg (*args, u32);

  switch (ack)
    {
#define _(n, v)                                                                                    \
  case VIRTIO_NET_##n:                                                                             \
    return format (s, "%s", #n);
      foreach_virtio_net_ctrl_ack
#undef _
    }

  return format (s, "ack %u", ack);
}
