/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/*
 * af_packet.c - linux kernel packet interface
 */

#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_psh_cksum.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>

#include <af_packet/af_packet.h>
#include <vnet/devices/virtio/virtio_std.h>
#include <vnet/devices/netlink.h>

#define foreach_af_packet_tx_func_error               \
_(FRAME_NOT_READY, "tx frame not ready")              \
_(TXRING_EAGAIN,   "tx sendto temporary failure")     \
_(TXRING_FATAL,    "tx sendto fatal failure")         \
_(TXRING_OVERRUN,  "tx ring overrun")

typedef enum
{
#define _(f,s) AF_PACKET_TX_ERROR_##f,
  foreach_af_packet_tx_func_error
#undef _
    AF_PACKET_TX_N_ERROR,
} af_packet_tx_func_error_t;

static char *af_packet_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_af_packet_tx_func_error
#undef _
};

typedef struct
{
  u32 buffer_index;
  u32 hw_if_index;
  u16 queue_id;
  u8 is_v2;
  union
  {
    tpacket2_hdr_t tph2;
    tpacket3_hdr_t tph3;
  };
  vnet_virtio_net_hdr_t vnet_hdr;
  vlib_buffer_t buffer;
} af_packet_tx_trace_t;

always_inline word
af_packet_error_is_fatal (word error)
{
  switch (error)
    {
#ifdef CLIB_UNIX
    case EAGAIN:
    case ENOBUFS:
    case EINTR:
      return 0;
#endif
    }
  return 1;
}

#ifndef CLIB_MARCH_VARIANT
u8 *
format_af_packet_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif = pool_elt_at_index (apm->interfaces, i);

  s = format (s, "host-%s", apif->host_if_name);
  return s;
}
#endif /* CLIB_MARCH_VARIANT */

static u8 *
format_af_packet_offload_flag (u8 *s, va_list *args)
{
  af_packet_offload_flag_t af_oflags =
    va_arg (*args, af_packet_offload_flag_t);
  u32 indent = va_arg (*args, u32);

#define _(o, n, str)                                                          \
  if (af_oflags & AF_PACKET_OFFLOAD_FLAG_##o)                                 \
    s = format (s, "\n%U%s", format_white_space, indent + 3, str);
  foreach_af_packet_offload_flag
#undef _
    return s;
}

static u8 *
format_af_packet_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  u32 indent = format_get_indent (s);
  int __clib_unused verbose = va_arg (*args, int);

  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif = pool_elt_at_index (apm->interfaces, dev_instance);
  af_packet_queue_t *rx_queue = 0;
  af_packet_queue_t *tx_queue = 0;

  s = format (s, "Linux PACKET socket interface %s",
	      (apif->version == TPACKET_V2) ? "v2" : "v3");
  s = format (s, "\n%UFEATURES:", format_white_space, indent);
  if (apif->is_qdisc_bypass_enabled)
    s = format (s, "\n%Uqdisc-bpass-enabled", format_white_space, indent + 2);
  if (apif->is_cksum_gso_enabled)
    s = format (s, "\n%Ucksum-gso-enabled", format_white_space, indent + 2);
  if (apif->is_fanout_enabled)
    s = format (s, "\n%Ufanout-enabled", format_white_space, indent + 2);
  s = format (s, "\n%UHost Interface Offload:", format_white_space, indent);
  s = format (s, "\n%Ucreation time:%U", format_white_space, indent + 2,
	      format_af_packet_offload_flag, apif->host_interface_oflags,
	      indent);
  s = format (s, "\n%Unow:%U", format_white_space, indent + 2,
	      format_af_packet_offload_flag,
	      af_packet_get_if_capabilities (apif->host_if_name), indent);

  vec_foreach (rx_queue, apif->rx_queues)
    {
      u32 rx_block_size = rx_queue->rx_req->req.tp_block_size;
      u32 rx_frame_size = rx_queue->rx_req->req.tp_frame_size;
      u32 rx_frame_nr = rx_queue->rx_req->req.tp_frame_nr;
      u32 rx_block_nr = rx_queue->rx_req->req.tp_block_nr;

      s = format (s, "\n%URX Queue %u:", format_white_space, indent,
		  rx_queue->queue_id);
      s = format (s, "\n%Ublock size:%d nr:%d  frame size:%d nr:%d",
		  format_white_space, indent + 2, rx_block_size, rx_block_nr,
		  rx_frame_size, rx_frame_nr);
      if (apif->version == TPACKET_V2)
	s = format (s, " next frame:%d", rx_queue->next_rx_frame);
      else
	s = format (s, " next block:%d", rx_queue->next_rx_block);
      if (rx_queue->is_rx_pending)
	{
	  s = format (
	    s, "\n%UPending Request: num-rx-pkts:%d next-frame-offset:%d",
	    format_white_space, indent + 2, rx_queue->num_rx_pkts,
	    rx_queue->rx_frame_offset);
	}
    }

  vec_foreach (tx_queue, apif->tx_queues)
    {
      clib_spinlock_lock (&tx_queue->lockp);
      u32 tx_block_sz = tx_queue->tx_req->req.tp_block_size;
      u32 tx_frame_sz = tx_queue->tx_req->req.tp_frame_size;
      u32 tx_frame_nr = tx_queue->tx_req->req.tp_frame_nr;
      u32 tx_block_nr = tx_queue->tx_req->req.tp_block_nr;
      int block = 0;
      int n_send_req = 0, n_avail = 0, n_sending = 0, n_tot = 0, n_wrong = 0;
      u8 *tx_block_start = tx_queue->tx_ring[block];
      u32 tx_frame = tx_queue->next_tx_frame;
      tpacket3_hdr_t *tph3;
      tpacket2_hdr_t *tph2;

      s = format (s, "\n%UTX Queue %u:", format_white_space, indent,
		  tx_queue->queue_id);
      s = format (s, "\n%Ublock size:%d nr:%d  frame size:%d nr:%d",
		  format_white_space, indent + 2, tx_block_sz, tx_block_nr,
		  tx_frame_sz, tx_frame_nr);
      s = format (s, " next frame:%d", tx_queue->next_tx_frame);
      if (apif->version & TPACKET_V3)
	do
	  {
	    tph3 =
	      (tpacket3_hdr_t *) (tx_block_start + tx_frame * tx_frame_sz);
	    tx_frame = (tx_frame + 1) % tx_frame_nr;
	    if (tph3->tp_status == 0)
	      n_avail++;
	    else if (tph3->tp_status & TP_STATUS_SEND_REQUEST)
	      n_send_req++;
	    else if (tph3->tp_status & TP_STATUS_SENDING)
	      n_sending++;
	    else
	      n_wrong++;
	    n_tot++;
	  }
	while (tx_frame != tx_queue->next_tx_frame);
      else
	do
	  {
	    tph2 =
	      (tpacket2_hdr_t *) (tx_block_start + tx_frame * tx_frame_sz);
	    tx_frame = (tx_frame + 1) % tx_frame_nr;
	    if (tph2->tp_status == 0)
	      n_avail++;
	    else if (tph2->tp_status & TP_STATUS_SEND_REQUEST)
	      n_send_req++;
	    else if (tph2->tp_status & TP_STATUS_SENDING)
	      n_sending++;
	    else
	      n_wrong++;
	    n_tot++;
	  }
	while (tx_frame != tx_queue->next_tx_frame);
      s =
	format (s, "\n%Uavailable:%d request:%d sending:%d wrong:%d total:%d",
		format_white_space, indent + 2, n_avail, n_send_req, n_sending,
		n_wrong, n_tot);
      clib_spinlock_unlock (&tx_queue->lockp);
    }
  return s;
}

static u8 *
format_af_packet_tx_trace (u8 *s, va_list *va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  af_packet_tx_trace_t *t = va_arg (*va, af_packet_tx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "af_packet: hw_if_index %u tx-queue %u", t->hw_if_index,
	      t->queue_id);

  if (t->is_v2)
    {
      s = format (
	s,
	"\n%Utpacket2_hdr:\n%Ustatus 0x%x len %u snaplen %u mac %u net %u"
	"\n%Usec 0x%x nsec 0x%x vlan %U"
#ifdef TP_STATUS_VLAN_TPID_VALID
	" vlan_tpid %u"
#endif
	,
	format_white_space, indent + 2, format_white_space, indent + 4,
	t->tph2.tp_status, t->tph2.tp_len, t->tph2.tp_snaplen, t->tph2.tp_mac,
	t->tph2.tp_net, format_white_space, indent + 4, t->tph2.tp_sec,
	t->tph2.tp_nsec, format_ethernet_vlan_tci, t->tph2.tp_vlan_tci
#ifdef TP_STATUS_VLAN_TPID_VALID
	,
	t->tph2.tp_vlan_tpid
#endif
      );
    }
  else
    {
      s = format (
	s,
	"\n%Utpacket3_hdr:\n%Ustatus 0x%x len %u snaplen %u mac %u net %u"
	"\n%Usec 0x%x nsec 0x%x vlan %U"
#ifdef TP_STATUS_VLAN_TPID_VALID
	" vlan_tpid %u"
#endif
	,
	format_white_space, indent + 2, format_white_space, indent + 4,
	t->tph3.tp_status, t->tph3.tp_len, t->tph3.tp_snaplen, t->tph3.tp_mac,
	t->tph3.tp_net, format_white_space, indent + 4, t->tph3.tp_sec,
	t->tph3.tp_nsec, format_ethernet_vlan_tci, t->tph3.hv1.tp_vlan_tci
#ifdef TP_STATUS_VLAN_TPID_VALID
	,
	t->tph3.hv1.tp_vlan_tpid
#endif
      );
    }
  s = format (s,
	      "\n%Uvnet-hdr:\n%Uflags 0x%02x gso_type 0x%02x hdr_len %u"
	      "\n%Ugso_size %u csum_start %u csum_offset %u",
	      format_white_space, indent + 2, format_white_space, indent + 4,
	      t->vnet_hdr.flags, t->vnet_hdr.gso_type, t->vnet_hdr.hdr_len,
	      format_white_space, indent + 4, t->vnet_hdr.gso_size,
	      t->vnet_hdr.csum_start, t->vnet_hdr.csum_offset);

  s = format (s, "\n%Ubuffer 0x%x:\n%U%U", format_white_space, indent + 2,
	      t->buffer_index, format_white_space, indent + 4,
	      format_vnet_buffer_no_chain, &t->buffer);
  s = format (s, "\n%U%U", format_white_space, indent + 2,
	      format_ethernet_header_with_length, t->buffer.pre_data,
	      sizeof (t->buffer.pre_data));
  return s;
}

static void
af_packet_tx_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_buffer_t *b0, u32 bi, void *tph,
		    vnet_virtio_net_hdr_t *vnet_hdr, u32 hw_if_index,
		    u16 queue_id, u8 is_v2)
{
  af_packet_tx_trace_t *t;
  t = vlib_add_trace (vm, node, b0, sizeof (t[0]));
  t->hw_if_index = hw_if_index;
  t->queue_id = queue_id;
  t->buffer_index = bi;
  t->is_v2 = is_v2;

  if (is_v2)
    clib_memcpy_fast (&t->tph2, (tpacket2_hdr_t *) tph,
		      sizeof (tpacket2_hdr_t));
  else
    clib_memcpy_fast (&t->tph3, (tpacket3_hdr_t *) tph,
		      sizeof (tpacket3_hdr_t));
  clib_memcpy_fast (&t->vnet_hdr, vnet_hdr, sizeof (*vnet_hdr));
  clib_memcpy_fast (&t->buffer, b0, sizeof (*b0) - sizeof (b0->pre_data));
  clib_memcpy_fast (t->buffer.pre_data, vlib_buffer_get_current (b0),
		    sizeof (t->buffer.pre_data));
}

static_always_inline void
fill_gso_offload (vlib_buffer_t *b0, vnet_virtio_net_hdr_t *vnet_hdr)
{
  vnet_buffer_oflags_t oflags = vnet_buffer (b0)->oflags;
  i16 l4_hdr_offset = vnet_buffer (b0)->l4_hdr_offset - b0->current_data;
  if (b0->flags & VNET_BUFFER_F_IS_IP4)
    {
      ip4_header_t *ip4;
      vnet_hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      vnet_hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
      vnet_hdr->hdr_len = l4_hdr_offset + vnet_buffer2 (b0)->gso_l4_hdr_sz;
      vnet_hdr->gso_size = vnet_buffer2 (b0)->gso_size;
      vnet_hdr->csum_start = l4_hdr_offset;
      vnet_hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
      ip4 = (ip4_header_t *) (b0->data + vnet_buffer (b0)->l3_hdr_offset);
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	ip4->checksum = ip4_header_checksum (ip4);
      tcp_header_t *tcp =
	(tcp_header_t *) (b0->data + vnet_buffer (b0)->l4_hdr_offset);
      tcp->checksum = ip4_pseudo_header_cksum (ip4);
    }
  else if (b0->flags & VNET_BUFFER_F_IS_IP6)
    {
      ip6_header_t *ip6;
      vnet_hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      vnet_hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
      vnet_hdr->hdr_len = l4_hdr_offset + vnet_buffer2 (b0)->gso_l4_hdr_sz;
      vnet_hdr->gso_size = vnet_buffer2 (b0)->gso_size;
      vnet_hdr->csum_start = l4_hdr_offset;
      vnet_hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
      ip6 = (ip6_header_t *) (b0->data + vnet_buffer (b0)->l3_hdr_offset);
      tcp_header_t *tcp =
	(tcp_header_t *) (b0->data + vnet_buffer (b0)->l4_hdr_offset);
      tcp->checksum = ip6_pseudo_header_cksum (ip6);
    }
}

static_always_inline void
fill_cksum_offload (vlib_buffer_t *b0, vnet_virtio_net_hdr_t *vnet_hdr)
{
  vnet_buffer_oflags_t oflags = vnet_buffer (b0)->oflags;
  i16 l4_hdr_offset = vnet_buffer (b0)->l4_hdr_offset - b0->current_data;
  if (b0->flags & VNET_BUFFER_F_IS_IP4)
    {
      ip4_header_t *ip4;
      ip4 = (ip4_header_t *) (b0->data + vnet_buffer (b0)->l3_hdr_offset);
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	ip4->checksum = ip4_header_checksum (ip4);
      if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  tcp_header_t *tcp =
	    (tcp_header_t *) (b0->data + vnet_buffer (b0)->l4_hdr_offset);
	  tcp->checksum = ip4_pseudo_header_cksum (ip4);
	  vnet_hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	  vnet_hdr->hdr_len = l4_hdr_offset + tcp_header_bytes (tcp);
	  vnet_hdr->csum_start = l4_hdr_offset;
	  vnet_hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  udp_header_t *udp =
	    (udp_header_t *) (b0->data + vnet_buffer (b0)->l4_hdr_offset);
	  udp->checksum = ip4_pseudo_header_cksum (ip4);
	  vnet_hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	  vnet_hdr->hdr_len = l4_hdr_offset + sizeof (udp_header_t);
	  vnet_hdr->csum_start = l4_hdr_offset;
	  vnet_hdr->csum_offset = STRUCT_OFFSET_OF (udp_header_t, checksum);
	}
    }
  else if (b0->flags & VNET_BUFFER_F_IS_IP6)
    {
      ip6_header_t *ip6;
      ip6 = (ip6_header_t *) (b0->data + vnet_buffer (b0)->l3_hdr_offset);
      if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  tcp_header_t *tcp =
	    (tcp_header_t *) (b0->data + vnet_buffer (b0)->l4_hdr_offset);
	  tcp->checksum = ip6_pseudo_header_cksum (ip6);
	  vnet_hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	  vnet_hdr->hdr_len = l4_hdr_offset + tcp_header_bytes (tcp);
	  vnet_hdr->csum_start = l4_hdr_offset;
	  vnet_hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  udp_header_t *udp =
	    (udp_header_t *) (b0->data + vnet_buffer (b0)->l4_hdr_offset);
	  udp->checksum = ip6_pseudo_header_cksum (ip6);
	  vnet_hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	  vnet_hdr->hdr_len = l4_hdr_offset + sizeof (udp_header_t);
	  vnet_hdr->csum_start = l4_hdr_offset;
	  vnet_hdr->csum_offset = STRUCT_OFFSET_OF (udp_header_t, checksum);
	}
    }
}

VNET_DEVICE_CLASS_TX_FN (af_packet_device_class) (vlib_main_t * vm,
						  vlib_node_runtime_t * node,
						  vlib_frame_t * frame)
{
  af_packet_main_t *apm = &af_packet_main;
  vnet_hw_if_tx_frame_t *tf = vlib_frame_scalar_args (frame);
  u32 *buffers = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_sent = 0;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  af_packet_if_t *apif =
    pool_elt_at_index (apm->interfaces, rd->dev_instance);
  u16 queue_id = tf->queue_id;
  af_packet_queue_t *tx_queue = vec_elt_at_index (apif->tx_queues, queue_id);
  u32 block = 0, frame_size = 0, frame_num = 0, tx_frame = 0;
  u8 *block_start = 0;
  tpacket3_hdr_t *tph3 = 0;
  tpacket2_hdr_t *tph2 = 0;
  u32 frame_not_ready = 0;
  u8 is_cksum_gso_enabled = (apif->is_cksum_gso_enabled == 1) ? 1 : 0;
  u32 tpacket_align = 0;
  u8 is_v2 = (apif->version == TPACKET_V2) ? 1 : 0;

  if (tf->shared_queue)
    clib_spinlock_lock (&tx_queue->lockp);

  frame_size = tx_queue->tx_req->req.tp_frame_size;
  frame_num = tx_queue->tx_req->req.tp_frame_nr;
  block_start = tx_queue->tx_ring[block];
  tx_frame = tx_queue->next_tx_frame;
  if (is_v2)
    {
      tpacket_align = TPACKET_ALIGN (sizeof (tpacket2_hdr_t));
      while (n_left)
	{
	  u32 len;
	  vnet_virtio_net_hdr_t *vnet_hdr = 0;
	  u32 offset = 0;
	  vlib_buffer_t *b0 = 0, *b0_first = 0;
	  u32 bi, bi_first;

	  bi = bi_first = buffers[0];
	  n_left--;
	  buffers++;

	  tph2 = (tpacket2_hdr_t *) (block_start + tx_frame * frame_size);
	  if (PREDICT_FALSE (tph2->tp_status &
			     (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING)))
	    {
	      frame_not_ready++;
	      goto nextv2;
	    }

	  b0_first = b0 = vlib_get_buffer (vm, bi);

	  if (PREDICT_TRUE (is_cksum_gso_enabled))
	    {
	      vnet_hdr =
		(vnet_virtio_net_hdr_t *) ((u8 *) tph2 + tpacket_align);

	      clib_memset_u8 (vnet_hdr, 0, sizeof (vnet_virtio_net_hdr_t));
	      offset = sizeof (vnet_virtio_net_hdr_t);

	      if (b0->flags & VNET_BUFFER_F_GSO)
		fill_gso_offload (b0, vnet_hdr);
	      else if (b0->flags & VNET_BUFFER_F_OFFLOAD)
		fill_cksum_offload (b0, vnet_hdr);
	    }

	  len = b0->current_length;
	  clib_memcpy_fast ((u8 *) tph2 + tpacket_align + offset,
			    vlib_buffer_get_current (b0), len);
	  offset += len;

	  while (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      b0 = vlib_get_buffer (vm, b0->next_buffer);
	      len = b0->current_length;
	      clib_memcpy_fast ((u8 *) tph2 + tpacket_align + offset,
				vlib_buffer_get_current (b0), len);
	      offset += len;
	    }

	  tph2->tp_len = tph2->tp_snaplen = offset;
	  tph2->tp_status = TP_STATUS_SEND_REQUEST;
	  n_sent++;

	  if (PREDICT_FALSE (b0_first->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      if (PREDICT_TRUE (is_cksum_gso_enabled))
		af_packet_tx_trace (vm, node, b0_first, bi_first, tph2,
				    vnet_hdr, apif->hw_if_index, queue_id, 1);
	      else
		{
		  vnet_virtio_net_hdr_t vnet_hdr2 = {};
		  af_packet_tx_trace (vm, node, b0_first, bi_first, tph2,
				      &vnet_hdr2, apif->hw_if_index, queue_id,
				      1);
		}
	    }
	  tx_frame = (tx_frame + 1) % frame_num;

	nextv2:
	  /* check if we've exhausted the ring */
	  if (PREDICT_FALSE (frame_not_ready + n_sent == frame_num))
	    break;
	}
    }
  else
    {
      tpacket_align = TPACKET_ALIGN (sizeof (tpacket3_hdr_t));

      while (n_left)
	{
	  u32 len;
	  vnet_virtio_net_hdr_t *vnet_hdr = 0;
	  u32 offset = 0;
	  vlib_buffer_t *b0 = 0, *b0_first = 0;
	  u32 bi, bi_first;

	  bi = bi_first = buffers[0];
	  n_left--;
	  buffers++;

	  tph3 = (tpacket3_hdr_t *) (block_start + tx_frame * frame_size);
	  if (PREDICT_FALSE (tph3->tp_status &
			     (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING)))
	    {
	      frame_not_ready++;
	      goto nextv3;
	    }

	  b0_first = b0 = vlib_get_buffer (vm, bi);

	  if (PREDICT_TRUE (is_cksum_gso_enabled))
	    {
	      vnet_hdr =
		(vnet_virtio_net_hdr_t *) ((u8 *) tph3 + tpacket_align);

	      clib_memset_u8 (vnet_hdr, 0, sizeof (vnet_virtio_net_hdr_t));
	      offset = sizeof (vnet_virtio_net_hdr_t);

	      if (b0->flags & VNET_BUFFER_F_GSO)
		fill_gso_offload (b0, vnet_hdr);
	      else if (b0->flags & VNET_BUFFER_F_OFFLOAD)
		fill_cksum_offload (b0, vnet_hdr);
	    }

	  len = b0->current_length;
	  clib_memcpy_fast ((u8 *) tph3 + tpacket_align + offset,
			    vlib_buffer_get_current (b0), len);
	  offset += len;

	  while (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      b0 = vlib_get_buffer (vm, b0->next_buffer);
	      len = b0->current_length;
	      clib_memcpy_fast ((u8 *) tph3 + tpacket_align + offset,
				vlib_buffer_get_current (b0), len);
	      offset += len;
	    }

	  tph3->tp_len = tph3->tp_snaplen = offset;
	  tph3->tp_status = TP_STATUS_SEND_REQUEST;
	  n_sent++;

	  if (PREDICT_FALSE (b0_first->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      if (PREDICT_TRUE (is_cksum_gso_enabled))
		af_packet_tx_trace (vm, node, b0_first, bi_first, tph3,
				    vnet_hdr, apif->hw_if_index, queue_id, 0);
	      else
		{
		  vnet_virtio_net_hdr_t vnet_hdr2 = {};
		  af_packet_tx_trace (vm, node, b0_first, bi_first, tph3,
				      &vnet_hdr2, apif->hw_if_index, queue_id,
				      0);
		}
	    }
	  tx_frame = (tx_frame + 1) % frame_num;

	nextv3:
	  /* check if we've exhausted the ring */
	  if (PREDICT_FALSE (frame_not_ready + n_sent == frame_num))
	    break;
	}
    }
  CLIB_MEMORY_BARRIER ();

  if (PREDICT_TRUE (n_sent || tx_queue->is_tx_pending))
    {
      tx_queue->next_tx_frame = tx_frame;
      tx_queue->is_tx_pending = 0;

      if (PREDICT_FALSE (
	    sendto (tx_queue->fd, NULL, 0, MSG_DONTWAIT, NULL, 0) == -1))
	{
	  /* Uh-oh, drop & move on, but count whether it was fatal or not.
	   * Note that we have no reliable way to properly determine the
	   * disposition of the packets we just enqueued for delivery.
	   */
	  uword counter;

	  if (af_packet_error_is_fatal (errno))
	    {
	      counter = AF_PACKET_TX_ERROR_TXRING_FATAL;
	      vlib_log_err (apm->log_class,
			    "af_packet_%s sendto failed: %d %s",
			    apif->host_if_name, errno, strerror (errno));
	      /* TODO attempt to reattach */
	    }
	  else
	    {
	      counter = AF_PACKET_TX_ERROR_TXRING_EAGAIN;
	      /* non-fatal error: kick again next time
	       * note that you could still end up in a deadlock: if you do not
	       * try to send new packets (ie reschedule this tx node), eg.
	       * because your peer is waiting for the unsent packets to reply
	       * to you but your waiting for its reply etc., you are not going
	       * to kick again, and everybody is waiting for the other to talk
	       * 1st... */
	      tx_queue->is_tx_pending = 1;
	    }

	  vlib_error_count (vm, node->node_index, counter, 1);
	}
    }

  if (tf->shared_queue)
    clib_spinlock_unlock (&tx_queue->lockp);

  if (PREDICT_FALSE (frame_not_ready))
    vlib_error_count (vm, node->node_index,
		      AF_PACKET_TX_ERROR_FRAME_NOT_READY, frame_not_ready);

  if (PREDICT_FALSE (frame_not_ready + n_sent == frame_num))
    vlib_error_count (vm, node->node_index, AF_PACKET_TX_ERROR_TXRING_OVERRUN,
		      n_left);

  vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);
  return frame->n_vectors;
}

static void
af_packet_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				   u32 node_index)
{
  af_packet_main_t *apm = &af_packet_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_packet_if_t *apif =
    pool_elt_at_index (apm->interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      apif->per_interface_next_index = node_index;
      return;
    }

  apif->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), af_packet_input_node.index,
			node_index);
}

static void
af_packet_clear_hw_interface_counters (u32 instance)
{
  /* Nothing for now */
}

static clib_error_t *
af_packet_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				   u32 flags)
{
  af_packet_main_t *apm = &af_packet_main;
  clib_error_t *error;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_packet_if_t *apif =
    pool_elt_at_index (apm->interfaces, hw->dev_instance);
  u32 hw_flags;

  if (apif->host_if_index < 0)
    return 0; /* no error */

  apif->is_admin_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (apif->is_admin_up)
    {
      hw_flags = VNET_HW_INTERFACE_FLAG_LINK_UP;
      error = vnet_netlink_set_link_state (apif->host_if_index, 1);
    }
  else
    {
      hw_flags = 0;
      error = vnet_netlink_set_link_state (apif->host_if_index, 0);
    }
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      clib_error_free (error);
    }

  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return 0;			/* no error */
}

static clib_error_t *af_packet_set_mac_address_function
  (struct vnet_hw_interface_t *hi, const u8 * old_address, const u8 * address)
{
  af_packet_main_t *apm = &af_packet_main;
  af_packet_if_t *apif =
    pool_elt_at_index (apm->interfaces, hi->dev_instance);
  int rv, fd;
  struct ifreq ifr;

  if (apif->mode == AF_PACKET_IF_MODE_IP)
    {
      vlib_log_warn (apm->log_class, "af_packet_%s interface is in IP mode",
		     apif->host_if_name);
      return clib_error_return (0,
				" MAC update failed, interface is in IP mode");
    }

  fd = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (0 > fd)
    {
      vlib_log_warn (apm->log_class, "af_packet_%s could not open socket",
		     apif->host_if_name);
      return 0;
    }

  /* if interface is a bridge ignore */
  if (apif->host_if_index < 0)
    goto error;			/* no error */

  /* use host_if_index in case host name has changed */
  ifr.ifr_ifindex = apif->host_if_index;
  if ((rv = ioctl (fd, SIOCGIFNAME, &ifr)) < 0)
    {
      vlib_log_warn
	(apm->log_class,
	 "af_packet_%s ioctl could not retrieve eth name, error: %d",
	 apif->host_if_name, rv);
      goto error;
    }

  clib_memcpy (ifr.ifr_hwaddr.sa_data, address, 6);
  ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

  if ((rv = ioctl (fd, SIOCSIFHWADDR, &ifr)) < 0)
    {
      vlib_log_warn (apm->log_class,
		     "af_packet_%s ioctl could not set mac, error: %d",
		     apif->host_if_name, rv);
      goto error;
    }

error:

  if (0 <= fd)
    close (fd);

  return 0;			/* no error */
}

static clib_error_t *
af_packet_interface_rx_mode_change (vnet_main_t *vnm, u32 hw_if_index, u32 qid,
				    vnet_hw_if_rx_mode mode)
{
  af_packet_main_t *apm = &af_packet_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  af_packet_if_t *apif;

  apif = vec_elt_at_index (apm->interfaces, hw->dev_instance);

  if (mode == VNET_HW_IF_RX_MODE_ADAPTIVE)
    {
      vlib_log_err (apm->log_class,
		    "af_packet_%s adaptive mode is not supported",
		    apif->host_if_name);
      return clib_error_return (
	0, "af_packet_%s adaptive mode is not supported", apif->host_if_name);
    }

  af_packet_queue_t *rx_queue = vec_elt_at_index (apif->rx_queues, qid);

  if (rx_queue->mode != mode)
    {
      rx_queue->mode = mode;

      if (mode == VNET_HW_IF_RX_MODE_POLLING)
	apm->polling_count++;
      else if (mode == VNET_HW_IF_RX_MODE_INTERRUPT && apm->polling_count > 0)
	apm->polling_count--;
    }

  return 0;
}

VNET_DEVICE_CLASS (af_packet_device_class) = {
  .name = "af-packet",
  .format_device_name = format_af_packet_device_name,
  .format_device = format_af_packet_device,
  .format_tx_trace = format_af_packet_tx_trace,
  .tx_function_n_errors = AF_PACKET_TX_N_ERROR,
  .tx_function_error_strings = af_packet_tx_func_error_strings,
  .rx_redirect_to_node = af_packet_set_interface_next_node,
  .clear_counters = af_packet_clear_hw_interface_counters,
  .admin_up_down_function = af_packet_interface_admin_up_down,
  .mac_addr_change_function = af_packet_set_mac_address_function,
  .rx_mode_change_function = af_packet_interface_rx_mode_change,
};
