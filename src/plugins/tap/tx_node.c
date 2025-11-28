/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016-2025 Cisco and/or its affiliates.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/gso/gro_func.h>
#include <vnet/gso/hdr_offset_parser.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_psh_cksum.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <tap/internal.h>

#define VIRTIO_TX_MAX_CHAIN_LEN 127

static void
tap_tx_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b0,
	      u32 bi, int is_tun)
{
  tap_tx_trace_t *t;
  t = vlib_add_trace (vm, node, b0, sizeof (t[0]));
  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
  t->buffer_index = bi;
  clib_memset (&t->gho, 0, sizeof (t->gho));
  if (is_tun)
    {
      int is_ip4 = 0, is_ip6 = 0;

      switch (((u8 *) vlib_buffer_get_current (b0))[0] & 0xf0)
	{
	case 0x40:
	  is_ip4 = 1;
	  break;
	case 0x60:
	  is_ip6 = 1;
	  break;
	default:
	  break;
	}
      vnet_generic_header_offset_parser (b0, &t->gho, 0, is_ip4, is_ip6);
    }
  else
    vnet_generic_header_offset_parser (b0, &t->gho, 1,
				       b0->flags & VNET_BUFFER_F_IS_IP4,
				       b0->flags & VNET_BUFFER_F_IS_IP6);

  clib_memcpy_fast (&t->buffer, b0, sizeof (*b0) - sizeof (b0->pre_data));
  clib_memcpy_fast (t->buffer.pre_data, vlib_buffer_get_current (b0),
		    sizeof (t->buffer.pre_data));
}

static void
tap_free_used_device_desc (vlib_main_t *vm, tap_txq_t *txq)
{
  u16 sz = txq->queue_size;
  u32 to_free[sz];
  u16 n_left, n_free = 0;
  u16 mask = sz - 1;
  u16 last = txq->last_used_idx;
  vnet_virtio_vring_used_elem_t *ring = txq->used->ring;
  vnet_virtio_vring_desc_t *desc = txq->desc;
  u32 *buffers = txq->buffers;
  u16 desc_freelist = txq->desc_freelist_head;

  n_left = __atomic_load_n (&txq->used->idx, __ATOMIC_ACQUIRE) - last;

  if (n_left == 0)
    return;

  for (; n_left; n_left--, last++)
    {
      vnet_virtio_vring_used_elem_t *e = ring + (last & mask);
      u16 desc_index = e->id;
      vnet_virtio_vring_desc_t *d;
      u16 next;

      to_free[n_free++] = buffers[desc_index];

    next_in_chain:
      d = desc + desc_index;
      next = d->next;
      d->next = desc_freelist;
      desc_freelist = desc_index;
      if (d->flags & VRING_DESC_F_NEXT)
	{
	  desc_index = next;
	  goto next_in_chain;
	}
    }

  if (n_free == 0)
    return;

  vlib_buffer_free (vm, to_free, n_free);

  txq->desc_freelist_head = desc_freelist;
  txq->desc_in_use -= n_free;
  txq->last_used_idx = last;
}

static void
set_checksum_offsets (vlib_buffer_t *b, vnet_virtio_net_hdr_v1_t *hdr)
{
  vnet_buffer_oflags_t oflags = vnet_buffer (b)->oflags;
  i16 l4_hdr_offset = vnet_buffer (b)->l4_hdr_offset - b->current_data;
  typeof (b->flags) flags = b->flags;

  if (flags & VNET_BUFFER_F_IS_IP4)
    {
      ip4_header_t *ip4;
      /*
       * virtio devices do not support IP4 checksum offload. So driver takes
       * care of it while doing tx.
       */
      ip4 = (ip4_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	ip4->checksum = ip4_header_checksum (ip4);

      /*
       * virtio devices assume the l4 header is set to the checksum of the
       * l3 pseudo-header, so we compute it before tx-ing
       */
      if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  tcp_header_t *tcp =
	    (tcp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
	  tcp->checksum = ip4_pseudo_header_cksum (ip4);
	  hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	  hdr->hdr_len = l4_hdr_offset + tcp_header_bytes (tcp);
	  hdr->csum_start = l4_hdr_offset;
	  hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  udp_header_t *udp =
	    (udp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
	  udp->checksum = ip4_pseudo_header_cksum (ip4);
	  hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	  hdr->hdr_len = l4_hdr_offset + sizeof (udp_header_t);
	  hdr->csum_start = l4_hdr_offset;
	  hdr->csum_offset = STRUCT_OFFSET_OF (udp_header_t, checksum);
	}
    }
  else if (flags & VNET_BUFFER_F_IS_IP6)
    {
      ip6_header_t *ip6;
      ip6 = (ip6_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);

      /*
       * virtio devices assume the l4 header is set to the checksum of the
       * l3 pseudo-header, so we compute it before tx-ing
       */
      if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  tcp_header_t *tcp =
	    (tcp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
	  tcp->checksum = ip6_pseudo_header_cksum (ip6);
	  hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	  hdr->hdr_len = l4_hdr_offset + tcp_header_bytes (tcp);
	  hdr->csum_start = l4_hdr_offset;
	  hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  udp_header_t *udp =
	    (udp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
	  udp->checksum = ip6_pseudo_header_cksum (ip6);
	  hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	  hdr->hdr_len = l4_hdr_offset + sizeof (udp_header_t);
	  hdr->csum_start = l4_hdr_offset;
	  hdr->csum_offset = STRUCT_OFFSET_OF (udp_header_t, checksum);
	}
    }
}

static void
set_gso_offsets (vlib_buffer_t *b, vnet_virtio_net_hdr_v1_t *hdr)
{
  vnet_buffer_oflags_t oflags = vnet_buffer (b)->oflags;
  i16 l4_hdr_offset = vnet_buffer (b)->l4_hdr_offset - b->current_data;
  typeof (b->flags) flags = b->flags;

  if (flags & VNET_BUFFER_F_IS_IP4)
    {
      ip4_header_t *ip4;
      hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
      hdr->hdr_len = l4_hdr_offset + vnet_buffer2 (b)->gso_l4_hdr_sz;
      hdr->gso_size = vnet_buffer2 (b)->gso_size;
      hdr->csum_start = l4_hdr_offset;
      hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
      ip4 = (ip4_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
      /*
       * virtio devices do not support IP4 checksum offload. So driver takes
       * care of it while doing tx.
       */
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	ip4->checksum = ip4_header_checksum (ip4);
    }
  else if (flags & VNET_BUFFER_F_IS_IP6)
    {
      hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
      hdr->hdr_len = l4_hdr_offset + vnet_buffer2 (b)->gso_l4_hdr_sz;
      hdr->gso_size = vnet_buffer2 (b)->gso_size;
      hdr->csum_start = l4_hdr_offset;
      hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
    }
}

static u16
tap_if_tx_inline (vlib_main_t *vm, vlib_node_runtime_t *node, tap_if_t *tif,
		  tap_txq_t *txq, u32 *buffers, u16 n_buffers, int is_tun)
{
  u16 avail;
  u16 sz = txq->queue_size;
  u16 mask = sz - 1;
  u16 *avail_ring = txq->avail->ring;
  u16 desc_freelist_head = txq->desc_freelist_head;
  u32 *vring_buffers = txq->buffers;
  vnet_virtio_vring_desc_t *desc = txq->desc;
  u16 drop_reasons[TAP_TX_N_ERROR] = {};
  u32 to_drop[VLIB_FRAME_SIZE], n_drop = 0;
  int hdr_sz = VIRTIO_NET_HDR_SZ;
  u32 n_enq = 0;

  avail = txq->avail->idx;
  u16 n_desc = sz - txq->desc_in_use;

  while (n_buffers && n_enq < n_desc)
    {
      vnet_virtio_vring_desc_t d = {}, *dp;
      u32 bi;
      vlib_buffer_t *b;
      vnet_virtio_net_hdr_v1_t *hdr;
      typeof (b->flags) flags;
      u16 desc_index;

      bi = buffers++[0];
      n_buffers--;
      b = vlib_get_buffer (vm, bi);
      flags = b->flags;
      hdr = vlib_buffer_get_current (b) - hdr_sz;
      *hdr = (vnet_virtio_net_hdr_v1_t){};

      if (flags & VNET_BUFFER_F_GSO)
	{
	  if (tif->gso_enabled)
	    set_gso_offsets (b, hdr);
	  else
	    {
	      drop_reasons[TAP_TX_ERROR_GSO_PACKET_DROP]++;
	      to_drop[n_drop++] = bi;
	      continue;
	    }
	}
      else if (flags & VNET_BUFFER_F_OFFLOAD)
	{
	  if (tif->csum_offload_enabled)
	    set_checksum_offsets (b, hdr);
	  else
	    {
	      drop_reasons[TAP_TX_ERROR_CSUM_OFFLOAD_PACKET_DROP]++;
	      to_drop[n_drop++] = bi;
	      continue;
	    }
	}

      if (PREDICT_FALSE (flags & VLIB_BUFFER_IS_TRACED))
	tap_tx_trace (vm, node, b, bi, is_tun);

      if (PREDICT_FALSE (flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  u32 indirect_buffer;
	  vnet_virtio_vring_desc_t *id;
	  vlib_buffer_t *idb;
	  u32 count = 1;

	  if (PREDICT_FALSE (vlib_buffer_alloc (vm, &indirect_buffer, 1) == 0))
	    {
	      drop_reasons[TAP_TX_ERROR_INDIRECT_DESC_ALLOC_FAILED]++;
	      to_drop[n_drop++] = bi;
	      continue;
	    }

	  idb = vlib_get_buffer (vm, indirect_buffer);
	  idb->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  idb->next_buffer = bi;
	  bi = indirect_buffer;
	  id = (vnet_virtio_vring_desc_t *) idb->data;

	  d.addr = pointer_to_uword (id);
	  id->addr = pointer_to_uword (vlib_buffer_get_current (b)) - hdr_sz;
	  id->len = b->current_length + hdr_sz;

	  while (flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      id->flags = VRING_DESC_F_NEXT;
	      id->next = count++;
	      id++;
	      b = vlib_get_buffer (vm, b->next_buffer);
	      id->addr = pointer_to_uword (vlib_buffer_get_current (b));
	      id->len = b->current_length;
	      if (PREDICT_FALSE (count == VIRTIO_TX_MAX_CHAIN_LEN))
		{
		  drop_reasons[TAP_TX_ERROR_TRUNC_PACKET]++;
		  to_drop[n_drop++] = bi;
		  continue;
		}
	      flags = b->flags;
	    }
	  id->flags = 0;
	  id->next = 0;
	  d.len = count * sizeof (vnet_virtio_vring_desc_t);
	  d.flags = VRING_DESC_F_INDIRECT;
	}
      else
	{
	  d.addr = pointer_to_uword (hdr);
	  d.len = b->current_length + hdr_sz;
	}

      /* take free descriptor from the freelist */
      desc_index = desc_freelist_head;
      dp = desc + desc_index;
      desc_freelist_head = dp->next;
      *dp = d;

      /* enqueue */
      vring_buffers[desc_index] = bi;
      avail_ring[avail++ & mask] = desc_index;
      n_enq++;
    }

  if (n_enq)
    {
      __atomic_store_n (&txq->avail->idx, avail, __ATOMIC_RELEASE);
      txq->desc_freelist_head = desc_freelist_head;
      txq->desc_in_use += n_enq;
      txq->total_packets += n_enq;
      if ((__atomic_load_n (&txq->used->flags, __ATOMIC_ACQUIRE) &
	   VRING_USED_F_NO_NOTIFY) == 0)
	{
	  ssize_t __clib_unused rv;
	  rv = write (txq->kick_fd, &(u64){ 1 }, sizeof (u64));
	}
    }

  if (n_drop)
    {
      for (u32 i = 0; i < ARRAY_LEN (drop_reasons); i++)
	if (drop_reasons[i])
	  vlib_error_count (vm, node->node_index, i, drop_reasons[i]);
      vlib_buffer_free (vm, to_drop, n_drop);
      vlib_increment_simple_counter (
	vnet_main.interface_main.sw_if_counters + VNET_INTERFACE_COUNTER_DROP,
	vm->thread_index, tif->sw_if_index, n_drop);
      txq->total_packets += n_drop;
    }

  return n_enq + n_drop;
}

VNET_DEVICE_CLASS_TX_FN (tap_device_class)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  tap_main_t *tm = &tap_main;
  vnet_interface_output_runtime_t *rund = (void *) node->runtime_data;
  tap_if_t *tif = pool_elt_at_index (tm->interfaces, rund->dev_instance);
  vnet_hw_if_tx_frame_t *tf = vlib_frame_scalar_args (frame);
  u16 qid = tf->queue_id;
  tap_txq_t *txq = tap_get_tx_queue (tif, qid);
  u16 n, n_pkts = frame->n_vectors, n_left = n_pkts;
  u32 *buffers = vlib_frame_vector_args (frame);
  u32 to[GRO_TO_VECTOR_SIZE (n_pkts)];
  u16 retry_count = 2;

  if (tf->shared_queue)
    CLIB_SPINLOCK_LOCK (txq->lock)

  if (tif->packet_coalesce)
    {
      n_pkts = vnet_gro_inline (vm, txq->flow_table, buffers, n_pkts, to);
      buffers = to;
      txq->tx_is_scheduled = 0;
    }

retry:
  /* free consumed buffers */
  tap_free_used_device_desc (vm, txq);

  if (tif->is_tun)
    n = tap_if_tx_inline (vm, node, tif, txq, buffers, n_left, 1);
  else
    n = tap_if_tx_inline (vm, node, tif, txq, buffers, n_left, 0);

  n_left -= n;
  buffers += n;

  if (n_left && retry_count--)
    goto retry;

  if (tf->shared_queue)
    CLIB_SPINLOCK_UNLOCK (txq->lock);

  if (n_left)
    {
      vlib_error_count (vm, node->node_index, TAP_TX_ERROR_NO_FREE_SLOTS,
			n_left);
      vlib_increment_simple_counter (
	vnet_main.interface_main.sw_if_counters + VNET_INTERFACE_COUNTER_DROP,
	vm->thread_index, tif->sw_if_index, n_left);
      vlib_buffer_free (vm, buffers, n_left);
    }

  return n_pkts - n_left;
}
