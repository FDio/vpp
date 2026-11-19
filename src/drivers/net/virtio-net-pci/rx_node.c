/* SPDX-License-Identifier: Apache-2.0 */
#include <inline_funcs.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vppinfra/vector/ip_csum.h>

static_always_inline void
vnp_rx_offload (vlib_main_t *vm, vlib_buffer_t *b, virtio_net_hdr_t *h)
{
  u16 start = h->csum_start;
  u16 offset = h->csum_offset;

  ASSERT ((h->flags & ~(VIRTIO_NET_HDR_F_NEEDS_CSUM | VIRTIO_NET_HDR_F_DATA_VALID)) == 0);

  if (!(h->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM))
    {
      ASSERT (h->gso_type == VIRTIO_NET_HDR_GSO_NONE);
      return;
    }

  ASSERT (start + offset + 2 <= b->current_length && start <= vlib_buffer_length_in_chain (vm, b));

  if (!h->gso_type)
    {
      vlib_buffer_t *seg = b;
      u32 position = 0, sum = 0, n_bytes = 0;

      while (1)
	{
	  u8 *data = vlib_buffer_get_current (seg);

	  for (u32 i = 0; i < seg->current_length; i++, position++)
	    if (position >= start)
	      sum += data[i] << ((n_bytes++ & 1) ? 0 : 8);

	  if (!(seg->flags & VLIB_BUFFER_NEXT_PRESENT))
	    break;

	  seg = vlib_get_buffer (vm, seg->next_buffer);
	}

      while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);

      u16 checksum = clib_host_to_net_u16 (~sum);

      if (checksum == 0 && offset == STRUCT_OFFSET_OF (udp_header_t, checksum))
	checksum = CLIB_U16_MAX;

      clib_memcpy_fast (b->data + start + offset, &checksum, sizeof (checksum));
      return;
    }

  ASSERT ((h->gso_type == VIRTIO_NET_HDR_GSO_TCPV4 || h->gso_type == VIRTIO_NET_HDR_GSO_TCPV6) &&
	  h->gso_size && offset == STRUCT_OFFSET_OF (tcp_header_t, checksum) &&
	  start + sizeof (tcp_header_t) <= b->current_length);

  ethernet_header_t *eth = (void *) b->data;
  u16 type = clib_net_to_host_u16 (eth->type), l3 = sizeof (*eth);

  for (u32 i = 0; i < 2 && ethernet_frame_is_tagged (type); i++)
    {
      ethernet_vlan_header_t *vlan = (void *) (b->data + l3);

      ASSERT (l3 + sizeof (*vlan) <= start);
      type = clib_net_to_host_u16 (vlan->type);
      l3 += sizeof (*vlan);
    }

  if (type == ETHERNET_TYPE_IP4)
    {
      ip4_header_t *ip = (void *) (b->data + l3);

      ASSERT (h->gso_type == VIRTIO_NET_HDR_GSO_TCPV4 && l3 + ip4_header_bytes (ip) == start &&
	      ip->protocol == IP_PROTOCOL_TCP);
      ip->checksum = ip4_header_checksum (ip);
      b->flags |= VNET_BUFFER_F_IS_IP4;
    }
  else
    {
      ASSERT (type == ETHERNET_TYPE_IP6 && h->gso_type == VIRTIO_NET_HDR_GSO_TCPV6 &&
	      l3 + sizeof (ip6_header_t) <= start);
      b->flags |= VNET_BUFFER_F_IS_IP6;
    }

  tcp_header_t *tcp = (void *) (b->data + start);
  u16 tcp_size = tcp_header_bytes (tcp);

  ASSERT (tcp_size >= sizeof (*tcp) && start + tcp_size <= b->current_length);

  b->flags |= VNET_BUFFER_F_GSO | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	      VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
  vnet_buffer (b)->l2_hdr_offset = 0;
  vnet_buffer (b)->l3_hdr_offset = l3;
  vnet_buffer (b)->l4_hdr_offset = start;
  vnet_buffer2 (b)->gso_size = h->gso_size;
  vnet_buffer2 (b)->gso_l4_hdr_sz = tcp_size;
  vnet_buffer_offload_flags_set (b, VNET_BUFFER_OFFLOAD_F_TCP_CKSUM);
}

/* lens[] do not include the virtio-net header */
static_always_inline u32
vnp_rx_attach_tail (vnp_rxq_t *q, vlib_buffer_t **bufs, u32 *bis, u16 *lens, u16 n_buffers)
{
  vlib_buffer_t *previous = bufs[0];
  u32 tail_length = 0;

  if (PREDICT_TRUE (n_buffers == 1))
    return 0;

  for (u16 j = 1; j < n_buffers; j++)
    {
      vlib_buffer_t *b = bufs[j];
      u16 len = lens[j] + VIRTIO_NET_HDR_V1_SZ;

      ASSERT (len <= q->desc_len);

      b->current_data = -VIRTIO_NET_HDR_V1_SZ;
      b->current_length = len;
      tail_length += len;

      previous->flags |= VLIB_BUFFER_NEXT_PRESENT;
      previous->next_buffer = bis[j];
      previous = b;
    }

  bufs[0]->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  bufs[0]->total_length_not_including_first_buffer = tail_length;

  return tail_length;
}

static_always_inline u8
vnp_rx_n_bufs (vlib_buffer_t *b)
{
  union
  {
    u8x16 as_u8x16;
    u16x8 as_u16x8;
    u64x2 as_u64x2;
    struct
    {
      u8 pre_data[4];
      virtio_net_hdr_t hdr;
    };
  } mask, match, v;
  u64x2 eq;

  mask = (typeof (mask)) { .hdr = { .flags = 0xff, .gso_type = 0xff, .num_buffers = 0xffff } };
  match = (typeof (mask)) { .hdr = { .num_buffers = 1 } };
  v = (typeof (mask)) { .as_u8x16 = *(u8x16u *) ((u8 *) virtio_net_rx_hdr (b) - 4) };
  eq = (u64x2) ((v.as_u64x2 & mask.as_u64x2) == match.as_u64x2);

  /* num_buffers is in the second lane, it needs the result of the first lane as well */
  eq &= u64x2_interleave_lo (eq, eq);

  return ((u16x8) (v.as_u64x2 & ~eq))[7];
}

static_always_inline u32
vnp_rx_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 initial_n_trace = n_trace, n_invalid = 0;
  vnp_rxq_t *q = vnet_dev_get_rx_queue_data (rxq);
  u32 *buffer_indices = q->buffer_indices, max_len = q->max_len;
  pvirtq_desc_t *packed = q->packed;
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 next = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 buffers[VLIB_FRAME_SIZE], drops[VLIB_FRAME_SIZE];
  u32 bis[VLIB_FRAME_SIZE];
  u16 lens[VLIB_FRAME_SIZE];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE + 4], **bp = bufs;
  u8 n_bufs[VLIB_FRAME_SIZE], *nb;
  u16 *ln;
  u32 n_rx = 0, n_drop = 0, bytes = 0, missing;
  u16 size = rxq->size, mask = size - 1;
  u16 count, consumed, n_free, n_left;
  u16 *ids;

  n_free = q->n_free;
  /* the returned ids are written where they will be pushed to the free list */
  ids = q->free_ids + n_free;

  if (packed)
    {
      u16 used = q->packed_used;

      for (count = 0; count < VLIB_FRAME_SIZE; count++, used++)
	{
	  pvirtq_desc_t *d = packed + (used & mask);
	  u16 flags = __atomic_load_n (&d->flags, __ATOMIC_ACQUIRE);

	  if (!vnp_packed_is_used (flags, used, size))
	    break;

	  ASSERT (d->id < size);
	  ids[count] = d->id;
	  lens[count] = d->len;
	  bis[count] = buffer_indices[d->id];
	}
    }
  else
    {
      virtq_used_elem_t *ring = q->used->ring;
      u16 last_used = q->last_used;
      u16 used = __atomic_load_n (&q->used->idx, __ATOMIC_ACQUIRE);

      ASSERT ((u16) (used - last_used) <= size);
      count = clib_min ((u16) (used - last_used), VLIB_FRAME_SIZE);

      for (u16 i = 0; i < count; i++)
	{
	  virtq_used_elem_t e = ring[(last_used + i) & mask];

	  ASSERT (e.id < size);
	  ids[i] = e.id;
	  lens[i] = e.len;
	  bis[i] = buffer_indices[e.id];
	}
    }

  if (count == 0)
    goto done;

  vlib_get_buffers (vm, bis, bufs, count);

  vlib_buffers_prefetch_pad (bufs, count, 4);

  vnp_u16_add (lens, count, -VIRTIO_NET_HDR_V1_SZ);

  /* all buffers are set up as single buffer packets, chains are fixed by vnp_rx_attach_tail, and
   * bytes counts lens[] of all of them, which the slow path corrects */
  for (n_left = count, nb = n_bufs, ln = lens; n_left >= 4; n_left -= 4, bp += 4, nb += 4, ln += 4)
    {
      vlib_prefetch_buffer_header (bp[4], STORE);
      vlib_prefetch_buffer_header (bp[5], STORE);
      vlib_prefetch_buffer_header (bp[6], STORE);
      vlib_prefetch_buffer_header (bp[7], STORE);
      clib_prefetch_load (virtio_net_rx_hdr (bp[4]));
      clib_prefetch_load (virtio_net_rx_hdr (bp[5]));
      clib_prefetch_load (virtio_net_rx_hdr (bp[6]));
      clib_prefetch_load (virtio_net_rx_hdr (bp[7]));

      nb[0] = vnp_rx_n_bufs (bp[0]);
      nb[1] = vnp_rx_n_bufs (bp[1]);
      nb[2] = vnp_rx_n_bufs (bp[2]);
      nb[3] = vnp_rx_n_bufs (bp[3]);

      vlib_buffer_copy_template (bp[0], &bt);
      vlib_buffer_copy_template (bp[1], &bt);
      vlib_buffer_copy_template (bp[2], &bt);
      vlib_buffer_copy_template (bp[3], &bt);

      bp[0]->current_length = ln[0];
      bp[1]->current_length = ln[1];
      bp[2]->current_length = ln[2];
      bp[3]->current_length = ln[3];

      bytes += ln[0] + ln[1] + ln[2] + ln[3];
    }

  for (; n_left; n_left--, bp++, nb++, ln++)
    {
      nb[0] = vnp_rx_n_bufs (bp[0]);
      vlib_buffer_copy_template (bp[0], &bt);
      bp[0]->current_length = ln[0];
      bytes += ln[0];
    }

  for (n_left = count; n_left;)
    {
      u16 i = count - n_left, n_buffers = n_bufs[i];
      vlib_buffer_t *head = bufs[i];
      virtio_net_hdr_t *hdr = virtio_net_rx_hdr (head);
      u32 packet_length = lens[i];
      u8 invalid;

      if (n_left >= 16 && u8x16_is_all_zero (*(u8x16u *) (n_bufs + i)))
	{
	  vlib_buffer_copy_indices (buffers + n_rx, bis + i, 16);
	  n_rx += 16;
	  n_left -= 16;
	  continue;
	}

      if (n_buffers == 0)
	{
	  buffers[n_rx++] = bis[i];
	  n_left--;
	  continue;
	}

      ASSERT (n_buffers && n_buffers <= size);
      ASSERT (packet_length + VIRTIO_NET_HDR_V1_SZ <= q->desc_len &&
	      packet_length >= sizeof (ethernet_header_t));

      if (PREDICT_FALSE (n_buffers > n_left))
	{
	  for (u16 k = i; k < count; k++)
	    bytes -= lens[k];

	  break;
	}

      packet_length += vnp_rx_attach_tail (q, bufs + i, bis + i, lens + i, n_buffers);

      invalid = !hdr->gso_type && packet_length > max_len;

      if (PREDICT_FALSE (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) && !invalid)
	vnp_rx_offload (vm, head, hdr);

      if (PREDICT_FALSE (hdr->gso_type) && !invalid)
	{
	  u32 headers = vnet_buffer (head)->l4_hdr_offset + vnet_buffer2 (head)->gso_l4_hdr_sz;

	  invalid = headers + vnet_buffer2 (head)->gso_size > max_len;
	}

      if (PREDICT_FALSE (invalid))
	{
	  n_invalid++;
	  drops[n_drop++] = bis[i];
	  bytes -= packet_length - (n_buffers - 1) * VIRTIO_NET_HDR_V1_SZ;
	}
      else
	{
	  buffers[n_rx++] = bis[i];
	  bytes += (n_buffers - 1) * VIRTIO_NET_HDR_V1_SZ;
	}

      n_left -= n_buffers;
    }

  consumed = count - n_left;

  if (PREDICT_FALSE (n_trace))
    for (u32 i = 0; i < n_rx + n_drop && n_trace; i++)
      {
	vlib_buffer_t *b = vlib_get_buffer (vm, i < n_rx ? buffers[i] : drops[i - n_rx]);

	if (vlib_trace_buffer (vm, node, next, b, 0))
	  {
	    vnp_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	    tr->length = vlib_buffer_length_in_chain (vm, b);
	    tr->queue_id = rxq->queue_id;
	    tr->hdr = *virtio_net_rx_hdr (b);
	    n_trace--;
	  }
      }

  vlib_buffer_free (vm, drops, n_drop);

  if (packed)
    q->packed_used += consumed;
  else
    q->last_used += consumed;

  n_free += consumed;
  q->n_free = n_free;

  vlib_buffer_enqueue_to_single_next (vm, node, buffers, next, n_rx);
  vnet_dev_increment_interface_counters (vm, rxq->port, n_rx, bytes);

done:
  missing = vnp_rxq_refill (vm, rxq);
  if (PREDICT_FALSE (missing))
    vlib_error_count (vm, node->node_index, VNP_RX_ALLOC, missing);

  if (rxq->interrupt_mode)
    vnp_rxq_irq (vm, rxq, 1);

  if (PREDICT_FALSE (initial_n_trace))
    vlib_set_trace_count (vm, node, n_trace);

  if (PREDICT_FALSE (n_invalid))
    vlib_error_count (vm, node->node_index, VNP_RX_INVALID, n_invalid);

  return n_rx;
}

VNET_DEV_NODE_FN (vnp_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame __clib_unused)
{
  u32 total = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    total += vnp_rx_node_inline (vm, node, rxq);

  return total;
}
