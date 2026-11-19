/* SPDX-License-Identifier: Apache-2.0 */
#include <inline_funcs.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vppinfra/vector/ip_csum.h>

static_always_inline u8
vnp_rx_offload (vlib_main_t *vm, vlib_buffer_t *b, virtio_net_hdr_t *h)
{
  u32 length = vlib_buffer_length_in_chain (vm, b);
  u16 start = h->csum_start;
  u16 offset = h->csum_offset;

  if (h->flags & ~(VIRTIO_NET_HDR_F_NEEDS_CSUM | VIRTIO_NET_HDR_F_DATA_VALID))
    return 0;

  if (!(h->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM))
    return h->gso_type == VIRTIO_NET_HDR_GSO_NONE;

  if (start + offset + 2 > b->current_length || start > length)
    return 0;

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
      return 1;
    }

  if ((h->gso_type != VIRTIO_NET_HDR_GSO_TCPV4 && h->gso_type != VIRTIO_NET_HDR_GSO_TCPV6) ||
      !h->gso_size || offset != STRUCT_OFFSET_OF (tcp_header_t, checksum) ||
      start + sizeof (tcp_header_t) > b->current_length)
    return 0;

  ethernet_header_t *eth = (void *) b->data;
  u16 type = clib_net_to_host_u16 (eth->type), l3 = sizeof (*eth);

  for (u32 i = 0; i < 2 && ethernet_frame_is_tagged (type); i++)
    {
      ethernet_vlan_header_t *vlan = (void *) (b->data + l3);

      if (l3 + sizeof (*vlan) > start)
	return 0;

      type = clib_net_to_host_u16 (vlan->type);
      l3 += sizeof (*vlan);
    }

  if (type == ETHERNET_TYPE_IP4 && h->gso_type == VIRTIO_NET_HDR_GSO_TCPV4 &&
      l3 + sizeof (ip4_header_t) <= start)
    {
      ip4_header_t *ip = (void *) (b->data + l3);

      if (l3 + ip4_header_bytes (ip) != start || ip->protocol != 6)
	return 0;

      ip->checksum = ip4_header_checksum (ip);
      b->flags |= VNET_BUFFER_F_IS_IP4;
    }
  else if (type == ETHERNET_TYPE_IP6 && h->gso_type == VIRTIO_NET_HDR_GSO_TCPV6 &&
	   l3 + sizeof (ip6_header_t) <= start)
    b->flags |= VNET_BUFFER_F_IS_IP6;
  else
    return 0;

  tcp_header_t *tcp = (void *) (b->data + start);
  u16 tcp_size = tcp_header_bytes (tcp);

  if (tcp_size < sizeof (*tcp) || start + tcp_size > b->current_length)
    return 0;

  b->flags |= VNET_BUFFER_F_GSO | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	      VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
  vnet_buffer (b)->l2_hdr_offset = 0;
  vnet_buffer (b)->l3_hdr_offset = l3;
  vnet_buffer (b)->l4_hdr_offset = start;
  vnet_buffer2 (b)->gso_size = h->gso_size;
  vnet_buffer2 (b)->gso_l4_hdr_sz = tcp_size;
  vnet_buffer_offload_flags_set (b, VNET_BUFFER_OFFLOAD_F_TCP_CKSUM);
  return 1;
}

VNET_DEV_NODE_FN (vnp_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame __clib_unused)
{
  u32 total = 0, n_invalid = 0;
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 initial_n_trace = n_trace;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      vnp_rxq_t *q = vnet_dev_get_rx_queue_data (rxq);
      vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
      u32 next = vnet_dev_get_rx_queue_if_next_index (rxq);
      u32 buffers[VLIB_FRAME_SIZE], drops[VLIB_FRAME_SIZE];
      u32 n_rx = 0, n_drop = 0, bytes = 0, missing;
      u16 size = rxq->size, mask = size - 1;
      u16 used, count, consumed = 0, last_used, n_free;

      vnp_rxq_sync_used (q, size);
      last_used = q->last_used;
      n_free = q->n_free;
      used = __atomic_load_n (&q->used->idx, __ATOMIC_ACQUIRE);
      count = clib_min ((u16) (used - last_used), VLIB_FRAME_SIZE);

      if ((u16) (used - last_used) > size)
	{
	  n_invalid++;
	  continue;
	}

      while (consumed < count)
	{
	  virtq_used_elem_t first = q->used->ring[last_used & mask];
	  u32 first_id = first.id;
	  u16 n_buffers = 1;
	  u32 packet_length = 0, head_bi = 0;
	  vlib_buffer_t *head = 0, *previous = 0, *first_buffer;
	  virtio_net_hdr_t *hdr;
	  u8 invalid;

	  if (PREDICT_FALSE (first_id >= size ||
			     q->buffer_indices[first_id] == VLIB_BUFFER_INVALID_INDEX))
	    {
	      n_invalid++;
	      last_used++;
	      consumed++;
	      continue;
	    }

	  first_buffer = vlib_get_buffer (vm, q->buffer_indices[first_id]);
	  hdr = (void *) (first_buffer->data - VIRTIO_NET_HDR_V1_SZ);

	  if (q->mrg_rxbuf)
	    n_buffers = hdr->num_buffers;

	  if (PREDICT_FALSE (!n_buffers || n_buffers > size))
	    {
	      n_invalid++;
	      q->free_ids[n_free++] = first_id;
	      vlib_buffer_free (vm, q->buffer_indices + first_id, 1);
	      q->buffer_indices[first_id] = VLIB_BUFFER_INVALID_INDEX;
	      last_used++;
	      consumed++;
	      continue;
	    }

	  if (PREDICT_FALSE (n_buffers > (u16) (used - last_used)))
	    break;

	  invalid = 0;

	  for (u16 j = 0; j < n_buffers; j++)
	    {
	      virtq_used_elem_t e = q->used->ring[last_used++ & mask];
	      u32 id = e.id;
	      u32 len = e.len;
	      u32 bi;
	      vlib_buffer_t *b;

	      if (PREDICT_FALSE (id >= size || q->buffer_indices[id] == VLIB_BUFFER_INVALID_INDEX))
		{
		  invalid = 1;
		  continue;
		}

	      bi = q->buffer_indices[id];
	      b = vlib_get_buffer (vm, bi);
	      q->buffer_indices[id] = VLIB_BUFFER_INVALID_INDEX;
	      q->free_ids[n_free++] = id;
	      vlib_buffer_copy_template (b, &bt);

	      if (PREDICT_FALSE (
		    len > q->desc[id].len ||
		    (j == 0 && len < VIRTIO_NET_HDR_V1_SZ + sizeof (ethernet_header_t))))
		{
		  invalid = 1;
		  len = j == 0 ? VIRTIO_NET_HDR_V1_SZ : 0;
		}

	      b->current_data = j == 0 ? 0 : -VIRTIO_NET_HDR_V1_SZ;
	      b->current_length = len - (j == 0 ? VIRTIO_NET_HDR_V1_SZ : 0);
	      packet_length += b->current_length;

	      if (previous)
		{
		  previous->flags |= VLIB_BUFFER_NEXT_PRESENT;
		  previous->next_buffer = bi;
		}
	      else
		{
		  head = b;
		  head_bi = bi;
		}

	      previous = b;
	    }

	  consumed += n_buffers;

	  if (!hdr->gso_type)
	    invalid |= packet_length > q->max_len;

	  if (head)
	    {
	      head->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	      head->total_length_not_including_first_buffer = packet_length - head->current_length;

	      if (!invalid)
		invalid = !vnp_rx_offload (vm, head, hdr);

	      if (!invalid && (head->flags & VNET_BUFFER_F_GSO))
		invalid = vnet_buffer (head)->l4_hdr_offset + vnet_buffer2 (head)->gso_l4_hdr_sz +
			    vnet_buffer2 (head)->gso_size >
			  q->max_len;

	      if (PREDICT_FALSE (invalid))
		{
		  n_invalid++;
		  drops[n_drop++] = head_bi;
		}
	      else
		{
		  buffers[n_rx++] = head_bi;
		  bytes += packet_length;
		}
	    }
	}

      if (PREDICT_FALSE (n_trace))
	for (u32 i = 0; i < n_rx + n_drop && n_trace; i++)
	  {
	    vlib_buffer_t *b = vlib_get_buffer (vm, i < n_rx ? buffers[i] : drops[i - n_rx]);

	    if (vlib_trace_buffer (vm, node, next, b, 0))
	      {
		vnp_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
		tr->length = vlib_buffer_length_in_chain (vm, b);
		tr->queue_id = rxq->queue_id;
		tr->hdr = *(virtio_net_hdr_t *) (b->data - VIRTIO_NET_HDR_V1_SZ);
		n_trace--;
	      }
	  }

      vlib_buffer_free (vm, drops, n_drop);

      q->last_used = last_used;
      q->n_free = n_free;

      missing = vnp_rxq_refill (vm, rxq);
      if (PREDICT_FALSE (missing))
	vlib_error_count (vm, node->node_index, VNP_RX_ALLOC, missing);

      vlib_buffer_enqueue_to_single_next (vm, node, buffers, next, n_rx);
      vnet_dev_increment_interface_counters (vm, rxq->port, n_rx, bytes);
      total += n_rx;

      if (rxq->interrupt_mode)
	vnp_rxq_irq (vm, rxq, 1);
    }

  if (PREDICT_FALSE (initial_n_trace))
    vlib_set_trace_count (vm, node, n_trace);

  if (PREDICT_FALSE (n_invalid))
    vlib_error_count (vm, node->node_index, VNP_RX_INVALID, n_invalid);

  return total;
}
