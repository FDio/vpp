/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vppinfra/ring.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>

#include <vnet/devices/devices.h>

#include <avf/avf.h>

static_always_inline u8
avf_tx_desc_get_dtyp (avf_tx_desc_t * d)
{
  return d->qword[1] & 0x0f;
}

struct avf_ip4_psh
{
  u32 src;
  u32 dst;
  u8 zero;
  u8 proto;
  u16 l4len;
};

struct avf_ip6_psh
{
  u32 src[4];
  u32 dst[4];
  u32 l4len;
  u32 proto;
};

static_always_inline u64
avf_tx_prepare_cksum (vlib_buffer_t * b, u8 is_tso)
{
  u64 flags = 0;
  if (!is_tso && !(b->flags & ((VNET_BUFFER_F_OFFLOAD_IP_CKSUM |
				VNET_BUFFER_F_OFFLOAD_TCP_CKSUM |
				VNET_BUFFER_F_OFFLOAD_UDP_CKSUM))))
    return 0;
  u32 is_tcp = is_tso || b->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
  u32 is_udp = !is_tso && b->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
  u32 is_ip4 = b->flags & VNET_BUFFER_F_IS_IP4;
  u32 is_ip6 = b->flags & VNET_BUFFER_F_IS_IP6;
  ASSERT (!is_tcp || !is_udp);
  ASSERT (is_ip4 || is_ip6);
  i16 l2_hdr_offset = vnet_buffer (b)->l2_hdr_offset;
  i16 l3_hdr_offset = vnet_buffer (b)->l3_hdr_offset;
  i16 l4_hdr_offset = vnet_buffer (b)->l4_hdr_offset;
  u16 l2_len = l3_hdr_offset - l2_hdr_offset;
  u16 l3_len = l4_hdr_offset - l3_hdr_offset;
  ip4_header_t *ip4 = (void *) (b->data + l3_hdr_offset);
  ip6_header_t *ip6 = (void *) (b->data + l3_hdr_offset);
  tcp_header_t *tcp = (void *) (b->data + l4_hdr_offset);
  udp_header_t *udp = (void *) (b->data + l4_hdr_offset);
  u16 l4_len =
    is_tcp ? tcp_header_bytes (tcp) : is_udp ? sizeof (udp_header_t) : 0;
  u16 sum = 0;

  flags |= AVF_TXD_OFFSET_MACLEN (l2_len) |
    AVF_TXD_OFFSET_IPLEN (l3_len) | AVF_TXD_OFFSET_L4LEN (l4_len);
  flags |= is_ip4 ? AVF_TXD_CMD_IIPT_IPV4 : AVF_TXD_CMD_IIPT_IPV6;
  flags |= is_tcp ? AVF_TXD_CMD_L4T_TCP : is_udp ? AVF_TXD_CMD_L4T_UDP : 0;

  if (is_ip4)
    ip4->checksum = 0;

  if (is_tso)
    {
      if (is_ip4)
	ip4->length = 0;
      else
	ip6->payload_length = 0;
    }

  if (is_tcp || is_udp)
    {
      if (is_ip4)
	{
	  struct avf_ip4_psh psh = { 0 };
	  psh.src = ip4->src_address.as_u32;
	  psh.dst = ip4->dst_address.as_u32;
	  psh.proto = ip4->protocol;
	  psh.l4len =
	    is_tso ? 0 :
	    clib_host_to_net_u16 (clib_net_to_host_u16 (ip4->length) -
				  (l4_hdr_offset - l3_hdr_offset));
	  sum = ~ip_csum (&psh, sizeof (psh));
	}
      else
	{
	  struct avf_ip6_psh psh = { 0 };
	  clib_memcpy_fast (&psh.src, &ip6->src_address, 32);
	  psh.proto = clib_host_to_net_u32 ((u32) ip6->protocol);
	  psh.l4len = is_tso ? 0 : ip6->payload_length;
	  sum = ~ip_csum (&psh, sizeof (psh));
	}
    }
  /* ip_csum does a byte swap for some reason... */
  sum = clib_net_to_host_u16 (sum);
  if (is_tcp)
    tcp->checksum = sum;
  else if (is_udp)
    udp->checksum = sum;
  return flags;
}

static_always_inline void
avf_tx_fill_ctx_desc (vlib_main_t * vm, avf_tx_desc_t * d, vlib_buffer_t * b)
{
  u16 l234hdr_sz =
    vnet_buffer (b)->l4_hdr_offset -
    vnet_buffer (b)->l2_hdr_offset + vnet_buffer2 (b)->gso_l4_hdr_sz;
  u16 tlen = vlib_buffer_length_in_chain (vm, b) - l234hdr_sz;
  d[0].qword[0] = 0;
  d[0].qword[1] = AVF_TXD_DTYP_CTX | AVF_TXD_CTX_CMD_TSO
    | AVF_TXD_CTX_SEG_MSS (vnet_buffer2 (b)->gso_size) |
    AVF_TXD_CTX_SEG_TLEN (tlen);
}


static_always_inline u16
avf_tx_enqueue (vlib_main_t * vm, vlib_node_runtime_t * node, avf_txq_t * txq,
		u32 * buffers, u32 n_packets, int use_va_dma)
{
  u16 next = txq->next;
  u64 bits = AVF_TXD_CMD_EOP | AVF_TXD_CMD_RSV;
  const u32 offload_mask = VNET_BUFFER_F_OFFLOAD_IP_CKSUM |
    VNET_BUFFER_F_OFFLOAD_TCP_CKSUM | VNET_BUFFER_F_OFFLOAD_UDP_CKSUM |
    VNET_BUFFER_F_GSO;
  u64 one_by_one_offload_flags = 0;
  int is_tso;
  u16 n_desc = 0;
  u16 *slot, n_desc_left, n_packets_left = n_packets;
  u16 mask = txq->size - 1;
  vlib_buffer_t *b[4];
  avf_tx_desc_t *d = txq->descs + next;
  u16 n_desc_needed;
  vlib_buffer_t *b0;

  /* avoid ring wrap */
  n_desc_left = txq->size - clib_max (txq->next, txq->n_enqueued + 8);

  if (n_desc_left == 0)
    return 0;

  /* Fast path, no ring wrap */
  while (n_packets_left && n_desc_left)
    {
      u32 or_flags;
      if (n_packets_left < 8 || n_desc_left < 4)
	goto one_by_one;

      vlib_prefetch_buffer_with_index (vm, buffers[4], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[5], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[6], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[7], LOAD);

      b[0] = vlib_get_buffer (vm, buffers[0]);
      b[1] = vlib_get_buffer (vm, buffers[1]);
      b[2] = vlib_get_buffer (vm, buffers[2]);
      b[3] = vlib_get_buffer (vm, buffers[3]);

      or_flags = b[0]->flags | b[1]->flags | b[2]->flags | b[3]->flags;

      if (or_flags & (VLIB_BUFFER_NEXT_PRESENT | offload_mask))
	goto one_by_one;

      vlib_buffer_copy_indices (txq->bufs + next, buffers, 4);

      if (use_va_dma)
	{
	  d[0].qword[0] = vlib_buffer_get_current_va (b[0]);
	  d[1].qword[0] = vlib_buffer_get_current_va (b[1]);
	  d[2].qword[0] = vlib_buffer_get_current_va (b[2]);
	  d[3].qword[0] = vlib_buffer_get_current_va (b[3]);
	}
      else
	{
	  d[0].qword[0] = vlib_buffer_get_current_pa (vm, b[0]);
	  d[1].qword[0] = vlib_buffer_get_current_pa (vm, b[1]);
	  d[2].qword[0] = vlib_buffer_get_current_pa (vm, b[2]);
	  d[3].qword[0] = vlib_buffer_get_current_pa (vm, b[3]);
	}

      d[0].qword[1] = ((u64) b[0]->current_length) << 34 | bits;
      d[1].qword[1] = ((u64) b[1]->current_length) << 34 | bits;
      d[2].qword[1] = ((u64) b[2]->current_length) << 34 | bits;
      d[3].qword[1] = ((u64) b[3]->current_length) << 34 | bits;

      next += 4;
      n_desc += 4;
      buffers += 4;
      n_packets_left -= 4;
      n_desc_left -= 4;
      d += 4;
      continue;

    one_by_one:
      one_by_one_offload_flags = 0;
      txq->bufs[next] = buffers[0];
      b[0] = vlib_get_buffer (vm, buffers[0]);
      is_tso = ! !(b[0]->flags & VNET_BUFFER_F_GSO);
      if (PREDICT_FALSE (is_tso || b[0]->flags & offload_mask))
	one_by_one_offload_flags |= avf_tx_prepare_cksum (b[0], is_tso);

      /* Deal with chain buffer if present */
      if (is_tso || b[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  n_desc_needed = 1 + is_tso;
	  b0 = b[0];

	  /* Wish there were a buffer count for chain buffer */
	  while (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      b0 = vlib_get_buffer (vm, b0->next_buffer);
	      n_desc_needed++;
	    }

	  /* spec says data descriptor is limited to 8 segments */
	  if (PREDICT_FALSE (!is_tso && n_desc_needed > 8))
	    {
	      vlib_buffer_free_one (vm, buffers[0]);
	      vlib_error_count (vm, node->node_index,
				AVF_TX_ERROR_SEGMENT_SIZE_EXCEEDED, 1);
	      n_packets_left -= 1;
	      buffers += 1;
	      continue;
	    }

	  if (PREDICT_FALSE (n_desc_left < n_desc_needed))
	    /*
	     * Slow path may be able to to deal with this since it can handle
	     * ring wrap
	     */
	    break;

	  /* Enqueue a context descriptor if needed */
	  if (PREDICT_FALSE (is_tso))
	    {
	      avf_tx_fill_ctx_desc (vm, d, b[0]);
	      vlib_get_buffer (vm, txq->ctx_desc_placeholder_bi)->ref_count++;
	      txq->bufs[next + 1] = txq->bufs[next];
	      txq->bufs[next] = txq->ctx_desc_placeholder_bi;
	      next += 1;
	      n_desc += 1;
	      n_desc_left -= 1;
	      d += 1;
	    }
	  while (b[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      if (use_va_dma)
		d[0].qword[0] = vlib_buffer_get_current_va (b[0]);
	      else
		d[0].qword[0] = vlib_buffer_get_current_pa (vm, b[0]);

	      d[0].qword[1] = (((u64) b[0]->current_length) << 34) |
		AVF_TXD_CMD_RSV | one_by_one_offload_flags;

	      next += 1;
	      n_desc += 1;
	      n_desc_left -= 1;
	      d += 1;

	      txq->bufs[next] = b[0]->next_buffer;
	      b[0] = vlib_get_buffer (vm, b[0]->next_buffer);
	    }
	}

      if (use_va_dma)
	d[0].qword[0] = vlib_buffer_get_current_va (b[0]);
      else
	d[0].qword[0] = vlib_buffer_get_current_pa (vm, b[0]);

      d[0].qword[1] =
	(((u64) b[0]->current_length) << 34) | bits |
	one_by_one_offload_flags;

      next += 1;
      n_desc += 1;
      buffers += 1;
      n_packets_left -= 1;
      n_desc_left -= 1;
      d += 1;
    }

  /* Slow path to support ring wrap */
  if (PREDICT_FALSE (n_packets_left))
    {
      txq->n_enqueued += n_desc;

      n_desc = 0;
      d = txq->descs + (next & mask);

      /* +8 to be consistent with fast path */
      n_desc_left = txq->size - (txq->n_enqueued + 8);

      while (n_packets_left && n_desc_left)
	{

	  txq->bufs[next & mask] = buffers[0];
	  b[0] = vlib_get_buffer (vm, buffers[0]);

	  one_by_one_offload_flags = 0;
	  is_tso = ! !(b[0]->flags & VNET_BUFFER_F_GSO);
	  if (PREDICT_FALSE (is_tso || b[0]->flags & offload_mask))
	    one_by_one_offload_flags |= avf_tx_prepare_cksum (b[0], is_tso);

	  /* Deal with chain buffer if present */
	  if (is_tso || b[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      n_desc_needed = 1 + is_tso;
	      b0 = b[0];

	      while (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
		{
		  b0 = vlib_get_buffer (vm, b0->next_buffer);
		  n_desc_needed++;
		}

	      /* Spec says data descriptor is limited to 8 segments */
	      if (PREDICT_FALSE (!is_tso && n_desc_needed > 8))
		{
		  vlib_buffer_free_one (vm, buffers[0]);
		  vlib_error_count (vm, node->node_index,
				    AVF_TX_ERROR_SEGMENT_SIZE_EXCEEDED, 1);
		  n_packets_left -= 1;
		  buffers += 1;
		  continue;
		}

	      if (PREDICT_FALSE (n_desc_left < n_desc_needed))
		break;

	      /* Enqueue a context descriptor if needed */
	      if (PREDICT_FALSE (is_tso))
		{
		  avf_tx_fill_ctx_desc (vm, d, b[0]);
		  vlib_get_buffer (vm,
				   txq->ctx_desc_placeholder_bi)->ref_count++;
		  txq->bufs[(next + 1) & mask] = txq->bufs[next & mask];
		  txq->bufs[next & mask] = txq->ctx_desc_placeholder_bi;
		  next += 1;
		  n_desc += 1;
		  n_desc_left -= 1;
		  d = txq->descs + (next & mask);
		}
	      while (b[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
		{
		  if (use_va_dma)
		    d[0].qword[0] = vlib_buffer_get_current_va (b[0]);
		  else
		    d[0].qword[0] = vlib_buffer_get_current_pa (vm, b[0]);

		  d[0].qword[1] = (((u64) b[0]->current_length) << 34) |
		    AVF_TXD_CMD_RSV | one_by_one_offload_flags;

		  next += 1;
		  n_desc += 1;
		  n_desc_left -= 1;
		  d = txq->descs + (next & mask);

		  txq->bufs[next & mask] = b[0]->next_buffer;
		  b[0] = vlib_get_buffer (vm, b[0]->next_buffer);
		}
	    }

	  if (use_va_dma)
	    d[0].qword[0] = vlib_buffer_get_current_va (b[0]);
	  else
	    d[0].qword[0] = vlib_buffer_get_current_pa (vm, b[0]);

	  d[0].qword[1] =
	    (((u64) b[0]->current_length) << 34) | bits |
	    one_by_one_offload_flags;

	  next += 1;
	  n_desc += 1;
	  buffers += 1;
	  n_packets_left -= 1;
	  n_desc_left -= 1;
	  d = txq->descs + (next & mask);
	}
    }

  if ((slot = clib_ring_enq (txq->rs_slots)))
    {
      u16 rs_slot = slot[0] = (next - 1) & mask;
      d = txq->descs + rs_slot;
      d[0].qword[1] |= AVF_TXD_CMD_RS;
    }

  txq->next = next & mask;
  clib_atomic_store_rel_n (txq->qtx_tail, txq->next);
  txq->n_enqueued += n_desc;
  return n_packets - n_packets_left;
}

VNET_DEVICE_CLASS_TX_FN (avf_device_class) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  avf_device_t *ad = avf_get_device (rd->dev_instance);
  u32 thread_index = vm->thread_index;
  u8 qid = thread_index;
  avf_txq_t *txq = vec_elt_at_index (ad->txqs, qid % ad->num_queue_pairs);
  u32 *buffers = vlib_frame_vector_args (frame);
  u16 n_enq, n_left;
  u16 n_retry = 2;

  clib_spinlock_lock_if_init (&txq->lock);

  n_left = frame->n_vectors;

retry:
  /* release consumed bufs */
  if (txq->n_enqueued)
    {
      i32 complete_slot = -1;
      while (1)
	{
	  u16 *slot = clib_ring_get_first (txq->rs_slots);

	  if (slot == 0)
	    break;

	  if (avf_tx_desc_get_dtyp (txq->descs + slot[0]) != 0x0F)
	    break;

	  complete_slot = slot[0];

	  clib_ring_deq (txq->rs_slots);
	}

      if (complete_slot >= 0)
	{
	  u16 first, mask, n_free;
	  mask = txq->size - 1;
	  first = (txq->next - txq->n_enqueued) & mask;
	  n_free = (complete_slot + 1 - first) & mask;

	  txq->n_enqueued -= n_free;
	  vlib_buffer_free_from_ring_no_next (vm, txq->bufs, first, txq->size,
					      n_free);
	}
    }

  if (ad->flags & AVF_DEVICE_F_VA_DMA)
    n_enq = avf_tx_enqueue (vm, node, txq, buffers, n_left, 1);
  else
    n_enq = avf_tx_enqueue (vm, node, txq, buffers, n_left, 0);

  n_left -= n_enq;

  if (n_left)
    {
      buffers += n_enq;

      if (n_retry--)
	goto retry;

      vlib_buffer_free (vm, buffers, n_left);
      vlib_error_count (vm, node->node_index,
			AVF_TX_ERROR_NO_FREE_SLOTS, n_left);
    }

  clib_spinlock_unlock_if_init (&txq->lock);

  return frame->n_vectors - n_left;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
