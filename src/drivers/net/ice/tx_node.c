/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vppinfra/ring.h>
#include <vppinfra/vector/ip_csum.h>
#include <ice.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>

#define ICE_TX_MAX_TAIL_LEN (ICE_TX_DESC_MAX_GSO_CHAIN_LENGTH - 1)

static_always_inline void
ice_tx_prepare_offload (vlib_buffer_t *b, ice_tx_cmd_t *cmd, u8 is_gso)
{
  vnet_buffer_oflags_t oflags;
  u32 is_tcp, is_udp, is_ip4;
  i16 l3_hdr_offset;
  u16 l2_len, l3_len;
  ip4_header_t *ip4;
  ip6_header_t *ip6;

  if (!is_gso && (b->flags & VNET_BUFFER_F_OFFLOAD) == 0)
    return;

  oflags = vnet_buffer (b)->oflags;
  is_tcp = oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM;
  is_udp = oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;

  if (!is_tcp && !is_udp && !is_gso && (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM) == 0)
    return;

  is_ip4 = b->flags & VNET_BUFFER_F_IS_IP4;
  ASSERT (!(is_tcp && is_udp));
  ASSERT (is_ip4 || (b->flags & VNET_BUFFER_F_IS_IP6));
  ASSERT (b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID);
  ASSERT (vnet_buffer (b)->l3_hdr_offset >= b->current_data);

  l3_hdr_offset = vnet_buffer (b)->l3_hdr_offset;
  l2_len = l3_hdr_offset - b->current_data;
  ASSERT ((l2_len & 1) == 0 && l2_len <= ICE_TX_MAC_LENGTH_MAX);

  ip4 = (void *) (b->data + l3_hdr_offset);
  ip6 = (void *) (b->data + l3_hdr_offset);

  if (is_tcp || is_udp)
    {
      i16 l4_hdr_offset;
      u16 l4_len;
      tcp_header_t *tcp;
      udp_header_t *udp;
      u16 sum;

      ASSERT (b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
      l4_hdr_offset = vnet_buffer (b)->l4_hdr_offset;
      l3_len = l4_hdr_offset - l3_hdr_offset;
      tcp = (void *) (b->data + l4_hdr_offset);
      udp = (void *) (b->data + l4_hdr_offset);
      l4_len = is_tcp ? tcp_header_bytes (tcp) : sizeof (udp_header_t);

      cmd->l4_type = is_tcp ? ICE_TX_L4_TYPE_TCP : ICE_TX_L4_TYPE_UDP;
      cmd->l4_length = l4_len / ICE_TX_L4_LENGTH_UNIT;

      if (is_gso)
	{
	  if (is_ip4)
	    ip4->length = 0;
	  else
	    ip6->payload_length = 0;
	}

      if (is_ip4)
	{
	  struct
	  {
	    u32 src;
	    u32 dst;
	    u8 zero;
	    u8 proto;
	    u16 l4len;
	  } psh = {
	    .src = ip4->src_address.as_u32,
	    .dst = ip4->dst_address.as_u32,
	    .proto = ip4->protocol,
	    .l4len =
	      is_gso ? 0 : clib_host_to_net_u16 (clib_net_to_host_u16 (ip4->length) - l3_len),
	  };
	  sum = ~clib_ip_csum ((u8 *) &psh, sizeof (psh));
	}
      else
	{
	  u32 l4_length = 0;

	  if (!is_gso)
	    l4_length = clib_net_to_host_u16 (ip6->payload_length) - (l3_len - sizeof (*ip6));

	  struct
	  {
	    ip6_address_t src;
	    ip6_address_t dst;
	    u32 l4len;
	    u32 proto;
	  } psh = {
	    .src = ip6->src_address,
	    .dst = ip6->dst_address,
	    .proto = clib_host_to_net_u32 (is_tcp ? IP_PROTOCOL_TCP : IP_PROTOCOL_UDP),
	    .l4len = clib_host_to_net_u32 (l4_length),
	  };
	  sum = ~clib_ip_csum ((u8 *) &psh, sizeof (psh));
	}

      if (is_tcp)
	tcp->checksum = sum;
      else
	udp->checksum = sum;
    }
  else
    l3_len = ip4_header_bytes (ip4);

  if (is_ip4)
    {
      ip4->checksum = 0;
      cmd->ip_type =
	(oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM) ? ICE_TX_IP_TYPE_IPV4_CKSUM : ICE_TX_IP_TYPE_IPV4;
    }
  else
    cmd->ip_type = ICE_TX_IP_TYPE_IPV6;

  cmd->mac_length = l2_len / ICE_TX_MAC_LENGTH_UNIT;
  cmd->ip_length = l3_len / ICE_TX_IP_LENGTH_UNIT;
}

static_always_inline void
ice_tx_wr_desc (ice_txq_t *iq, u16 slot, uword addr, ice_tx_cmd_t cmd, u16 buffer_size, u32 bi)
{
  cmd.buffer_size = buffer_size;

  ice_tx_desc_t d = {
    .buf_addr = addr,
    .cmd = cmd,
  };

  iq->descs[slot].as_vec128.as_u64x2 = d.as_vec128.as_u64x2;
  iq->buffer_indices[slot] = bi;
}

static_always_inline void
ice_tx_wr_ctx_desc (vlib_main_t *vm, ice_txq_t *iq, u16 slot, vlib_buffer_t *b, u32 bi)
{
  u16 l4_hdr_sz;
  u32 tso_len;
  ice_tx_ctx_desc_t d;

  l4_hdr_sz = vnet_buffer (b)->l4_hdr_offset - b->current_data + vnet_buffer2 (b)->gso_l4_hdr_sz;
  tso_len = vlib_buffer_length_in_chain (vm, b) - l4_hdr_sz;

  d = (ice_tx_ctx_desc_t) {
    .tunnel_params = 0,
    .cmd = {
      .descriptor_type = ICE_TX_DESC_TYPE_CTX,
      .tso = 1,
      .tso_len = tso_len,
      .mss = vnet_buffer2 (b)->gso_size,
    },
  };

  /* the head buffer's own index is reused here and at the data descriptor
   * below it writes; ref_count accounts for the extra ring slot so reclaim
   * frees it only once both slots have been retired */
  iq->descs[slot].as_vec128 = d.as_vec128;
  iq->buffer_indices[slot] = bi;
  b->ref_count++;
}

static_always_inline void
ice_tx_wr_desc4 (ice_txq_t *iq, u16 slot, u16 mask, vlib_buffer_t *bp[4], uword dma[4], u32 bi[4])
{
  ice_tx_desc4_t d = {
    .desc[0].cmd = { .end_of_packet = 1, .reserved_command = 1 },
    .desc[1].cmd = { .end_of_packet = 1, .reserved_command = 1 },
    .desc[2].cmd = { .end_of_packet = 1, .reserved_command = 1 },
    .desc[3].cmd = { .end_of_packet = 1, .reserved_command = 1 },
  };

  ASSERT (bp[0]->current_length < ICE_TX_DESC_MAX_BUFFER_SIZE);
  ASSERT (bp[1]->current_length < ICE_TX_DESC_MAX_BUFFER_SIZE);
  ASSERT (bp[2]->current_length < ICE_TX_DESC_MAX_BUFFER_SIZE);
  ASSERT (bp[3]->current_length < ICE_TX_DESC_MAX_BUFFER_SIZE);

#if defined(CLIB_HAVE_VEC512)
  vec512_t addr = {};
  vec512_t cmd = {};

  addr.as_u64x4[0] = *(u64x4u *) dma;
  u64x4 cd4 = {
    bp[0]->current_data,
    bp[1]->current_data,
    bp[2]->current_data,
    bp[3]->current_data,
  };
  addr.as_u64x4[0] += cd4;

  cmd.as_u64x4[0] = (u64x4) {
    bp[0]->current_length,
    bp[1]->current_length,
    bp[2]->current_length,
    bp[3]->current_length,
  };
  cmd.as_u64x4[0] <<= ICE_TX_BUFFER_SIZE_SHIFT;

  d.as_vec512.as_u64x8 |= u64x8_shuffle2 (addr.as_u64x8, cmd.as_u64x8, 0, 8, 1, 9, 2, 10, 3, 11);
#elif defined(CLIB_HAVE_VEC256)
  u64x4 addr4 = *(u64x4u *) dma;
  u64x4 cd4 = {
    bp[0]->current_data,
    bp[1]->current_data,
    bp[2]->current_data,
    bp[3]->current_data,
  };
  u64x4 cmd4 = {
    bp[0]->current_length,
    bp[1]->current_length,
    bp[2]->current_length,
    bp[3]->current_length,
  };

  addr4 += cd4;
  cmd4 <<= ICE_TX_BUFFER_SIZE_SHIFT;

  d.as_vec512.as_u64x4[0] += u64x4_shuffle2 (addr4, cmd4, 0, 4, 1, 5);
  d.as_vec512.as_u64x4[1] += u64x4_shuffle2 (addr4, cmd4, 2, 6, 3, 7);
#elif defined(CLIB_HAVE_VEC128)
  /* one descriptor is exactly one u64x2 (buf_addr, cmd) - no cross-descriptor
   * packing is possible at this width, so build and OR in each one directly */
  d.as_vec512.as_u64x2[0] |= (u64x2) {
    dma[0] + bp[0]->current_data,
    (u64) bp[0]->current_length << ICE_TX_BUFFER_SIZE_SHIFT,
  };
  d.as_vec512.as_u64x2[1] |= (u64x2) {
    dma[1] + bp[1]->current_data,
    (u64) bp[1]->current_length << ICE_TX_BUFFER_SIZE_SHIFT,
  };
  d.as_vec512.as_u64x2[2] |= (u64x2) {
    dma[2] + bp[2]->current_data,
    (u64) bp[2]->current_length << ICE_TX_BUFFER_SIZE_SHIFT,
  };
  d.as_vec512.as_u64x2[3] |= (u64x2) {
    dma[3] + bp[3]->current_data,
    (u64) bp[3]->current_length << ICE_TX_BUFFER_SIZE_SHIFT,
  };
#else
  for (u16 i = 0; i < 4; i++)
    {
      d.desc[i].buf_addr = dma[i] + bp[i]->current_data;
      d.desc[i].cmd.buffer_size = bp[i]->current_length;
    }
#endif

  if (PREDICT_FALSE (slot + 3 > mask))
    {
      for (u16 i = 0; i < 4; i++)
	{
	  u16 s = (slot + i) & mask;
	  iq->descs[s].as_vec128.as_u64x2 = d.desc[i].as_vec128.as_u64x2;
	  iq->buffer_indices[s] = bi[i];
	}

      return;
    }

  *(u64x8u *) (iq->descs + slot) = d.as_vec512.as_u64x8;
  vlib_buffer_copy_indices (iq->buffer_indices + slot, bi, 4);
}

static_always_inline u32
ice_tx_reclaim (vlib_main_t *vm, ice_txq_t *iq, u16 txq_size, u16 mask, u32 head)
{
  i32 complete_slot = -1;
  u16 *slot = clib_ring_get_first (iq->rs_slots);

  if (PREDICT_TRUE (slot == 0))
    return head;

  while (slot)
    {
      ice_tx_cmd_t cmd;

      cmd.as_u64 = __atomic_load_n (&iq->descs[slot[0]].cmd.as_u64, __ATOMIC_ACQUIRE);

      if (cmd.descriptor_type != ICE_TX_DESC_TYPE_DONE)
	break;

      complete_slot = slot[0];
      clib_ring_deq (iq->rs_slots);
      slot = clib_ring_get_first (iq->rs_slots);
    }

  if (complete_slot >= 0)
    {
      u16 first = head & mask;
      u16 n_done = (complete_slot + 1 - first) & mask;

      vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, first, txq_size, n_done);
      head += n_done;
    }

  return head;
}

VNET_DEV_NODE_FN (ice_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_t *dev = txq->port->dev;
  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
  u32 *from = vlib_frame_vector_args (frame);
  u32 *from0 = from;
  u32 n_left = frame->n_vectors;
  u16 mask = txq->size - 1;
  u16 n_retry = 2;
  u32 head, tail, tail_start, n_left_start;
  u16 n_free;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE + 4];
  vlib_buffer_t **bp = bufs;
  uword dma_addrs[VLIB_FRAME_SIZE];
  uword *dma = dma_addrs;
  u32 drop_bi[VLIB_FRAME_SIZE];
  u32 n_drop = 0;
  u32 n_chain_too_long = 0;

  vlib_get_buffers (vm, from, bufs, n_left);
  bp[n_left] = bp[n_left + 1] = bp[n_left + 2] = bp[n_left + 3] = bp[n_left - 1];

  vnet_dev_va_to_iova (dev, (void **) dma_addrs, (void **) bufs, n_left,
		       STRUCT_OFFSET_OF (vlib_buffer_t, data));

  vnet_dev_tx_queue_lock_if_needed (txq);
  head = iq->head;
  tail = iq->tail;

retry:
  head = ice_tx_reclaim (vm, iq, txq->size, mask, head);

  tail_start = tail;
  n_left_start = n_left;
  n_free = txq->size - 1 - (tail - head);

  while (n_left && n_free)
    {
      u32 bi;
      vlib_buffer_t *b, *cb;
      ice_tx_cmd_t cmd;
      u32 tail_indices[ICE_TX_MAX_TAIL_LEN];
      uword tail_data[ICE_TX_MAX_TAIL_LEN];
      u16 tail_cl[ICE_TX_MAX_TAIL_LEN];
      u16 n_tail, n_desc, slot, max_tail;
      u8 is_gso;

      if (PREDICT_TRUE (n_left >= 4 && n_free >= 4))
	{
	  u32 or_flags = bp[0]->flags | bp[1]->flags | bp[2]->flags | bp[3]->flags;

	  vlib_prefetch_buffer_header (bp[4], LOAD);
	  vlib_prefetch_buffer_header (bp[5], LOAD);
	  vlib_prefetch_buffer_header (bp[6], LOAD);
	  vlib_prefetch_buffer_header (bp[7], LOAD);

	  if (PREDICT_TRUE ((or_flags & (VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_OFFLOAD |
					 VNET_BUFFER_F_GSO)) == 0))
	    {
	      u16 slot = tail & mask;

	      ice_tx_wr_desc4 (iq, slot, mask, bp, dma, from);

	      tail += 4;
	      from += 4;
	      bp += 4;
	      dma += 4;
	      n_left -= 4;
	      n_free -= 4;
	      continue;
	    }
	}

      /* slow path: chained buffers, checksum offload and/or gso, one packet at a time */
      bi = from[0];
      b = bp[0];
      cb = b;
      is_gso = (b->flags & VNET_BUFFER_F_GSO) != 0;
      max_tail = is_gso ? ICE_TX_MAX_TAIL_LEN : ICE_TX_DESC_MAX_CHAIN_LENGTH - 1;
      cmd = (ice_tx_cmd_t) {
	.reserved_command = 1,
      };
      n_tail = 0;

      while (cb->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  u32 next_bi = cb->next_buffer;

	  if (PREDICT_FALSE (n_tail >= max_tail))
	    {
	      b->error = node->errors[ICE_TX_NODE_CTR_CHAIN_TOO_LONG];
	      n_chain_too_long++;
	      drop_bi[n_drop++] = bi;
	      goto next;
	    }

	  cb = vlib_get_buffer (vm, next_bi);
	  tail_indices[n_tail] = next_bi;
	  tail_data[n_tail] = (uword) vlib_buffer_get_current (cb);
	  tail_cl[n_tail] = cb->current_length;
	  n_tail++;
	}

      n_desc = n_tail + 1 + is_gso;

      if (PREDICT_FALSE (n_desc > n_free))
	break;

      ice_tx_prepare_offload (b, &cmd, is_gso);

      if (is_gso)
	{
	  slot = tail & mask;
	  ice_tx_wr_ctx_desc (vm, iq, slot, b, bi);
	  tail++;
	  n_free--;
	}

      slot = tail & mask;
      cmd.end_of_packet = (n_tail == 0);
      ice_tx_wr_desc (iq, slot, dma[0] + b->current_data, cmd, b->current_length, bi);

      tail++;
      n_free--;

      for (u16 i = 0; i < n_tail; i++)
	{
	  uword dma_addr = vnet_dev_get_dma_addr (vm, dev, (void *) tail_data[i]);

	  slot = tail & mask;
	  cmd.end_of_packet = (i == n_tail - 1);
	  ice_tx_wr_desc (iq, slot, dma_addr, cmd, tail_cl[i], tail_indices[i]);

	  tail++;
	  n_free--;
	}

    next:
      from++;
      bp++;
      dma++;
      n_left--;
    }

  if (tail != tail_start)
    {
      /* set checkpoint */
      u16 last_slot = (tail - 1) & mask;
      u16 *rs_slot = clib_ring_enq (iq->rs_slots);

      if (PREDICT_FALSE (!rs_slot))
	rs_slot = clib_ring_get_last (iq->rs_slots);

      iq->descs[last_slot].cmd.report_status = 1;
      rs_slot[0] = last_slot;
    }

  /* packet tracing */
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      u32 pos = tail_start;
      u32 leftover_start = from - from0;
      u32 trace_end = leftover_start;

      if (!n_left || !n_retry)
	trace_end = frame->n_vectors;

      for (u32 i = frame->n_vectors - n_left_start; i < trace_end; i++)
	{
	  vlib_buffer_t *b = bufs[i];
	  u16 start_slot = pos & mask;
	  u16 n_desc = 0;
	  u32 data_pos = pos;

	  if (data_pos != tail &&
	      iq->descs[data_pos & mask].cmd.descriptor_type == ICE_TX_DESC_TYPE_CTX)
	    data_pos++;

	  if (data_pos != tail && iq->buffer_indices[data_pos & mask] == from0[i])
	    {
	      while (1)
		{
		  ice_tx_cmd_t c = iq->descs[pos & mask].cmd;
		  n_desc++;
		  pos++;

		  if (c.descriptor_type == ICE_TX_DESC_TYPE_DATA && c.end_of_packet)
		    break;
		}
	    }

	  if (b->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      u16 trace_size = sizeof (ice_tx_trace_t) + n_desc * sizeof (ice_tx_desc_t);
	      ice_tx_trace_t *tr = vlib_add_trace (vm, node, b, trace_size);

	      tr->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
	      tr->buffer_index = from0[i];
	      tr->queue_id = txq->queue_id;
	      tr->n_descs = n_desc;

	      if (n_desc == 0 && i >= leftover_start)
		tr->error = node->errors[ICE_TX_NODE_CTR_NO_FREE_SLOTS];
	      else
		tr->error = b->error;

	      for (u16 j = 0; j < n_desc; j++)
		tr->descs[j] = iq->descs[(start_slot + j) & mask];
	    }
	}
    }

  if (tail != head)
    __atomic_store_n (iq->tail_reg, tail & mask, __ATOMIC_RELEASE);

  if (n_left && n_retry--)
    goto retry;

  iq->head = head;
  iq->tail = tail;
  vnet_dev_tx_queue_unlock_if_needed (txq);

  if (n_drop)
    vlib_buffer_free (vm, drop_bi, n_drop);

  if (n_chain_too_long)
    vlib_error_count (vm, node->node_index, ICE_TX_NODE_CTR_CHAIN_TOO_LONG, n_chain_too_long);

  if (n_left)
    {
      vlib_buffer_free (vm, from, n_left);
      vlib_error_count (vm, node->node_index, ICE_TX_NODE_CTR_NO_FREE_SLOTS, n_left);
    }

  /* coverity[return_overflow] - n_left never exceeds frame->n_vectors */
  return frame->n_vectors - n_left;
}
