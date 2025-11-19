/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <dpdk/dev/dpdk.h>
#include <dpdk/buffer.h>

#define DEV_DPDK_RX_BURST_SZ 64

static_always_inline uword
dev_dpdk_attach_tail (vlib_main_t *vm, struct rte_mbuf *mb, vlib_buffer_template_t bt)
{
  u8 nb_seg = 1;
  struct rte_mbuf *mb_seg = 0;
  vlib_buffer_t *b_seg, *b_chain = 0;
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);
  mb_seg = mb->next;
  b_chain = b;
  u32 tlnifb = 0;

  if (mb->nb_segs < 2)
    return 0;

  while (nb_seg < mb->nb_segs)
    {
      ASSERT (mb_seg != 0);

      b_seg = vlib_buffer_from_rte_mbuf (mb_seg);
      b_seg->template = bt;

      b_seg->current_data = (mb_seg->buf_addr + mb_seg->data_off) - (void *) b_seg->data;

      b_seg->current_length = mb_seg->data_len;
      tlnifb += mb_seg->data_len;

      b_chain->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b_chain->next_buffer = vlib_get_buffer_index (vm, b_seg);

      b_chain = b_seg;
      mb_seg = mb_seg->next;
      nb_seg++;
    }

  b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  b->total_length_not_including_first_buffer = tlnifb;
  return tlnifb;
}

static_always_inline u32
dev_dpdk_rx_inline (vlib_main_t *vm, vnet_main_t *vnm, vlib_node_runtime_t *node,
		    vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  dev_dpdk_port_t *dp = vnet_dev_get_port_data (port);
  vlib_buffer_template_t bt = rxq->if_rt_data.buffer_template;
  u32 to_next[VLIB_FRAME_SIZE];
  u16 n, i;
  u16 pid = dp->port_id, qid = rxq->queue_id;
  u32 n_left, n_rx_bytes = 0;
  u64 bit = 1, chained_bmp = 0, offload_bmp = 0;
  struct rte_mbuf *mbufs[DEV_DPDK_RX_BURST_SZ + 4], **mb = mbufs;
  const u64 offload_flags = RTE_MBUF_F_RX_LRO;
  u16 next_indices[DEV_DPDK_RX_BURST_SZ];
  u16 n_nondefault_nexts = 0;
  u16 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);

  n = rte_eth_rx_burst (pid, qid, mbufs, DEV_DPDK_RX_BURST_SZ);
  if (n == 0)
    return 0;

  if (n < DEV_DPDK_RX_BURST_SZ)
    n += rte_eth_rx_burst (pid, qid, mbufs + n, DEV_DPDK_RX_BURST_SZ - n);

  mbufs[n] = mbufs[n + 1] = mbufs[n + 2] = mbufs[n + 3] = mbufs[n - 1];

  for (n_left = n; n_left > 4; n_left -= 4, mb += 4)
    {
      vlib_buffer_t *b0 = vlib_buffer_from_rte_mbuf (mb[0]);
      vlib_buffer_t *b1 = vlib_buffer_from_rte_mbuf (mb[1]);
      vlib_buffer_t *b2 = vlib_buffer_from_rte_mbuf (mb[2]);
      vlib_buffer_t *b3 = vlib_buffer_from_rte_mbuf (mb[3]);

      b0->template = b1->template = b2->template = b3->template = bt;

      n_rx_bytes += b0->current_length = mb[0]->data_len;
      n_rx_bytes += b1->current_length = mb[1]->data_len;
      n_rx_bytes += b2->current_length = mb[2]->data_len;
      n_rx_bytes += b3->current_length = mb[3]->data_len;

      b0->current_data = (i16) (mb[0]->data_off - RTE_PKTMBUF_HEADROOM);
      b1->current_data = (i16) (mb[1]->data_off - RTE_PKTMBUF_HEADROOM);
      b2->current_data = (i16) (mb[2]->data_off - RTE_PKTMBUF_HEADROOM);
      b3->current_data = (i16) (mb[3]->data_off - RTE_PKTMBUF_HEADROOM);

      clib_prefetch_load (mb[4]);
      clib_prefetch_store (vlib_buffer_from_rte_mbuf (mb[4]));

      clib_prefetch_load (mb[5]);
      clib_prefetch_store (vlib_buffer_from_rte_mbuf (mb[5]));

      clib_prefetch_load (mb[6]);
      clib_prefetch_store (vlib_buffer_from_rte_mbuf (mb[6]));

      clib_prefetch_load (mb[7]);
      clib_prefetch_store (vlib_buffer_from_rte_mbuf (mb[7]));

      chained_bmp |= mb[0]->nb_segs > 1 ? bit : 0;
      offload_bmp |= mb[0]->ol_flags & offload_flags ? bit : 0;
      bit <<= 1;
      chained_bmp |= mb[1]->nb_segs > 1 ? bit : 0;
      offload_bmp |= mb[1]->ol_flags & offload_flags ? bit : 0;
      bit <<= 1;
      chained_bmp |= mb[2]->nb_segs > 1 ? bit : 0;
      offload_bmp |= mb[2]->ol_flags & offload_flags ? bit : 0;
      bit <<= 1;
      chained_bmp |= mb[3]->nb_segs > 1 ? bit : 0;
      offload_bmp |= mb[3]->ol_flags & offload_flags ? bit : 0;
      bit <<= 1;
    }

  for (n_left = n; n_left > 4; n_left -= 4, mb += 4)
    {
      vlib_buffer_t *b0 = vlib_buffer_from_rte_mbuf (mb[0]);

      b0->template = bt;
      n_rx_bytes += b0->current_length = mb[0]->data_len;
      b0->current_data = (i16) (mb[0]->data_off - RTE_PKTMBUF_HEADROOM);
      chained_bmp |= mb[0]->nb_segs > 1 ? bit : 0;
      offload_bmp |= mb[0]->ol_flags & offload_flags ? bit : 0;
      bit <<= 1;
    }

  if (PREDICT_FALSE (chained_bmp))
    foreach_set_bit_index (i, chained_bmp)
      n_rx_bytes += dev_dpdk_attach_tail (vm, mbufs[i], bt);

  if (PREDICT_FALSE (offload_bmp))
    foreach_set_bit_index (i, offload_bmp)
      {
	u64 ol_flags = mbufs[i]->ol_flags;
	vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mbufs[i]);

	if (PREDICT_FALSE (ol_flags & RTE_MBUF_F_RX_LRO))
	  {
	    b->flags |= VNET_BUFFER_F_GSO;
	    vnet_buffer2 (b)->gso_size = mbufs[i]->tso_segsz;
	    /* intentionally not setting gso_l4_hdr_sz here,
	     * it is not driver job to parse TCP header */
	  }

	if (PREDICT_FALSE (ol_flags & RTE_MBUF_F_RX_L4_CKSUM_BAD))
	  b->flags &= ~VNET_BUFFER_F_LOG2_L4_CHECKSUM_CORRECT;

	if (PREDICT_FALSE (ol_flags & RTE_MBUF_F_RX_FDIR))
	  {
	    dev_dpdk_flow_lookup_entry_t *fle;

	    fle = pool_elt_at_index (dp->flow_lookup_entries, mbufs[n]->hash.fdir.hi);

	    if (fle->next_index != (u16) ~0)
	      {
		if (n_nondefault_nexts++ == 0)
		  clib_memset_u16 (next_indices, next_index, 64);
		next_indices[i] = fle->next_index;
	      }

	    if (fle->flow_id != ~0)
	      b->flow_id = fle->flow_id;

	    if (fle->buffer_advance != ~0)
	      vlib_buffer_advance (b, fle->buffer_advance);
	  }
      }

  if (PREDICT_FALSE (n_nondefault_nexts))
    vlib_buffer_enqueue_to_next (vm, node, to_next, next_indices, n);
  else
    vlib_buffer_enqueue_to_single_next (vm, node, to_next, next_index, n);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX, vm->thread_index,
    vnet_dev_get_rx_queue_if_hw_if_index (rxq), n, n_rx_bytes);

  return n;
}

VNET_DEV_NODE_FN (dev_dpdk_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword n_rx_total = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    n_rx_total += dev_dpdk_rx_inline (vm, vnm, node, rxq);

  return n_rx_total;
}
