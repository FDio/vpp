/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <dev_octeon/octeon.h>
#include <dev_octeon/hw_defs.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 hw_if_index;
  u32 trace_count;
  u32 n_traced;
  oct_nix_rx_cqe_desc_t *next_desc;
  u64 parse_w0_or;
  u32 n_left_to_next;
  u32 *to_next;
  u32 n_rx_pkts;
  u32 n_rx_bytes;
  u32 n_segs;
} oct_rx_node_ctx_t;

static_always_inline vlib_buffer_t *
oct_seg_to_bp (void *p)
{
  return (vlib_buffer_t *) p - 1;
}

static_always_inline void
oct_rx_attach_tail (vlib_main_t *vm, oct_rx_node_ctx_t *ctx, vlib_buffer_t *h,
		    oct_nix_rx_cqe_desc_t *d)
{
  u32 tail_sz = 0, n_tail_segs = 0;
  vlib_buffer_t *p, *b;
  u8 segs0 = d->sg0.segs, segs1 = 0;

  if (segs0 < 2)
    return;

  b = oct_seg_to_bp (d->segs0[1]);
  h->next_buffer = vlib_get_buffer_index (vm, b);
  tail_sz += b->current_length = d->sg0.seg2_size;
  n_tail_segs++;

  if (segs0 == 2)
    goto done;

  p = b;
  p->flags = VLIB_BUFFER_NEXT_PRESENT;
  b = oct_seg_to_bp (d->segs0[2]);
  p->next_buffer = vlib_get_buffer_index (vm, b);
  tail_sz += b->current_length = d->sg0.seg3_size;
  n_tail_segs++;

  if (d->sg1.subdc != NIX_SUBDC_SG)
    goto done;

  segs1 = d->sg1.segs;
  if (segs1 == 0)
    goto done;

  p = b;
  p->flags = VLIB_BUFFER_NEXT_PRESENT;
  b = oct_seg_to_bp (d->segs1[0]);
  p->next_buffer = vlib_get_buffer_index (vm, b);
  tail_sz += b->current_length = d->sg1.seg1_size;
  n_tail_segs++;

  if (segs1 == 1)
    goto done;

  p = b;
  p->flags = VLIB_BUFFER_NEXT_PRESENT;
  b = oct_seg_to_bp (d->segs1[1]);
  p->next_buffer = vlib_get_buffer_index (vm, b);
  tail_sz += b->current_length = d->sg1.seg2_size;
  n_tail_segs++;

  if (segs1 == 2)
    goto done;

  p = b;
  p->flags = VLIB_BUFFER_NEXT_PRESENT;
  b = oct_seg_to_bp (d->segs1[2]);
  p->next_buffer = vlib_get_buffer_index (vm, b);
  tail_sz += b->current_length = d->sg1.seg3_size;
  n_tail_segs++;

done:
  b->flags = 0;
  h->total_length_not_including_first_buffer = tail_sz;
  h->flags |= VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID;
  ctx->n_rx_bytes += tail_sz;
  ctx->n_segs += n_tail_segs;
}

static_always_inline u32
oct_rx_batch (vlib_main_t *vm, oct_rx_node_ctx_t *ctx,
	      vnet_dev_rx_queue_t *rxq, u32 n)
{
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 b0_err_flags = 0, b1_err_flags = 0;
  u32 b2_err_flags = 0, b3_err_flags = 0;
  u32 n_left, err_flags = 0;
  oct_nix_rx_cqe_desc_t *d = ctx->next_desc;
  vlib_buffer_t *b[4];

  for (n_left = n; n_left >= 8; d += 4, n_left -= 4, ctx->to_next += 4)
    {
      u32 segs = 0;
      clib_prefetch_store (oct_seg_to_bp (d[4].segs0[0]));
      clib_prefetch_store (oct_seg_to_bp (d[5].segs0[0]));
      b[0] = oct_seg_to_bp (d[0].segs0[0]);
      clib_prefetch_store (oct_seg_to_bp (d[6].segs0[0]));
      b[1] = oct_seg_to_bp (d[1].segs0[0]);
      clib_prefetch_store (oct_seg_to_bp (d[7].segs0[0]));
      b[2] = oct_seg_to_bp (d[2].segs0[0]);
      b[3] = oct_seg_to_bp (d[3].segs0[0]);
      ctx->to_next[0] = vlib_get_buffer_index (vm, b[0]);
      ctx->to_next[1] = vlib_get_buffer_index (vm, b[1]);
      ctx->to_next[2] = vlib_get_buffer_index (vm, b[2]);
      ctx->to_next[3] = vlib_get_buffer_index (vm, b[3]);
      b[0]->template = bt;
      b[1]->template = bt;
      b[2]->template = bt;
      b[3]->template = bt;
      ctx->n_rx_bytes += b[0]->current_length = d[0].sg0.seg1_size;
      ctx->n_rx_bytes += b[1]->current_length = d[1].sg0.seg1_size;
      ctx->n_rx_bytes += b[2]->current_length = d[2].sg0.seg1_size;
      ctx->n_rx_bytes += b[3]->current_length = d[3].sg0.seg1_size;
      b[0]->flow_id = d[0].parse.w[3] >> 48;
      b[1]->flow_id = d[1].parse.w[3] >> 48;
      b[2]->flow_id = d[2].parse.w[3] >> 48;
      b[3]->flow_id = d[3].parse.w[3] >> 48;
      ctx->n_segs += 4;
      segs = d[0].sg0.segs + d[1].sg0.segs + d[2].sg0.segs + d[3].sg0.segs;

      if (PREDICT_FALSE (segs > 4))
	{
	  oct_rx_attach_tail (vm, ctx, b[0], d + 0);
	  oct_rx_attach_tail (vm, ctx, b[1], d + 1);
	  oct_rx_attach_tail (vm, ctx, b[2], d + 2);
	  oct_rx_attach_tail (vm, ctx, b[3], d + 3);
	}

      b0_err_flags = (d[0].parse.w[0] >> 20) & 0xFFF;
      b1_err_flags = (d[1].parse.w[0] >> 20) & 0xFFF;
      b2_err_flags = (d[2].parse.w[0] >> 20) & 0xFFF;
      b3_err_flags = (d[3].parse.w[0] >> 20) & 0xFFF;

      err_flags |= b0_err_flags | b1_err_flags | b2_err_flags | b3_err_flags;
    }

  for (; n_left; d += 1, n_left -= 1, ctx->to_next += 1)
    {
      b[0] = (vlib_buffer_t *) d->segs0[0] - 1;
      ctx->to_next[0] = vlib_get_buffer_index (vm, b[0]);
      b[0]->template = bt;
      ctx->n_rx_bytes += b[0]->current_length = d[0].sg0.seg1_size;
      b[0]->flow_id = d[0].parse.w[3] >> 48;
      ctx->n_segs += 1;
      if (d[0].sg0.segs > 1)
	oct_rx_attach_tail (vm, ctx, b[0], d + 0);

      err_flags |= ((d[0].parse.w[0] >> 20) & 0xFFF);
    }

  plt_write64 ((crq->cq.wdata | n), crq->cq.door);
  ctx->n_rx_pkts += n;
  ctx->n_left_to_next -= n;
  if (err_flags)
    ctx->parse_w0_or = (err_flags << 20);

  return n;
}

#ifdef PLATFORM_OCTEON9
static_always_inline u32
oct_rxq_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u16 n_refill)
{
  u32 n_alloc, n_free;
  u32 buffer_indices[n_refill];
  vlib_buffer_t *buffers[n_refill];
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  u64 aura = roc_npa_aura_handle_to_aura (crq->aura_handle);
  const uint64_t addr =
    roc_npa_aura_handle_to_base (crq->aura_handle) + NPA_LF_AURA_OP_FREE0;

  if (n_refill < 256)
    return 0;

  n_alloc = vlib_buffer_alloc (vm, buffer_indices, n_refill);
  if (PREDICT_FALSE (n_alloc < n_refill))
    goto alloc_fail;

  vlib_get_buffers (vm, buffer_indices, (vlib_buffer_t **) buffers, n_alloc);

  for (n_free = 0; n_free < n_alloc; n_free++)
    roc_store_pair ((u64) buffers[n_free], aura, addr);

  return n_alloc;

alloc_fail:
  vlib_buffer_unalloc_to_pool (vm, buffer_indices, n_alloc, bpi);
  return 0;
}
#else
static_always_inline void
oct_rxq_refill_batch (vlib_main_t *vm, u64 lmt_id, u64 addr,
		      oct_npa_lf_aura_batch_free_line_t *lines, u32 *bi,
		      oct_npa_lf_aura_batch_free0_t w0, u64 n_lines)
{
  u64 data;

  for (u32 i = 0; i < n_lines; i++, bi += 15)
    {
      lines[i].w0 = w0;
      vlib_get_buffers (vm, bi, (vlib_buffer_t **) lines[i].data, 15);
    }

  data = lmt_id | ((n_lines - 1) << 12) | ((1ULL << (n_lines * 3)) - 1) << 19;
  roc_lmt_submit_steorl (data, addr);

  /* Data Store Memory Barrier - outer shareable domain */
  asm volatile("dmb oshst" ::: "memory");
}

static_always_inline u32
oct_rxq_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u16 n_refill)
{
  const u32 batch_max_lines = 16;
  const u32 bufs_per_line = 15;
  const u32 batch_max_bufs = 15 * 16;

  u32 batch_bufs, n_lines, n_alloc;
  u32 buffer_indices[batch_max_bufs];
  u64 lmt_addr, lmt_id, addr, n_enq = 0;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  oct_npa_lf_aura_batch_free_line_t *lines;

  if (n_refill < bufs_per_line)
    return 0;

  n_lines = n_refill / bufs_per_line;

  addr = crq->aura_batch_free_ioaddr;
  lmt_addr = crq->lmt_base_addr;
  lmt_id = vm->thread_index << ROC_LMT_LINES_PER_CORE_LOG2;
  lmt_addr += lmt_id << ROC_LMT_LINE_SIZE_LOG2;
  lines = (oct_npa_lf_aura_batch_free_line_t *) lmt_addr;

  oct_npa_lf_aura_batch_free0_t w0 = {
    .aura = roc_npa_aura_handle_to_aura (crq->aura_handle),
    .count_eot = 1,
  };

  while (n_lines >= batch_max_lines)
    {
      n_alloc =
	vlib_buffer_alloc_from_pool (vm, buffer_indices, batch_max_bufs, bpi);
      if (PREDICT_FALSE (n_alloc < batch_max_bufs))
	goto alloc_fail;
      oct_rxq_refill_batch (vm, lmt_id, addr, lines, buffer_indices, w0,
			    batch_max_lines);
      n_lines -= batch_max_lines;
      n_enq += batch_max_bufs;
    }

  if (n_lines == 0)
    return n_enq;

  batch_bufs = n_lines * bufs_per_line;
  n_alloc = vlib_buffer_alloc_from_pool (vm, buffer_indices, batch_bufs, bpi);

  if (PREDICT_FALSE (n_alloc < batch_bufs))
    {
    alloc_fail:
      if (n_alloc >= bufs_per_line)
	{
	  u32 n_unalloc;
	  n_lines = n_alloc / bufs_per_line;
	  batch_bufs = n_lines * bufs_per_line;
	  n_unalloc = n_alloc - batch_bufs;

	  if (n_unalloc)
	    vlib_buffer_unalloc_to_pool (vm, buffer_indices + batch_bufs,
					 n_unalloc, bpi);
	}
      else
	{
	  if (n_alloc)
	    vlib_buffer_unalloc_to_pool (vm, buffer_indices, n_alloc, bpi);
	  return n_enq;
	}
    }

  oct_rxq_refill_batch (vm, lmt_id, addr, lines, buffer_indices, w0, n_lines);
  n_enq += batch_bufs;

  return n_enq;
}
#endif

static_always_inline void
oct_rx_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
	      oct_rx_node_ctx_t *ctx, oct_nix_rx_cqe_desc_t *d, u32 n_desc)
{
  u32 i = 0;
  if (PREDICT_TRUE (ctx->trace_count == 0))
    return;

  while (ctx->n_traced < ctx->trace_count && i < n_desc)
    {
      vlib_buffer_t *b = (vlib_buffer_t *) d[i].segs0[0] - 1;

      if (PREDICT_TRUE (vlib_trace_buffer (vm, node, ctx->next_index, b,
					   /* follow_chain */ 0)))
	{
	  oct_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->next_index = ctx->next_index;
	  tr->sw_if_index = ctx->sw_if_index;
	  tr->desc = d[i];
	  ctx->n_traced++;
	}
      i++;
    }
}

static_always_inline uword
oct_rx_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, vnet_dev_port_t *port,
		    vnet_dev_rx_queue_t *rxq, int with_flows)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 thr_idx = vlib_get_thread_index ();
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  u32 n_desc, head, n, n_enq;
  u32 cq_size = crq->cq.nb_desc;
  u32 cq_mask = crq->cq.qmask;
  oct_nix_rx_cqe_desc_t *descs = crq->cq.desc_base;
  oct_nix_lf_cq_op_status_t status;
  oct_rx_node_ctx_t _ctx = {
    .next_index = vnet_dev_get_rx_queue_if_next_index(rxq),
    .sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq),
    .hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq),
  }, *ctx = &_ctx;

  /* get head and tail from NIX_LF_CQ_OP_STATUS */
  status.as_u64 = roc_atomic64_add_sync (crq->cq.wdata, crq->cq.status);
  if (status.cq_err || status.op_err)
    return 0;

  head = status.head;
  n_desc = (status.tail - head) & cq_mask;

  if (n_desc == 0)
    goto refill;

  vlib_get_new_next_frame (vm, node, ctx->next_index, ctx->to_next,
			   ctx->n_left_to_next);

  ctx->trace_count = vlib_get_trace_count (vm, node);

  while (1)
    {
      ctx->next_desc = descs + head;
      n = clib_min (cq_size - head, clib_min (n_desc, ctx->n_left_to_next));
      n = oct_rx_batch (vm, ctx, rxq, n);
      oct_rx_trace (vm, node, ctx, descs + head, n);

      if (ctx->n_left_to_next == 0)
	break;

      status.as_u64 = roc_atomic64_add_sync (crq->cq.wdata, crq->cq.status);
      if (status.cq_err || status.op_err)
	break;

      head = status.head;
      n_desc = (status.tail - head) & cq_mask;
      if (n_desc == 0)
	break;
    }

  if (ctx->n_traced)
    vlib_set_trace_count (vm, node, ctx->trace_count - ctx->n_traced);

  if (PREDICT_TRUE (ctx->next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      ethernet_input_frame_t *ef;
      oct_nix_rx_parse_t p = { .w[0] = ctx->parse_w0_or };
      nf = vlib_node_runtime_get_next_frame (vm, node, ctx->next_index);
      f = vlib_get_frame (vm, nf->frame);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = ctx->sw_if_index;
      ef->hw_if_index = ctx->hw_if_index;

      if (p.f.errcode == 0 && p.f.errlev == 0)
	f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;

      vlib_frame_no_append (f);
    }

  vlib_put_next_frame (vm, node, ctx->next_index, ctx->n_left_to_next);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    thr_idx, ctx->hw_if_index, ctx->n_rx_pkts, ctx->n_rx_bytes);

refill:
  n_enq = crq->n_enq - ctx->n_segs;
  n_enq += oct_rxq_refill (vm, rxq, rxq->size - n_enq);
  crq->n_enq = n_enq;

  return ctx->n_rx_pkts;
}

VNET_DEV_NODE_FN (oct_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      vnet_dev_port_t *port = rxq->port;

      if (!rxq->started)
	continue;

      n_rx += oct_rx_node_inline (vm, node, frame, port, rxq, 0);
    }

  return n_rx;
}
