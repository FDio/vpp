/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <dev_cnxk/cnxk.h>

#define BATCH_SZ 32

typedef union
{
  struct
  {
    u64 tail : 20;
    u64 head : 20;
    u64 resv40 : 6;
    u64 cq_err : 1;
    u64 resv47 : 16;
    u64 op_err : 1;
  };
  u64 as_u64;
} cnxk_nix_lf_cq_op_status_t;

STATIC_ASSERT_SIZEOF (cnxk_nix_lf_cq_op_status_t, 8);

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 hw_if_index;
  u32 trace_count;
  u32 n_traced;
  cnxk_nix_rx_cqe_desc_t *next_desc;
  u64 parse_w0_or;
  u32 n_left_to_next;
  u32 *to_next;
  u32 n_rx_pkts;
  u32 n_rx_bytes;
  u32 n_segs;
  u64 aura;
  u64 reg;
  u64 aura_op_free0_addr;
} cnxk_rx_node_ctx_t;

static_always_inline u32
cnxk_rx_batch (vlib_main_t *vm, cnxk_rx_node_ctx_t *ctx,
	       vnet_dev_rx_queue_t *rxq, u32 n)
{
  cnxk_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = rxq->buffer_template;
  u32 n_dequeued = 0, n_consumed = 0;
  cnxk_nix_rx_cqe_desc_t *d = ctx->next_desc;

  while (n)
    {
      u16 sz;

      vlib_buffer_t *b = (vlib_buffer_t *) d->segs0[0] - 1;
      ctx->to_next++[0] = vlib_get_buffer_index (vm, b);
      sz = d->sg0.seg1_size;
      b->template = bt;
      b->current_length = sz; // d->parse.pkt_lenm1 + 1;
      ctx->n_segs += d->sg0.segs;
      ctx->n_rx_bytes += sz;

      d++;
      n_consumed++;
      n_dequeued++;
      n--;
    }

  plt_write64 ((crq->cq.wdata | n_consumed), crq->cq.door);
  ctx->n_rx_pkts += n_dequeued;
  ctx->n_left_to_next -= n_dequeued;
  return n_dequeued;
}

static_always_inline u32
cnxk_alloc_buffers (vlib_main_t *vm, cnxk_rx_node_ctx_t *ctx, u8 bpi,
		    u16 n_buffers)
{
  u32 buffer_indices[64];
  vlib_buffer_t *b[64];
  u64 reg = ctx->reg;
  u64 addr = ctx->aura_op_free0_addr;
  u32 n;

  n = vlib_buffer_alloc_from_pool (vm, buffer_indices, n_buffers, bpi);
  if (PREDICT_FALSE (n < n_buffers))
    {
      vlib_get_buffers (vm, buffer_indices, b, n);

      for (u32 i = 0; i < n; i++)
	roc_store_pair (pointer_to_uword (b[i]), reg, addr);
      return n;
    }

  vlib_get_buffers (vm, buffer_indices, b, n_buffers);

  for (u32 i = 0; i < n_buffers; i++)
    roc_store_pair (pointer_to_uword (b[i]), reg, addr);

  return n_buffers;
}

static_always_inline void
cnxk_rx_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
	       cnxk_rx_node_ctx_t *ctx, cnxk_nix_rx_cqe_desc_t *d, u32 n_desc)
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
	  cnxk_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->next_index = ctx->next_index;
	  tr->sw_if_index = ctx->sw_if_index;
	  tr->desc = d[i];
	  ctx->n_traced++;
	}
      i++;
    }
}

static_always_inline uword
cnxk_rx_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, vnet_dev_port_t *port,
		     vnet_dev_rx_queue_t *rxq, int with_flows)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 thr_idx = vlib_get_thread_index ();
  cnxk_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  u32 n_desc, head, n, n_enq, sz = rxq->size;
  u32 cq_size = crq->cq.nb_desc;
  u32 cq_mask = crq->cq.qmask;
  cnxk_nix_rx_cqe_desc_t *descs = crq->cq.desc_base;
  cnxk_nix_lf_cq_op_status_t status;
  cnxk_rx_node_ctx_t _ctx = {
    .next_index = rxq->next_index,
    .sw_if_index = port->intf.sw_if_index,
    .hw_if_index = port->intf.hw_if_index,
  }, *ctx = &_ctx;

  /* get head and tail from NIX_LF_CQ_OP_STATUS */
  status.as_u64 = roc_atomic64_add_sync (crq->cq.wdata, crq->cq.status);
  if (status.cq_err || status.cq_err)
    return 0;

  head = status.head;
  n_desc = (status.tail - head) & cq_mask;

  if (n_desc == 0)
    return 0;

  vlib_get_new_next_frame (vm, node, ctx->next_index, ctx->to_next,
			   ctx->n_left_to_next);

  ctx->trace_count = vlib_get_trace_count (vm, node);

  while (1)
    {
      ctx->next_desc = descs + head;
      n = clib_min (cq_size - head, clib_min (n_desc, ctx->n_left_to_next));
      n = cnxk_rx_batch (vm, ctx, rxq, n);
      cnxk_rx_trace (vm, node, ctx, descs + head, n);

      if (ctx->n_left_to_next == 0)
	break;

      status.as_u64 = roc_atomic64_add_sync (crq->cq.wdata, crq->cq.status);
      if (status.cq_err || status.cq_err)
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
      cnxk_nix_rx_parse_t p = { .w[0] = ctx->parse_w0_or };
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

  n_enq = crq->n_enq - ctx->n_segs;

  if (n_enq + 16 < rxq->size)
    {
      u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
      u64 aura_handle = crq->aura_handle;
      ctx->reg = roc_npa_aura_handle_to_aura (aura_handle);
      ctx->aura_op_free0_addr =
	roc_npa_aura_handle_to_base (aura_handle) + NPA_LF_AURA_OP_FREE0;
      u32 n_alloc;

      for (n_alloc = sz - n_enq; n_alloc >= 64; n_alloc -= 64)
	{
	  n = cnxk_alloc_buffers (vm, ctx, bpi, 64);
	  n_enq += n;
	  if (n < 64)
	    break;
	}

      if (n_alloc > 0)
	n_enq += cnxk_alloc_buffers (vm, ctx, bpi, n_alloc);
    }

  crq->n_enq = n_enq;

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    thr_idx, ctx->hw_if_index, ctx->n_rx_pkts, ctx->n_rx_bytes);

  return ctx->n_rx_pkts;
}

VNET_DEV_NODE_FN (cnxk_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      vnet_dev_port_t *port = rxq->port;
      n_rx += cnxk_rx_node_inline (vm, node, frame, port, rxq, 0);
    }

  return n_rx;
}
