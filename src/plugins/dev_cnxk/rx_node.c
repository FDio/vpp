/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <dev_cnxk/cnxk.h>

typedef struct
{
  u32 cached_pkts;
} cnxk_fprq_t;

typedef struct
{
  CLIB_ALIGN_MARK (desc, 128);
  struct nix_cqe_hdr_s hdr;
  union nix_rx_parse_u parse;
  struct nix_rx_sg_s sg;
  void *bp;
} nix_rx_cqe_desc_t;

STATIC_ASSERT_SIZEOF (nix_rx_cqe_desc_t, 128);

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
} nix_lf_cq_op_status_t;

STATIC_ASSERT_SIZEOF (nix_lf_cq_op_status_t, 8);

static_always_inline vlib_buffer_t *
cnxk_get_vlib_buffer_from_iova (void *p)
{
  return p - sizeof (vlib_buffer_t);
}

typedef struct
{
  u32 *bi;
  u32 n_rx_pkts;
  u32 n_rx_bytes;
} cnxk_rx_node_ctx_t;

static_always_inline u32
cnxk_rx_node_no_wrap (vlib_main_t *vm, cnxk_rx_node_ctx_t *ctx,
		      vnet_dev_rx_queue_t *rxq, nix_rx_cqe_desc_t *d,
		      u32 n_left)
{
  cnxk_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = rxq->buffer_template;
  u32 n_dequeued = 0, n_consumed = 0;

  while (n_left)
    {
      fformat (stderr, "%U\n", format_hexdump_u64, d, 16);
      if (d->bp)
	fformat (stderr, "%U\n", format_hexdump, d->bp,
		 d->parse.pkt_lenm1 + 1);
      fformat (stderr, "hdr: tag %u q %u cqe_type %u node %u\n", d->hdr.tag,
	       d->hdr.q, d->hdr.cqe_type, d->hdr.node);
      fformat (
	stderr,
	"sg: segs %u subdc %u seg1sz %u seg2sz %u seg3sz %u rsvd_59_50 0x%x\n",
	d->sg.segs, d->sg.subdc, d->sg.seg1_size, d->sg.seg2_size,
	d->sg.seg3_size, d->sg.rsvd_59_50);

      vlib_buffer_t *b = cnxk_get_vlib_buffer_from_iova (d->bp);
      ctx->bi++[0] = vlib_get_buffer_index (vm, b);
      b->template = bt;
      b->current_length = d->parse.pkt_lenm1 + 1;

      d++;
      n_consumed++;
      n_dequeued++;
      n_left--;
    }

  plt_write64 ((crq->cq.wdata | n_consumed), crq->cq.door);
  return n_dequeued;
}

static_always_inline uword
cnxk_rx_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, vnet_dev_port_t *port,
		     vnet_dev_rx_queue_t *rxq, int with_flows)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 thr_idx = vlib_get_thread_index ();
  cnxk_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  u32 n_desc, head, n;
  u32 cq_size = crq->cq.nb_desc;
  u32 cq_mask = crq->cq.qmask;
  u32 *to_next, n_left_to_next;
  u32 next_index = rxq->next_index;
  u32 sw_if_index = port->intf.sw_if_index;
  u32 hw_if_index = port->intf.hw_if_index;
  nix_rx_cqe_desc_t *descs = crq->cq.desc_base;
  nix_lf_cq_op_status_t status;
  cnxk_rx_node_ctx_t _ctx = {}, *ctx = &_ctx;

  /* get head and tail from NIX_LF_CQ_OP_STATUS */
  status.as_u64 = roc_atomic64_add_sync (crq->cq.wdata, crq->cq.status);
  if (status.cq_err || status.cq_err)
    return 0;

  head = status.head;
  n_desc = (status.tail - head) & cq_mask;

  if (n_desc == 0)
    return 0;

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);
  ctx->bi = to_next;

  while (1)
    {
      n = clib_min (cq_size - head, clib_min (n_desc, n_left_to_next));
      n = cnxk_rx_node_no_wrap (vm, ctx, rxq, descs + head, n);

      n_left_to_next -= n;
      if (n_left_to_next == 0)
	break;

      status.as_u64 = roc_atomic64_add_sync (crq->cq.wdata, crq->cq.status);
      if (status.cq_err || status.cq_err)
	break;

      head = status.head;
      n_desc = (status.tail - head) & cq_mask;
      if (n_desc == 0)
	break;
    }

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      ethernet_input_frame_t *ef;
      nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      f = vlib_get_frame (vm, nf->frame);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = hw_if_index;

#if 0
      if ((or_qw1 & mask_ipe.as_u64) == 0)
	f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
#endif
      vlib_frame_no_append (f);
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    thr_idx, hw_if_index, ctx->n_rx_pkts, ctx->n_rx_bytes);

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
