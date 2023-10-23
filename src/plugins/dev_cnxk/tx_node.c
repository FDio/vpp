/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vppinfra/vector/ip_csum.h>

#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>

#include <dev_cnxk/cnxk.h>
#include <dev_cnxk/common.h>

// APR_LMT_ARG_S
typedef struct
{
  u64 lmt_id : 11;
  u64 reserved11 : 1;
  u64 cntm1 : 4;
  u64 reserved16 : 3;
} apr_lmt_arg_s;

typedef struct
{
  struct nix_send_hdr_s hdr;
  union nix_send_sg_s sg[4];
} cnxk_sq_desc_t;

typedef union
{
  struct
  {
    union nix_send_hdr_w0_u w0;
    union nix_send_hdr_w1_u w1;
  };
  u128 as_u128;
} nix_send_hdr_t;

typedef union
{
  union nix_send_sg_s sg[2];
  u128 as_u128;
} nix_send_sg_pair_t;

#define CN10K_PKTIO_LMT_GET_LINE_ADDR(lmt_addr, lmt_num)                      \
  (void *) ((u64) (lmt_addr) + ((u64) (lmt_num) << ROC_LMT_LINE_SIZE_LOG2))

typedef struct
{
  u64 ioaddr;
  void *lmt_base_addr;
  u16 lmt_id;
} lmt_ctx_t;

static_always_inline lmt_ctx_t
lmt_ctx (u16 core, u64 ioaddr, void *lmt_addr)
{
  u16 lmt_id = core << ROC_LMT_LINES_PER_CORE_LOG2;

  return (lmt_ctx_t){
    .ioaddr = ioaddr & ~0x7fULL,
    .lmt_id = lmt_id,
    .lmt_base_addr = lmt_addr + ((u64) lmt_id << ROC_LMT_LINE_SIZE_LOG2),
  };
}

static_always_inline void
lmt_store (lmt_ctx_t ctx, const u128 *line_data, const u8 *dwords_per_line,
	   u8 n_lmt_lines)
{
  u64 lmt_arg = ctx.lmt_id;
  void *line_addr = ctx.lmt_base_addr;
  u64 io_addr = ctx.ioaddr | (*dwords_per_line - 1) << 4;

  cnxk_wmb ();
  roc_lmt_mov_seg (line_addr, line_data, *dwords_per_line);

  if (n_lmt_lines > 1)
    {
      lmt_arg |= (--n_lmt_lines) << 12;

      for (u8 bit_off = 19; n_lmt_lines; n_lmt_lines--, bit_off += 3)
	{
	  line_addr += 1ULL << ROC_LMT_LINE_SIZE_LOG2;
	  dwords_per_line++;
	  roc_lmt_mov_seg (line_addr, line_data, *dwords_per_line);
	  lmt_arg |= *dwords_per_line << bit_off;
	}
    }

  roc_lmt_submit_steorl (lmt_arg, io_addr);
}

typedef struct
{
  nix_send_hdr_t hdr;
  nix_send_sg_pair_t sgpair0;
  lmt_ctx_t lmtctx;
} cnxk_tx_ctx_t;

static_always_inline void
cnxk_enq16 (vlib_main_t *vm, cnxk_tx_ctx_t *ctx, vnet_dev_tx_queue_t *txq,
	    vlib_buffer_t **b, u32 n_pkts)
{
  u8 dwords_per_line[16];
  u128 dwords[16 * 3], *dword = dwords;
  int no_multiseg = 1;

  for (u32 i = 0, n_left = n_pkts; i < n_left; i++, b++)
    {
      nix_send_hdr_t h = ctx->hdr;
      nix_send_sg_pair_t sgpair0 = ctx->sgpair0;
      u16 len = b[0]->current_length;

      h.w0.total = len;
      sgpair0.sg[0].seg1_size = len;
      sgpair0.sg[1].u = (u64) vlib_buffer_get_current (b[0]);

      dword[0] = h.as_u128;
      dword[1] = sgpair0.as_u128;
      dwords_per_line[i] = 2;
      dword += dwords_per_line[i];

      fformat (stderr, "%u: %p\n", i, b[0]);
    }

  if (no_multiseg)
    {
      /* help comiler to optimize by passing constant array for case
       * when all packets are single segment */
      const u8 all2[16] = { 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2 };
      lmt_store (ctx->lmtctx, dwords, all2, n_pkts);
    }
  else
    lmt_store (ctx->lmtctx, dwords, dwords_per_line, n_pkts);
}

VNET_DEV_NODE_FN (cnxk_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  cnxk_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  u32 n_pkts = frame->n_vectors;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 4], **b = buffers;

  cnxk_tx_ctx_t ctx = {
    .hdr.w0 = {
      .aura = roc_npa_aura_handle_to_aura (ctq->aura_handle),
      .sq = ctq->sq.qid,
      .sizem1 = 1,
    },
    .sgpair0.sg[0] = {
      .segs = 1,
      .subdc = NIX_SUBDC_SG,
    },
    .lmtctx = lmt_ctx (vm->thread_index, ctq->sq.io_addr, ctq->sq.lmt_addr),
  };

  vlib_get_buffers (vm, vlib_frame_vector_args (frame), b, n_pkts);
  for (int i = 0; i < 4; i++)
    b[n_pkts + i] = b[n_pkts - 1];

  vnet_dev_tx_queue_lock_if_needed (txq);

  u32 avail = roc_npa_aura_op_available (ctq->aura_handle);

  if (avail > 0)
    {
      fformat (stderr, "%u: n_avail %u\n", vm->thread_index,
	       roc_npa_aura_op_available (ctq->aura_handle));
      cnxk_aura_free_buffers (vm, ctq->aura_handle, avail, ctq->hdr_off);
      fformat (stderr, "%u: n_avail %u\n", vm->thread_index,
	       roc_npa_aura_op_available (ctq->aura_handle));
    }

  while (n_pkts >= 16)
    {
      cnxk_enq16 (vm, &ctx, txq, buffers, 16);
      b += 16;
      n_pkts -= 16;
    }

  if (n_pkts)
    cnxk_enq16 (vm, &ctx, txq, buffers, n_pkts);

  vnet_dev_tx_queue_unlock_if_needed (txq);

  return n_pkts;
}
