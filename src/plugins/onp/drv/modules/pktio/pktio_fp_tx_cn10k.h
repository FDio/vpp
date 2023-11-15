/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_pktio_pktio_fp_tx_cn10k_h
#define included_onp_drv_modules_pktio_pktio_fp_tx_cn10k_h

#include <onp/drv/modules/pktio/pktio_tx.h>
#include <vnet/ethernet/ethernet.h>

#define CN10K_PKTIO_LMT_GET_LINE_ADDR(lmt_addr, lmt_num)                      \
  (void *) ((u64) (lmt_addr) + ((u64) (lmt_num) << ROC_LMT_LINE_SIZE_LOG2))

static_always_inline u64
cn10k_pktio_add_sg_desc (union nix_send_sg_s *sg, int n_segs,
			 vlib_buffer_t *seg1, vlib_buffer_t *seg2,
			 vlib_buffer_t *seg3)
{
  sg[0].u = 0;
  sg[0].segs = n_segs;
  sg[0].subdc = NIX_SUBDC_SG;

  switch (n_segs)
    {
    case 3:
      sg[0].seg3_size = seg3->current_length;
      sg[3].u = (u64) vlib_buffer_get_current (seg3);
      /* Fall through */
    case 2:
      sg[0].seg2_size = seg2->current_length;
      sg[2].u = (u64) vlib_buffer_get_current (seg2);
      /* Fall through */
    case 1:
      sg[0].seg1_size = seg1->current_length;
      sg[1].u = (u64) vlib_buffer_get_current (seg1);
      break;
    default:
      ASSERT (0);
      return 0;
    }

  /* Return number of dwords in sub-descriptor */
  return n_segs == 1 ? 1 : 2;
}

static_always_inline u64
cn10k_pktio_add_sg_list (union nix_send_sg_s *sg, vlib_buffer_t *b, u64 n_segs,
			 const u64 off_flags)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t *seg1, *seg2, *seg3;
  u64 n_dwords;

  if (!(off_flags & CNXK_PKTIO_TX_OFF_FLAG_MSEG))
    return cn10k_pktio_add_sg_desc (sg, 1, b, NULL, NULL);

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    return cn10k_pktio_add_sg_desc (sg, 1, b, NULL, NULL);

  seg1 = b;
  n_dwords = 0;
  while (n_segs > 2)
    {
      seg2 = vlib_get_buffer (vm, seg1->next_buffer);
      seg3 = vlib_get_buffer (vm, seg2->next_buffer);

      n_dwords += cn10k_pktio_add_sg_desc (sg, 3, seg1, seg2, seg3);

      if (seg3->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  seg1 = vlib_get_buffer (vm, seg3->next_buffer);
	  sg += 4;
	}
      n_segs -= 3;
    }

  if (n_segs == 1)
    n_dwords += cn10k_pktio_add_sg_desc (sg, 1, seg1, NULL, NULL);
  else if (n_segs == 2)
    {
      seg2 = vlib_get_buffer (vm, seg1->next_buffer);
      n_dwords += cn10k_pktio_add_sg_desc (sg, 2, seg1, seg2, NULL);
    }

  return n_dwords;
}

static_always_inline u64
cn10k_pktio_add_send_hdr (struct nix_send_hdr_s *hdr, vlib_buffer_t *b,
			  u64 aura_handle, u64 sq, u64 n_dwords,
			  const u64 off_flags)
{
  vnet_buffer_oflags_t oflags;

  hdr->w0.u = 0;
  hdr->w1.u = 0;
  hdr->w0.sq = sq;
  hdr->w0.aura = roc_npa_aura_handle_to_aura (aura_handle);
  hdr->w0.total = b->current_length;
  hdr->w0.sizem1 = n_dwords + CNXK_PKTIO_SEND_HDR_DWORDS - 1;

  if (off_flags & CNXK_PKTIO_TX_OFF_FLAG_MSEG)
    hdr->w0.total = vlib_buffer_length_in_chain (vlib_get_main (), b);

  if (!(b->flags & VNET_BUFFER_F_OFFLOAD))
    return CNXK_PKTIO_SEND_HDR_DWORDS;

  if (off_flags & CNXK_PKTIO_TX_OFF_FLAG_OUTER_CKSUM)
    {
      oflags = vnet_buffer (b)->oflags;
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	{
	  hdr->w1.ol3type = CNXK_PKTIO_NIX_SEND_L3TYPE_IP4_CKSUM;
	  hdr->w1.ol3ptr = vnet_buffer (b)->l3_hdr_offset;
	  hdr->w1.ol4ptr =
	    vnet_buffer (b)->l3_hdr_offset + sizeof (ip4_header_t);
	}

      if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  hdr->w1.ol4type = CNXK_PKTIO_NIX_SEND_L4TYPE_UDP_CKSUM;
	  hdr->w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset;
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  hdr->w1.ol4type = CNXK_PKTIO_NIX_SEND_L4TYPE_TCP_CKSUM;
	  hdr->w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset;
	}
    }
  return CNXK_PKTIO_SEND_HDR_DWORDS;
}

i32 static_always_inline
cn10k_pkts_send (vlib_main_t *vm, vlib_node_runtime_t *node, u32 txq,
		 u16 tx_pkts, cnxk_per_thread_data_t *ptd, const u32 desc_sz,
		 const u64 fp_flags, const u64 off_flags)
{
  union nix_send_sg_s *sg8, *sg9, *sg10, *sg11, *sg12, *sg13, *sg14, *sg15;
  struct nix_send_hdr_s *send_hdr12, *send_hdr13, *send_hdr14, *send_hdr15;
  struct nix_send_hdr_s *send_hdr8, *send_hdr9, *send_hdr10, *send_hdr11;
  u64 desc12[desc_sz], desc13[desc_sz], desc14[desc_sz], desc15[desc_sz];
  u64 desc8[desc_sz], desc9[desc_sz], desc10[desc_sz], desc11[desc_sz];
  struct nix_send_hdr_s *send_hdr4, *send_hdr5, *send_hdr6, *send_hdr7;
  struct nix_send_hdr_s *send_hdr0, *send_hdr1, *send_hdr2, *send_hdr3;
  union nix_send_sg_s *sg0, *sg1, *sg2, *sg3, *sg4, *sg5, *sg6, *sg7;
  u64 desc0[desc_sz], desc1[desc_sz], desc2[desc_sz], desc3[desc_sz];
  u64 desc4[desc_sz], desc5[desc_sz], desc6[desc_sz], desc7[desc_sz];
  u64 io_addr, sq_handle, n_dwords[16], n_packets, cached_aura = ~0;
  void *lmt_line12, *lmt_line13, *lmt_line14, *lmt_line15;
  void *lmt_line8, *lmt_line9, *lmt_line10, *lmt_line11;
  void *lmt_line0, *lmt_line1, *lmt_line2, *lmt_line3;
  void *lmt_line4, *lmt_line5, *lmt_line6, *lmt_line7;
  u64 aura_handle[16], n_segs[16], n_total_segs = 0;
  u64 lmt_arg, core_lmt_base_addr, core_lmt_id;
  u16 refill_counter = 0, n_drop = 0;
  cnxk_pktio_ops_map_t *pktio_ops;
  u32 from[VLIB_FRAME_SIZE];
  u8 cached_bp_index = ~0;
  struct roc_nix_sq *sq;
  cnxk_pktio_t *pktio;
  cnxk_fpsq_t *fpsq;
  vlib_buffer_t **b;

  pktio_ops = cnxk_pktio_get_pktio_ops (ptd->pktio_index);
  pktio = &pktio_ops->pktio;
  fpsq = vec_elt_at_index (pktio->fpsqs, txq);
  sq = &pktio->sqs[txq];
  b = ptd->buffers;
  io_addr = sq->io_addr;
  sq_handle = fpsq->sq_id;

  if (PREDICT_FALSE (fpsq->cached_pkts < tx_pkts))
    {
      fpsq->cached_pkts = (sq->nb_sqb_bufs_adj - *((u64 *) sq->fc))
			  << sq->sqes_per_sqb_log2;

      if (PREDICT_FALSE (fpsq->cached_pkts < tx_pkts))
	{
	  if (fpsq->cached_pkts < 0)
	    {
	      n_drop = tx_pkts;
	      tx_pkts = 0;
	      goto free_pkts;
	    }
	  n_drop = tx_pkts - fpsq->cached_pkts;
	  tx_pkts = fpsq->cached_pkts;
	}
    }

  send_hdr0 = (struct nix_send_hdr_s *) &desc0[0];
  send_hdr1 = (struct nix_send_hdr_s *) &desc1[0];
  send_hdr2 = (struct nix_send_hdr_s *) &desc2[0];
  send_hdr3 = (struct nix_send_hdr_s *) &desc3[0];
  send_hdr4 = (struct nix_send_hdr_s *) &desc4[0];
  send_hdr5 = (struct nix_send_hdr_s *) &desc5[0];
  send_hdr6 = (struct nix_send_hdr_s *) &desc6[0];
  send_hdr7 = (struct nix_send_hdr_s *) &desc7[0];
  send_hdr8 = (struct nix_send_hdr_s *) &desc8[0];
  send_hdr9 = (struct nix_send_hdr_s *) &desc9[0];
  send_hdr10 = (struct nix_send_hdr_s *) &desc10[0];
  send_hdr11 = (struct nix_send_hdr_s *) &desc11[0];
  send_hdr12 = (struct nix_send_hdr_s *) &desc12[0];
  send_hdr13 = (struct nix_send_hdr_s *) &desc13[0];
  send_hdr14 = (struct nix_send_hdr_s *) &desc14[0];
  send_hdr15 = (struct nix_send_hdr_s *) &desc15[0];

  sg0 = (union nix_send_sg_s *) &desc0[2];
  sg1 = (union nix_send_sg_s *) &desc1[2];
  sg2 = (union nix_send_sg_s *) &desc2[2];
  sg3 = (union nix_send_sg_s *) &desc3[2];
  sg4 = (union nix_send_sg_s *) &desc4[2];
  sg5 = (union nix_send_sg_s *) &desc5[2];
  sg6 = (union nix_send_sg_s *) &desc6[2];
  sg7 = (union nix_send_sg_s *) &desc7[2];
  sg8 = (union nix_send_sg_s *) &desc8[2];
  sg9 = (union nix_send_sg_s *) &desc9[2];
  sg10 = (union nix_send_sg_s *) &desc10[2];
  sg11 = (union nix_send_sg_s *) &desc11[2];
  sg12 = (union nix_send_sg_s *) &desc12[2];
  sg13 = (union nix_send_sg_s *) &desc13[2];
  sg14 = (union nix_send_sg_s *) &desc14[2];
  sg15 = (union nix_send_sg_s *) &desc15[2];

  core_lmt_base_addr = (u64) sq->lmt_addr;
  ROC_LMT_BASE_ID_GET (core_lmt_base_addr, core_lmt_id);

  lmt_line0 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 0);
  lmt_line1 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 1);
  lmt_line2 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 2);
  lmt_line3 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 3);
  lmt_line4 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 4);
  lmt_line5 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 5);
  lmt_line6 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 6);
  lmt_line7 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 7);
  lmt_line8 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 8);
  lmt_line9 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 9);
  lmt_line10 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 10);
  lmt_line11 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 11);
  lmt_line12 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 12);
  lmt_line13 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 13);
  lmt_line14 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 14);
  lmt_line15 = CN10K_PKTIO_LMT_GET_LINE_ADDR (core_lmt_base_addr, 15);

  n_packets = tx_pkts;

  while (n_packets > 16)
    {
      n_segs[0] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[0], off_flags);
      n_segs[1] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[1], off_flags);
      n_segs[2] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[2], off_flags);
      n_segs[3] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[3], off_flags);
      n_segs[4] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[4], off_flags);
      n_segs[5] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[5], off_flags);
      n_segs[6] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[6], off_flags);
      n_segs[7] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[7], off_flags);
      n_segs[8] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[8], off_flags);
      n_segs[9] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[9], off_flags);
      n_segs[10] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[10], off_flags);
      n_segs[11] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[11], off_flags);
      n_segs[12] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[12], off_flags);
      n_segs[13] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[13], off_flags);
      n_segs[14] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[14], off_flags);
      n_segs[15] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[15], off_flags);

      aura_handle[0] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[0], n_segs[0], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[1] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[1], n_segs[1], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[2] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[2], n_segs[2], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[3] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[3], n_segs[3], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[4] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[4], n_segs[4], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[5] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[5], n_segs[5], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[6] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[6], n_segs[6], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[7] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[7], n_segs[7], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[8] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[8], n_segs[8], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[9] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[9], n_segs[9], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[10] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[10], n_segs[10], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[11] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[11], n_segs[11], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[12] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[12], n_segs[12], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[13] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[13], n_segs[13], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[14] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[14], n_segs[14], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[15] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[15], n_segs[15], &cached_aura,
				    &cached_bp_index, &refill_counter);

      n_dwords[0] = cn10k_pktio_add_sg_list (sg0, b[0], n_segs[0], off_flags);
      n_dwords[1] = cn10k_pktio_add_sg_list (sg1, b[1], n_segs[1], off_flags);
      n_dwords[2] = cn10k_pktio_add_sg_list (sg2, b[2], n_segs[2], off_flags);
      n_dwords[3] = cn10k_pktio_add_sg_list (sg3, b[3], n_segs[3], off_flags);
      n_dwords[4] = cn10k_pktio_add_sg_list (sg4, b[4], n_segs[4], off_flags);
      n_dwords[5] = cn10k_pktio_add_sg_list (sg5, b[5], n_segs[5], off_flags);
      n_dwords[6] = cn10k_pktio_add_sg_list (sg6, b[6], n_segs[6], off_flags);
      n_dwords[7] = cn10k_pktio_add_sg_list (sg7, b[7], n_segs[7], off_flags);
      n_dwords[8] = cn10k_pktio_add_sg_list (sg8, b[8], n_segs[8], off_flags);
      n_dwords[9] = cn10k_pktio_add_sg_list (sg9, b[9], n_segs[9], off_flags);
      n_dwords[10] =
	cn10k_pktio_add_sg_list (sg10, b[10], n_segs[10], off_flags);
      n_dwords[11] =
	cn10k_pktio_add_sg_list (sg11, b[11], n_segs[11], off_flags);
      n_dwords[12] =
	cn10k_pktio_add_sg_list (sg12, b[12], n_segs[12], off_flags);
      n_dwords[13] =
	cn10k_pktio_add_sg_list (sg13, b[13], n_segs[13], off_flags);
      n_dwords[14] =
	cn10k_pktio_add_sg_list (sg14, b[14], n_segs[14], off_flags);
      n_dwords[15] =
	cn10k_pktio_add_sg_list (sg15, b[15], n_segs[15], off_flags);

      n_dwords[0] += cn10k_pktio_add_send_hdr (
	send_hdr0, b[0], aura_handle[0], sq_handle, n_dwords[0], off_flags);
      n_dwords[1] += cn10k_pktio_add_send_hdr (
	send_hdr1, b[1], aura_handle[1], sq_handle, n_dwords[1], off_flags);
      n_dwords[2] += cn10k_pktio_add_send_hdr (
	send_hdr2, b[2], aura_handle[2], sq_handle, n_dwords[2], off_flags);
      n_dwords[3] += cn10k_pktio_add_send_hdr (
	send_hdr3, b[3], aura_handle[3], sq_handle, n_dwords[3], off_flags);
      n_dwords[4] += cn10k_pktio_add_send_hdr (
	send_hdr4, b[4], aura_handle[4], sq_handle, n_dwords[4], off_flags);
      n_dwords[5] += cn10k_pktio_add_send_hdr (
	send_hdr5, b[5], aura_handle[5], sq_handle, n_dwords[5], off_flags);
      n_dwords[6] += cn10k_pktio_add_send_hdr (
	send_hdr6, b[6], aura_handle[6], sq_handle, n_dwords[6], off_flags);
      n_dwords[7] += cn10k_pktio_add_send_hdr (
	send_hdr7, b[7], aura_handle[7], sq_handle, n_dwords[7], off_flags);

      n_dwords[8] += cn10k_pktio_add_send_hdr (
	send_hdr8, b[8], aura_handle[8], sq_handle, n_dwords[8], off_flags);
      n_dwords[9] += cn10k_pktio_add_send_hdr (
	send_hdr9, b[9], aura_handle[9], sq_handle, n_dwords[9], off_flags);
      n_dwords[10] +=
	cn10k_pktio_add_send_hdr (send_hdr10, b[10], aura_handle[10],
				  sq_handle, n_dwords[10], off_flags);
      n_dwords[11] +=
	cn10k_pktio_add_send_hdr (send_hdr11, b[11], aura_handle[11],
				  sq_handle, n_dwords[11], off_flags);
      n_dwords[12] +=
	cn10k_pktio_add_send_hdr (send_hdr12, b[12], aura_handle[12],
				  sq_handle, n_dwords[12], off_flags);
      n_dwords[13] +=
	cn10k_pktio_add_send_hdr (send_hdr13, b[13], aura_handle[13],
				  sq_handle, n_dwords[13], off_flags);
      n_dwords[14] +=
	cn10k_pktio_add_send_hdr (send_hdr14, b[14], aura_handle[14],
				  sq_handle, n_dwords[14], off_flags);
      n_dwords[15] +=
	cn10k_pktio_add_send_hdr (send_hdr15, b[15], aura_handle[15],
				  sq_handle, n_dwords[15], off_flags);

      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      cnxk_wmb ();

      /* Clear io_addr[6:0] bits */
      io_addr &= ~0x7FULL;
      lmt_arg = core_lmt_id;

      /* Set size-1 of first LMTST at io_addr[6:4] */
      io_addr |= (n_dwords[0] - 1) << 4;

      roc_lmt_mov_seg (lmt_line0, desc0, n_dwords[0]);
      roc_lmt_mov_seg (lmt_line1, desc1, n_dwords[1]);
      roc_lmt_mov_seg (lmt_line2, desc2, n_dwords[2]);
      roc_lmt_mov_seg (lmt_line3, desc3, n_dwords[3]);
      roc_lmt_mov_seg (lmt_line4, desc4, n_dwords[4]);
      roc_lmt_mov_seg (lmt_line5, desc5, n_dwords[5]);
      roc_lmt_mov_seg (lmt_line6, desc6, n_dwords[6]);
      roc_lmt_mov_seg (lmt_line7, desc7, n_dwords[7]);
      roc_lmt_mov_seg (lmt_line8, desc8, n_dwords[8]);
      roc_lmt_mov_seg (lmt_line9, desc9, n_dwords[9]);
      roc_lmt_mov_seg (lmt_line10, desc10, n_dwords[10]);
      roc_lmt_mov_seg (lmt_line11, desc11, n_dwords[11]);
      roc_lmt_mov_seg (lmt_line12, desc12, n_dwords[12]);
      roc_lmt_mov_seg (lmt_line13, desc13, n_dwords[13]);
      roc_lmt_mov_seg (lmt_line14, desc14, n_dwords[14]);
      roc_lmt_mov_seg (lmt_line15, desc15, n_dwords[15]);

      /* Set number of LMTSTs, excluding the first */
      lmt_arg |= (16 - 1) << 12;

      /*
       * Set vector of sizes of next 15 LMTSTs.
       * Every 3 bits represent size-1 of one LMTST
       */
      lmt_arg |= (n_dwords[1] - 1) << (19 + (3 * 0));
      lmt_arg |= (n_dwords[2] - 1) << (19 + (3 * 1));
      lmt_arg |= (n_dwords[3] - 1) << (19 + (3 * 2));
      lmt_arg |= (n_dwords[4] - 1) << (19 + (3 * 3));
      lmt_arg |= (n_dwords[5] - 1) << (19 + (3 * 4));
      lmt_arg |= (n_dwords[6] - 1) << (19 + (3 * 5));
      lmt_arg |= (n_dwords[7] - 1) << (19 + (3 * 6));
      lmt_arg |= (n_dwords[8] - 1) << (19 + (3 * 7));
      lmt_arg |= (n_dwords[9] - 1) << (19 + (3 * 8));
      lmt_arg |= (n_dwords[10] - 1) << (19 + (3 * 9));
      lmt_arg |= (n_dwords[11] - 1) << (19 + (3 * 10));
      lmt_arg |= (n_dwords[12] - 1) << (19 + (3 * 11));
      lmt_arg |= (n_dwords[13] - 1) << (19 + (3 * 12));
      lmt_arg |= (n_dwords[14] - 1) << (19 + (3 * 13));
      lmt_arg |= (n_dwords[15] - 1) << (19 + (3 * 14));

      roc_lmt_submit_steorl (lmt_arg, io_addr);

      n_total_segs += n_segs[0] + n_segs[1] + n_segs[2] + n_segs[3];
      n_total_segs += n_segs[4] + n_segs[5] + n_segs[6] + n_segs[7];
      n_total_segs += n_segs[8] + n_segs[9] + n_segs[10] + n_segs[11];
      n_total_segs += n_segs[12] + n_segs[13] + n_segs[14] + n_segs[15];

      n_packets -= 16;
      b += 16;
    }

  while (n_packets > 8)
    {
      n_segs[0] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[0], off_flags);
      n_segs[1] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[1], off_flags);
      n_segs[2] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[2], off_flags);
      n_segs[3] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[3], off_flags);
      n_segs[4] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[4], off_flags);
      n_segs[5] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[5], off_flags);
      n_segs[6] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[6], off_flags);
      n_segs[7] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[7], off_flags);

      aura_handle[0] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[0], n_segs[0], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[1] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[1], n_segs[1], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[2] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[2], n_segs[2], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[3] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[3], n_segs[3], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[4] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[4], n_segs[4], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[5] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[5], n_segs[5], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[6] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[6], n_segs[6], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[7] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[7], n_segs[7], &cached_aura,
				    &cached_bp_index, &refill_counter);

      n_dwords[0] = cn10k_pktio_add_sg_list (sg0, b[0], n_segs[0], off_flags);
      n_dwords[1] = cn10k_pktio_add_sg_list (sg1, b[1], n_segs[1], off_flags);
      n_dwords[2] = cn10k_pktio_add_sg_list (sg2, b[2], n_segs[2], off_flags);
      n_dwords[3] = cn10k_pktio_add_sg_list (sg3, b[3], n_segs[3], off_flags);
      n_dwords[4] = cn10k_pktio_add_sg_list (sg4, b[4], n_segs[4], off_flags);
      n_dwords[5] = cn10k_pktio_add_sg_list (sg5, b[5], n_segs[5], off_flags);
      n_dwords[6] = cn10k_pktio_add_sg_list (sg6, b[6], n_segs[6], off_flags);
      n_dwords[7] = cn10k_pktio_add_sg_list (sg7, b[7], n_segs[7], off_flags);

      n_dwords[0] += cn10k_pktio_add_send_hdr (
	send_hdr0, b[0], aura_handle[0], sq_handle, n_dwords[0], off_flags);
      n_dwords[1] += cn10k_pktio_add_send_hdr (
	send_hdr1, b[1], aura_handle[1], sq_handle, n_dwords[1], off_flags);
      n_dwords[2] += cn10k_pktio_add_send_hdr (
	send_hdr2, b[2], aura_handle[2], sq_handle, n_dwords[2], off_flags);
      n_dwords[3] += cn10k_pktio_add_send_hdr (
	send_hdr3, b[3], aura_handle[3], sq_handle, n_dwords[3], off_flags);
      n_dwords[4] += cn10k_pktio_add_send_hdr (
	send_hdr4, b[4], aura_handle[4], sq_handle, n_dwords[4], off_flags);
      n_dwords[5] += cn10k_pktio_add_send_hdr (
	send_hdr5, b[5], aura_handle[5], sq_handle, n_dwords[5], off_flags);
      n_dwords[6] += cn10k_pktio_add_send_hdr (
	send_hdr6, b[6], aura_handle[6], sq_handle, n_dwords[6], off_flags);
      n_dwords[7] += cn10k_pktio_add_send_hdr (
	send_hdr7, b[7], aura_handle[7], sq_handle, n_dwords[7], off_flags);

      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      cnxk_wmb ();

      /* Clear io_addr[6:0] bits */
      io_addr &= ~0x7FULL;
      lmt_arg = core_lmt_id;

      /* Set size-1 of first LMTST at io_addr[6:4] */
      io_addr |= (n_dwords[0] - 1) << 4;

      roc_lmt_mov_seg (lmt_line0, desc0, n_dwords[0]);
      roc_lmt_mov_seg (lmt_line1, desc1, n_dwords[1]);
      roc_lmt_mov_seg (lmt_line2, desc2, n_dwords[2]);
      roc_lmt_mov_seg (lmt_line3, desc3, n_dwords[3]);
      roc_lmt_mov_seg (lmt_line4, desc4, n_dwords[4]);
      roc_lmt_mov_seg (lmt_line5, desc5, n_dwords[5]);
      roc_lmt_mov_seg (lmt_line6, desc6, n_dwords[6]);
      roc_lmt_mov_seg (lmt_line7, desc7, n_dwords[7]);

      /* Set number of LMTSTs, excluding the first */
      lmt_arg |= (8 - 1) << 12;

      /*
       * Set vector of sizes of next 7 LMTSTs.
       * Every 3 bits represent size-1 of one LMTST
       */
      lmt_arg |= (n_dwords[1] - 1) << (19 + (3 * 0));
      lmt_arg |= (n_dwords[2] - 1) << (19 + (3 * 1));
      lmt_arg |= (n_dwords[3] - 1) << (19 + (3 * 2));
      lmt_arg |= (n_dwords[4] - 1) << (19 + (3 * 3));
      lmt_arg |= (n_dwords[5] - 1) << (19 + (3 * 4));
      lmt_arg |= (n_dwords[6] - 1) << (19 + (3 * 5));
      lmt_arg |= (n_dwords[7] - 1) << (19 + (3 * 6));

      roc_lmt_submit_steorl (lmt_arg, io_addr);

      n_total_segs += n_segs[0] + n_segs[1] + n_segs[2] + n_segs[3];
      n_total_segs += n_segs[4] + n_segs[5] + n_segs[6] + n_segs[7];
      n_packets -= 8;
      b += 8;
    }

  while (n_packets > 4)
    {
      n_segs[0] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[0], off_flags);
      n_segs[1] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[1], off_flags);
      n_segs[2] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[2], off_flags);
      n_segs[3] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[3], off_flags);

      aura_handle[0] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[0], n_segs[0], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[1] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[1], n_segs[1], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[2] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[2], n_segs[2], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[3] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[3], n_segs[3], &cached_aura,
				    &cached_bp_index, &refill_counter);

      n_dwords[0] = cn10k_pktio_add_sg_list (sg0, b[0], n_segs[0], off_flags);
      n_dwords[1] = cn10k_pktio_add_sg_list (sg1, b[1], n_segs[1], off_flags);
      n_dwords[2] = cn10k_pktio_add_sg_list (sg2, b[2], n_segs[2], off_flags);
      n_dwords[3] = cn10k_pktio_add_sg_list (sg3, b[3], n_segs[3], off_flags);

      n_dwords[0] += cn10k_pktio_add_send_hdr (
	send_hdr0, b[0], aura_handle[0], sq_handle, n_dwords[0], off_flags);
      n_dwords[1] += cn10k_pktio_add_send_hdr (
	send_hdr1, b[1], aura_handle[1], sq_handle, n_dwords[1], off_flags);
      n_dwords[2] += cn10k_pktio_add_send_hdr (
	send_hdr2, b[2], aura_handle[2], sq_handle, n_dwords[2], off_flags);
      n_dwords[3] += cn10k_pktio_add_send_hdr (
	send_hdr3, b[3], aura_handle[3], sq_handle, n_dwords[3], off_flags);

      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      cnxk_wmb ();

      /* Clear io_addr[6:0] bits */
      io_addr &= ~0x7FULL;
      lmt_arg = core_lmt_id;

      /* Set size-1 of first LMTST at io_addr[6:4] */
      io_addr |= (n_dwords[0] - 1) << 4;

      roc_lmt_mov_seg (lmt_line0, desc0, n_dwords[0]);
      roc_lmt_mov_seg (lmt_line1, desc1, n_dwords[1]);
      roc_lmt_mov_seg (lmt_line2, desc2, n_dwords[2]);
      roc_lmt_mov_seg (lmt_line3, desc3, n_dwords[3]);

      /* Set number of LMTSTs, excluding the first */
      lmt_arg |= (4 - 1) << 12;

      /*
       * Set vector of sizes of next 3 LMTSTs.
       * Every 3 bits represent size-1 of one LMTST
       */
      lmt_arg |= (n_dwords[1] - 1) << (19 + (3 * 0));
      lmt_arg |= (n_dwords[2] - 1) << (19 + (3 * 1));
      lmt_arg |= (n_dwords[3] - 1) << (19 + (3 * 2));

      roc_lmt_submit_steorl (lmt_arg, io_addr);

      n_total_segs += n_segs[0] + n_segs[1] + n_segs[2] + n_segs[3];
      n_packets -= 4;
      b += 4;
    }

  while (n_packets)
    {
      lmt_arg = core_lmt_id;

      if (n_packets > 2)
	vlib_prefetch_buffer_header (b[2], LOAD);

      n_segs[0] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[0], off_flags);

      aura_handle[0] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[0], n_segs[0], &cached_aura,
				    &cached_bp_index, &refill_counter);

      n_dwords[0] = cn10k_pktio_add_sg_list (sg0, b[0], n_segs[0], off_flags);
      n_dwords[0] += cn10k_pktio_add_send_hdr (
	send_hdr0, b[0], aura_handle[0], sq_handle, n_dwords[0], off_flags);

      /* Clear io_addr[6:0] bits */
      io_addr &= ~0x7FULL;

      /* Set size-1 of first LMTST at io_addr[6:4] */
      io_addr |= (n_dwords[0] - 1) << 4;

      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      cnxk_wmb ();

      roc_lmt_mov_seg (lmt_line0, desc0, n_dwords[0]);

      roc_lmt_submit_steorl (lmt_arg, io_addr);

      n_total_segs += n_segs[0];
      n_packets -= 1;
      b += 1;
    }

  cnxk_update_sq_cached_pkts (fpsq, tx_pkts);

  /*
   * TODO: Fix deplete count from different buffer pools
   */
  cnxk_pktpool_update_deplete_count (vm, ptd, refill_counter, cached_bp_index);
  cnxk_pktpool_deplete_single_aura (vm, node, cached_bp_index, ptd,
				    -(CNXK_POOL_MAX_REFILL_DEPLTE_COUNT * 2));
free_pkts:
  if (PREDICT_FALSE (n_drop))
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) b, from, n_drop, 0);
      vlib_buffer_free (vm, from, n_drop);
    }

  return tx_pkts;
}

#endif /* included_onp_drv_modules_pktio_pktio_fp_tx_cn10k_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
