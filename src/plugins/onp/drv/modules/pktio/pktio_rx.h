/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_pktio_pktio_rx_h
#define included_onp_drv_modules_pktio_pktio_rx_h

#include <onp/drv/modules/pktio/pktio_priv.h>
#include <onp/drv/inc/pool_fp.h>

#define CNXK_NIX_CQ_SZ	   128
#define CNXK_SEG_LEN_SHIFT 16
#define CNXK_SEG_LEN_MASK  0xFFFF

static_always_inline u32
cnxk_cqe_cached_pkts_get (cnxk_pktio_t *pktio, cnxk_fprq_t *fprq, u16 req_pkts,
			  const u64 fp_flags)
{
  u64 npkts, head, tail, reg;

  if (PREDICT_FALSE (fprq->cached_pkts < req_pkts))
    {
      reg = roc_atomic64_add_sync (fprq->wdata, fprq->cq_status);
      if (reg &
	  (BIT_ULL (NIX_CQ_OP_STAT_OP_ERR) | BIT_ULL (NIX_CQ_OP_STAT_CQ_ERR)))
	return 0;

      tail = reg & 0xFFFFF;
      head = (reg >> 20) & 0xFFFFF;

      if (tail < head)
	npkts = tail - head + fprq->qmask + 1;
      else
	npkts = tail - head;

      fprq->cached_pkts = npkts;
    }

  return clib_min (fprq->cached_pkts, req_pkts);
}

static_always_inline void
cnxk_pktio_cq_door_bell_update (cnxk_fprq_t *fprq, u32 n_pkts)
{
  *(volatile u64 *) fprq->cq_door = fprq->wdata | n_pkts;
}

static_always_inline void
cnxk_pktio_verify_rx_vlib (vlib_main_t *vm, vlib_buffer_t *b)
{
  /*
   * Warning: Since this assertion is performed in a critical section,
   * with increasing number of worker cores, scaling of packet receive-rates
   * will be impacted in debug builds
   */
  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
	  vlib_buffer_is_known (vm, vlib_get_buffer_index (vm, b)));
}

static_always_inline u32
cnxk_pktio_n_segs (vlib_main_t *vm, const cnxk_pktio_nix_parse_t *rxp)
{
  struct nix_rx_sg_s *sg;
  sg = (struct nix_rx_sg_s *) (((char *) rxp) + sizeof (rxp->parse));
  return sg->segs;
}

static_always_inline u32
cnxk_pktio_chain_segs (vlib_main_t *vm, const cnxk_pktio_nix_parse_t *rxp0,
		       vlib_buffer_t *bt, vlib_buffer_t **b, i32 data_off,
		       const u64 fp_flags, const u64 off_flags)
{
  u32 n_words, n_words_processed, desc_sizem1;
  vlib_buffer_t *last_buf, *seg_buf;
  u32 n_sg_desc, n_segs, next_seg;
  vlib_buffer_t *buf = *b;
  struct nix_rx_sg_s *sg;
  u32 current_desc, bi;
  u32 total_segs = 1;
  u64 seg_len;

  desc_sizem1 = rxp0->parse.desc_sizem1;
  if (desc_sizem1 == 0)
    return total_segs;

  n_words = desc_sizem1 << 1;
  n_sg_desc = (n_words / 4) + 1;

  sg = (struct nix_rx_sg_s *) (((char *) rxp0) + sizeof (rxp0->parse));
  /* Typecast to u64 to read each seg length swiftly */
  seg_len = *(u64 *) sg;
  n_segs = sg->segs;

  /* Start with first descriptor */
  current_desc = 0;

  /*
   * We updated length which is valid in single segment case.
   * incase of multi seg, update seg1 length and advance total words processed.
   * also, updates total bytes in buffer.
   */
  buf->current_length = seg_len & CNXK_SEG_LEN_MASK;

  /* Process from 2nd segment */
  next_seg = 2;
  seg_len = seg_len >> CNXK_SEG_LEN_SHIFT;
  n_words_processed = 2;

  buf->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  buf->total_length_not_including_first_buffer = 0;
  last_buf = buf;

  while (current_desc <= n_sg_desc)
    {
      while (next_seg <= n_segs)
	{
	  seg_buf = (vlib_buffer_t *) ((*(((u64 *) sg) + n_words_processed)) -
				       data_off);
	  cnxk_pktio_verify_rx_vlib (vm, seg_buf);
	  vlib_buffer_copy_template (seg_buf, bt);
	  seg_buf->current_length = seg_len & CNXK_SEG_LEN_MASK;
	  bi = vlib_get_buffer_index (vm, seg_buf);
	  last_buf->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  last_buf->next_buffer = bi;
	  last_buf = seg_buf;
	  seg_len = seg_len >> CNXK_SEG_LEN_SHIFT;
	  buf->total_length_not_including_first_buffer +=
	    seg_buf->current_length;
	  n_words_processed++;
	  next_seg++;
	  total_segs++;
	}
      current_desc++;
      n_sg_desc--;
      if (n_sg_desc)
	{
	  struct nix_rx_sg_s *tsg;

	  tsg = (struct nix_rx_sg_s *) ((u64 *) sg + n_words_processed);
	  seg_len = *((u64 *) (tsg));
	  n_words_processed++;
	  /* Start over */
	  n_segs = tsg->segs;
	  next_seg = 1;
	}
    }

  return total_segs;
}

static_always_inline vlib_buffer_t *
cnxk_pktio_init_vlib_from_cq (vlib_main_t *vm, i32 data_off, u64 *cq_hdr,
			      cnxk_pktio_nix_parse_t *rxp, vlib_buffer_t *bt,
			      cnxk_per_thread_data_t *ptd, cnxk_fprq_t *fprq,
			      vlib_buffer_t **buf, u16 *buffer_next_index,
			      u16 mp_index, const u64 fp_flags,
			      const u64 off_flags, u32 *n_frags_except_first)
{
  const u16 rx_parse_bytes = sizeof (union nix_rx_parse_u);
  vlib_buffer_t *b;

  /* Plain packet path */
  b = (vlib_buffer_t *) (*(cq_hdr + 9) - data_off);
  cnxk_pktio_verify_rx_vlib (vm, b);
  vlib_buffer_copy_template (b, bt);

  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);

  if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM)
    ptd->out_flags |= (rxp->u[0] >> 20) & 0xFFF;

  b->current_length = rxp->parse.pkt_lenm1 + 1;
  ptd->out_user_nstats += b->current_length;

  if (fp_flags & CNXK_PKTIO_FP_FLAG_TRACE_EN)
    clib_memcpy_fast (b->pre_data, &rxp->parse, rx_parse_bytes);

  return b;
}

static_always_inline i32
cnxk_pkts_recv_process_burst (vlib_main_t *vm, vlib_node_runtime_t *node,
			      cnxk_per_thread_data_t *ptd, cnxk_fprq_t *fprq,
			      u32 head, u32 req_pkts, const u64 fp_flags,
			      const u64 off_flags)
{
  vlib_buffer_t **b = ptd->buffers + ptd->buffer_start_index;
  const u16 rx_parse_bytes = sizeof (union nix_rx_parse_u);
  cnxk_pktio_nix_parse_t *rxp0, *rxp1, *rxp2, *rxp3;
  u16 buffer_next_index, n_processed_pkts = 0;
  u64 *cq0_hdr, *cq1_hdr, *cq2_hdr, *cq3_hdr;
  u32 qmask, head_cnt, n_left, n_segs = 0;
  u32 b0_err_flags = 0, b1_err_flags = 0;
  u32 b2_err_flags = 0, b3_err_flags = 0;
  i32 data_off = fprq->data_off;
  u32 n_frags_except_first = 0;
  vlib_buffer_t **start_buffer;
  uintptr_t desc = fprq->desc;
  u16 i = 0, bp_index;
  vlib_buffer_t *bt;
  u16 mp_index;

  bt = &ptd->buffer_template;
  vnet_buffer (bt)->sw_if_index[VLIB_RX] = fprq->pktio_rx_sw_if_index;
  bt->buffer_pool_index = bp_index = fprq->vlib_buffer_pool_index;
  bt->current_data = 0;

  if (roc_errata_nix_no_meta_aura ())
    mp_index = bp_index;
  else
    mp_index = cnxk_pool_get_meta_index ();

  qmask = fprq->qmask;
  n_left = req_pkts;
  head_cnt = head;

  if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM)
    ptd->out_flags = 0;

  while (n_left > 8)
    {
      cnxk_prefetch_non_temporal (
	(void *) (desc + ((head + i + 4) & qmask) * CNXK_NIX_CQ_SZ));
      cnxk_prefetch_non_temporal (
	(void *) (desc + ((head + i + 5) & qmask) * CNXK_NIX_CQ_SZ));
      cnxk_prefetch_non_temporal (
	(void *) (desc + ((head + i + 6) & qmask) * CNXK_NIX_CQ_SZ));
      cnxk_prefetch_non_temporal (
	(void *) (desc + ((head + i + 7) & qmask) * CNXK_NIX_CQ_SZ));

      cq0_hdr = (u64 *) (desc + ((head + i) & qmask) * CNXK_NIX_CQ_SZ);
      cq1_hdr = (u64 *) (desc + ((head + i + 1) & qmask) * CNXK_NIX_CQ_SZ);
      cq2_hdr = (u64 *) (desc + ((head + i + 2) & qmask) * CNXK_NIX_CQ_SZ);
      cq3_hdr = (u64 *) (desc + ((head + i + 3) & qmask) * CNXK_NIX_CQ_SZ);

      rxp0 = (cnxk_pktio_nix_parse_t *) (cq0_hdr + 1);
      rxp1 = (cnxk_pktio_nix_parse_t *) (cq1_hdr + 1);
      rxp2 = (cnxk_pktio_nix_parse_t *) (cq2_hdr + 1);
      rxp3 = (cnxk_pktio_nix_parse_t *) (cq3_hdr + 1);

      buffer_next_index = 4;

      /* None of the 4 packets are from CPT */
      b[0] = (vlib_buffer_t *) (*(cq0_hdr + 9) - data_off);
      b[1] = (vlib_buffer_t *) (*(cq1_hdr + 9) - data_off);
      b[2] = (vlib_buffer_t *) (*(cq2_hdr + 9) - data_off);
      b[3] = (vlib_buffer_t *) (*(cq3_hdr + 9) - data_off);

      cnxk_pktio_verify_rx_vlib (vm, b[0]);
      cnxk_pktio_verify_rx_vlib (vm, b[1]);
      cnxk_pktio_verify_rx_vlib (vm, b[2]);
      cnxk_pktio_verify_rx_vlib (vm, b[3]);

      vlib_buffer_copy_template (b[0], bt);
      vlib_buffer_copy_template (b[1], bt);
      vlib_buffer_copy_template (b[2], bt);
      vlib_buffer_copy_template (b[3], bt);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

      if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM)
	{
	  b0_err_flags = (rxp0->u[0] >> 20) & 0xFFF;
	  b1_err_flags = (rxp1->u[0] >> 20) & 0xFFF;
	  b2_err_flags = (rxp2->u[0] >> 20) & 0xFFF;
	  b3_err_flags = (rxp3->u[0] >> 20) & 0xFFF;

	  ptd->out_flags |=
	    b0_err_flags | b1_err_flags | b2_err_flags | b3_err_flags;
	}

      b[0]->current_length = (rxp0->u[1] & 0xFFFF) + 1;
      b[1]->current_length = (rxp1->u[1] & 0xFFFF) + 1;
      b[2]->current_length = (rxp2->u[1] & 0xFFFF) + 1;
      b[3]->current_length = (rxp3->u[1] & 0xFFFF) + 1;

      ptd->out_user_nstats += b[0]->current_length + b[1]->current_length +
			      b[2]->current_length + b[3]->current_length;

      if (fp_flags & CNXK_PKTIO_FP_FLAG_TRACE_EN)
	{
	  clib_memcpy_fast (b[0]->pre_data, &rxp0->parse, rx_parse_bytes);
	  clib_memcpy_fast (b[1]->pre_data, &rxp1->parse, rx_parse_bytes);
	  clib_memcpy_fast (b[2]->pre_data, &rxp2->parse, rx_parse_bytes);
	  clib_memcpy_fast (b[3]->pre_data, &rxp3->parse, rx_parse_bytes);
	}

      n_segs += n_frags_except_first;

      /*
       * Following call to cnxk_pktio_chain_segs function will count
       * the base fragment into n_segs.
       * Current O10 implementation doesn't support multiple segments
       * for single fragment.
       */
      if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_MSEG)
	{
	  n_segs += cnxk_pktio_chain_segs (vm, rxp0, bt, &b[0], data_off,
					   fp_flags, off_flags);
	  n_segs += cnxk_pktio_chain_segs (vm, rxp1, bt, &b[1], data_off,
					   fp_flags, off_flags);
	  n_segs += cnxk_pktio_chain_segs (vm, rxp2, bt, &b[2], data_off,
					   fp_flags, off_flags);
	  n_segs += cnxk_pktio_chain_segs (vm, rxp3, bt, &b[3], data_off,
					   fp_flags, off_flags);
	}
      else
	n_segs += 4;

      i += 4;
      b += buffer_next_index;
      n_left -= 4;
      head_cnt += 4;
      n_frags_except_first = 0;
      n_processed_pkts += buffer_next_index;
    }

  while (n_left)
    {
      cq0_hdr = (u64 *) (desc + ((head + i) & qmask) * CNXK_NIX_CQ_SZ);
      rxp0 = (cnxk_pktio_nix_parse_t *) (cq0_hdr + 1);

      start_buffer = &b[0];
      buffer_next_index = 1;

      b[0] = cnxk_pktio_init_vlib_from_cq (
	vm, data_off, cq0_hdr, rxp0, bt, ptd, fprq, start_buffer,
	&buffer_next_index, mp_index, fp_flags, off_flags,
	&n_frags_except_first);

      n_segs += n_frags_except_first;

      /*
       * Following call to cnxk_pktio_chain_segs function will count
       * the base fragment into n_segs.
       * Current O10 implementation doesn't support multiple segments
       * for single fragment.
       */
      if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_MSEG)
	n_segs += cnxk_pktio_chain_segs (vm, rxp0, bt, &b[0], data_off,
					 fp_flags, off_flags);
      else
	n_segs += 1;

      i += 1;
      b += buffer_next_index;
      n_left -= 1;
      head_cnt += 1;
      n_frags_except_first = 0;
      n_processed_pkts += buffer_next_index;
    }

  /* All packets belongs to same pool index */
  cnxk_pktpool_update_refill_count (vm, ptd, n_segs, bp_index);

  fprq->cached_pkts -= req_pkts;
  fprq->head = head_cnt;

  ptd->buffer_start_index += n_processed_pkts;

  return n_processed_pkts;
}

static_always_inline u32
cnxk_pktio_rq_peek (vlib_main_t *vm, vlib_node_runtime_t *node, u32 rqid,
		    u16 req_pkts, cnxk_per_thread_data_t *ptd,
		    const u64 fp_flags)
{
  cnxk_pktio_ops_map_t *pktio_ops;
  cnxk_pktio_t *pktio;
  cnxk_fprq_t *fprq;

  pktio_ops = cnxk_pktio_get_pktio_ops (ptd->pktio_index);
  pktio = &pktio_ops->pktio;
  fprq = vec_elt_at_index (pktio->fprqs, rqid);

  return cnxk_cqe_cached_pkts_get (pktio, fprq, req_pkts, fp_flags);
}

static_always_inline i32
cnxk_pkts_recv_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       cnxk_pktio_t *pktio, cnxk_fprq_t *fprq, u16 req_pkts,
		       cnxk_per_thread_data_t *ptd, const u64 fp_flags,
		       const u64 off_flags)
{
  u16 rx_pkts = 0, n_processed_pkts = 0;

  ptd->buffer_start_index = 0;
  ptd->out_user_nstats = 0;

  while (n_processed_pkts < req_pkts)
    {
      rx_pkts = cnxk_cqe_cached_pkts_get (
	pktio, fprq, req_pkts - n_processed_pkts, fp_flags);

      if (PREDICT_FALSE (!rx_pkts))
	break;

      n_processed_pkts += cnxk_pkts_recv_process_burst (
	vm, node, ptd, fprq, fprq->head, rx_pkts, fp_flags, off_flags);

      cnxk_pktio_cq_door_bell_update (fprq, rx_pkts);

      if (rx_pkts < fprq->rxq_min_vec_size)
	break;
    }
  return n_processed_pkts;
}

static_always_inline i32
cnxk_pkts_recv (vlib_main_t *vm, vlib_node_runtime_t *node, u32 rqid,
		u16 req_pkts, cnxk_per_thread_data_t *ptd, const u64 fp_flags,
		const u64 off_flags)
{
  cnxk_pktio_ops_map_t *pktio_ops;
  cnxk_pktio_t *pktio;
  cnxk_fprq_t *fprq;

  pktio_ops = cnxk_pktio_get_pktio_ops (ptd->pktio_index);
  pktio = &pktio_ops->pktio;
  fprq = vec_elt_at_index (pktio->fprqs, rqid);

  return cnxk_pkts_recv_inline (vm, node, pktio, fprq, req_pkts, ptd, fp_flags,
				off_flags);
}

#endif /* included_onp_drv_modules_pktio_pktio_rx_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
