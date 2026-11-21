/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <mlx5.h>
#include <vnet/dev/counters.h>

static_always_inline u8
mlx5_tx_cs_flags (vlib_buffer_t *b)
{
  vnet_buffer_oflags_t oflags;
  u8 cs_flags = 0;

  if (PREDICT_TRUE ((b->flags & VNET_BUFFER_F_OFFLOAD) == 0))
    return 0;

  oflags = vnet_buffer (b)->oflags;
  if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
    cs_flags |= MLX5_ETH_WQE_L3_CSUM;
  if (oflags & (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM | VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
    cs_flags |= MLX5_ETH_WQE_L4_CSUM;
  return cs_flags;
}

static_always_inline void
mlx5_txq_deq (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq)
{
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  u32 cq_mask = tq->dv_cq_size - 1;
  u32 mask = txq->size - 1;
  u32 log2_cq_size = tq->dv_cq_log2;
  u32 idx = tq->dv_cq_idx;
  struct mlx5_cqe64 *cqes = tq->dv_cq_cqes;
  struct mlx5_cqe64 *cur;
  u8 op_own, opcode;
  u32 slot;

  for (;;)
    {
      cur = cqes + (idx & cq_mask);
      op_own = __atomic_load_n (&cur->op_own, __ATOMIC_ACQUIRE);
      opcode = op_own >> 4;
      if (((idx >> log2_cq_size) & MLX5_CQE_OWNER_MASK) != (op_own & MLX5_CQE_OWNER_MASK) ||
	  opcode == MLX5_CQE_INVALID)
	break;
      idx++;
      if (PREDICT_FALSE (opcode == MLX5_CQE_REQ_ERR || opcode == MLX5_CQE_RESP_ERR))
	{
	  tq->dv_cq_idx = idx;
	  vlib_error_count (vm, node->node_index, RDMA_MLX5_TX_NODE_CTR_CQE_ERROR, 1);
	  mlx5_txq_recover (vm, txq, ((struct mlx5_err_cqe *) cur)->syndrome);
	  return;
	}
    }

  if (idx == tq->dv_cq_idx)
    return;

  cur = cqes + ((idx - 1) & cq_mask);
  slot = clib_net_to_host_u16 (cur->wqe_counter) & mask;
  cur->op_own = 0xf0;
  tq->head = clib_net_to_host_u16 (cur->wqe_counter) + tq->wqe_n_bb[slot];
  mlx5_txq_free_bufs (vm, tq, tq->wqe_buf_tail[slot]);

  tq->dv_cq_idx = idx;
  __atomic_store_n (&tq->dv_cq_dbrec[0], clib_host_to_net_u32 (idx & MLX5_CQ_DB_CI_MASK),
		    __ATOMIC_RELEASE);
}

static_always_inline mlx5_wqe_data_seg_t *
mlx5_txq_ds (mlx5_txq_t *tq, u32 mask, u16 tail, u32 i)
{
  u32 ds_mask = ((mask + 1) << RDMA_MLX5_LOG2_WQE_DS) - 1;

  return (mlx5_wqe_data_seg_t *) tq->dv_sq_wqes +
	 ((((u32) tail << RDMA_MLX5_LOG2_WQE_DS) + i) & ds_mask);
}

static_always_inline void
mlx5_txq_wqe_inline (mlx5_txq_t *tq, u32 mask, u16 tail, const u8 *src, u32 len)
{
  u8 *ring = (u8 *) tq->dv_sq_wqes;
  u32 off = ((tail & mask) << MLX5_SEND_WQE_SHIFT) + MLX5_TX_INLINE_OFF;
  u32 n = clib_min (len, ((mask + 1) << MLX5_SEND_WQE_SHIFT) - off);

  clib_memcpy_fast (ring + off, src, n);

  if (PREDICT_FALSE (n < len))
    clib_memcpy_fast (ring, src + n, len - n);
}
static_always_inline u32
mlx5_tx_n_segs (vlib_main_t *vm, vlib_buffer_t *b, u32 max_segs)
{
  vlib_buffer_t *cb = b;
  u32 n = 1;

  while (cb->flags & VLIB_BUFFER_NEXT_PRESENT && n <= max_segs)
    {
      cb = vlib_get_buffer (vm, cb->next_buffer);
      n++;
    }

  if (PREDICT_FALSE (n > max_segs))
    {
      n = vlib_buffer_chain_linearize (vm, b);
      if (n == 0 || n > max_segs)
	return 0;
    }

  return n;
}

static_always_inline void
mlx5_tx_dseg_store (mlx5_wqe_data_seg_t *ds, mlx5_wqe_data_seg_t t, u32 len, void *p)
{
  t.vec128.as_u32x4[0] = len;
  t.vec128.as_u64x2[1] = pointer_to_uword (p);

  ds->vec128.as_u8x16 =
    u8x16_shuffle (t.vec128.as_u8x16, 3, 2, 1, 0, 4, 5, 6, 7, 15, 14, 13, 12, 11, 10, 9, 8);
}

static const u32 mlx5_tx_empw_not_plain =
  VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_GSO | VNET_BUFFER_F_OFFLOAD;

#if !defined(CLIB_HAVE_VEC256)
static_always_inline u64x2
mlx5_tx_dseg_x2 (vlib_buffer_t **b, mlx5_wqe_data_seg_t *ds, mlx5_wqe_data_seg_t t)
{
  u64x2 off = u64x2_splat (STRUCT_OFFSET_OF (vlib_buffer_t, data));
  u8x16 dm = {
    0, 0, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };
  u64x2 w = { *(u64 *) b[0], *(u64 *) b[1] };
  u64x2 a = *(u64x2u *) b + off + ((i64x2) (w << 48) >> 48);
  u8x16 ds0 = u8x16_shuffle2 (w, a, 0, 0, 3, 2, 0, 0, 0, 0, 23, 22, 21, 20, 19, 18, 17, 16);
  u8x16 ds1 = u8x16_shuffle2 (w, a, 0, 0, 11, 10, 0, 0, 0, 0, 31, 30, 29, 28, 27, 26, 25, 24);

  ds[0].vec128.as_u8x16 = (ds0 & dm) | t.vec128.as_u8x16;
  ds[1].vec128.as_u8x16 = (ds1 & dm) | t.vec128.as_u8x16;
  return w;
}
#endif

#if defined(CLIB_HAVE_VEC256)
static_always_inline u64x4
mlx5_tx_dseg_x4 (vlib_buffer_t **b, mlx5_wqe_data_seg_t *ds, mlx5_wqe_data_seg_t t)
{
  u64x4 off = u64x4_splat (STRUCT_OFFSET_OF (vlib_buffer_t, data));
  u8x32 dm = u8x32_splat_u8x16 (
    (u8x16) { 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff });
  u8x32 tv = u8x32_splat_u8x16 (t.vec128.as_u8x16);
  u64x4 w = { *(u64 *) b[0], *(u64 *) b[1], *(u64 *) b[2], *(u64 *) b[3] };
  u64x4 a = *(u64x4u *) b + off + ((i64x4) (w << 48) >> 48);
  u8x32 lo = u8x32_shuffle2 (w, a, 0, 0, 3, 2, 0, 0, 0, 0, 39, 38, 37, 36, 35, 34, 33, 32, 16, 16,
			     19, 18, 16, 16, 16, 16, 55, 54, 53, 52, 51, 50, 49, 48);
  u8x32 hi = u8x32_shuffle2 (w, a, 0, 0, 11, 10, 0, 0, 0, 0, 47, 46, 45, 44, 43, 42, 41, 40, 16, 16,
			     27, 26, 16, 16, 16, 16, 63, 62, 61, 60, 59, 58, 57, 56);

  lo = (lo & dm) | tv;
  hi = (hi & dm) | tv;
  ds[0].vec128.as_u8x16 = u8x32_extract_lo (lo);
  ds[1].vec128.as_u8x16 = u8x32_extract_lo (hi);
  ds[2].vec128.as_u8x16 = u8x32_extract_hi (lo);
  ds[3].vec128.as_u8x16 = u8x32_extract_hi (hi);
  return w;
}
#endif

static_always_inline void
mlx5_tx_prep (vlib_buffer_t **b, mlx5_wqe_data_seg_t *ds, uword *slow_bmp, u32 n_left,
	      mlx5_wqe_data_seg_t t)
{
  u32x4 np = u32x4_splat (mlx5_tx_empw_not_plain), zero = {};
#if defined(CLIB_HAVE_VEC256)
  u32x8 np8 = u32x8_splat (mlx5_tx_empw_not_plain), zero8 = {};
  u64x4 w0, w1;
  u32x8 f;
#else
  u64x2 w0, w1, w2, w3;
  u32x4 f0, f1;
#endif
  uword bits = 0;
  u32 bit = 0;

  for (; n_left >= 8; n_left -= 8, b += 8, ds += 8)
    {
      clib_prefetch_load (b[8]);
      clib_prefetch_load (b[9]);
      clib_prefetch_load (b[10]);
      clib_prefetch_load (b[11]);

#if defined(CLIB_HAVE_VEC256)
      w0 = mlx5_tx_dseg_x4 (b, ds, t);
#else
      w0 = mlx5_tx_dseg_x2 (b, ds, t);
      w1 = mlx5_tx_dseg_x2 (b + 2, ds + 2, t);
#endif

      clib_prefetch_load (b[12]);
      clib_prefetch_load (b[13]);
      clib_prefetch_load (b[14]);
      clib_prefetch_load (b[15]);

#if defined(CLIB_HAVE_VEC256)
      w1 = mlx5_tx_dseg_x4 (b + 4, ds + 4, t);
#else
      w2 = mlx5_tx_dseg_x2 (b + 4, ds + 4, t);
      w3 = mlx5_tx_dseg_x2 (b + 6, ds + 6, t);
#endif

#if defined(CLIB_HAVE_VEC256)
      f = u32x8_shuffle2 (w0, w1, 1, 3, 5, 7, 9, 11, 13, 15);
      bits |= (uword) u32x8_compare_mask ((f & np8) != zero8) << bit;
#else
      f0 = u32x4_shuffle2 (w0, w1, 1, 3, 5, 7);
      f1 = u32x4_shuffle2 (w2, w3, 1, 3, 5, 7);
      bits |= (uword) (u32x4_compare_mask ((f0 & np) != zero) |
		       u32x4_compare_mask ((f1 & np) != zero) << 4)
	      << bit;
#endif
      bit += 8;

      if (bit == uword_bits)
	{
	  *slow_bmp++ = bits;
	  bits = bit = 0;
	}
    }

  if (n_left >= 4)
    {
      u32x4 f4;

#if defined(CLIB_HAVE_VEC256)
      w0 = mlx5_tx_dseg_x4 (b, ds, t);
      f4 = u32x4_shuffle2 (u64x4_extract_lo (w0), u64x4_extract_hi (w0), 1, 3, 5, 7);
#else
      w0 = mlx5_tx_dseg_x2 (b, ds, t);
      w1 = mlx5_tx_dseg_x2 (b + 2, ds + 2, t);
      f4 = u32x4_shuffle2 (w0, w1, 1, 3, 5, 7);
#endif

      bits |= (uword) u32x4_compare_mask ((f4 & np) != zero) << bit;
      bit += 4;
      n_left -= 4;
      b += 4;
      ds += 4;
    }

  for (; n_left; n_left--, b++, ds++)
    {
      mlx5_tx_dseg_store (ds, t, b[0]->current_length, b[0]->data + b[0]->current_data);
      bits |= (uword) ((b[0]->flags & mlx5_tx_empw_not_plain) != 0) << bit++;
    }

  if (bit)
    *slow_bmp = bits;
}

static_always_inline int
mlx5_tx_empw_ok (u32 flags)
{
  return (flags & (VLIB_BUFFER_NEXT_PRESENT | VNET_BUFFER_F_GSO)) == 0;
}

static_always_inline u16
mlx5_tx_n_bb (u32 n_ds)
{
  return (n_ds + RDMA_MLX5_WQE_DS - 1) >> RDMA_MLX5_LOG2_WQE_DS;
}

static_always_inline void
mlx5_tx_ctrl (mlx5_wqe_ctrl_seg_t *ctrl, mlx5_wqe_ctrl_seg_t t, u16 tail, u32 n_ds)
{
  u32x4 v = { tail, n_ds };

  ctrl->vec128.as_u8x16 = u8x16_shuffle2 (v, t.vec128.as_u8x16, 16, 1, 0, 19, 20, 21, 22, 4, 24, 25,
					  26, 27, 28, 29, 30, 31);
}
static_always_inline u16
mlx5_txq_empw_wqe (mlx5_txq_t *tq, u32 slot, u16 tail, mlx5_wqe_data_seg_t *s, u32 n, u8 cs_flags)
{
  mlx5_wqe_t *wqe = tq->dv_sq_wqes + slot;
  mlx5_wqe_data_seg_t *d = (mlx5_wqe_data_seg_t *) wqe + MLX5_TX_EMPW_TITLE_DS;
  u32 n_ds = MLX5_TX_EMPW_TITLE_DS + n, n_left = n;
  u8x16 eseg = {};

#if defined(CLIB_HAVE_VEC512)
  for (; n_left >= 4; n_left -= 4, s += 4, d += 4)
    *(u8x64u *) d = *(u8x64u *) s;
#elif defined(CLIB_HAVE_VEC256)
  for (; n_left >= 4; n_left -= 4, s += 4, d += 4)
    {
      ((u8x32u *) d)[0] = ((u8x32u *) s)[0];
      ((u8x32u *) d)[1] = ((u8x32u *) s)[1];
    }
#else
  for (; n_left >= 4; n_left -= 4, s += 4, d += 4)
    {
      d[0] = s[0];
      d[1] = s[1];
      d[2] = s[2];
      d[3] = s[3];
    }
#endif

  for (; n_left; n_left--, s++, d++)
    d[0] = s[0];

  /* write eMPW control and ethernet segments */
  eseg[STRUCT_OFFSET_OF (struct mlx5_wqe_eth_seg, cs_flags)] = cs_flags;
  mlx5_tx_ctrl (&wqe->ctrl, tq->tmpl_empw_ctrl, tail, n_ds);
  *(u8x16 *) &wqe->eseg = eseg;
  return mlx5_tx_n_bb (n_ds);
}

static_always_inline u32
mlx5_txq_enq_empw_offload (mlx5_txq_t *tq, u32 mask, u16 tail, u32 *from, vlib_buffer_t **b,
			   mlx5_wqe_data_seg_t *dsegs, u32 max, u32 *buf_tail, u16 *n_bb_p)
{
  u8 cs_flags = mlx5_tx_cs_flags (b[0]);
  u32 n = 1, bt = *buf_tail;

  while (n < max && mlx5_tx_empw_ok (b[n]->flags) && mlx5_tx_cs_flags (b[n]) == cs_flags)
    n++;

  if (n < 2)
    return 0;

  *n_bb_p = mlx5_txq_empw_wqe (tq, tail & mask, tail, dsegs, n, cs_flags);
  vlib_buffer_copy_indices_to_ring (tq->buffers, from, bt & tq->buf_mask, tq->buf_mask + 1, n);
  *buf_tail = bt + n;
  return n;
}

#define MLX5_TX_SEND_DS                                                                            \
  ((MLX5_TX_INLINE_OFF + MLX5_ETH_L2_INLINE_HEADER_SIZE + 15) >> RDMA_MLX5_LOG2_DS_SZ)

static_always_inline void
mlx5_txq_wqe_dsegs (vlib_main_t *vm, mlx5_txq_t *tq, u32 mask, u16 tail, u32 i,
		    mlx5_wqe_data_seg_t t, vlib_buffer_t *b, u32 skip)
{
  u8 *cur = b->data + b->current_data;

  if (b->current_length > skip)
    mlx5_tx_dseg_store (mlx5_txq_ds (tq, mask, tail, i++), t, b->current_length - skip, cur + skip);

  for (vlib_buffer_t *cb = b; cb->flags & VLIB_BUFFER_NEXT_PRESENT;)
    {
      cb = vlib_get_buffer (vm, cb->next_buffer);
      mlx5_tx_dseg_store (mlx5_txq_ds (tq, mask, tail, i++), t, cb->current_length,
			  cb->data + cb->current_data);
    }
}
static_always_inline u16
mlx5_txq_wqe_send (vlib_main_t *vm, mlx5_txq_t *tq, u32 mask, u16 tail, vlib_buffer_t *b,
		   mlx5_wqe_data_seg_t t, u16 n_free)
{
  mlx5_wqe_t *wqe = tq->dv_sq_wqes + (tail & mask);
  u32 n_segs = mlx5_tx_n_segs (vm, b, MLX5_TX_MAX_SEGS), n_ds;
  u16 n_bb;

  if (PREDICT_FALSE (n_segs == 0))
    return 0;

  n_ds = MLX5_TX_SEND_DS + n_segs - (b->current_length == MLX5_ETH_L2_INLINE_HEADER_SIZE);
  n_bb = mlx5_tx_n_bb (n_ds);
  if (PREDICT_FALSE (n_bb > n_free))
    return n_bb;

  mlx5_tx_ctrl (&wqe->ctrl, tq->tmpl_ctrl, tail, n_ds);
  wqe->eseg = tq->tmpl_eseg;
  wqe->eseg.cs_flags = mlx5_tx_cs_flags (b);
  /* coverity[overrun-buffer-arg] - the inline header continues past eseg into the wqe */
  clib_memcpy_fast (wqe->eseg.inline_hdr_start, b->data + b->current_data,
		    MLX5_ETH_L2_INLINE_HEADER_SIZE);
  mlx5_txq_wqe_dsegs (vm, tq, mask, tail, MLX5_TX_SEND_DS, t, b, MLX5_ETH_L2_INLINE_HEADER_SIZE);
  return n_bb;
}

static_always_inline u16
mlx5_txq_wqe_tso (vlib_main_t *vm, mlx5_txq_t *tq, u32 mask, u16 tail, vlib_buffer_t *b,
		  mlx5_wqe_data_seg_t t, u16 n_free)
{
  mlx5_wqe_t *wqe = tq->dv_sq_wqes + (tail & mask);
  u32 inline_sz =
    vnet_buffer (b)->l4_hdr_offset - b->current_data + vnet_buffer2 (b)->gso_l4_hdr_sz;
  u32 ds_idx = (MLX5_TX_INLINE_OFF + inline_sz + 15) >> RDMA_MLX5_LOG2_DS_SZ, n_ds;
  u32 n_segs = mlx5_tx_n_segs (vm, b, MLX5_TX_MAX_GSO_SEGS);
  u8 cs_flags = MLX5_ETH_WQE_L4_CSUM;
  u16 n_bb;

  if (n_segs == 0)
    return 0;

  n_ds = ds_idx + n_segs - (b->current_length == inline_sz);
  n_bb = mlx5_tx_n_bb (n_ds);
  if (n_bb > n_free)
    return n_bb;

  if (b->flags & VNET_BUFFER_F_IS_IP4)
    cs_flags |= MLX5_ETH_WQE_L3_CSUM;

  mlx5_tx_ctrl (&wqe->ctrl, tq->tmpl_ctrl, tail, n_ds);
  wqe->opcode = MLX5_OPCODE_TSO;
  wqe->eseg = tq->tmpl_eseg;
  wqe->eseg.cs_flags = cs_flags;
  wqe->eseg.mss = clib_host_to_net_u16 (vnet_buffer2 (b)->gso_size);
  wqe->eseg.inline_hdr_sz = clib_host_to_net_u16 (inline_sz);
  mlx5_txq_wqe_inline (tq, mask, tail, b->data + b->current_data, inline_sz);
  mlx5_txq_wqe_dsegs (vm, tq, mask, tail, ds_idx, t, b, inline_sz);
  return n_bb;
}

static_always_inline u32
mlx5_txq_enq (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, u32 *from, u32 n_left, u32 *drops,
	      u32 *n_drops)
{
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  mlx5_wqe_t *wqe = 0;
  u32 mask = txq->size - 1;
  mlx5_wqe_data_seg_t t = {
    .seg.lkey = tq->lkey_be,
  };
  u16 tail = tq->tail, n_free = txq->size - (u16) (tq->tail - tq->head);
  u32 buf_tail = tq->buf_tail;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE + 8];
  mlx5_wqe_data_seg_t dsegs[VLIB_FRAME_SIZE];
  vlib_frame_bitmap_t slow_bmp;
  const u32 empw_max = MLX5_TX_EMPW_MAX_PACKETS;
  const u32 empw_full_bb = mlx5_tx_n_bb (MLX5_TX_EMPW_TITLE_DS + MLX5_TX_EMPW_MAX_PACKETS);
  int empw = tq->empw;
  u32 i = 0;

  vlib_get_buffers (vm, from, bufs, n_left);
  vlib_buffers_prefetch_pad (bufs, n_left, 8);
  mlx5_tx_prep (bufs, dsegs, slow_bmp, n_left, t);

  while (i < n_left)
    {
      vlib_buffer_t *b = bufs[i];
      u32 slot, n_fast = vlib_frame_bitmap_count_clear_bits_at_index (slow_bmp, i, n_left - i);
      u16 n_bb;

      /* fastpath with eMPW */
      if (empw && n_fast >= 2)
	{
	  mlx5_wqe_data_seg_t *s = dsegs + i;
	  u32 room = clib_min (n_free, mask + 1 - (tail & mask)), room0 = room;
	  u32 bt = buf_tail, slot = tail & mask, last = slot, n_rem = n_fast, n_done = n_fast, n;

	  while (n_rem >= 2 && room)
	    {
	      u16 n_bb;

	      n = clib_min (n_rem, empw_max);

	      /* never leave a single packet behind */
	      if (n_rem == n + 1)
		n--;

	      if (room < empw_full_bb)
		n = clib_min (n, (room << RDMA_MLX5_LOG2_WQE_DS) - MLX5_TX_EMPW_TITLE_DS);

	      n_bb = mlx5_txq_empw_wqe (tq, slot, tail, s, n, 0);
	      buf_tail += n;
	      tq->wqe_n_bb[slot] = n_bb;
	      tq->wqe_buf_tail[slot] = buf_tail;
	      last = slot;
	      slot += n_bb;
	      tail += n_bb;
	      room -= n_bb;
	      n_rem -= n;
	      s += n;
	    }

	  n_free -= room0 - room;
	  n_done -= n_rem;

	  if (n_done)
	    {
	      vlib_buffer_copy_indices_to_ring (tq->buffers, from + i, bt & tq->buf_mask,
						tq->buf_mask + 1, n_done);
	      wqe = tq->dv_sq_wqes + last;
	    }

	  i += n_done;
	  if (n_fast - n_done >= 2)
	    break;
	  continue;
	}

      slot = tail & mask;

      /* fastpath with WQE */
      if (n_fast)
	{
	  n_bb = mlx5_txq_wqe_send (vm, tq, mask, tail, b, t, n_free);
	  if (n_bb > n_free)
	    break;
	  goto one_pkt;
	}

      /* slowpath */
      if (empw && mlx5_tx_empw_ok (b->flags))
	{
	  u32 n_bb_avail = clib_min (n_free, mask + 1 - slot);
	  u32 max = clib_min (n_left - i, MLX5_TX_EMPW_MAX_PACKETS), n;

	  if (n_bb_avail == 0)
	    break;

	  max = clib_min (max, (n_bb_avail << RDMA_MLX5_LOG2_WQE_DS) - MLX5_TX_EMPW_TITLE_DS);
	  n = mlx5_txq_enq_empw_offload (tq, mask, tail, from + i, bufs + i, dsegs + i, max,
					 &buf_tail, &n_bb);
	  if (n)
	    {
	      i += n;
	      goto next;
	    }
	}

      if (PREDICT_FALSE (b->flags & VNET_BUFFER_F_GSO))
	n_bb = mlx5_txq_wqe_tso (vm, tq, mask, tail, b, t, n_free);
      else
	n_bb = mlx5_txq_wqe_send (vm, tq, mask, tail, b, t, n_free);

      if (PREDICT_FALSE (n_bb == 0))
	{
	  drops[n_drops[0]++] = from[i++];
	  continue;
	}

      if (n_bb > n_free)
	break;

    one_pkt:
      tq->buffers[buf_tail++ & tq->buf_mask] = from[i++];

    next:
      wqe = tq->dv_sq_wqes + slot;
      tq->wqe_n_bb[slot] = n_bb;
      tq->wqe_buf_tail[slot] = buf_tail;
      tail += n_bb;
      n_free -= n_bb;
    }

  if (wqe)
    {
      wqe->ctrl.seg.fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;
      __atomic_store_n (&tq->dv_sq_dbrec[MLX5_SND_DBR], clib_host_to_net_u32 (tail),
			__ATOMIC_RELEASE);
      __atomic_store_n (&tq->dv_sq_db[0], *(u64 *) wqe, __ATOMIC_RELEASE);
      tq->tail = tail;
      tq->buf_tail = buf_tail;
    }
  return i;
}

static_always_inline void
mlx5_txq_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *from,
		u32 n, u16 tail, u32 buf_tail)
{
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  u32 hw_if_index = vnet_dev_get_tx_queue_if_hw_if_index (txq);
  u32 mask = txq->size - 1;

  for (u32 i = 0; i < n; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 slot = tail & mask;
      u8 sent = buf_tail != tq->buf_tail && tq->buffers[buf_tail & tq->buf_mask] == from[i];
      mlx5_wqe_t *wqe = tq->dv_sq_wqes + slot;
      u8 n_ds = ((u8 *) &wqe->ctrl.seg.qpn_ds)[3];
      u8 empw = sent && wqe->opcode == MLX5_OPCODE_ENHANCED_MPSW;
      u32 n_copy = sent ? (empw ? MLX5_TX_EMPW_TITLE_DS + 1 : n_ds) : 0;
      mlx5_tx_trace_t *tr;

      if (b->flags & VLIB_BUFFER_IS_TRACED)
	{
	  tr = vlib_add_trace (vm, node, b, sizeof (*tr) + (n_copy << RDMA_MLX5_LOG2_DS_SZ));
	  *tr = (mlx5_tx_trace_t) {
	    .qid = txq->queue_id,
	    .wqe_index = slot,
	    .dropped = sent == 0,
	    .n_ds = n_copy,
	    .hw_if_index = hw_if_index,
	    .buffer_index = from[i],
	    .data_len = vlib_buffer_length_in_chain (vm, b),
	  };
	  for (u32 j = 0; j < n_copy; j++)
	    {
	      u32 ds = j;
	      if (empw && j == MLX5_TX_EMPW_TITLE_DS)
		{
		  tr->empw_n_pkts = n_ds - MLX5_TX_EMPW_TITLE_DS;
		  tr->empw_pkt = tr->empw_n_pkts - (tq->wqe_buf_tail[slot] - buf_tail);
		  ds = MLX5_TX_EMPW_TITLE_DS + tr->empw_pkt;
		}
	      *(u8x16u *) (tr->wqe + (j << RDMA_MLX5_LOG2_DS_SZ)) =
		mlx5_txq_ds (tq, mask, slot, ds)->vec128.as_u8x16;
	    }
	}
      if (sent && ++buf_tail == tq->wqe_buf_tail[slot])
	tail += tq->wqe_n_bb[slot];
    }
}

static_always_inline uword
mlx5_tx_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 drops[VLIB_FRAME_SIZE];
  u32 n_drops = 0, n_enq = 0;
  int n_retries = 2;
  u32 buf_tail;
  u16 tail;

  vnet_dev_tx_queue_lock_if_needed (txq);

  tail = tq->tail;
  buf_tail = tq->buf_tail;
  while (n_retries-- && n_enq < n_left)
    {
      u32 n;
      mlx5_txq_deq (vm, node, txq);
      n = mlx5_txq_enq (vm, txq, from + n_enq, n_left - n_enq, drops, &n_drops);
      n_enq += n;
      if (n == 0)
	break;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    mlx5_txq_trace (vm, node, txq, from, n_left, tail, buf_tail);

  vnet_dev_tx_queue_unlock_if_needed (txq);

  if (PREDICT_FALSE (n_drops))
    {
      vlib_buffer_free (vm, drops, n_drops);
      vlib_error_count (vm, node->node_index, RDMA_MLX5_TX_NODE_CTR_CHAIN_TOO_LONG, n_drops);
    }

  if (PREDICT_FALSE (n_enq < n_left))
    {
      vlib_buffer_free (vm, from + n_enq, n_left - n_enq);
      vlib_error_count (vm, node->node_index, RDMA_MLX5_TX_NODE_CTR_NO_FREE_SLOTS, n_left - n_enq);
    }

  return n_enq - n_drops;
}

VNET_DEV_NODE_FN (mlx5_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return mlx5_tx_node_inline (vm, node, frame);
}
