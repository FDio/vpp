/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/counters.h>
#include <mlx5.h>

#define RDMA_MLX5_RXQ_REFILL_BATCH_SZ 32

STATIC_ASSERT ((VLIB_FRAME_SIZE % 16) == 0, "rx SIMD passes overrun to a multiple of 16");
#define MLX5_CQE_FLAGS_BE(...) clib_host_to_net_u16 (((mlx5_cqe_flags_t) { __VA_ARGS__ }).as_u16)
#define MLX5_CQE_L3_MASK_BE    MLX5_CQE_FLAGS_BE (.l3_hdr_type = 3, .l3_ok = 1, )
#define MLX5_CQE_L3_IP4_BAD_BE MLX5_CQE_FLAGS_BE (.l3_hdr_type = MLX5_CQE_L3_HDR_TYPE_IPV4, )
#define MLX5_CQE_L4_TYPE_BE    MLX5_CQE_FLAGS_BE (.l4_hdr_type = 7, )
#define MLX5_CQE_L4_OK_BE      MLX5_CQE_FLAGS_BE (.l4_ok = 1, )

static_always_inline u32
mlx5_cqe_l4_flags (u16 raw_flags)
{
  mlx5_cqe_flags_t f = { .as_u16 = clib_net_to_host_u16 (raw_flags) };

  if (f.l4_hdr_type == 0)
    return 0;
  return VNET_BUFFER_F_L4_CHECKSUM_COMPUTED | (f.l4_ok ? VNET_BUFFER_F_L4_CHECKSUM_CORRECT : 0);
}

static_always_inline void
mlx5_cqe_flags_check (u16 f, int *ip4_bad, int *l4_bad)
{
  *ip4_bad |= (f & MLX5_CQE_L3_MASK_BE) == MLX5_CQE_L3_IP4_BAD_BE;
  *l4_bad |= (f & MLX5_CQE_L4_TYPE_BE) == 0 || (f & MLX5_CQE_L4_OK_BE) == 0;
}

static_always_inline void
mlx5_va_to_be (u64 *va, u32 n)
{
#if defined(CLIB_HAVE_VEC256)
  for (u64x4 *v = (u64x4 *) va, *e = v + n / 4; v < e; v++)
    v[0] = u64x4_byte_swap (v[0]);
#elif defined(CLIB_HAVE_VEC128)
  for (u8x16 *v = (u8x16 *) va, *e = v + n / 2; v < e; v++)
    v[0] = u8x16_shuffle (v[0], 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
#else
  for (u32 i = 0; i < n; i++)
    va[i] = clib_host_to_net_u64 (va[i]);
#endif
}

typedef struct
{
#if defined(CLIB_HAVE_VEC512)
  u8x64 v;
#elif defined(CLIB_HAVE_VEC256)
  u8x32 v[2];
#elif defined(CLIB_HAVE_VEC128)
  u8x16 v[4];
#else
  vlib_buffer_template_t v;
#endif
} mlx5_rx_tmpl_t;

static_always_inline mlx5_rx_tmpl_t
mlx5_rx_tmpl_load (vlib_buffer_template_t *bt)
{
#if defined(CLIB_HAVE_VEC512)
  return (mlx5_rx_tmpl_t) {
    .v = *(u8x64 *) bt,
  };
#elif defined(CLIB_HAVE_VEC256)
  return (mlx5_rx_tmpl_t){ .v = { bt->as_u8x32[0], bt->as_u8x32[1], }, };
#elif defined(CLIB_HAVE_VEC128)
  return (mlx5_rx_tmpl_t){
    .v = { bt->as_u8x16[0], bt->as_u8x16[1], bt->as_u8x16[2], bt->as_u8x16[3], },
  };
#else
  return (mlx5_rx_tmpl_t) {
    .v = *bt,
  };
#endif
}

static_always_inline void
mlx5_rx_tmpl_store (vlib_buffer_t *b, mlx5_rx_tmpl_t t, u16 len)
{
#if defined(CLIB_HAVE_VEC512)
  *(u8x64 *) b = t.v;
#elif defined(CLIB_HAVE_VEC256)
  ((u8x32 *) b)[0] = t.v[0];
  ((u8x32 *) b)[1] = t.v[1];
#elif defined(CLIB_HAVE_VEC128)
  ((u8x16 *) b)[0] = t.v[0];
  ((u8x16 *) b)[1] = t.v[1];
  ((u8x16 *) b)[2] = t.v[2];
  ((u8x16 *) b)[3] = t.v[3];
#else
  b->template = t.v;
#endif
  b->current_length = len;
}

static_always_inline mlx5dv_mini_cqe_t *
mlx5_mini_cqe_array (mlx5dv_cqe_t *cqes, u32 cq_ci, u32 k, u32 mask)
{
  return (mlx5dv_mini_cqe_t *) (cqes + ((cq_ci + (k & ~7) + (k < 8)) & mask));
}

static_always_inline void
mlx5_cqe_set_owner (mlx5dv_cqe_t *cqe, u32 n_left, u8 owner)
{
  while (n_left >= 8)
    {
      cqe[0].op_own.as_u8 = owner;
      cqe[1].op_own.as_u8 = owner;
      cqe[2].op_own.as_u8 = owner;
      cqe[3].op_own.as_u8 = owner;
      cqe[4].op_own.as_u8 = owner;
      cqe[5].op_own.as_u8 = owner;
      cqe[6].op_own.as_u8 = owner;
      cqe[7].op_own.as_u8 = owner;
      n_left -= 8;
      cqe += 8;
    }

  while (n_left)
    {
      cqe[0].op_own.as_u8 = owner;
      n_left--;
      cqe++;
    }
}

static_always_inline void
mlx5_compressed_cqe_reset_owner (mlx5_rxq_t *mq, u32 n_mini_cqes, u32 cq_ci, u32 mask)
{
  mlx5dv_cqe_t *cqes = (mlx5dv_cqe_t *) mq->dv_cq_cqes;
  u32 offset, cq_size = mask + 1, n;
  u8 owner;

  /* first CQE is reset by hardware */
  cq_ci++;
  n_mini_cqes--;

  offset = cq_ci & mask;
  owner = ((mlx5_cqe_op_own_t) {
	     .opcode = MLX5_CQE_INVALID,
	     .owner = (cq_ci & cq_size) != 0,
	   })
	    .as_u8;

  if (offset + n_mini_cqes < cq_size)
    {
      mlx5_cqe_set_owner (cqes + offset, n_mini_cqes, owner);
    }
  else
    {
      n = cq_size - offset;
      mlx5_cqe_set_owner (cqes + offset, n, owner);
      mlx5_cqe_set_owner (cqes, n_mini_cqes - n, owner ^ 1);
    }
}

static_always_inline void
mlx5_rx_cqe_copy_mini (mlx5_rxq_t *mq, mlx5_rx_cqe_copy_t *tc, mlx5dv_cqe_t *title, u32 cq_ci,
		       u32 mask, u32 skip, u32 n)
{
  mlx5dv_cqe_t *cqes = (mlx5dv_cqe_t *) mq->dv_cq_cqes;
  struct mlx5_cqe64 *t = (struct mlx5_cqe64 *) title;

  for (u32 k = skip; k < skip + n; k++, tc++)
    {
      mlx5dv_mini_cqe_t *m = mlx5_mini_cqe_array (cqes, cq_ci, k, mask);

      *tc = (mlx5_rx_cqe_copy_t) {
	.cqe = *t,
	.mini_cqe = m[k & 7],
	.compressed = 1,
      };
    }
}

typedef struct
{
  u32 n_bytes;
  u32 n_segs;
  u8 ip4_bad;
  u8 l4_ok;
  u8 filler;
} mlx5_rx_finish_t;

static_always_inline mlx5_rx_finish_t
mlx5_rx_cqe_finish (u32 *bc, u16 *cf, u32 n, const int striding)
{
  u16 l3_mask = MLX5_CQE_L3_MASK_BE, l3_ip4_bad = MLX5_CQE_L3_IP4_BAD_BE;
  u16 l4_type = MLX5_CQE_L4_TYPE_BE, l4_ok = MLX5_CQE_L4_OK_BE;
  mlx5_rx_finish_t r = {};

#if defined(CLIB_HAVE_VEC256)
  u16x16u *fv = (u16x16u *) cf;
  u32x8u *bv = (u32x8u *) bc;
  u16x16 bad3 = {}, bad4 = {}, zero = {};
  u16x16 idx = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  };
  u16x16 l3_mask_v = u16x16_splat (l3_mask), l3_ip4_bad_v = u16x16_splat (l3_ip4_bad);
  u16x16 l4_type_v = u16x16_splat (l4_type), l4_ok_v = u16x16_splat (l4_ok);
  u32x8 sv = {}, segv = {}, fillv = {}, idx0 = { 0, 1, 2, 3, 4, 5, 6, 7, }, idx1 = idx0 + 8;
  u32x8 bcm = u32x8_splat (CQE_BC_BYTE_COUNT_MASK), sm = u32x8_splat (0x3fff);

  for (u32 i = 0; i < n; i += 16, fv++, bv += 2)
    {
      u16x16 f = fv[0], valid = idx < u16x16_splat (n - i);
      u32x8 b0 = bv[0], b1 = bv[1], r0 = u32x8_splat (n - i);

      b0 = u32x8_byte_swap (b0);
      b1 = u32x8_byte_swap (b1);
      bv[0] = b0;
      bv[1] = b1;
      b0 &= idx0 < r0;
      b1 &= idx1 < r0;

      if (striding)
	{
	  sv += (b0 & bcm) + (b1 & bcm);
	  segv += ((b0 >> CQE_BC_CONSUMED_STRIDES_SHIFT) & sm) +
		  ((b1 >> CQE_BC_CONSUMED_STRIDES_SHIFT) & sm);
	  fillv |= b0 | b1;
	}
      else
	sv += b0 + b1;

      bad3 |= ((f & l3_mask_v) == l3_ip4_bad_v) & valid;
      bad4 |= (((f & l4_type_v) == zero) | ((f & l4_ok_v) == zero)) & valid;
    }

  r.n_bytes = u32x8_sum_elts (sv);
  if (striding)
    {
      r.n_segs = u32x8_sum_elts (segv);
      r.filler = !u32x8_is_all_zero (fillv & u32x8_splat (CQE_BC_FILLER_MASK));
    }
  r.ip4_bad = !u16x16_is_all_zero (bad3);
  r.l4_ok = u16x16_is_all_zero (bad4);
#elif defined(CLIB_HAVE_VEC128)
  u16x8u *fv = (u16x8u *) cf;
  u32x4u *bv = (u32x4u *) bc;
  u16x8 bad3 = {}, bad4 = {}, zero = {},
	idx = {
	  0, 1, 2, 3, 4, 5, 6, 7,
	};
  u16x8 l3_mask_v = u16x8_splat (l3_mask), l3_ip4_bad_v = u16x8_splat (l3_ip4_bad);
  u16x8 l4_type_v = u16x8_splat (l4_type), l4_ok_v = u16x8_splat (l4_ok);
  u32x4 sv = {}, segv = {}, fillv = {}, idx0 = { 0, 1, 2, 3, }, idx1 = idx0 + 4;
  u32x4 bcm = u32x4_splat (CQE_BC_BYTE_COUNT_MASK), sm = u32x4_splat (0x3fff);

  for (u32 i = 0; i < n; i += 8, fv++, bv += 2)
    {
      u16x8 f = fv[0], valid = idx < u16x8_splat (n - i);
      u32x4 b0 = bv[0], b1 = bv[1], r0 = u32x4_splat (n - i);

      b0 = u32x4_byte_swap (b0);
      b1 = u32x4_byte_swap (b1);
      bv[0] = b0;
      bv[1] = b1;
      b0 &= idx0 < r0;
      b1 &= idx1 < r0;

      if (striding)
	{
	  sv += (b0 & bcm) + (b1 & bcm);
	  segv += ((b0 >> CQE_BC_CONSUMED_STRIDES_SHIFT) & sm) +
		  ((b1 >> CQE_BC_CONSUMED_STRIDES_SHIFT) & sm);
	  fillv |= b0 | b1;
	}
      else
	sv += b0 + b1;

      bad3 |= ((f & l3_mask_v) == l3_ip4_bad_v) & valid;
      bad4 |= (((f & l4_type_v) == zero) | ((f & l4_ok_v) == zero)) & valid;
    }

  r.n_bytes = u32x4_sum_elts (sv);
  if (striding)
    {
      r.n_segs = u32x4_sum_elts (segv);
      r.filler = !u32x4_is_all_zero (fillv & u32x4_splat (CQE_BC_FILLER_MASK));
    }
  r.ip4_bad = !u16x8_is_all_zero (bad3);
  r.l4_ok = u16x8_is_all_zero (bad4);
#else
  int ip4b = 0, l4_bad = 0;

  for (u32 i = 0; i < n; i++)
    {
      u32 b = clib_net_to_host_u32 (bc[i]);

      bc[i] = b;
      mlx5_cqe_flags_check (cf[i], &ip4b, &l4_bad);

      if (striding)
	{
	  r.n_bytes += b & CQE_BC_BYTE_COUNT_MASK;
	  r.n_segs += (b & CQE_BC_CONSUMED_STRIDES_MASK) >> CQE_BC_CONSUMED_STRIDES_SHIFT;
	  r.filler |= (b & CQE_BC_FILLER_MASK) != 0;
	}
      else
	r.n_bytes += b;
    }

  r.ip4_bad = ip4b;
  r.l4_ok = !l4_bad;
#endif

  return r;
}

static_always_inline u32
mlx5_rxq_poll (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq, u32 *byte_cnt,
	       u16 *cqe_flags, mlx5_rx_cqe_copy_t *tc)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  mlx5dv_cqe_t *cqes = (mlx5dv_cqe_t *) mq->dv_cq_cqes;
  u32 mask = mq->dv_cq_size - 1;
  u32 dv_cq_idx = mq->dv_cq_idx, n_rx = 0;

  while (n_rx < VLIB_FRAME_SIZE)
    {
      mlx5dv_cqe_t *cqe = cqes + (dv_cq_idx & mask);
      u8 owner = (dv_cq_idx & (mask + 1)) != 0;
      mlx5_cqe_op_own_t op;

      clib_prefetch_load (cqes + ((dv_cq_idx + 8) & mask));
      op.as_u8 = __atomic_load_n (&cqe->op_own.as_u8, __ATOMIC_ACQUIRE);

      if (PREDICT_FALSE (op.owner != owner))
	break;

      if (op.opcode == MLX5_CQE_RESP_SEND && op.format == MLX5_CQE_FORMAT_COMPRESSED)
	{
	  u32 n_mini_cqes = clib_net_to_host_u32 (cqe->mini_cqe_num);
	  u32 skip = mq->mini_cqe_skip;
	  u32 n = clib_min (n_mini_cqes - skip, VLIB_FRAME_SIZE - n_rx);
	  u16 f = cqe->flags;

	  ASSERT (n_mini_cqes <= VLIB_FRAME_SIZE && skip < n_mini_cqes);

	  if (PREDICT_FALSE (tc != 0))
	    {
	      mlx5_rx_cqe_copy_mini (mq, tc, cqe, dv_cq_idx, mask, skip, n);
	      tc += n;
	    }

	  for (u32 k = skip, end = skip + n; k < end;)
	    {
	      mlx5dv_mini_cqe_t *m = mlx5_mini_cqe_array (cqes, dv_cq_idx, k, mask);

	      for (u32 e = clib_min (end, (k | 7) + 1); k < e; k++)
		{
		  *byte_cnt++ = m[k & 7].byte_count;
		  *cqe_flags++ = f;
		}
	    }

	  n_rx += n;

	  if (PREDICT_FALSE (skip + n < n_mini_cqes))
	    {
	      mq->mini_cqe_skip = skip + n;
	      break;
	    }

	  mq->mini_cqe_skip = 0;
	  mlx5_compressed_cqe_reset_owner (mq, n_mini_cqes, dv_cq_idx, mask);
	  dv_cq_idx += n_mini_cqes;
	  continue;
	}

      if (PREDICT_TRUE (op.opcode == MLX5_CQE_RESP_SEND && op.format == MLX5_CQE_FORMAT_NONE))
	{
	  byte_cnt[0] = cqe->byte_cnt;
	  cqe_flags[0] = cqe->flags;
	  if (PREDICT_FALSE (tc != 0))
	    *tc++ = (mlx5_rx_cqe_copy_t) {
	      .cqe = *(struct mlx5_cqe64 *) cqe,
	    };
	  n_rx++;
	  dv_cq_idx++;
	  byte_cnt++;
	  cqe_flags++;
	  continue;
	}

      if (op.opcode == MLX5_CQE_RESP_ERR || op.opcode == MLX5_CQE_REQ_ERR)
	{
	  if (mq->rx_error == 0)
	    vlib_error_count (vm, node->node_index, RDMA_MLX5_RX_NODE_CTR_DESC_ERROR, 1);
	  mq->rx_error_syndrome = ((struct mlx5_err_cqe *) cqe)->syndrome;
	  mq->rx_error = 1;
	}

      break;
    }

  if (n_rx)
    {
      mq->dv_cq_idx = dv_cq_idx;
      __atomic_store_n (&mq->dv_cq_dbrec[0], clib_host_to_net_u32 (dv_cq_idx & MLX5_CQ_DB_CI_MASK),
			__ATOMIC_RELEASE);
    }

  return n_rx;
}
