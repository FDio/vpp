/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vppinfra/clib.h>
#undef always_inline
#include <infiniband/mlx5dv.h>
#define always_inline static_always_inline
#include <vppinfra/error.h>

/* CQE byte count (Striding RQ) */
#define CQE_BC_FILLER_MASK	      (1 << 31)
#define CQE_BC_CONSUMED_STRIDES_SHIFT (16)
#define CQE_BC_CONSUMED_STRIDES_MASK  (0x3fff << CQE_BC_CONSUMED_STRIDES_SHIFT)
#define CQE_BC_BYTE_COUNT_MASK	      (0xffff)
#define MLX5_CQE_FORMAT_NONE	      0
#define MLX5_CQE_FORMAT_COMPRESSED    3
#define MLX5_CQ_DB_CI_MASK	      0xffffff

typedef union
{
  struct
  {
    u16 cv : 1;
    u16 ip_ext_opts : 1;
    u16 l3_hdr_type : 2;
    u16 l4_hdr_type : 3;
    u16 ip_frag : 1;
    u16 l2_ok : 1;
    u16 l3_ok : 1;
    u16 l4_ok : 1;
    u16 rsvd : 5;
  };
  u16 as_u16;
} mlx5_cqe_flags_t;

STATIC_ASSERT_SIZEOF (mlx5_cqe_flags_t, 2);

typedef union
{
  struct
  {
    u8 owner : 1;
    u8 se : 1;
    u8 format : 2;
    u8 opcode : 4;
  };
  u8 as_u8;
} mlx5_cqe_op_own_t;

STATIC_ASSERT_SIZEOF (mlx5_cqe_op_own_t, 1);

typedef struct
{
  u8 pad1[28];
  u16 flags;
  u8 pad2[14];
  union
  {
    u32 byte_cnt;
    u32 mini_cqe_num;
  };
  u8 pad3[12];
  u16 wqe_counter;
  u8 signature;
  mlx5_cqe_op_own_t op_own;
} mlx5dv_cqe_t;

STATIC_ASSERT_SIZEOF (mlx5dv_cqe_t, 64);

typedef struct
{
  union
  {
    u32 checksum;
    u32 rx_hash_result;
  };
  u32 byte_count;
} mlx5dv_mini_cqe_t;

typedef struct
{
  u64 dsz_and_lkey;
  u64 addr;
} mlx5dv_wqe_ds_t; /* a WQE data segment */

typedef struct
{
  u8 rsvd0[2];
  u16 next_wqe_index;
  u8 signature;
  u8 rsvd1[11];
} mlx5dv_wqe_srq_next_t;
