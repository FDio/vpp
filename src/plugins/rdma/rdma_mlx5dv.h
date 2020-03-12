/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#ifndef _RDMA_MLX5DV_H_
#define _RDMA_MLX5DV_H_

#undef always_inline
#include <infiniband/mlx5dv.h>
#define always_inline static_always_inline

/* CQE flags - bits 16-31 of qword at offset 0x1c */
#define CQE_FLAG_L4_OK			10
#define CQE_FLAG_L3_OK			9
#define CQE_FLAG_L2_OK			8
#define CQE_FLAG_IP_FRAG		7
#define CQE_FLAG_L4_HDR_TYPE(f)		(((f) >> 4) & 7)
#define CQE_FLAG_L3_HDR_TYPE_SHIFT	(2)
#define CQE_FLAG_L3_HDR_TYPE_MASK	(3 << CQE_FLAG_L3_HDR_TYPE_SHIFT)
#define CQE_FLAG_L3_HDR_TYPE(f)		(((f) & CQE_FLAG_L3_HDR_TYPE_MASK)  >> CQE_FLAG_L3_HDR_TYPE_SHIFT)
#define CQE_FLAG_L3_HDR_TYPE_IP4	1
#define CQE_FLAG_L3_HDR_TYPE_IP6	2
#define CQE_FLAG_IP_EXT_OPTS		1

typedef struct
{
  struct
  {
    u8 pad1[28];
    u16 flags;
    u8 pad2[14];
    union
    {
      u32 byte_cnt;
      u32 mini_cqe_num;
    };
    u8 pad3[15];
    u8 opcode_cqefmt_se_owner;
  };
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
} mlx5dv_rwq_t;

#define foreach_cqe_rx_field \
  _(0x1c, 26, 26, l4_ok)	\
  _(0x1c, 25, 25, l3_ok)	\
  _(0x1c, 24, 24, l2_ok)	\
  _(0x1c, 23, 23, ip_frag)	\
  _(0x1c, 22, 20, l4_hdr_type)	\
  _(0x1c, 19, 18, l3_hdr_type)	\
  _(0x1c, 17, 17, ip_ext_opts)	\
  _(0x1c, 16, 16, cv)	\
  _(0x2c, 31,  0, byte_cnt)	\
  _(0x30, 63,  0, timestamp)	\
  _(0x38, 31, 24, rx_drop_counter)	\
  _(0x38, 23,  0, flow_tag)	\
  _(0x3c, 31, 16, wqe_counter)	\
  _(0x3c, 15,  8, signature)	\
  _(0x3c,  7,  4, opcode)	\
  _(0x3c,  3,  2, cqe_format)	\
  _(0x3c,  1,  1, sc)	\
  _(0x3c,  0,  0, owner)


/* inline functions */

static inline u32
mlx5_get_u32 (void *start, int offset)
{
  return clib_net_to_host_u32 (*(u32 *) (((u8 *) start) + offset));
}

static inline u64
mlx5_get_u64 (void *start, int offset)
{
  return clib_net_to_host_u64 (*(u64 *) (((u8 *) start) + offset));
}

static inline void
mlx5_set_u32 (void *start, int offset, u32 value)
{
  (*(u32 *) (((u8 *) start) + offset)) = clib_host_to_net_u32 (value);
}

static inline void
mlx5_set_u64 (void *start, int offset, u64 value)
{
  (*(u64 *) (((u8 *) start) + offset)) = clib_host_to_net_u64 (value);
}

static inline void
mlx5_set_bits (void *start, int offset, int first, int last, u32 value)
{
  u32 mask = (1 << (first - last + 1)) - 1;
  u32 old = mlx5_get_u32 (start, offset);
  if ((last == 0) && (first == 31))
    {
      mlx5_set_u32 (start, offset, value);
      return;
    }
  ASSERT (value == (value & mask));
  value &= mask;
  old &= ~(mask << last);
  mlx5_set_u32 (start, offset, old | value << last);
}

static inline u32
mlx5_get_bits (void *start, int offset, int first, int last)
{
  u32 value = mlx5_get_u32 (start, offset);
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}


#endif /* RDMA_MLX5DV_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
