/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_IO_DEFS_H_
#define _ENA_IO_DEFS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/vector.h>

typedef struct
{
  u16 length; /* 0 = 64K */
  u8 reserved2;
  union
  {
    struct
    {
      u8 phase : 1;
      u8 reserved1 : 1;
      u8 first : 1;    /* first descriptor in transaction */
      u8 last : 1;     /* last descriptor in transaction */
      u8 comp_req : 1; /* should completion be posted? */
      u8 reserved5 : 1;
      u8 reserved67 : 2;
    };
    u8 ctrl;
  };
  u16 req_id;
  u16 reserved6;
} ena_rx_desc_lo_t;

STATIC_ASSERT_SIZEOF (ena_rx_desc_lo_t, 8);

typedef struct
{
  union
  {
    struct
    {
      ena_rx_desc_lo_t lo;
      u32 buff_addr_lo;
      u16 buff_addr_hi;
      u16 reserved16_w3;
    };
    u64x2 as_u64x2;
  };
} ena_rx_desc_t;

STATIC_ASSERT_SIZEOF (ena_rx_desc_t, 16);

#define foreach_ena_rx_cdesc_status                                           \
  _ (5, l3_proto_idx)                                                         \
  _ (2, src_vlan_cnt)                                                         \
  _ (1, _reserved7)                                                           \
  _ (5, l4_proto_idx)                                                         \
  _ (1, l3_csum_err)                                                          \
  _ (1, l4_csum_err)                                                          \
  _ (1, ipv4_frag)                                                            \
  _ (1, l4_csum_checked)                                                      \
  _ (7, _reserved17)                                                          \
  _ (1, phase)                                                                \
  _ (1, l3_csum2)                                                             \
  _ (1, first)                                                                \
  _ (1, last)                                                                 \
  _ (2, _reserved28)                                                          \
  _ (1, buffer)                                                               \
  _ (1, _reserved31)

typedef struct
{
  union
  {
    struct
    {
#define _(b, n) u32 n : (b);
      foreach_ena_rx_cdesc_status
#undef _
    };
    u32 as_u32;
  };
} ena_rx_cdesc_status_t;

typedef struct
{
  ena_rx_cdesc_status_t status;
  u16 length;
  u16 req_id;
  u32 hash;
  u16 sub_qid;
  u8 offset;
  u8 reserved;
} ena_rx_cdesc_t;

STATIC_ASSERT_SIZEOF (ena_rx_cdesc_t, 16);

#define foreach_ena_tx_desc                                                   \
  /* len_ctrl */                                                              \
  _ (16, length)                                                              \
  _ (6, req_id_hi)                                                            \
  _ (1, _reserved0_22)                                                        \
  _ (1, meta_desc)                                                            \
  _ (1, phase)                                                                \
  _ (1, _reserved0_25)                                                        \
  _ (1, first)                                                                \
  _ (1, last)                                                                 \
  _ (1, comp_req)                                                             \
  _ (2, _reserved0_29)                                                        \
  _ (1, _reserved0_31)                                                        \
  /* meta_ctrl */                                                             \
  _ (4, l3_proto_idx)                                                         \
  _ (1, df)                                                                   \
  _ (2, _reserved1_5)                                                         \
  _ (1, tso_en)                                                               \
  _ (5, l4_proto_idx)                                                         \
  _ (1, l3_csum_en)                                                           \
  _ (1, l4_csum_en)                                                           \
  _ (1, ethernet_fcs_dis)                                                     \
  _ (1, _reserved1_16)                                                        \
  _ (1, l4_csum_partial)                                                      \
  _ (3, _reserved_1_18)                                                       \
  _ (1, _reserved_1_21)                                                       \
  _ (10, req_id_lo)

typedef struct
{
  union
  {
    struct
    {
#define _(b, n) u32 n : (b);
      foreach_ena_tx_desc
#undef _
	u32 buff_addr_lo;
      u16 buff_addr_hi;
      u8 _reserved3_16;
      u8 header_length;
    };

    u16x8 as_u16x8;
    u32x4 as_u32x4;
    u64x2 as_u64x2;
  };
} ena_tx_desc_t;

STATIC_ASSERT_SIZEOF (ena_tx_desc_t, 16);

typedef union
{
  struct
  {
    u16 req_id;
    u8 status;
    union
    {
      struct
      {
	u8 phase : 1;
      };
      u8 flags;
    };
    u16 sub_qid;
    u16 sq_head_idx;
  };
  u64 as_u64;
} ena_tx_cdesc_t;

STATIC_ASSERT_SIZEOF (ena_tx_cdesc_t, 8);

#endif /* _ENA_IO_DEFS_H_ */
