/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#ifndef _OCT_HW_DEFS_H_
#define _OCT_HW_DEFS_H_

#include <vppinfra/clib.h>
#include <base/roc_api.h>

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
} oct_nix_lf_cq_op_status_t;

STATIC_ASSERT_SIZEOF (oct_nix_lf_cq_op_status_t, 8);

typedef union
{
  struct
  {
    u64 aura : 20;
    u64 _reseved20 : 12;
    u64 count_eot : 1;
    u64 _reserved33 : 30;
    u64 fabs : 1;
  };
  u64 as_u64;
} oct_npa_lf_aura_batch_free0_t;

STATIC_ASSERT_SIZEOF (oct_npa_lf_aura_batch_free0_t, 8);

typedef struct
{
  oct_npa_lf_aura_batch_free0_t w0;
  u64 data[15];
} oct_npa_lf_aura_batch_free_line_t;

STATIC_ASSERT_SIZEOF (oct_npa_lf_aura_batch_free_line_t, 128);

typedef union
{
  struct npa_batch_alloc_compare_s compare_s;
  u64 as_u64;
} oct_npa_batch_alloc_compare_t;

typedef union
{
  struct
  {
    union nix_send_hdr_w0_u hdr_w0;
    union nix_send_hdr_w1_u hdr_w1;
    union nix_send_sg_s sg[8];
  };
  u128 as_u128[5];
} oct_tx_desc_t;

STATIC_ASSERT_SIZEOF (oct_tx_desc_t, 80);

typedef union
{
  u128 dwords[8];
  u64 words[16];
} lmt_line_t;

STATIC_ASSERT_SIZEOF (lmt_line_t, 1 << ROC_LMT_LINE_SIZE_LOG2);

typedef union
{
  union nix_rx_parse_u f;
  u64 w[7];
} oct_nix_rx_parse_t;

STATIC_ASSERT_SIZEOF (oct_nix_rx_parse_t, 56);

typedef struct
{
  CLIB_ALIGN_MARK (desc, 128);
  struct nix_cqe_hdr_s hdr;
  oct_nix_rx_parse_t parse;
  struct nix_rx_sg_s sg0;
  void *segs0[3];
  struct nix_rx_sg_s sg1;
  void *segs1[3];
} oct_nix_rx_cqe_desc_t;

STATIC_ASSERT_SIZEOF (oct_nix_rx_cqe_desc_t, 128);

#endif /* _OCT_HW_DEFS_H_ */
