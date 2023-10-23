/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _CNXK_HW_DEFS_H_
#define _CNXK_HW_DEFS_H_

#include <vppinfra/clib.h>
#include <roc/base/roc_api.h>

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
} cnxk_nix_lf_cq_op_status_t;

STATIC_ASSERT_SIZEOF (cnxk_nix_lf_cq_op_status_t, 8);

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
} cnxk_npa_lf_aura_batch_free0_t;

STATIC_ASSERT_SIZEOF (cnxk_npa_lf_aura_batch_free0_t, 8);

typedef struct
{
  cnxk_npa_lf_aura_batch_free0_t w0;
  u64 data[15];
} cnxk_npa_lf_aura_batch_free_line_t;

STATIC_ASSERT_SIZEOF (cnxk_npa_lf_aura_batch_free_line_t, 128);

typedef union
{
  struct npa_batch_alloc_compare_s compare_s;
  u64 as_u64;
} cnxk_npa_batch_alloc_compare_t;

typedef union
{
  struct
  {
    union nix_send_hdr_w0_u hdr_w0;
    union nix_send_hdr_w1_u hdr_w1;
    union nix_send_sg_s sg[8];
  };
  u128 as_u128[5];
} cnxk_tx_desc_t;

STATIC_ASSERT_SIZEOF (cnxk_tx_desc_t, 80);

#endif /* _CNXK_HW_DEFS_H_ */
