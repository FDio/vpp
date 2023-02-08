/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_IO_DEFS_H_
#define _ENA_IO_DEFS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

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
  u32 buff_addr_lo;
  u16 buff_addr_hi;
  u16 reserved16_w3;
} ena_rx_desc_t;

STATIC_ASSERT_SIZEOF (ena_rx_desc_t, 16);

typedef struct
{
  union
  {
    struct
    {
      u32 l3_proto_idx : 5;
      u32 src_vlan_cnt : 2;
      u32 reserved7 : 1;
      u32 l4_proto_idx : 5;
      u32 l3_csum_err : 1; /* l3 cksum error or not validated - valid only when
			      l3_proto_idx indicates ipv4 packet */
      u32 l4_csum_err : 1; /* l4 cksum error or not validated  - valid only
			      when l3_proto_idx indicates TCP/UDP packet and
			      ipv4_frag not set */
      u32 ipv4_frag : 1;   /* ipv4 fragmented packet */
      u32 l4_csum_checked : 1; /* L4 cksum was verified, may be good or bad */
      u32 reserved17 : 7;
      u32 phase : 1;
      u32 l3_csum2 : 1; /* 2nd cksum engine result */
      u32 first : 1;	/* first descriptor in transaction */
      u32 last : 1;	/* last descriptor in transaction */
      u32 reserved28 : 2;
      u32 buffer : 1; /* 0 = metadata desc, 1 = buffer desc */
      u32 reserved31 : 1;
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

typedef struct
{
  u32 len_ctrl;
  u32 meta_ctrl;
  u32 buff_addr_lo;
  u32 buff_addr_hi_hdr_sz;
} ena_tx_desc_t;

STATIC_ASSERT_SIZEOF (ena_tx_desc_t, 16);

typedef struct
{
  u16 req_id;
  u8 status;
  u8 flags;
  u16 sub_qid;
  u16 sq_head_idx;
} ena_tx_cdesc_t;

STATIC_ASSERT_SIZEOF (ena_tx_cdesc_t, 8);

#endif /* _ENA_IO_DEFS_H_ */
