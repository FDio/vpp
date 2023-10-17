/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _IIAVF_DESC_H_
#define _IIAVF_DESC_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_iavf/virtchnl.h>

#define IAVF_RX_MAX_DESC_IN_CHAIN 5

#define IAVF_TXD_CMD(x)		       (1 << (x + 4))
#define IAVF_TXD_CMD_EXT(x, val)       ((u64) val << (x + 4))
#define IAVF_TXD_CMD_EOP	       IAVF_TXD_CMD (0)
#define IAVF_TXD_CMD_RS		       IAVF_TXD_CMD (1)
#define IAVF_TXD_CMD_RSV	       IAVF_TXD_CMD (2)
#define IAVF_TXD_CMD_IIPT_NONE	       IAVF_TXD_CMD_EXT (5, 0)
#define IAVF_TXD_CMD_IIPT_IPV6	       IAVF_TXD_CMD_EXT (5, 1)
#define IAVF_TXD_CMD_IIPT_IPV4_NO_CSUM IAVF_TXD_CMD_EXT (5, 2)
#define IAVF_TXD_CMD_IIPT_IPV4	       IAVF_TXD_CMD_EXT (5, 3)
#define IAVF_TXD_CMD_L4T_UNKNOWN       IAVF_TXD_CMD_EXT (8, 0)
#define IAVF_TXD_CMD_L4T_TCP	       IAVF_TXD_CMD_EXT (8, 1)
#define IAVF_TXD_CMD_L4T_SCTP	       IAVF_TXD_CMD_EXT (8, 2)
#define IAVF_TXD_CMD_L4T_UDP	       IAVF_TXD_CMD_EXT (8, 3)
#define IAVF_TXD_OFFSET(x, factor, val)                                       \
  (((u64) val / (u64) factor) << (16 + x))
#define IAVF_TXD_OFFSET_MACLEN(val) IAVF_TXD_OFFSET (0, 2, val)
#define IAVF_TXD_OFFSET_IPLEN(val)  IAVF_TXD_OFFSET (7, 4, val)
#define IAVF_TXD_OFFSET_L4LEN(val)  IAVF_TXD_OFFSET (14, 4, val)
#define IAVF_TXD_DTYP_CTX	    0x1ULL
#define IAVF_TXD_CTX_CMD_TSO	    IAVF_TXD_CMD (0)
#define IAVF_TXD_CTX_SEG(val, x)    (((u64) val) << (30 + x))
#define IAVF_TXD_CTX_SEG_TLEN(val)  IAVF_TXD_CTX_SEG (val, 0)
#define IAVF_TXD_CTX_SEG_MSS(val)   IAVF_TXD_CTX_SEG (val, 20)

typedef union
{
  struct
  {
    u32 mirr : 13;
    u32 _reserved1 : 3;
    u32 l2tag1 : 16;
    u32 filter_status;
  };
  u64 as_u64;
} iavf_rx_desc_qw0_t;

typedef union
{
  struct
  {
    /* status */
    u64 dd : 1;
    u64 eop : 1;
    u64 l2tag1p : 1;
    u64 l3l4p : 1;
    u64 crcp : 1;
    u64 _reserved2 : 4;
    u64 ubmcast : 2;
    u64 flm : 1;
    u64 fltstat : 2;
    u64 lpbk : 1;
    u64 ipv6exadd : 1;
    u64 _reserved3 : 2;
    u64 int_udp_0 : 1;

    /* error */
    u64 _reserved_err0 : 3;
    u64 ipe : 1;
    u64 l4e : 1;
    u64 _reserved_err5 : 1;
    u64 oversize : 1;
    u64 _reserved_err7 : 1;

    u64 rsv2 : 3;
    u64 ptype : 8;
    u64 length : 26;
  };
  u64 as_u64;
} iavf_rx_desc_qw1_t;

STATIC_ASSERT_SIZEOF (iavf_rx_desc_qw0_t, 8);
STATIC_ASSERT_SIZEOF (iavf_rx_desc_qw1_t, 8);

typedef struct
{
  union
  {
    struct
    {
      iavf_rx_desc_qw0_t qw0;
      iavf_rx_desc_qw0_t qw1;
      u64 rsv3 : 64;
      u32 flex_lo;
      u32 fdid_flex_hi;
    };
    u64 qword[4];
    u64 addr;
#ifdef CLIB_HAVE_VEC256
    u64x4 as_u64x4;
#endif
  };
} iavf_rx_desc_t;

STATIC_ASSERT_SIZEOF (iavf_rx_desc_t, 32);

typedef struct
{
  union
  {
    u64 qword[2];
#ifdef CLIB_HAVE_VEC128
    u64x2 as_u64x2;
#endif
  };
} iavf_tx_desc_t;

STATIC_ASSERT_SIZEOF (iavf_tx_desc_t, 16);

#endif /* _IIAVF_DESC_H_ */
