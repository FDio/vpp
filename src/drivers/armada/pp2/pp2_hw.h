/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/types.h>

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

/* Common hardware definitions */

#define ALIGN(x, a)	       __ALIGN_MASK (x, (typeof (x)) (a) - 1)
#define BYTE_MASK	       (0xFF)
#define DWORD_BITS_LEN	       (32)
#define HW_BYTE_OFFS(_offs_)   (_offs_)
#define L1_CACHE_LINE_BYTES    BIT (6)
#define PP2_TCLK_FREQ	       333000000
#define MVPP22_DESC_ADDR_SHIFT (9 - 1) /*Applies to RXQ, AGGR_TXQ*/
#define MVPP22_F_IF_MUSDK_PRIV BIT (0)
#define MVPP2_MTU_PKT_SIZE(mtu)                                                                    \
  (ALIGN ((mtu) + MV_MH_SIZE + MV_VLAN_TAG_LEN + MV_ETH_HLEN + MV_ETH_FCS_LEN, L1_CACHE_LINE_BYTES))
#define MVPP2_SNOOP_BUF_HDR_MASK       BIT (9)
#define MVPP2_SNOOP_PKT_SIZE_MASK      0x1ff
#define MVPP2_VER_ID_REG	       0x50b0
#define MVPP2_VER_PP22		       0x10
#define MVPP2_VER_PP23		       0x11
#define MV_ETH_FCS_LEN		       4
#define MVPP2_MAX_RX_FRAME_SIZE	       (10 * 1024 - MV_ETH_FCS_LEN)
#define MV_ETH_HLEN		       14
#define MV_VLAN_TAG_LEN		       4
#define SRAM_BIT_IN_WORD(_bit_)	       HW_BYTE_OFFS ((_bit_) % 32)
#define SRAM_BIT_TO_BYTE(_bit_)	       HW_BYTE_OFFS ((_bit_) / 8)
#define SRAM_BIT_TO_WORD(_bit_)	       HW_BYTE_OFFS ((_bit_) / 32)
#define TCAM_DATA_BYTE(_offs_)	       (HW_BYTE_OFFS (TCAM_DATA_BYTE_OFFS_LE (_offs_)))
#define TCAM_DATA_BYTE_OFFS_LE(_offs_) (((_offs_) - ((_offs_) % 2)) * 2 + ((_offs_) % 2))
#define TCAM_DATA_MASK(_offs_)	       (HW_BYTE_OFFS (TCAM_DATA_MASK_OFFS_LE (_offs_)))
#define TCAM_DATA_MASK_OFFS_LE(_offs_) (((_offs_) * 2) - ((_offs_) % 2) + 2)
#define WORD_BYTES		       (4)
#define __ALIGN_MASK(x, mask)	       (((x) + (mask)) & ~(mask))
#define max(x, y)                                                                                  \
  ({                                                                                               \
    typeof (x) _max1 = (x);                                                                        \
    typeof (y) _max2 = (y);                                                                        \
    (void) (&_max1 == &_max2);                                                                     \
    _max1 > _max2 ? _max1 : _max2;                                                                 \
  })

/* Descriptor formats */

#define MVPP2_CPU_DESC_CHUNK		64
#define MVPP2_DESC_ALIGNED_SIZE		32ull
#define MVPP2_DESC_Q_ALIGN		512
#define MVPP2_RX_PACKET_OFFSET_BYTES	L1_CACHE_LINE_BYTES
#define MVPP2_BPOOL_DUMMY_PKT_EFEC_OFFS (MVPP2_RX_PACKET_OFFSET_BYTES + MV_MH_SIZE)

/* Little-endian TX descriptor layout. */
#define foreach_mvpp2_tx_desc_cmd_field                                                            \
  _ (l3_offset, 7)                                                                                 \
  _ (buf_mode, 1)                                                                                  \
  _ (ip_hdr_len, 5)                                                                                \
  _ (l4_chk_disable, 2)                                                                            \
  _ (ip_chk_disable, 1)                                                                            \
  _ (pool_id, 4)                                                                                   \
  R (4)                                                                                            \
  _ (l4_info, 2)                                                                                   \
  _ (l3_info, 2)                                                                                   \
  _ (last, 1)                                                                                      \
  _ (first, 1)                                                                                     \
  R (2)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n, w) u32 n : w;
#define R(w)                                                                                       \
  u32:                                                                                             \
  w;
    foreach_mvpp2_tx_desc_cmd_field
#undef R
#undef _
  };
} mvpp2_tx_desc_cmd_t;

#define foreach_mvpp2_tx_desc_field                                                                \
  _ (pkt_offset, 8)                                                                                \
  _ (dest_qid, 8)                                                                                  \
  _ (byte_count, 16)                                                                               \
  R (32)                                                                                           \
  R (26)                                                                                           \
  _ (err_sum, 1)                                                                                   \
  R (5)                                                                                            \
  P (buf_phys_ptr_lo, 32)                                                                          \
  P (buf_phys_ptr_hi, 8)                                                                           \
  R (24)                                                                                           \
  P (buf_virt_ptr_lo, 32)                                                                          \
  P (buf_virt_ptr_hi, 8)                                                                           \
  R (24)

typedef union
{
  u32x4 as_u32x4[2];
  struct
  {
    mvpp2_tx_desc_cmd_t cmd;
#define _(n, w) u32 n : w;
#define P(n, w) u32 n : w;
#define R(w)                                                                                       \
  u32:                                                                                             \
  w;
    foreach_mvpp2_tx_desc_field
#undef R
#undef P
#undef _
  };
} mvpp2_tx_desc_t;

STATIC_ASSERT_SIZEOF (mvpp2_tx_desc_t, MVPP2_DESC_ALIGNED_SIZE);

/* Little-endian RX descriptor status layout. */
#define foreach_mvpp2_rx_desc_status_lo_field                                                      \
  _ (l3_offset, 7)                                                                                 \
  R (1)                                                                                            \
  _ (ip_hdlen, 5)                                                                                  \
  _ (ec, 2)                                                                                        \
  _ (es, 1)

#define foreach_mvpp2_rx_desc_status_hi_field                                                      \
  _ (pool_id, 4)                                                                                   \
  R (1)                                                                                            \
  _ (hwf_sync, 1)                                                                                  \
  _ (l4_chk_ok, 1)                                                                                 \
  _ (ip_frg, 1)                                                                                    \
  _ (ipv4_hdr_err, 1)                                                                              \
  _ (l4_info, 3)                                                                                   \
  _ (l3_info, 3)                                                                                   \
  _ (buf_header, 1)

typedef union
{
  u16 as_u16;
  struct
  {
#define _(n, w) u16 n : w;
#define R(w)                                                                                       \
  u16:                                                                                             \
  w;
    foreach_mvpp2_rx_desc_status_lo_field
#undef R
#undef _
  };
} mvpp2_rx_desc_status_lo_t;

typedef union
{
  u16 as_u16;
  struct
  {
#define _(n, w) u16 n : w;
#define R(w)                                                                                       \
  u16:                                                                                             \
  w;
    foreach_mvpp2_rx_desc_status_hi_field
#undef R
#undef _
  };
} mvpp2_rx_desc_status_hi_t;

typedef union
{
  u32 as_u32;
  struct
  {
    mvpp2_rx_desc_status_lo_t lo;
    mvpp2_rx_desc_status_hi_t hi;
  };
} mvpp2_rx_desc_status_t;

/* Little-endian RX descriptor layout. */
#define foreach_mvpp2_rx_desc_field                                                                \
  _ (lookup_id, 6)                                                                                 \
  _ (cpu_code, 3)                                                                                  \
  _ (pppoe, 1)                                                                                     \
  _ (l3_cast_info, 2)                                                                              \
  _ (l2_cast_info, 2)                                                                              \
  _ (vlan_info, 2)                                                                                 \
  _ (byte_count, 16)                                                                               \
  _ (gem_port_id, 12)                                                                              \
  _ (color, 2)                                                                                     \
  _ (gop_sop_u, 1)                                                                                 \
  _ (key_hash_enable, 1)                                                                           \
  _ (l4chk, 16)                                                                                    \
  _ (timestamp, 32)                                                                                \
  P (buf_phys_ptr_lo, 32)                                                                          \
  P (buf_phys_ptr_hi, 8)                                                                           \
  _ (key_hash, 24)                                                                                 \
  P (buf_virt_ptr_lo, 32)                                                                          \
  P (buf_virt_ptr_hi, 8)                                                                           \
  _ (buf_qset_no, 7)                                                                               \
  _ (buf_type, 1)                                                                                  \
  _ (mod_dscp, 6)                                                                                  \
  _ (mod_pri, 3)                                                                                   \
  _ (mdscp, 1)                                                                                     \
  _ (mpri, 1)                                                                                      \
  _ (mgpid, 1)                                                                                     \
  R (1)                                                                                            \
  _ (port_num, 3)

typedef union
{
  vec128_t vec128[2];
  struct
  {
    mvpp2_rx_desc_status_t status;
#define _(n, w) u32 n : w;
#define P(n, w) u32 n : w;
#define R(w)                                                                                       \
  u32:                                                                                             \
  w;
    foreach_mvpp2_rx_desc_field
#undef R
#undef P
#undef _
  };
} mvpp2_rx_desc_t;

STATIC_ASSERT_SIZEOF (mvpp2_rx_desc_t, MVPP2_DESC_ALIGNED_SIZE);

/* RX buffer header */
typedef union
{
  u16 as_u16;
  struct
  {
    u16 mc_id : 12;
    u16 last : 1;
    u16 : 3;
  };
} mvpp2_rx_buf_hdr_info_t;

typedef struct
{
  u32 next_phys_addr;
  u32 next_dma_addr;
  u16 byte_count;
  mvpp2_rx_buf_hdr_info_t info;
  u16 reserved1;
  u8 next_phys_addr_high;
  u8 next_dma_addr_high;
  u16 reserved2[4];
} mvpp2_rx_buf_hdr_t;

/* Parser */

enum mv_pp2x_prs_lookup
{
  MVPP2_PRS_LU_MH,
  MVPP2_PRS_LU_MAC,
  MVPP2_PRS_LU_DSA,
  MVPP2_PRS_LU_VLAN,
  MVPP2_PRS_LU_VID,
  MVPP2_PRS_LU_L2,
  MVPP2_PRS_LU_PPPOE,
  MVPP2_PRS_LU_IP4,
  MVPP2_PRS_LU_IP6,
  MVPP2_PRS_LU_FLOWS,
  MVPP2_PRS_LU_LAST,
};

#define MVPP2_PORT_MAX_MC_ADDR 21
#define MVPP2_PORT_MAX_UC_ADDR 4
#define MVPP2_DSA_EN_MASK      (0x3 << MVPP2_DSA_EN_OFFS)
#define MVPP2_DSA_EN_OFFS      4
#define MVPP2_DSA_EXTENDED     (0x2 << MVPP2_DSA_EN_OFFS)
#define MVPP2_DSA_NON_EXTENDED (0x1 << MVPP2_DSA_EN_OFFS)
#define MVPP2_MH_EN_MASK       (1 << MVPP2_MH_EN_OFFS)
#define MVPP2_MH_EN_OFFS       0
#define MVPP2_MH_REG(port)     (0x5040 + 4 * (port))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 mh_enable : 1;
    u32 : 3;
    u32 dsa_mode : 2;
    u32 : 26;
  };
} mvpp22_mh_reg_t;

#define MVPP2_PE_DSA_TAGGED	     (MVPP2_PRS_TCAM_SRAM_SIZE - 19)
#define MVPP2_PE_DSA_UNTAGGED	     (MVPP2_PRS_TCAM_SRAM_SIZE - 18)
#define MVPP2_PE_EDSA_TAGGED	     (MVPP2_PRS_TCAM_SRAM_SIZE - 21)
#define MVPP2_PE_EDSA_UNTAGGED	     (MVPP2_PRS_TCAM_SRAM_SIZE - 20)
#define MVPP2_PE_ETYPE_DSA_TAGGED    (MVPP2_PRS_TCAM_SRAM_SIZE - 15)
#define MVPP2_PE_ETYPE_DSA_UNTAGGED  (MVPP2_PRS_TCAM_SRAM_SIZE - 14)
#define MVPP2_PE_ETYPE_EDSA_TAGGED   (MVPP2_PRS_TCAM_SRAM_SIZE - 17)
#define MVPP2_PE_ETYPE_EDSA_UNTAGGED (MVPP2_PRS_TCAM_SRAM_SIZE - 16)
#define MVPP2_PE_FIRST_FREE_TID	     1
#define MVPP2_PE_LAST_FREE_TID	     (MVPP2_PE_MAC_RANGE_START - 1)
#define MVPP2_PE_MAC_RANGE_END	     (MVPP2_PE_VID_FILT_RANGE_START - 1)
#define MVPP2_PE_MAC_RANGE_START     (MVPP2_PE_MAC_RANGE_END - MVPP2_PRS_MAC_RANGE_SIZE + 1)
#define MVPP2_PE_MAC_UC_PROMISCUOUS  (MVPP2_PRS_TCAM_SRAM_SIZE - 2)
#define MVPP2_PE_MH_DEFAULT	     (MVPP2_PRS_TCAM_SRAM_SIZE - 13)
#define MVPP2_PE_MH_SKIP_PRS	     (MVPP2_PRS_TCAM_SRAM_SIZE - 31)
#define MVPP2_PE_TID_SIZE	     (MVPP2_PE_LAST_FREE_TID - MVPP2_PE_FIRST_FREE_TID)
#define MVPP2_PE_VID_FILT_RANGE_END  (MVPP2_PRS_TCAM_SRAM_SIZE - 32)
#define MVPP2_PE_VID_FILT_RANGE_START                                                              \
  (MVPP2_PE_VID_FILT_RANGE_END - MVPP2_PRS_VLAN_FILT_RANGE_SIZE + 1)
#define MVPP2_PRS_AI_BITS		   8
#define MVPP2_PRS_DSA			   false
#define MVPP2_PRS_EDSA			   true
#define MVPP2_PRS_FL_ATTR_ARP_BIT	   BIT (3)
#define MVPP2_PRS_FL_ATTR_FRAG_BIT	   BIT (4)
#define MVPP2_PRS_FL_ATTR_IP4_BIT	   BIT (1)
#define MVPP2_PRS_FL_ATTR_IP6_BIT	   BIT (2)
#define MVPP2_PRS_FL_ATTR_TCP_BIT	   BIT (5)
#define MVPP2_PRS_FL_ATTR_UDP_BIT	   BIT (6)
#define MVPP2_PRS_FL_ATTR_VLAN_BIT	   BIT (0)
#define MVPP2_PRS_L2_UDF_AI_BIT		   BIT (0)
#define MVPP2_PRS_LU_MASK		   0xf
#define MVPP2_PRS_MAC_RANGE_SIZE	   80
#define MVPP2_PRS_PORT_MASK		   0xff
#define MVPP2_PRS_RI_IP_FRAG_FALSE	   0x0
#define MVPP2_PRS_RI_IP_FRAG_MASK	   0x20000
#define MVPP2_PRS_RI_IP_FRAG_TRUE	   BIT (17)
#define MVPP2_PRS_RI_L2_BCAST		   BIT (10)
#define MVPP2_PRS_RI_L2_CAST_MASK	   0x600
#define MVPP2_PRS_RI_L2_MCAST		   BIT (9)
#define MVPP2_PRS_RI_L2_UCAST		   0x0
#define MVPP2_PRS_RI_L3_ARP		   (BIT (13) | BIT (14))
#define MVPP2_PRS_RI_L3_IP4		   BIT (12)
#define MVPP2_PRS_RI_L3_IP4_OPT		   BIT (13)
#define MVPP2_PRS_RI_L3_IP4_OTHER	   (BIT (12) | BIT (13))
#define MVPP2_PRS_RI_L3_IP6		   BIT (14)
#define MVPP2_PRS_RI_L3_IP6_EXT		   (BIT (12) | BIT (14))
#define MVPP2_PRS_RI_L3_PROTO_MASK	   0x7000
#define MVPP2_PRS_RI_L4_PROTO_MASK	   0x1c00000
#define MVPP2_PRS_RI_L4_TCP		   BIT (22)
#define MVPP2_PRS_RI_L4_UDP		   BIT (23)
#define MVPP2_PRS_RI_MAC_ME_MASK	   0x1
#define MVPP2_PRS_RI_UDF3_MASK		   0x300000
#define MVPP2_PRS_RI_UDF5_MASK		   0x6000000
#define MVPP2_PRS_RI_UDF6_MASK		   0x18000000
#define MVPP2_PRS_RI_UDF7_CLEAR		   0x0
#define MVPP2_PRS_RI_UDF7_LOG_PORT	   BIT (30)
#define MVPP2_PRS_RI_UDF7_MASK		   0x60000000
#define MVPP2_PRS_RI_UDF7_NIC		   BIT (29)
#define MVPP2_PRS_RI_VLAN_MASK		   0xc
#define MVPP2_PRS_RI_VLAN_NONE		   0x0
#define MVPP2_PRS_SRAM_AI_CTRL_BITS	   8
#define MVPP2_PRS_SRAM_AI_CTRL_OFFS	   98
#define MVPP2_PRS_SRAM_AI_MASK		   0xff
#define MVPP2_PRS_SRAM_AI_OFFS		   90
#define MVPP2_PRS_SRAM_DATA_REG(idx)	   (0x1204 + (idx) * 4)
#define MVPP2_PRS_SRAM_IDX_REG		   0x1200
#define MVPP2_PRS_SRAM_LU_GEN_BIT	   111
#define MVPP2_PRS_SRAM_NEXT_LU_MASK	   0xf
#define MVPP2_PRS_SRAM_NEXT_LU_OFFS	   106
#define MVPP2_PRS_SRAM_OP_SEL_BASE_OFFS	   89
#define MVPP2_PRS_SRAM_OP_SEL_SHIFT_ADD	   1
#define MVPP2_PRS_SRAM_OP_SEL_SHIFT_MASK   0x3
#define MVPP2_PRS_SRAM_OP_SEL_SHIFT_OFFS   85
#define MVPP2_PRS_SRAM_OP_SEL_UDF_ADD	   0
#define MVPP2_PRS_SRAM_OP_SEL_UDF_BITS	   2
#define MVPP2_PRS_SRAM_OP_SEL_UDF_MASK	   0x3
#define MVPP2_PRS_SRAM_OP_SEL_UDF_OFFS	   87
#define MVPP2_PRS_SRAM_RI_CTRL_BITS	   32
#define MVPP2_PRS_SRAM_RI_CTRL_OFFS	   32
#define MVPP2_PRS_SRAM_RI_CTRL_WORD	   1
#define MVPP2_PRS_SRAM_RI_OFFS		   0
#define MVPP2_PRS_SRAM_RI_WORD		   0
#define MVPP2_PRS_SRAM_SHIFT_OFFS	   64
#define MVPP2_PRS_SRAM_SHIFT_SIGN_BIT	   72
#define MVPP2_PRS_SRAM_UDF_BITS		   8
#define MVPP2_PRS_SRAM_UDF_MASK		   0xff
#define MVPP2_PRS_SRAM_UDF_OFFS		   73
#define MVPP2_PRS_SRAM_UDF_SIGN_BIT	   81
#define MVPP2_PRS_SRAM_UDF_TYPE_3	   3
#define MVPP2_PRS_SRAM_UDF_TYPE_5	   5
#define MVPP2_PRS_SRAM_UDF_TYPE_6	   6
#define MVPP2_PRS_SRAM_UDF_TYPE_MASK	   0x7
#define MVPP2_PRS_SRAM_UDF_TYPE_OFFS	   82
#define MVPP2_PRS_SRAM_WORDS		   4
#define MVPP2_PRS_TAGGED		   true
#define MVPP2_PRS_TCAM_AI_BYTE		   16
#define MVPP2_PRS_TCAM_CTRL_REG		   0x1230
#define MVPP2_PRS_TCAM_DATA_REG(idx)	   (0x1104 + (idx) * 4)
#define MVPP2_PRS_TCAM_DSA_FORWARD_MODE	   (BIT (6) | BIT (7))
#define MVPP2_PRS_TCAM_DSA_FROM_CPU_MODE   BIT (6)
#define MVPP2_PRS_TCAM_DSA_MODE_MASK	   0xc0
#define MVPP2_PRS_TCAM_DSA_TAGGED_BIT	   BIT (5)
#define MVPP2_PRS_TCAM_DSA_TO_CPU_MODE	   0
#define MVPP2_PRS_TCAM_DSA_TO_SNIFFER_MODE BIT (7)
#define MVPP2_PRS_TCAM_ENTRY_INVALID	   1
#define MVPP2_PRS_TCAM_EN_MASK		   BIT (0)
#define MVPP2_PRS_TCAM_EN_OFFS(offs)	   ((offs) + 2)
#define MVPP2_PRS_TCAM_IDX_REG		   0x1100
#define MVPP2_PRS_TCAM_INV_MASK		   BIT (31)
#define MVPP2_PRS_TCAM_INV_OFFS		   31
#define MVPP2_PRS_TCAM_INV_WORD		   5
#define MVPP2_PRS_TCAM_LU_BYTE		   20
#define MVPP2_PRS_TCAM_PORT_BYTE	   17
#define MVPP2_PRS_TCAM_SRAM_SIZE	   256
#define MVPP2_PRS_TCAM_WORDS		   6
#define MVPP2_PRS_UNTAGGED		   false
#define MVPP2_PRS_VID_PORT_FIRST(port)                                                             \
  (MVPP2_PE_VID_FILT_RANGE_START + ((port) * MVPP2_PRS_VLAN_FILT_MAX))
#define MVPP2_PRS_VID_PORT_LAST(port)                                                              \
  (MVPP2_PRS_VID_PORT_FIRST (port) + MVPP2_PRS_VLAN_FILT_MAX_ENTRY)
#define MVPP2_PRS_VLAN_FILT_MAX	       11
#define MVPP2_PRS_VLAN_FILT_MAX_ENTRY  (MVPP2_PRS_VLAN_FILT_MAX - 2)
#define MVPP2_PRS_VLAN_FILT_RANGE_SIZE 33
#define MV_MH_SIZE		       2

union mv_pp2x_prs_tcam_entry
{
  u32 word[MVPP2_PRS_TCAM_WORDS];
  u8 byte[MVPP2_PRS_TCAM_WORDS * 4];
};

union mv_pp2x_prs_sram_entry
{
  u32 word[MVPP2_PRS_SRAM_WORDS];
  u8 byte[MVPP2_PRS_SRAM_WORDS * 4];
};

/* Classifier */

enum mv_pp2x_qos_tbl_sel
{
  MVPP2_QOS_TBL_SEL_PRI = 0,
  MVPP2_QOS_TBL_SEL_DSCP,
};

enum mv_pp2x_cls_lkp_type
{
  MVPP2_CLS_LKP_HASH = 0,
  MVPP2_CLS_LKP_VLAN_PRI,
  MVPP2_CLS_LKP_DSCP_PRI,
  MVPP2_CLS_LKP_DEFAULT,
  MVPP2_CLS_LKP_ALL = 63,
};

#define MVPP2_C2_FIRST_ENTRY	   16 /* reserve 0-15 entries for kernel usage */
#define KEY_CTRL_HEK_SIZE	   24
#define KEY_CTRL_HEK_SIZE_BITS	   6
#define KEY_CTRL_HEK_SIZE_MASK	   (((1 << KEY_CTRL_HEK_SIZE_BITS) - 1) << KEY_CTRL_HEK_SIZE)
#define KEY_CTRL_HEK_SIZE_MAX	   36
#define KEY_CTRL_L4		   0
#define KEY_CTRL_L4_BITS	   3
#define KEY_CTRL_L4_MASK	   (((1 << KEY_CTRL_L4_BITS) - 1) << KEY_CTRL_L4)
#define KEY_CTRL_L4_MAX		   ((1 << KEY_CTRL_L4_BITS) - 1)
#define KEY_CTRL_LKP_TYPE	   4
#define KEY_CTRL_LKP_TYPE_BITS	   6
#define KEY_CTRL_LKP_TYPE_MASK	   (((1 << KEY_CTRL_LKP_TYPE_BITS) - 1) << KEY_CTRL_LKP_TYPE)
#define KEY_CTRL_LKP_TYPE_MAX	   ((1 << KEY_CTRL_LKP_TYPE_BITS) - 1)
#define KEY_CTRL_PRT_ID		   16
#define KEY_CTRL_PRT_ID_BITS	   8
#define KEY_CTRL_PRT_ID_MASK	   (((1 << KEY_CTRL_PRT_ID_BITS) - 1) << KEY_CTRL_PRT_ID)
#define KEY_CTRL_PRT_ID_MAX	   ((1 << KEY_CTRL_PRT_ID_BITS) - 1)
#define KEY_CTRL_PRT_ID_TYPE	   12
#define KEY_CTRL_PRT_ID_TYPE_BITS  2
#define KEY_CTRL_PRT_ID_TYPE_MASK  ((KEY_CTRL_PRT_ID_TYPE_MAX) << KEY_CTRL_PRT_ID_TYPE)
#define KEY_CTRL_PRT_ID_TYPE_MAX   ((1 << KEY_CTRL_PRT_ID_TYPE_BITS) - 1)
#define KEY_L4_INFO(ext_mode)	   ((ext_mode == 1) ? (88) : (96))
#define KEY_L4_INFO_MASK(ext_mode) (((1 << KEY_CTRL_L4_BITS) - 1) << (KEY_L4_INFO (ext_mode) % 32))
#define KEY_LKP_TYPE(ext_mode)	   ((ext_mode == 1) ? (91) : (99))
#define KEY_LKP_TYPE_MASK(ext_mode)                                                                \
  (((1 << KEY_CTRL_LKP_TYPE_BITS) - 1) << (KEY_LKP_TYPE (ext_mode) % 32))
#define KEY_PRT_ID(ext_mode) ((ext_mode == 1) ? (99) : (107))
#define KEY_PRT_ID_MASK(ext_mode)                                                                  \
  (((1 << KEY_CTRL_PRT_ID_BITS) - 1) << (KEY_PRT_ID (ext_mode) % 32))
#define KEY_PRT_ID_TYPE(ext_mode) ((ext_mode == 1) ? (97) : (105))
#define KEY_PRT_ID_TYPE_MASK(ext_mode)                                                             \
  ((KEY_CTRL_PRT_ID_TYPE_MAX) << (KEY_PRT_ID_TYPE (ext_mode) % 32))
#define MVPP21_CLS2_ACT_SEQ_ATTR_REG 0x1B70
#define MVPP22_RSS_IDX_REG	     0x1500

typedef union
{
  u32 as_u32;
  struct
  {
    u32 entry_num : 8;
    u32 table_num : 8;
    u32 rxq_num : 8;
    u32 : 8;
  };
} mvpp22_rss_idx_reg_t;

#define MVPP22_RSS_RXQ2RSS_TBL_REG	     0x1504
#define MVPP22_RSS_TBL_ENTRY_REG	     0x1508
#define MVPP22_RSS_TBL_LINE_NUM		     32
#define MVPP22_RSS_TBL_NUM		     8
#define MVPP22_RSS_WIDTH_MAX		     8
#define MVPP22_RSS_WIDTH_REG		     0x150c
#define MVPP2_C2_ENTRY_MAX		     (MVPP2_C2_LAST_ENTRY + 1)
#define MVPP2_C2_HEK_LKP_TYPE_MASK	     (0x3F << MVPP2_C2_HEK_LKP_TYPE_OFFS)
#define MVPP2_C2_HEK_LKP_TYPE_OFFS	     0
#define MVPP2_C2_HEK_PORT_TYPE_MASK	     (0x3 << MVPP2_C2_HEK_PORT_TYPE_OFFS)
#define MVPP2_C2_HEK_PORT_TYPE_OFFS	     6
#define MVPP2_C2_LAST_ENTRY		     255
#define MVPP2_C2_LKP_TYPE_MAX		     64
#define MVPP2_C2_TCAM_KEY_LEN_MAX	     8
#define MVPP2_CFI_OFFSET_BITS		     (3)
#define MVPP2_CLS2_ACT_COLOR_MASK	     0x00000007
#define MVPP2_CLS2_ACT_COLOR_OFF	     0
#define MVPP2_CLS2_ACT_DATA_REG		     0x1B30
#define MVPP2_CLS2_ACT_DATA_TBL_COLOR_OFF    11
#define MVPP2_CLS2_ACT_DATA_TBL_GEM_ID_OFF   8
#define MVPP2_CLS2_ACT_DATA_TBL_HIGH_Q_OFF   10
#define MVPP2_CLS2_ACT_DATA_TBL_ID_OFF	     0
#define MVPP2_CLS2_ACT_DATA_TBL_LOW_Q_OFF    9
#define MVPP2_CLS2_ACT_DATA_TBL_PRI_DSCP_OFF 7
#define MVPP2_CLS2_ACT_DATA_TBL_SEL_OFF	     6
#define MVPP2_CLS2_ACT_DSCP_MASK	     0x00000060
#define MVPP2_CLS2_ACT_DSCP_OFF		     5
#define MVPP2_CLS2_ACT_DUP_ATTR_DUPCNT_MASK  0x00000f00
#define MVPP2_CLS2_ACT_DUP_ATTR_DUPCNT_MAX   14
#define MVPP2_CLS2_ACT_DUP_ATTR_DUPCNT_OFF   8
#define MVPP2_CLS2_ACT_DUP_ATTR_DUPID_BITS   8
#define MVPP2_CLS2_ACT_DUP_ATTR_DUPID_MASK   0x000000ff
#define MVPP2_CLS2_ACT_DUP_ATTR_DUPID_MAX    ((1 << MVPP2_CLS2_ACT_DUP_ATTR_DUPID_BITS) - 1)
#define MVPP2_CLS2_ACT_DUP_ATTR_DUPID_OFF    0
#define MVPP2_CLS2_ACT_DUP_ATTR_PLCRBK_MASK  0x20000000
#define MVPP2_CLS2_ACT_DUP_ATTR_PLCRID_BITS  5
#define MVPP2_CLS2_ACT_DUP_ATTR_PLCRID_MASK  0x1f000000
#define MVPP2_CLS2_ACT_DUP_ATTR_PLCRID_MAX   ((1 << MVPP2_CLS2_ACT_DUP_ATTR_PLCRID_BITS) - 1)
#define MVPP2_CLS2_ACT_DUP_ATTR_PLCRID_OFF   24
#define MVPP2_CLS2_ACT_DUP_ATTR_REG	     0x1B6C
#define MVPP2_CLS2_ACT_DUP_ATTR_RSSEN_BITS   1
#define MVPP2_CLS2_ACT_DUP_ATTR_RSSEN_MASK   0x40000000
#define MVPP2_CLS2_ACT_DUP_ATTR_RSSEN_OFF    30
#define MVPP2_CLS2_ACT_FLD_EN_OFF	     18
#define MVPP2_CLS2_ACT_FRWD_MASK	     0x0000e000
#define MVPP2_CLS2_ACT_FRWD_OFF		     13
#define MVPP2_CLS2_ACT_GEM_MASK		     0x00000180
#define MVPP2_CLS2_ACT_GEM_OFF		     7
#define MVPP2_CLS2_ACT_HWF_ATTR_DPTR_BITS    15
#define MVPP2_CLS2_ACT_HWF_ATTR_DPTR_MASK    0x0000fffe
#define MVPP2_CLS2_ACT_HWF_ATTR_DPTR_MAX     ((1 << MVPP2_CLS2_ACT_HWF_ATTR_DPTR_BITS) - 1)
#define MVPP2_CLS2_ACT_HWF_ATTR_DPTR_OFF     1
#define MVPP2_CLS2_ACT_HWF_ATTR_IPTR_BITS    8
#define MVPP2_CLS2_ACT_HWF_ATTR_IPTR_MASK    0x00ff0000
#define MVPP2_CLS2_ACT_HWF_ATTR_IPTR_MAX     ((1 << MVPP2_CLS2_ACT_HWF_ATTR_IPTR_BITS) - 1)
#define MVPP2_CLS2_ACT_HWF_ATTR_IPTR_OFF     16
#define MVPP2_CLS2_ACT_HWF_ATTR_L4CHK_MASK   0x01000000
#define MVPP2_CLS2_ACT_HWF_ATTR_L4CHK_OFF    24
#define MVPP2_CLS2_ACT_HWF_ATTR_REG	     0x1B68
#define MVPP2_CLS2_ACT_PLCR_MASK	     0x00030000
#define MVPP2_CLS2_ACT_PLCR_OFF		     16
#define MVPP2_CLS2_ACT_PRI_MASK		     0x00000018
#define MVPP2_CLS2_ACT_PRI_OFF		     3
#define MVPP2_CLS2_ACT_QH_MASK		     0x00001800
#define MVPP2_CLS2_ACT_QH_OFF		     11
#define MVPP2_CLS2_ACT_QL_MASK		     0x00000600
#define MVPP2_CLS2_ACT_QL_OFF		     9
#define MVPP2_CLS2_ACT_QOS_ATTR_DSCP_MASK    0x000001f8
#define MVPP2_CLS2_ACT_QOS_ATTR_DSCP_OFF     3
#define MVPP2_CLS2_ACT_QOS_ATTR_GEM_BITS     12
#define MVPP2_CLS2_ACT_QOS_ATTR_GEM_MASK     0x001ffe00
#define MVPP2_CLS2_ACT_QOS_ATTR_GEM_MAX	     ((1 << MVPP2_CLS2_ACT_QOS_ATTR_GEM_BITS) - 1)
#define MVPP2_CLS2_ACT_QOS_ATTR_GEM_OFF	     9
#define MVPP2_CLS2_ACT_QOS_ATTR_PRI_MASK     0x00000007
#define MVPP2_CLS2_ACT_QOS_ATTR_PRI_OFF	     0
#define MVPP2_CLS2_ACT_QOS_ATTR_QH_BITS	     5
#define MVPP2_CLS2_ACT_QOS_ATTR_QH_MASK	     0x1f000000
#define MVPP2_CLS2_ACT_QOS_ATTR_QH_OFF	     24
#define MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS	     3
#define MVPP2_CLS2_ACT_QOS_ATTR_QL_MASK	     0x00e00000
#define MVPP2_CLS2_ACT_QOS_ATTR_QL_OFF	     21
#define MVPP2_CLS2_ACT_QOS_ATTR_REG	     0x1B64
#define MVPP2_CLS2_ACT_REG		     0x1B60
#define MVPP2_CLS2_ACT_RSS_MASK		     0x00180000
#define MVPP2_CLS2_ACT_RSS_OFF		     19
#define MVPP2_CLS2_DSCP_PRI_INDEX_LINE_OFF   0
#define MVPP2_CLS2_DSCP_PRI_INDEX_REG	     0x1B40
#define MVPP2_CLS2_DSCP_PRI_INDEX_SEL_OFF    6
#define MVPP2_CLS2_DSCP_PRI_INDEX_TBL_ID_OFF 8

typedef union
{
  u32 as_u32;
  struct
  {
    u32 line : 6;
    u32 select : 1;
    u32 : 1;
    u32 table_id : 6;
    u32 : 18;
  };
} mvpp22_cls2_dscp_pri_index_reg_t;

#define MVPP2_CLS2_QOS_TBL_COLOR_MASK	 0x00000e00
#define MVPP2_CLS2_QOS_TBL_COLOR_OFF	 9
#define MVPP2_CLS2_QOS_TBL_QUEUENUM_BITS 8
#define MVPP2_CLS2_QOS_TBL_QUEUENUM_MASK 0xff000000
#define MVPP2_CLS2_QOS_TBL_QUEUENUM_OFF	 24

typedef union
{
  u32 as_u32;
  struct
  {
    u32 : 9;
    u32 color : 3;
    u32 : 12;
    u32 queue : 8;
  };
} mvpp22_cls2_qos_tbl_reg_t;

#define MVPP2_CLS2_QOS_TBL_REG		 0x1B44
#define MVPP2_CLS2_TCAM_CTRL_REG	 0x1B90
#define MVPP2_CLS2_TCAM_DATA_REG(idx)	 (0x1B10 + (idx) * 4)
#define MVPP2_CLS2_TCAM_IDX_REG		 0x1B00
#define MVPP2_CLS2_TCAM_INV_INVALID_MASK BIT (31)
#define MVPP2_CLS2_TCAM_INV_INVALID_OFF	 31
#define MVPP2_CLS2_TCAM_INV_REG		 0x1B24
#define MVPP2_CLS3_ACT_COLOR		 0
#define MVPP2_CLS3_ACT_COLOR_BITS	 3
#define MVPP2_CLS3_ACT_COLOR_MASK	 (((1 << MVPP2_CLS3_ACT_COLOR_BITS) - 1) << MVPP2_CLS3_ACT_COLOR)
#define MVPP2_CLS3_ACT_DUP_ATTR_REG	 0x1D4C
#define MVPP2_CLS3_ACT_DUP_COUNT	 8
#define MVPP2_CLS3_ACT_DUP_COUNT_BITS	 4
#define MVPP2_CLS3_ACT_DUP_COUNT_MASK                                                              \
  (((1 << MVPP2_CLS3_ACT_DUP_COUNT_BITS) - 1) << MVPP2_CLS3_ACT_DUP_COUNT)
#define MVPP2_CLS3_ACT_DUP_COUNT_MAX 14
#define MVPP2_CLS3_ACT_DUP_FID	     0
#define MVPP2_CLS3_ACT_DUP_FID_BITS  8
#define MVPP2_CLS3_ACT_DUP_FID_MASK                                                                \
  (((1 << MVPP2_CLS3_ACT_DUP_FID_BITS) - 1) << MVPP2_CLS3_ACT_DUP_FID)
#define MVPP2_CLS3_ACT_DUP_FID_MAX	     ((1 << MVPP2_CLS3_ACT_DUP_FID_BITS) - 1)
#define MVPP2_CLS3_ACT_DUP_POLICER_BANK_BIT  29
#define MVPP2_CLS3_ACT_DUP_POLICER_BANK_MASK BIT (MVPP2_CLS3_ACT_DUP_POLICER_BANK_BIT)
#define MVPP2_CLS3_ACT_DUP_POLICER_ID	     24
#define MVPP2_CLS3_ACT_DUP_POLICER_ID_BITS   5
#define MVPP2_CLS3_ACT_DUP_POLICER_MASK                                                            \
  (((1 << MVPP2_CLS3_ACT_DUP_POLICER_ID_BITS) - 1) << MVPP2_CLS3_ACT_DUP_POLICER_ID)
#define MVPP2_CLS3_ACT_DUP_POLICER_MAX ((1 << MVPP2_CLS3_ACT_DUP_POLICER_ID_BITS) - 1)
#define MVPP2_CLS3_ACT_DUP_RSS_EN_BIT  30
#define MVPP2_CLS3_ACT_DUP_RSS_EN_MASK BIT (MVPP2_CLS3_ACT_DUP_RSS_EN_BIT)
#define MVPP2_CLS3_ACT_FLOW_ID_EN      18
#define MVPP2_CLS3_ACT_FWD	       13
#define MVPP2_CLS3_ACT_FWD_BITS	       3
#define MVPP2_CLS3_ACT_FWD_MASK	       (((1 << MVPP2_CLS3_ACT_FWD_BITS) - 1) << MVPP2_CLS3_ACT_FWD)
#define MVPP2_CLS3_ACT_HIGH_Q	       11
#define MVPP2_CLS3_ACT_HIGH_Q_BITS     2
#define MVPP2_CLS3_ACT_HIGH_Q_MASK                                                                 \
  (((1 << MVPP2_CLS3_ACT_HIGH_Q_BITS) - 1) << MVPP2_CLS3_ACT_HIGH_Q)
#define MVPP2_CLS3_ACT_HWF_ATTR_CHKSM_EN      24
#define MVPP2_CLS3_ACT_HWF_ATTR_CHKSM_EN_MASK BIT (MVPP2_CLS3_ACT_HWF_ATTR_CHKSM_EN)
#define MVPP2_CLS3_ACT_HWF_ATTR_DPTR	      1
#define MVPP2_CLS3_ACT_HWF_ATTR_DPTR_BITS     15
#define MVPP2_CLS3_ACT_HWF_ATTR_DPTR_MASK                                                          \
  (((1 << MVPP2_CLS3_ACT_HWF_ATTR_DPTR_BITS) - 1) << MVPP2_CLS3_ACT_HWF_ATTR_DPTR)
#define MVPP2_CLS3_ACT_HWF_ATTR_DPTR_MAX  ((1 << MVPP2_CLS3_ACT_HWF_ATTR_DPTR_BITS) - 1)
#define MVPP2_CLS3_ACT_HWF_ATTR_IPTR	  16
#define MVPP2_CLS3_ACT_HWF_ATTR_IPTR_BITS 8
#define MVPP2_CLS3_ACT_HWF_ATTR_IPTR_MASK                                                          \
  (((1 << MVPP2_CLS3_ACT_HWF_ATTR_IPTR_BITS) - 1) << MVPP2_CLS3_ACT_HWF_ATTR_IPTR)
#define MVPP2_CLS3_ACT_HWF_ATTR_IPTR_MAX   ((1 << MVPP2_CLS3_ACT_HWF_ATTR_IPTR_BITS) - 1)
#define MVPP2_CLS3_ACT_HWF_ATTR_REG	   0x1D48
#define MVPP2_CLS3_ACT_LOW_Q		   9
#define MVPP2_CLS3_ACT_LOW_Q_BITS	   2
#define MVPP2_CLS3_ACT_LOW_Q_MASK	   (((1 << MVPP2_CLS3_ACT_LOW_Q_BITS) - 1) << MVPP2_CLS3_ACT_LOW_Q)
#define MVPP2_CLS3_ACT_POLICER_SELECT	   16
#define MVPP2_CLS3_ACT_POLICER_SELECT_BITS 2
#define MVPP2_CLS3_ACT_POLICER_SELECT_MASK                                                         \
  (((1 << MVPP2_CLS3_ACT_POLICER_SELECT_BITS) - 1) << MVPP2_CLS3_ACT_POLICER_SELECT)
#define MVPP2_CLS3_ACT_QOS_ATTR_HIGH_Q	    24
#define MVPP2_CLS3_ACT_QOS_ATTR_HIGH_Q_BITS 5
#define MVPP2_CLS3_ACT_QOS_ATTR_HIGH_Q_MASK                                                        \
  (MVPP2_CLS3_ACT_QOS_ATTR_HIGH_Q_MAX << MVPP2_CLS3_ACT_QOS_ATTR_HIGH_Q)
#define MVPP2_CLS3_ACT_QOS_ATTR_HIGH_Q_MAX ((1 << MVPP2_CLS3_ACT_QOS_ATTR_HIGH_Q_BITS) - 1)
#define MVPP2_CLS3_ACT_QOS_ATTR_LOW_Q	   21
#define MVPP2_CLS3_ACT_QOS_ATTR_LOW_Q_BITS 3
#define MVPP2_CLS3_ACT_QOS_ATTR_LOW_Q_MASK                                                         \
  (MVPP2_CLS3_ACT_QOS_ATTR_LOW_Q_MAX << MVPP2_CLS3_ACT_QOS_ATTR_LOW_Q)
#define MVPP2_CLS3_ACT_QOS_ATTR_LOW_Q_MAX ((1 << MVPP2_CLS3_ACT_QOS_ATTR_LOW_Q_BITS) - 1)
#define MVPP2_CLS3_ACT_QOS_ATTR_REG	  0x1D44
#define MVPP2_CLS3_ACT_REG		  0x1D40
#define MVPP2_CLS3_ACT_RSS_EN		  19
#define MVPP2_CLS3_ACT_RSS_EN_BITS	  2
#define MVPP2_CLS3_ACT_RSS_EN_MASK                                                                 \
  (((1 << MVPP2_CLS3_ACT_RSS_EN_BITS) - 1) << MVPP2_CLS3_ACT_RSS_EN)
#define MVPP2_CLS3_ACT_SEQ_H_ATTR_REG	     0x1D54
#define MVPP2_CLS3_ACT_SEQ_L_ATTR_REG	     0x1D50
#define MVPP2_CLS3_CLEAR_ALL		     0x3f
#define MVPP2_CLS3_CLEAR_COUNTERS_REG	     0x1D00
#define MVPP2_CLS3_DB_INDEX_REG		     0x1C90
#define MVPP2_CLS3_HASH_BANKS_NUM	     8
#define MVPP2_CLS3_HASH_DATA_REG(num)	     (0x1CA0 + 4 * (num))
#define MVPP2_CLS3_HASH_DATA_REG_NUM	     4
#define MVPP2_CLS3_HASH_EXT_DATA_REG(num)    (0x1CC0 + 4 * (num))
#define MVPP2_CLS3_HASH_EXT_DATA_REG_NUM     7
#define MVPP2_CLS3_HASH_OP_ADD		     15
#define MVPP2_CLS3_HASH_OP_DEL		     14
#define MVPP2_CLS3_HASH_OP_EXT_TBL_ADDR	     16
#define MVPP2_CLS3_HASH_OP_EXT_TBL_ADDR_BITS 8
#define MVPP2_CLS3_HASH_OP_EXT_TBL_ADDR_MAX  ((1 << MVPP2_CLS3_HASH_OP_EXT_TBL_ADDR_BITS) - 1)
#define MVPP2_CLS3_HASH_OP_REG		     0x1C84
#define MVPP2_CLS3_HASH_OP_TBL_ADDR	     0
#define MVPP2_CLS3_HASH_OP_TBL_ADDR_BITS     12
#define MVPP2_CLS3_HASH_OP_TBL_ADDR_MAX	     ((1 << MVPP2_CLS3_HASH_OP_TBL_ADDR_BITS) - 1)
#define MVPP2_CLS3_INIT_HIT_CNT_OFFS	     6
#define MVPP2_CLS3_INIT_HIT_CNT_REG	     0x1C80
#define MVPP2_CLS3_KEY_CTRL_REG		     0x1C10
#define MVPP2_CLS3_KEY_HEK_REG(reg_num)	     (0x1C34 - 4 * (reg_num))
#define MVPP2_CLS3_MISS_PTR		     12
#define MVPP2_CLS3_MISS_PTR_MASK	     BIT (MVPP2_CLS3_MISS_PTR)

typedef union
{
  u32 as_u32;
  struct
  {
    u32 table_addr : 12;
    u32 miss : 1;
    u32 : 1;
    u32 delete : 1;
    u32 add : 1;
    u32 ext_table_addr : 8;
    u32 : 8;
  };
} mvpp22_cls3_hash_op_reg_t;

#define MVPP2_CLS3_QRY_ACT		     0
#define MVPP2_CLS3_QRY_ACT_REG		     0x1C40
#define MVPP2_CLS3_QRY_RES_HASH_REG(hash)    (0x1C50 + 4 * (hash))
#define MVPP2_CLS3_STATE_CLEAR_CTR_DONE	     1
#define MVPP2_CLS3_STATE_CLEAR_CTR_DONE_MASK (1 << MVPP2_CLS3_STATE_CLEAR_CTR_DONE)
#define MVPP2_CLS3_STATE_CPU_DONE	     0
#define MVPP2_CLS3_STATE_CPU_DONE_MASK	     (1 << MVPP2_CLS3_STATE_CPU_DONE)
#define MVPP2_CLS3_STATE_OCCIPIED	     8
#define MVPP2_CLS3_STATE_OCCIPIED_BITS	     8

typedef union
{
  u32 as_u32;
  struct
  {
    u32 cpu_done : 1;
    u32 clear_counters_done : 1;
    u32 : 6;
    u32 occupied : 8;
    u32 : 16;
  };
} mvpp22_cls3_state_reg_t;

#define MVPP2_CLS3_STATE_OCCIPIED_MASK                                                             \
  (((1 << MVPP2_CLS3_STATE_OCCIPIED_BITS) - 1) << MVPP2_CLS3_STATE_OCCIPIED)
#define MVPP2_CLS3_STATE_REG		     0x1C8C
#define MVPP2_CLS_C2_HEK_LKP_TYPE_MASK	     (0x3F << MVPP2_CLS_C2_HEK_LKP_TYPE_OFFS)
#define MVPP2_CLS_C2_HEK_LKP_TYPE_OFFS	     0
#define MVPP2_CLS_C2_RND_MAX		     (16) /* max C2 per CLS round		*/
#define MVPP2_CLS_C2_SRAM_WORDS		     5
#define MVPP2_CLS_C2_TCAM_DATA_BYTES	     10
#define MVPP2_CLS_C2_TCAM_SIZE		     256
#define MVPP2_CLS_C2_TCAM_WORDS		     5
#define MVPP2_CLS_C3_EXT_HEK_WORDS	     9
#define MVPP2_CLS_C3_EXT_TBL_SIZE	     (256)
#define MVPP2_CLS_C3_HASH_TBL_SIZE	     (4096)
#define MVPP2_CLS_C3_HEK_BYTES		     12 /* size in bytes */
#define MVPP2_CLS_C3_MAX_SEARCH_DEPTH	     (16)
#define MVPP2_CLS_C3_RND_MAX		     (8) /* max C3 per CLS round		*/
#define MVPP2_CLS_C3_SRAM_WORDS		     5
#define MVPP2_CLS_DEF_SEQ_CTRL		     0
#define MVPP2_CLS_FLOWS_TBL_DATA_WORDS	     3
#define MVPP2_CLS_FLOWS_TBL_FIELDS_MAX	     4
#define MVPP2_CLS_FLOWS_TBL_SIZE	     512
#define MVPP2_CLS_FLOW_INDEX_REG	     0x1820
#define MVPP2_CLS_FLOW_RND_MAX		     (2)   /* max CLS rounds		*/
#define MVPP2_CLS_FLOW_RULE_MAX		     (256) /* max flow rules		*/
#define MVPP2_CLS_FLOW_TBL0_REG		     0x1824
#define MVPP2_CLS_FLOW_TBL1_REG		     0x1828
#define MVPP2_CLS_FLOW_TBL2_REG		     0x182c
#define MVPP2_CLS_GEM_VIRT_REGS_NUM	     128
#define MVPP2_CLS_LKP_INDEX_LKP_OFFS	     0
#define MVPP2_CLS_LKP_INDEX_REG		     0x1814
#define MVPP2_CLS_LKP_INDEX_WAY_OFFS	     6
#define MVPP2_CLS_LKP_TBL_REG		     0x1818
#define MVPP2_CLS_LKP_TBL_SIZE		     64
#define MVPP2_CLS_LOG_FLOW_LUID_MAX	     (20) /* max lookup ID per flow	*/
#define MVPP2_CLS_MODE_REG		     0x1800
#define MVPP2_CLS_OVERSIZE_RXQ_LOW_REG(port) (0x1980 + ((port) * 4))
#define MVPP2_CLS_UDF_BASE_REG		     0x1860
#define MVPP2_CLS_UDF_OFFSET_3		     3
#define MVPP2_CLS_UDF_OFFSET_5		     5
#define MVPP2_CLS_UDF_OFFSET_6		     6
#define MVPP2_CLS_UDF_OFFSET_ID_BITS	     4
#define MVPP2_CLS_UDF_OFFSET_ID_MASK	     ((MVPP2_CLS_UDF_OFFSET_ID_MAX) << MVPP2_CLS_UDF_OFFSET_ID_OFFS)
#define MVPP2_CLS_UDF_OFFSET_ID_MAX	     ((1 << MVPP2_CLS_UDF_OFFSET_ID_BITS) - 1)
#define MVPP2_CLS_UDF_OFFSET_ID_OFFS	     0
#define MVPP2_CLS_UDF_REG(index)	     (MVPP2_CLS_UDF_BASE_REG + ((index) * 4)) /*index <=63*/
#define MVPP2_CLS_UDF_REL_OFFSET_BITS	     11
#define MVPP2_CLS_UDF_REL_OFFSET_MASK                                                              \
  ((MVPP2_CLS_UDF_REL_OFFSET_MAX) << MVPP2_CLS_UDF_REL_OFFSET_OFFS)
#define MVPP2_CLS_UDF_REL_OFFSET_MAX  ((1 << MVPP2_CLS_UDF_REL_OFFSET_BITS) - 1)
#define MVPP2_CLS_UDF_REL_OFFSET_OFFS 4
#define MVPP2_CLS_UDF_SIZE_BITS	      8
#define MVPP2_CLS_UDF_SIZE_MASK	      (((1 << MVPP2_CLS_UDF_SIZE_BITS) - 1) << MVPP2_CLS_UDF_SIZE_OFFS)
#define MVPP2_CLS_UDF_SIZE_MAX	      ((1 << MVPP2_CLS_UDF_SIZE_BITS) - 1)
#define MVPP2_CLS_UDF_SIZE_OFFS	      16
#define MVPP2_EDROP_MAX		      MVPP2_PLCR_EDROP_THRESH_NUM
#define MVPP2_EDROP_MAX_THESH	      ((1 << MVPP2_PLCR_EDROP_TR_BITS) - 1) /* max theshold value */
#define MVPP2_FLOWID_EN		      25				    /*one bit */
#define MVPP2_FLOWID_EN_MASK	      BIT (MVPP2_FLOWID_EN)
#define MVPP2_FLOWID_FLOW	      16
#define MVPP2_FLOWID_FLOW_BITS	      9
#define MVPP2_FLOWID_FLOW_MASK	      (((1 << MVPP2_FLOWID_FLOW_BITS) - 1) << MVPP2_FLOWID_FLOW)
#define MVPP2_FLOWID_MODE	      8
#define MVPP2_FLOWID_MODE_BITS	      1
#define MVPP2_FLOWID_MODE_MASK	      (((1 << MVPP2_FLOWID_MODE_BITS) - 1) << MVPP2_FLOWID_MODE)
#define MVPP2_FLOWID_RXQ	      0
#define MVPP2_FLOWID_RXQ_BITS	      8
#define MVPP2_FLOWID_RXQ_MASK	      (((1 << MVPP2_FLOWID_RXQ_BITS) - 1) << MVPP2_FLOWID_RXQ)
#define MVPP2_FLOW_ENGINE	      1
#define MVPP2_FLOW_ENGINE_BITS	      3
#define MVPP2_FLOW_ENGINE_MASK	      (((1 << MVPP2_FLOW_ENGINE_BITS) - 1) << MVPP2_FLOW_ENGINE)
#define MVPP2_FLOW_ENGINE_MAX	      7 /* valid value 1 - 7 */
#define MVPP2_FLOW_FIELD0_ID	      0
#define MVPP2_FLOW_FIELDS_NUM	      0
#define MVPP2_FLOW_FIELDS_NUM_BITS    3
#define MVPP2_FLOW_FIELDS_NUM_MASK                                                                 \
  (((1 << MVPP2_FLOW_FIELDS_NUM_BITS) - 1) << MVPP2_FLOW_FIELDS_NUM)
#define MVPP2_FLOW_FIELD_COUNT_MAX (4)
#define MVPP2_FLOW_FIELD_ID(num)   (MVPP2_FLOW_FIELD0_ID + (MVPP2_FLOW_FIELD_ID_BITS * (num)))
#define MVPP2_FLOW_FIELD_ID_BITS   6
#define MVPP2_FLOW_FIELD_MASK(num)                                                                 \
  (((1 << MVPP2_FLOW_FIELD_ID_BITS) - 1) << (MVPP2_FLOW_FIELD_ID_BITS * (num)))
#define MVPP2_FLOW_FIELD_PRIO	   9
#define MVPP2_FLOW_FIELD_PRIO_BITS 6
#define MVPP2_FLOW_FIELD_PRIO_MASK                                                                 \
  (((1 << MVPP2_FLOW_FIELD_PRIO_BITS) - 1) << MVPP2_FLOW_FIELD_PRIO)
#define MVPP2_FLOW_LAST_MASK	      1 /*one bit*/
#define MVPP2_FLOW_LKP_TYPE	      3
#define MVPP2_FLOW_LKP_TYPE_BITS      6
#define MVPP2_FLOW_LKP_TYPE_MASK      (((1 << MVPP2_FLOW_LKP_TYPE_BITS) - 1) << MVPP2_FLOW_LKP_TYPE)
#define MVPP2_FLOW_PORT_ID	      4
#define MVPP2_FLOW_PORT_ID_BITS	      8
#define MVPP2_FLOW_PORT_ID_MASK	      (((1 << MVPP2_FLOW_PORT_ID_BITS) - 1) << MVPP2_FLOW_PORT_ID)
#define MVPP2_FLOW_PORT_ID_MAX	      ((1 << MVPP2_FLOW_PORT_ID_BITS) - 1)
#define MVPP2_FLOW_PORT_ID_SEL	      23
#define MVPP2_FLOW_PORT_ID_SEL_MASK   BIT (MVPP2_FLOW_PORT_ID_SEL)
#define MVPP2_FLOW_PORT_TYPE	      12
#define MVPP2_FLOW_PORT_TYPE_BITS     2
#define MVPP2_FLOW_PORT_TYPE_MASK     (((1 << MVPP2_FLOW_PORT_TYPE_BITS) - 1) << MVPP2_FLOW_PORT_TYPE)
#define MVPP2_FLOW_SEQ_CTRL	      15
#define MVPP2_FLOW_SEQ_CTRL_BITS      3
#define MVPP2_FLOW_SEQ_CTRL_MASK      (((1 << MVPP2_FLOW_SEQ_CTRL_BITS) - 1) << MVPP2_FLOW_SEQ_CTRL)
#define MVPP2_FLOW_TBL_SIZE	      512
#define MVPP2_FLOW_UDF7		      21
#define MVPP2_FLOW_UDF7_BITS	      2
#define MVPP2_FLOW_UDF7_MASK	      (((1 << MVPP2_FLOW_UDF7_BITS) - 1) << MVPP2_FLOW_UDF7)
#define MVPP2_FLOW_UDF7_MAX	      ((1 << MVPP2_FLOW_UDF7_BITS) - 1)
#define MVPP2_HWF_MOD_IPTR_MAX	      (255)
#define MVPP2_HW_MOD_DPTR_MAX	      (23552) /* Private data 41KB, 41K/2 */
#define MVPP2_MNG_FLOW_ID_MAX	      50
#define MVPP2_PLCR_ADD_TOKENS_EN_BIT  16
#define MVPP2_PLCR_ADD_TOKENS_EN_MASK (1 << MVPP2_PLCR_ADD_TOKENS_EN_BIT)
#define MVPP2_PLCR_BASE_PERIOD_ALL_MASK                                                            \
  (((1 << MVPP2_PLCR_BASE_PERIOD_BITS) - 1) << MVPP2_PLCR_BASE_PERIOD_OFFS)
#define MVPP2_PLCR_BASE_PERIOD_BITS 16
#define MVPP2_PLCR_BASE_PERIOD_MASK(p)                                                             \
  (((p) << MVPP2_PLCR_BASE_PERIOD_OFFS) & MVPP2_PLCR_BASE_PERIOD_ALL_MASK)
#define MVPP2_PLCR_BASE_PERIOD_OFFS    0
#define MVPP2_PLCR_BASE_PERIOD_REG     0x1304
#define MVPP2_PLCR_EDROP_CPU_TR_REG(i) (0x1380 + ((i) * 4))
#define MVPP2_PLCR_EDROP_EN_BIT	       0
#define MVPP2_PLCR_EDROP_EN_MASK       (1 << MVPP2_PLCR_EDROP_EN_BIT)
#define MVPP2_PLCR_EDROP_EN_REG	       0x1330
#define MVPP2_PLCR_EDROP_RXQ_REG       0x1348
#define MVPP2_PLCR_EDROP_RXQ_TR_REG    0x134c
#define MVPP2_PLCR_EDROP_THRESH_NUM    16
#define MVPP2_PLCR_EDROP_TR_BITS       14
#define MVPP2_PLCR_ENABLE_BIT	       29
#define MVPP2_PLCR_ENABLE_MASK	       (1 << MVPP2_PLCR_ENABLE_BIT)
#define MVPP2_PLCR_MAX		       48
#define MVPP2_PLCR_MIN_PKT_LEN	       (0) /* default min packet length	*/
#define MVPP2_PLCR_MIN_PKT_LEN_ALL_MASK                                                            \
  (((1 << MVPP2_PLCR_MIN_PKT_LEN_BITS) - 1) << MVPP2_PLCR_MIN_PKT_LEN_OFFS)
#define MVPP2_PLCR_MIN_PKT_LEN_BITS 8
#define MVPP2_PLCR_MIN_PKT_LEN_MASK(len)                                                           \
  (((len) << MVPP2_PLCR_MIN_PKT_LEN_OFFS) & MVPP2_PLCR_MIN_PKT_LEN_ALL_MASK)
#define MVPP2_PLCR_MIN_PKT_LEN_OFFS 0
#define MVPP2_PLCR_MIN_PKT_LEN_REG  0x1320
#define MVPP2_PLCR_MODE_REG	    0x1308
#define MVPP2_PLCR_TABLE_INDEX_REG  0x130c
#define MVPP2_PLCR_TOKEN_CFG_REG    0x131c
#define MVPP2_QOS_TBL_LINE_NUM_DSCP 64
#define MVPP2_QOS_TBL_LINE_NUM_PRI  8
#define MVPP2_QOS_TBL_NUM_DSCP	    8
#define MVPP2_QOS_TBL_NUM_PRI	    64
#define MVPP2_VIRT_PORT_ID_MAX	    (MVPP2_CLS_GEM_VIRT_REGS_NUM - 1)

typedef union
{
  u32 as_u32;
  struct
  {
    u32 : 9;
    u32 low_queue_from_table : 1;
    u32 high_queue_from_table : 1;
    u32 color_from_table : 1;
    u32 : 20;
  };
} mvpp22_cls2_action_tbl_reg_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 color : 3;
    u32 : 6;
    u32 low_queue : 2;
    u32 high_queue : 2;
    u32 : 6;
    u32 rss : 2;
    u32 : 11;
  };
} mvpp22_cls2_actions_reg_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 : 21;
    u32 low_queue : 3;
    u32 high_queue : 5;
    u32 : 3;
  };
} mvpp22_cls2_qos_attr_reg_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 : 30;
    u32 rss_enable : 1;
    u32 : 1;
  };
} mvpp22_cls2_dup_attr_reg_t;

struct mv_pp2x_cls_c2_entry
{
  u32 index;
  u32 inv;
  union
  {
    u32 words[MVPP2_CLS_C2_TCAM_WORDS];
    u8 bytes[MVPP2_CLS_C2_TCAM_WORDS * 4];
  } tcam;
  union
  {
    u32 words[MVPP2_CLS_C2_SRAM_WORDS];
    struct
    {
      mvpp22_cls2_action_tbl_reg_t action_tbl;
      mvpp22_cls2_actions_reg_t actions;
      mvpp22_cls2_qos_attr_reg_t qos_attr;
      u32 hwf_attr;
      mvpp22_cls2_dup_attr_reg_t rss_attr;
      u32 seq_attr;
    } regs;
  } sram;
};

struct pp2_cls_c3_entry
{
  u32 index;
  u32 ext_index;
  struct
  {
    union
    {
      u32 words[MVPP2_CLS_C3_EXT_HEK_WORDS];
      u8 bytes[MVPP2_CLS_C3_EXT_HEK_WORDS * 4];
    } hek;
    u32 key_ctrl;
  } key;
  union
  {
    u32 words[MVPP2_CLS_C3_SRAM_WORDS];
    struct
    {
      u32 actions;
      u32 qos_attr;
      u32 hwf_attr;
      u32 dup_attr;
      u32 seq_l_attr;
      u32 seq_h_attr;
    } regs;
  } sram;
};

/* Buffer manager */

#define PP2_BUFFER_OFFSET		  32
#define PP2_BUFFER_OFFSET_GRAN		  32
#define MVPP22_BM_PHY_HIGH_ALLOC_MASK	  0x00ff
#define MVPP22_BM_PHY_HIGH_ALLOC_OFFSET	  0
#define MVPP22_BM_PHY_VIRT_HIGH_ALLOC_REG 0x6444

typedef union
{
  u32 as_u32;
  struct
  {
    u32 phys_addr : 8;
    u32 virt_addr : 8;
    u32 : 16;
  };
} mvpp22_bm_phy_virt_high_reg_t;

#define MVPP22_BM_PHY_VIRT_HIGH_RLS_REG	   0x64c4 /* Not a mixup */
#define MVPP22_BM_POOL_BASE_ADDR_HIGH_MASK 0xff
#define MVPP22_BM_POOL_BASE_ADDR_HIGH_REG  0x6310

typedef union
{
  u32 as_u32;
  struct
  {
    u32 addr : 8;
    u32 mode_8pool : 1;
    u32 : 23;
  };
} mvpp22_bm_pool_base_addr_high_reg_t;

#define MVPP22_BM_POOL_PTRS_NUM_MASK	  0xfff8
#define MVPP22_BM_VIRT_HIGH_ALLOC_MASK	  0xff00
#define MVPP22_BM_VIRT_HIGH_ALLOC_OFFSET  8
#define MVPP23_BM_8POOL_MODE		  BIT (8)
#define MVPP23_BM_BPPI_8POOL_HIGH_THRESH  0x36
#define MVPP23_BM_BPPI_8POOL_LOW_THRESH	  0x34
#define MVPP2_BM_BPPI_HIGH_THRESH	  0x1E
#define MVPP2_BM_BPPI_LOW_THRESH	  0x1C
#define MVPP2_BM_BPPI_PTRS_NUM_REG(pool)  (0x6140 + ((pool) * 4))
#define MVPP2_BM_BPPI_PTR_NUM_MASK	  0x7ff
#define MVPP2_BM_HIGH_THRESH_MASK	  0x7f0000
#define MVPP2_BM_HIGH_THRESH_OFFS	  16
#define MVPP2_BM_HIGH_THRESH_VALUE(val)	  ((val) << MVPP2_BM_HIGH_THRESH_OFFS)
#define MVPP2_BM_INTR_CAUSE_REG(pool)	  (0x6240 + ((pool) * 4))
#define MVPP2_BM_INTR_MASK_REG(pool)	  (0x6280 + ((pool) * 4))
#define MVPP2_BM_LOW_THRESH_MASK	  0x7f00
#define MVPP2_BM_LOW_THRESH_OFFS	  8
#define MVPP2_BM_LOW_THRESH_VALUE(val)	  ((val) << MVPP2_BM_LOW_THRESH_OFFS)
#define MVPP2_BM_PHY_ALLOC_REG(pool)	  (0x6400 + ((pool) * 4))
#define MVPP2_BM_POOL_BASE_ADDR_MASK	  0xFFFFFF80
#define MVPP2_BM_POOL_BASE_ADDR_REG(pool) (0x6000 + ((pool) * 4))
#define MVPP2_BM_POOL_CTRL_REG(pool)	  (0x6200 + ((pool) * 4))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 start : 1;
    u32 stop : 1;
    u32 : 2;
    u32 state : 1;
    u32 : 3;
    u32 low_threshold : 7;
    u32 : 1;
    u32 high_threshold : 7;
    u32 : 9;
  };
} mvpp22_bm_pool_ctrl_reg_t;

#define MVPP2_BM_POOL_PTRS_NUM_REG(pool) (0x60c0 + ((pool) * 4))
#define MVPP2_BM_POOL_PTR_ALIGN		 128
#define MVPP2_BM_POOL_SIZE_MAX		 (16 * 1024 - (MVPP2_BM_POOL_PTR_ALIGN / 4))
#define MVPP2_BM_POOL_SIZE_REG(pool)	 (0x6040 + ((pool) * 4))
#define MVPP2_BM_PRIO_CTRL_REG		 0x6800
#define MVPP2_BM_START_MASK		 BIT (0)
#define MVPP2_BM_STATE_MASK		 BIT (4)
#define MVPP2_BM_STOP_MASK		 BIT (1)
#define MVPP2_BM_VIRT_ALLOC_REG		 0x6440
#define MVPP2_POOL_BUF_SIZE_OFFSET	 5
#define MVPP2_POOL_BUF_SIZE_REG(pool)	 (0x180 + 4 * (pool))

/* Receive queues */

#define MVPP22_RXQ_POOL_LONG_MASK  0xf000000
#define MVPP22_RXQ_POOL_LONG_OFFS  24
#define MVPP22_RXQ_POOL_SHORT_MASK 0xf00000
#define MVPP22_RXQ_POOL_SHORT_OFFS 20
#define MVPP2_RXQ_CONFIG_REG(rxq)  (0x800 + 4 * (rxq))
#define MVPP2_SNOOP_PKT_SIZE_MAX   ((1 << 9) - 1)

typedef union
{
  u32 as_u32;
  struct
  {
    u32 snoop_pkt_size : 9;
    u32 snoop_buf_hdr : 1;
    u32 : 10;
    u32 short_pool : 4;
    u32 long_pool : 4;
    u32 packet_offset : 3;
    u32 disable : 1;
  };
} mvpp22_rxq_config_reg_t;

#define MVPP2_RXQ_DESC_ADDR_REG		 0x2044
#define MVPP2_RXQ_DESC_SIZE_REG		 0x2048
#define MVPP2_RXQ_DISABLE_MASK		 BIT (31)
#define MVPP2_RXQ_INDEX_REG		 0x2050
#define MVPP2_RXQ_NUM_NEW_OFFSET	 16
#define MVPP2_RXQ_NUM_REG		 0x2040
#define MVPP2_RXQ_OCCUPIED_MASK		 0x3fff
#define MVPP2_RXQ_PACKET_OFFSET_MASK	 0x70000000
#define MVPP2_RXQ_PACKET_OFFSET_OFFS	 28
#define MVPP2_RXQ_STATUS_REG(rxq)	 (0x3400 + 4 * (rxq))
#define MVPP2_RXQ_STATUS_UPDATE_REG(rxq) (0x3000 + 4 * (rxq))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 occupied : 14;
    u32 : 2;
    u32 available : 14;
    u32 : 2;
  };
} mvpp22_rxq_status_reg_t;

#define MVPP2_RX_CTRL_REG(port) (0x140 + 4 * (port))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 : 8;
    u32 gem_port_id_src : 3;
    u32 : 5;
    u32 low_latency_pkt_size : 12;
    u32 : 3;
    u32 use_pseudo_for_csum : 1;
  };
} mvpp22_rx_ctrl_reg_t;

#define MVPP2_RX_GEM_PORT_ID_SRC_SEL(s)	  (((s) & 0x7) << 8)
#define MVPP2_RX_LOW_LATENCY_PKT_SIZE(s)  (((s) & 0xfff) << 16)
#define MVPP2_RX_USE_PSEUDO_FOR_CSUM_MASK BIT (31)

/* Transmit queues and scheduler */

#define PP2_AMPLIFY_FACTOR_MTU	       3
#define PP2_ETH_PORT_TXQ_PREFETCH      16
#define PP2_WRR_WEIGHT_UNIT	       256
#define MVPP22_TXQ_DESC_ADDR_HIGH_MASK 0xff
#define MVPP22_TXQ_DESC_ADDR_HIGH_REG  0x20a8
#define MVPP22_TXQ_SENT_REG(txq)       (0x3e00 + 4 * (txq - 128))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 : 16;
    u32 count : 14;
    u32 : 2;
  };
} mvpp22_txq_sent_reg_t;

#define MVPP22_TX_FIFO_SIZE_MASK	     0xf
#define MVPP22_TX_FIFO_SIZE_REG(eth_tx_port) (0x8860 + ((eth_tx_port) << 2))
#define MVPP2_AGGR_TXQ_DESC_ADDR_REG(cpu)    (0x2100 + 4 * (cpu))
#define MVPP2_AGGR_TXQ_DESC_SIZE_REG(cpu)    (0x2140 + 4 * (cpu))
#define MVPP2_AGGR_TXQ_INDEX_REG(cpu)	     (0x21c0 + 4 * (cpu))
#define MVPP2_AGGR_TXQ_INIT(cpu)	     (0x20C0 + 4 * (cpu))
#define MVPP2_AGGR_TXQ_PENDING_MASK	     0x3fff
#define MVPP2_AGGR_TXQ_STATUS_REG(cpu)	     (0x2180 + 4 * (cpu))
#define MVPP2_AGGR_TXQ_UPDATE_REG	     0x2090
#define MVPP2_MAX_TCONT			     16
#define MVPP2_MAX_TXQ			     8
#define MVPP2_PREF_BUF_PTR(desc)	     ((desc) & 0xfff)
#define MVPP2_PREF_BUF_SIZE_16		     (BIT (12) | BIT (14))
#define MVPP2_PREF_BUF_SIZE_32		     (BIT (13) | BIT (14))
#define MVPP2_PREF_BUF_SIZE_4		     (BIT (12) | BIT (13))
#define MVPP2_PREF_BUF_SIZE_64		     (BIT (12) | BIT (13) | BIT (14))
#define MVPP2_PREF_BUF_THRESH(val)	     ((val) << 17)
#define MVPP2_TXP_MAX_CONFIGURABLE_BUCKET_SIZE                                                     \
  (MVPP2_TXP_TOKEN_SIZE_MAX - MVPP2_TXP_REFILL_TOKENS_MAX)
#define MVPP2_TXP_MTU_MAX		  0x7FFFF
#define MVPP2_TXP_REFILL_PERIOD_ALL_MASK  0x3ff00000
#define MVPP2_TXP_REFILL_PERIOD_MASK(v)	  ((v) << 20)
#define MVPP2_TXP_REFILL_PERIOD_MAX	  0x3FF
#define MVPP2_TXP_REFILL_PERIOD_MIN	  (1)
#define MVPP2_TXP_REFILL_TOKENS_ALL_MASK  0x7ffff
#define MVPP2_TXP_REFILL_TOKENS_MASK(val) ((val) << MVPP2_TXP_REFILL_TOKENS_OFFS)
#define MVPP2_TXP_REFILL_TOKENS_MAX	  0x7FFFF
#define MVPP2_TXP_REFILL_TOKENS_OFFS	  0
#define MVPP2_TXP_SCHED_CMD_1_REG	  0x8010
#define MVPP2_TXP_SCHED_DISQ_OFFSET	  8
#define MVPP2_TXP_SCHED_ENQ_MASK	  0xff
#define MVPP2_TXP_SCHED_FIXED_PRIO_REG	  0x8014
#define MVPP2_TXP_SCHED_MTU_REG		  0x801c
#define MVPP2_TXP_SCHED_PERIOD_REG	  0x8018
#define MVPP2_TXP_SCHED_PORT_INDEX_REG	  0x8000
#define MVPP2_TXP_SCHED_Q_CMD_REG	  0x8004

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 8;
    u32 disable : 8;
    u32 : 16;
  };
} mvpp22_txp_sched_q_cmd_reg_t;

#define MVPP2_TXP_SCHED_REFILL_REG 0x8020

typedef union
{
  u32 as_u32;
  struct
  {
    u32 tokens : 19;
    u32 : 1;
    u32 period : 10;
    u32 : 2;
  };
} mvpp22_txp_sched_refill_reg_t;

#define MVPP2_TXP_SCHED_TOKEN_SIZE_REG 0x8024
#define MVPP2_TXP_TOKEN_SIZE_MAX       0xffffffff

typedef union
{
  u32 as_u32;
  struct
  {
    u32 index : 5;
    u32 reserved : 27;
  };
} mvpp22_txp_sched_port_index_reg_t;

#define MVPP2_TXQ_DESC_ADDR_LOW_REG   0x2084
#define MVPP2_TXQ_DESC_ADDR_LOW_SHIFT 0
#define MVPP2_TXQ_DESC_SIZE_MASK      0x3ff0
#define MVPP2_TXQ_DESC_SIZE_REG	      0x2088
#define MVPP2_TXQ_INDEX_REG	      0x2098
#define MVPP2_TXQ_MAX_CONFIGURABLE_BUCKET_SIZE                                                     \
  (MVPP2_TXQ_TOKEN_SIZE_MAX - MVPP2_TXQ_REFILL_TOKENS_MAX)
#define MVPP2_TXQ_NUM_REG      0x2080
#define MVPP2_TXQ_PENDING_MASK 0x3fff
#define MVPP2_TXQ_PENDING_REG  0x20a0
#define MVPP2_TXQ_PREF_BUF_REG 0x209c

typedef union
{
  u32 as_u32;
  struct
  {
    u32 ptr : 12;
    u32 size : 3;
    u32 : 2;
    u32 threshold : 15;
  };
} mvpp22_txq_pref_buf_reg_t;

#define MVPP2_TXQ_REFILL_PERIOD_ALL_MASK  0x3ff00000
#define MVPP2_TXQ_REFILL_PERIOD_MASK(v)	  ((v) << 20)
#define MVPP2_TXQ_REFILL_PERIOD_MAX	  0x3FF
#define MVPP2_TXQ_REFILL_PERIOD_MIN	  (1)
#define MVPP2_TXQ_REFILL_TOKENS_ALL_MASK  0x7ffff
#define MVPP2_TXQ_REFILL_TOKENS_MASK(val) ((val) << MVPP2_TXQ_REFILL_TOKENS_OFFS)
#define MVPP2_TXQ_REFILL_TOKENS_MAX	  0x7FFFF
#define MVPP2_TXQ_REFILL_TOKENS_OFFS	  0
#define MVPP2_TXQ_RSVD_CLR_OFFSET	  16
#define MVPP2_TXQ_RSVD_CLR_REG		  0x20b8
#define MVPP2_TXQ_RSVD_REQ_Q_OFFSET	  16
#define MVPP2_TXQ_RSVD_REQ_REG		  0x20b0

typedef union
{
  u32 as_u32;
  struct
  {
    u32 count : 14;
    u32 : 2;
    u32 queue : 8;
    u32 : 8;
  };
} mvpp22_txq_rsvd_req_reg_t;

#define MVPP2_TXQ_RSVD_RSLT_MASK      0x3fff
#define MVPP2_TXQ_RSVD_RSLT_REG	      0x20b4
#define MVPP2_TXQ_SCHED_REFILL_REG(q) (0x8040 + ((q) << 2))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 tokens : 19;
    u32 : 1;
    u32 period : 10;
    u32 : 2;
  };
} mvpp22_txq_sched_refill_reg_t;

#define MVPP2_TXQ_SCHED_TOKEN_SIZE_REG(q) (0x8060 + ((q) << 2))
#define MVPP2_TXQ_SCHED_WRR_REG(q)	  (0x80A0 + ((q) << 2))
#define MVPP2_TXQ_TOKEN_SIZE_MAX	  0x7fffffff
#define MVPP2_TXQ_WRR_WEIGHT_ALL_MASK	  (MVPP2_TXQ_WRR_WEIGHT_MAX << MVPP2_TXQ_WRR_WEIGHT_OFFS)
#define MVPP2_TXQ_WRR_WEIGHT_MASK(weigth) ((weigth) << MVPP2_TXQ_WRR_WEIGHT_OFFS)
#define MVPP2_TXQ_WRR_WEIGHT_MAX	  0xFF
#define MVPP2_TXQ_WRR_WEIGHT_OFFS	  0
#define MVPP2_TX_DISABLE_TIMEOUT_MSEC	  1000
#define MVPP2_TX_MTU_MAX		  0x7ffff
#define MVPP2_TX_PENDING_TIMEOUT_USEC	  1000
#define MVPP2_TX_PORT_FLUSH_MASK(port)	  (1 << (port))
#define MVPP2_TX_PORT_FLUSH_REG		  0x8810
#define MVPP2_TX_PORT_NUM(port)		  (0x10 | port)

/* Interrupts */

#define PP2_MAX_NUM_USED_INTERRUPTS    4
#define MVPP22_ISR_RXQ_GROUP_INDEX_REG 0x5400

typedef union
{
  u32 as_u32;
  struct
  {
    u32 sub_group : 7;
    u32 group : 2;
    u32 : 23;
  };
} mvpp22_isr_rxq_group_index_reg_t;

#define MVPP22_ISR_RXQ_SUB_GROUP_CONFIG_REG 0x5404

typedef union
{
  u32 as_u32;
  struct
  {
    u32 start_queue : 5;
    u32 : 3;
    u32 size : 4;
    u32 : 20;
  };
} mvpp22_isr_rxq_sub_group_config_reg_t;

#define MVPP2_ISR_DISABLE_INTERRUPT(mask) (((mask) << 16) & 0xffff0000)
#define MVPP2_ISR_ENABLE_REG(port)	  (0x5420 + 4 * (port))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 16;
    u32 disable : 16;
  };
} mvpp22_isr_enable_reg_t;

#define MVPP2_RX_EX_INT_CAUSE_MASK_REG(port) (0x5520 + 4 * (port))

/* Counters */

#define MVPP2_CNT_IDX_REG		  0x7040
#define MVPP2_CNT_IDX_TX(port, txq)	  (((16 + (port)) << 3) | (txq))
#define MVPP2_CLS4_TBL_HIT_REG		  0x7708
#define MVPP2_CLS_FLOW_TBL_HIT_REG	  0x7704
#define MVPP2_CLS_LKP_TBL_HIT_REG	  0x7700
#define MVPP2_MC_OVF_DROP_REG		  0x770c
#define MVPP2_RX_DESC_ENQ_REG		  0x7120
#define MVPP2_RX_PKT_BM_DROP_REG	  0x7228
#define MVPP2_RX_PKT_EARLY_DROP_REG	  0x7224
#define MVPP2_RX_PKT_FULLQ_DROP_REG	  0x7220
#define MVPP2_TXQ_SCHED_TOKEN_CNTR_REG(q) (0x8080 + ((q) << 2))
#define MVPP2_TX_PKT_BM_DROP_REG	  0x7208
#define MVPP2_TX_PKT_BM_MC_DROP_REG	  0x720c
#define MVPP2_TX_PKT_EARLY_DROP_REG	  0x7204
#define MVPP2_TX_PKT_FULLQ_DROP_REG	  0x7200
#define MVPP2_TX_BUF_ENQ_TO_DRAM_REG	  0x7108
#define MVPP2_TX_DESC_ENQ_REG		  0x7100
#define MVPP2_TX_DESC_ENQ_TO_DRAM_REG	  0x7104
#define MVPP2_TX_PKT_DQ_REG		  0x7130

/* GOP and MAC */

#define PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_MASK                                                    \
  (0x00001fff << PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_OFFS)
#define PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_OFFS 2
#define PP2_GMAC_PORT_CTRL0_REG			0x0000

typedef union
{
  u32 as_u32;
  struct
  {
    u32 port_enable : 1;
    u32 port_type : 1;
    u32 frame_size_limit : 13;
    u32 count_enable : 1;
    u32 : 16;
  };
} mvpp22_gmac_port_ctrl0_reg_t;

#define PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_MASK                                                     \
  (0x00000001 << PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_OFFS)
#define PP2_GMAC_PORT_CTRL1_GMII_LOOPBACK_OFFS 5
#define PP2_GMAC_PORT_CTRL1_REG		       0x0004

typedef union
{
  u32 as_u32;
  struct
  {
    u32 crc_check_enable : 1;
    u32 periodic_xon_enable : 1;
    u32 mgmii_mode : 1;
    u32 pfc_cascade_port_enable : 1;
    u32 disable_excessive_collision : 1;
    u32 gmii_loopback : 1;
    u32 pcs_loopback : 1;
    u32 flow_control_sa : 8;
    u32 short_preamble_enable : 1;
    u32 : 16;
  };
} mvpp22_gmac_port_ctrl1_reg_t;

#define PP2_GMAC_PORT_CTRL4_REG 0x0090

typedef union
{
  u32 as_u32;
  struct
  {
    u32 ext_pin_gmii_select : 1;
    u32 preamble_fix : 1;
    u32 sq_detect_fix_enable : 1;
    u32 rx_flow_control_enable : 1;
    u32 tx_flow_control_enable : 1;
    u32 dp_clock_select : 1;
    u32 sync_bypass : 1;
    u32 qsgmii_bypass_active : 1;
    u32 count_external_flow_control_enable : 1;
    u32 marvell_header_enable : 1;
    u32 leds_number : 6;
    u32 : 16;
  };
} mvpp22_gmac_port_ctrl4_reg_t;

#define PP2_GMAC_PORT_STATUS0_FULLDX_MASK    (0x00000001 << PP2_GMAC_PORT_STATUS0_FULLDX_OFFS)
#define PP2_GMAC_PORT_STATUS0_FULLDX_OFFS    3
#define PP2_GMAC_PORT_STATUS0_GMIISPEED_MASK (0x00000001 << PP2_GMAC_PORT_STATUS0_GMIISPEED_OFFS)
#define PP2_GMAC_PORT_STATUS0_GMIISPEED_OFFS 1
#define PP2_GMAC_PORT_STATUS0_LINKUP_MASK    (0x00000001 << PP2_GMAC_PORT_STATUS0_LINKUP_OFFS)
#define PP2_GMAC_PORT_STATUS0_LINKUP_OFFS    0
#define PP2_GMAC_PORT_STATUS0_MIISPEED_MASK  (0x00000001 << PP2_GMAC_PORT_STATUS0_MIISPEED_OFFS)
#define PP2_GMAC_PORT_STATUS0_MIISPEED_OFFS  2
#define PP2_GMAC_PORT_STATUS0_REG	     0x0010

typedef union
{
  u32 as_u32;
  struct
  {
    u32 link_up : 1;
    u32 gmii_speed : 1;
    u32 mii_speed : 1;
    u32 full_duplex : 1;
    u32 : 28;
  };
} mvpp22_gmac_port_status0_reg_t;

#define PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_MASK (0x00001fff << PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_OFFS)
#define PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_OFFS 0
#define PP2_XLG_MAC_CTRL1_MACLOOPBACKEN_MASK  (0x00000001 << PP2_XLG_MAC_CTRL1_MACLOOPBACKEN_OFFS)
#define PP2_XLG_MAC_CTRL1_MACLOOPBACKEN_OFFS  13
#define PP2_XLG_MAC_CTRL1_XGMIILOOPBACKEN_MASK                                                     \
  (0x00000001 << PP2_XLG_MAC_CTRL1_XGMIILOOPBACKEN_OFFS)
#define PP2_XLG_MAC_CTRL1_XGMIILOOPBACKEN_OFFS 14

#define PP2_XLG_PORT_MAC_CTRL0_REG 0x0000

typedef union
{
  u32 as_u32;
  struct
  {
    u32 port_enable : 1;
    u32 mac_reset_n : 1;
    u32 force_link_down : 1;
    u32 force_link_up : 1;
    u32 : 1;
    u32 tx_ipg_mode : 2;
    u32 rx_flow_control_enable : 1;
    u32 tx_flow_control_enable : 1;
    u32 crc_check_enable : 1;
    u32 periodic_xon_enable : 1;
    u32 crc_strip_enable : 1;
    u32 : 1;
    u32 padding_disable : 1;
    u32 mib_counters_disable : 1;
    u32 pfc_cascade_port_enable : 1;
    u32 : 16;
  };
} mvpp22_xlg_mac_ctrl0_reg_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 frame_size_limit : 13;
    u32 mac_loopback : 1;
    u32 xgmii_loopback : 1;
    u32 : 17;
  };
} mvpp22_xlg_mac_ctrl1_reg_t;

#define PP2_XLG_MAC_CTRL3_MACMODESELECT_MASK (0x00000007 << PP2_XLG_MAC_CTRL3_MACMODESELECT_OFFS)
#define PP2_XLG_MAC_CTRL3_MACMODESELECT_OFFS 13

typedef union
{
  u32 as_u32;
  struct
  {
    u32 buffer_size : 6;
    u32 extra_ipg : 7;
    u32 mac_mode : 3;
    u32 : 16;
  };
} mvpp22_xlg_mac_ctrl3_reg_t;

#define PP2_XLG_MAC_PORT_STATUS_LINKSTATUS_MASK                                                    \
  (0x00000001 << PP2_XLG_MAC_PORT_STATUS_LINKSTATUS_OFFS)
#define PP2_XLG_MAC_PORT_STATUS_LINKSTATUS_OFFS 0
#define PP2_XLG_MAC_PORT_STATUS_REG		0x000c
#define PP2_XLG_PORT_MAC_CTRL1_REG		0x0004
#define PP2_XLG_PORT_MAC_CTRL3_REG		0x001c

/* Host interface */

#define MVPP22_HIF_ALLOCATION_REG (0x8610)

/* CM3 firmware interface */

#define FLOW_CONTROL_ENABLE_BIT	 BIT (0)
#define FLOW_CONTROL_UPD_COM_BIT BIT (31)

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 1;
    u32 : 30;
    u32 update : 1;
  };
} mvpp22_fc_com_reg_t;

#define MSS_CP_CM3_BUF_POOL_BASE   0x40
#define MSS_CP_CM3_BUF_POOL_OFFS   4
#define MSS_CP_CM3_RXQ_ASS_BASE	   0x80
#define MSS_CP_CM3_RXQ_ASS_OFFS	   4
#define MSS_CP_CM3_RXQ_ASS_PER_REG 4
#define MSS_CP_CM3_RXQ_ASS_PQ_BASE(queue)                                                          \
  (((queue) / MSS_CP_CM3_RXQ_ASS_PER_REG) * MSS_CP_CM3_RXQ_ASS_OFFS)
#define MSS_CP_CM3_RXQ_ASS_REG(queue)	(MSS_CP_CM3_RXQ_ASS_BASE + MSS_CP_CM3_RXQ_ASS_PQ_BASE (queue))
#define MSS_CP_CM3_RXQ_TRESH_REG(queue) (MSS_CP_CM3_RXQ_TR_BASE + (queue) * MSS_CP_CM3_RXQ_TR_OFFS)
#define MSS_CP_CM3_RXQ_TR_BASE		0x200
#define MSS_CP_CM3_RXQ_TR_OFFS		4
#define MSS_CP_FC_COM_REG		0
