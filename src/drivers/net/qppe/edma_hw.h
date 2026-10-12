/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/vector.h>

/* EDMA */

#define EDMA_CPU_PORT_ID		  0
#define EDMA_VP_BASE			  64
#define EDMA_RING_Q_MAP_WORDS		  10
#define EDMA_RX_QUEUE_ID_COUNT		  32
#define QPPE_CPU_MCAST_QUEUE_START	  256
#define QPPE_CPU_MCAST_QUEUE_COUNT	  16
#define EDMA_RX_QUEUES_PER_RING		  8
#define EDMA_RXDESC_RING_START		  0
#define EDMA_RX_RING_COUNT		  EDMA_RXDESC_RING_COUNT
#define EDMA_RX_QUEUES_PER_PORT		  4
#define QPPE_RX_PROFILE_COUNT		  4
#define EDMA_RX_MITIGATION_TIMER_US	  25
#define EDMA_CYCLE_PER_TIMER_UNIT	  128
#define EDMA_RXDESC_RING_COUNT		  24
#define EDMA_RXFILL_RING_COUNT		  8
#define EDMA_TXDESC_RING_COUNT		  32
#define EDMA_TXCMPL_RING_COUNT		  32
#define EDMA_QUEUE_MAP_COUNT		  300
#define EDMA_TX_QUEUES_PER_PORT		  4
#define EDMA_TX_RING_COUNT		  EDMA_TXDESC_RING_COUNT
#define EDMA_TXDESC_RING_START		  0
#define EDMA_TXCMPL_RING_START		  0
#define EDMA_RX_SOURCE_TYPE_PORT_ID	  2
#define EDMA_QID2RID_WORD_COUNT		  (EDMA_RX_QUEUE_ID_COUNT / 4)
#define QPPE_CPU_MCAST_QUEUES_PER_PROFILE (QPPE_CPU_MCAST_QUEUE_COUNT / QPPE_RX_PROFILE_COUNT)
#define EDMA_QID2RID_WORD(q0, q1, q2, q3) ((q0) | ((q1) << 8) | ((q2) << 16) | ((q3) << 24))
#define EDMA_RX_NE_INT_EN		  0x2
#define EDMA_RX_MITIGATION_PKT_CNT	  16
#define QPPE_CLOCK_RATE			  353000000

#define EDMA_RX_MOD_TIMER_VALUE                                                                    \
  (EDMA_RX_MITIGATION_TIMER_US * (QPPE_CLOCK_RATE / 1000000) / EDMA_CYCLE_PER_TIMER_UNIT)

#define EDMA_TXDESC2CMPL_MAP_RINGS_PER_WORD 6
#define EDMA_TXDESC2CMPL_MAP_RING_BITS	    5
#define EDMA_TXCMPL_RETMODE_OPAQUE	    0
#define EDMA_TX_NE_INT_EN		    0x2
#define EDMA_RING_Q_MAP_LAST_WORD_MASK	    0xfff
#define EDMA_SC_BYPASS_ID		    1
#define EDMA_TX_DST_PORT_TYPE		    2
#define EDMA_RESET_DELAY_US		    100

/* registers */

#define EDMA_BASE_OFFSET	       0xb00000
#define EDMA_REG_MAS_CTRL_ADDR	       0x0
#define EDMA_REG_PORT_CTRL_ADDR	       0x4
#define EDMA_REG_MISC_ERR_QID	       0x40
#define EDMA_REG_MISC_INT_STAT	       0x5c
#define EDMA_REG_MISC_ERR_QID_REG2     0x88
#define EDMA_REG_RXFILL_INT_STAT(ring) (0x31000 + 0x1000 * (ring))
#define EDMA_REG_RXDESC_INT_STAT(ring) (0x59000 + 0x1000 * (ring))

#define foreach_edma_reg_rxdesc_int_diag_t_fields                                                  \
  _ (1, packet)                                                                                    \
  _ (1, urgent)                                                                                    \
  _ (30, _reserved_2)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_edma_reg_rxdesc_int_diag_t_fields
#undef _
  };
} edma_reg_rxdesc_int_diag_t;

#define foreach_edma_reg_rxfill_int_diag_t_fields                                                  \
  _ (1, low_buffer)                                                                                \
  _ (31, _reserved_1)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_edma_reg_rxfill_int_diag_t_fields
#undef _
  };
} edma_reg_rxfill_int_diag_t;

#define EDMA_REG_RX_INT_CTRL(ring)     (0x5900c + (0x1000 * (ring)))
#define EDMA_REG_RXDESC2FILL_MAP_0     0x14
#define EDMA_REG_QID2RID_TABLE(qid)    (0xb9000 + (0x4 * ((qid) / 4)))
#define EDMA_REG_TXDESC_PROD_IDX(ring) (0x1004 + (0x1000 * (ring)))
#define EDMA_REG_TXDESC_CTRL(ring)     (0x1010 + (0x1000 * (ring)))
#define EDMA_REG_TXCMPL_CONS_IDX(ring) (0x79008 + (0x1000 * (ring)))

typedef union
{
  u32 as_u32;
  struct
  {
    u32 tx_padding_enable : 1;
    u32 edma_enable : 1;
    u32 reserved_2 : 30;
  };
} ppe_reg_edma_port_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 ring_size : 16;
    u32 preheader_offset : 9;
    u32 reserved_25 : 7;
  };
} ppe_reg_edma_rxdesc_ring_size_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 1;
    u32 reserved_1 : 31;
  };
} ppe_reg_edma_rxfill_ring_enable_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 rx_enable : 1;
    u32 reserved_1 : 31;
  };
} ppe_reg_edma_rxdesc_control_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 tx_enable : 1;
    u32 fc_grp_id : 3;
    u32 reserved_4_31 : 28;
  };
} ppe_reg_edma_txdesc_ctrl_t;

#define foreach_edma_reg_port_ctrl_diag_t_fields                                                   \
  _ (1, tx_padding_enable)                                                                         \
  _ (1, edma_enable)                                                                               \
  _ (30, _reserved_2)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_edma_reg_port_ctrl_diag_t_fields
#undef _
  };
} edma_reg_port_ctrl_diag_t;

#define EDMA_REG_VLAN_CTRL 0x8

#define foreach_edma_reg_vlan_ctrl_diag_t_fields                                                   \
  _ (16, stag_tpid)                                                                                \
  _ (16, ctag_tpid)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_edma_reg_vlan_ctrl_diag_t_fields
#undef _
  };
} edma_reg_vlan_ctrl_diag_t;

#define EDMA_REG_TXQ_CTRL 0x20

#define foreach_edma_reg_txq_ctrl_diag_t_fields                                                    \
  _ (4, txdesc_prefetch_threshold)                                                                 \
  _ (4, txcmpl_writeback_threshold)                                                                \
  _ (8, txdesc_packet_sram_threshold)                                                              \
  _ (16, txcmpl_writeback_timer)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_edma_reg_txq_ctrl_diag_t_fields
#undef _
  };
} edma_reg_txq_ctrl_diag_t;

#define EDMA_REG_RXQ_CTRL 0x3c

#define foreach_edma_reg_rxq_ctrl_diag_t_fields                                                    \
  _ (4, rxfill_prefetch_threshold)                                                                 \
  _ (4, rxdesc_writeback_threshold)                                                                \
  _ (8, _reserved_8)                                                                               \
  _ (16, rxdesc_writeback_timer)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_edma_reg_rxq_ctrl_diag_t_fields
#undef _
  };
} edma_reg_rxq_ctrl_diag_t;

#define EDMA_REG_RXQ_FC_THRE 0x44

#define foreach_edma_reg_rxq_fc_thre_diag_t_fields                                                 \
  _ (5, rxfill_fifo_xoff_threshold)                                                                \
  _ (11, _reserved_5)                                                                              \
  _ (6, desc_fifo_xoff_threshold)                                                                  \
  _ (10, _reserved_22)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_edma_reg_rxq_fc_thre_diag_t_fields
#undef _
  };
} edma_reg_rxq_fc_thre_diag_t;

#define EDMA_REG_DMAR_CTRL 0x48

#define foreach_edma_reg_dmar_ctrl_diag_t_fields                                                   \
  _ (3, request_priority)                                                                          \
  _ (1, burst_length)                                                                              \
  _ (5, txdata_outstanding)                                                                        \
  _ (3, txdesc_outstanding)                                                                        \
  _ (3, rxfill_outstanding)                                                                        \
  _ (17, _reserved_15)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_edma_reg_dmar_ctrl_diag_t_fields
#undef _
  };
} edma_reg_dmar_ctrl_diag_t;

#define EDMA_REG_AXIW_CTRL 0x50

#define foreach_edma_reg_axiw_ctrl_diag_t_fields                                                   \
  _ (10, _reserved_0)                                                                              \
  _ (1, max_write_size_enable)                                                                     \
  _ (21, _reserved_11)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_edma_reg_axiw_ctrl_diag_t_fields
#undef _
  };
} edma_reg_axiw_ctrl_diag_t;

#define foreach_edma_reg_loopback_ctrl_diag_t_fields                                               \
  _ (24, rxdesc_rings)                                                                             \
  _ (8, completion_rings)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_edma_reg_loopback_ctrl_diag_t_fields
#undef _
  };
} edma_reg_loopback_ctrl_diag_t;

#define foreach_edma_reg_misc_int_diag_t_fields                                                    \
  _ (1, axi_read_error)                                                                            \
  _ (1, axi_write_error)                                                                           \
  _ (1, rx_desc_fifo_full)                                                                         \
  _ (1, rx_buffer_size_error)                                                                      \
  _ (1, tx_sram_full)                                                                              \
  _ (1, tx_completion_buffer_full)                                                                 \
  _ (1, data_length_error)                                                                         \
  _ (1, tx_timeout)                                                                                \
  _ (24, _reserved_8)

typedef union
{
  u32 as_u32;
  struct
  {
#define _(n_bits, name) u32 name : n_bits;
    foreach_edma_reg_misc_int_diag_t_fields
#undef _
  };
} edma_reg_misc_int_diag_t;

#define EDMA_REG_TXQ_CTRL_2	   0x24
#define EDMA_REG_TXQ_FC_0	   0x28
#define EDMA_REG_TXQ_FC_1	   0x30
#define EDMA_REG_TXQ_FC_2	   0x34
#define EDMA_REG_TXQ_FC_3	   0x38
#define EDMA_REG_AXIR_CTRL	   0x4c
#define EDMA_REG_MIN_MSS	   0x54
#define EDMA_REG_DBG_CTRL	   0x64
#define EDMA_REG_TX_TIMEOUT_THRESH 0x6c
#define EDMA_REG_REQ0_FIFO_THRESH  0x80
#define EDMA_REG_WB_OS_THRESH	   0x84

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 1;
    u32 qdisc : 1;
    u32 ctag_remove : 1;
    u32 stag_remove : 1;
    u32 reserved : 28;
  };
} edma_reg_rxdesc_control_diag_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 enable : 1;
    u32 fc_group : 3;
    u32 arb_group : 2;
    u32 reserved_6 : 3;
    u32 reset : 1;
    u32 reserved_10 : 22;
  };
} edma_reg_txdesc_control_diag_t;

typedef union
{
  u32 as_u32;
  struct
  {
    u32 xoff : 11;
    u32 reserved_11 : 1;
    u32 xon : 11;
    u32 reserved_23 : 9;
  };
} edma_reg_fc_threshold_diag_t;

#define EDMA_REG_RXFILL_PROD_IDX(ring)	   (0x29004 + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_PROD_IDX(ring)	   (0x39004 + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_CONS_IDX(ring)	   (0x39008 + (0x1000 * (ring)))
#define EDMA_REG_TXDESC_CONS_IDX(ring)	   (0x1008 + (0x1000 * (ring)))
#define EDMA_REG_TXCMPL_PROD_IDX(ring)	   (0x79004 + (0x1000 * (ring)))
#define EDMA_REG_RXFILL_BA(ring)	   (0x29000 + (0x1000 * (ring)))
#define EDMA_REG_RXFILL_RING_SIZE(ring)	   (0x2900c + (0x1000 * (ring)))
#define EDMA_REG_RXFILL_RING_EN(ring)	   (0x2901c + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_BA(ring)	   (0x39000 + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_PREHEADER_BA(ring) (0x39028 + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_RING_SIZE(ring)	   (0x3900c + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_UGT_THRE(ring)	   (0x39014 + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_CTRL(ring)	   (0x39018 + (0x1000 * (ring)))
#define EDMA_REG_RX_MOD_TIMER(ring)	   (0x59008 + (0x1000 * (ring)))
#define EDMA_REG_TXDESC_BA(ring)	   (0x1000 + (0x1000 * (ring)))
#define EDMA_REG_TXDESC_RING_SIZE(ring)	   (0x100c + (0x1000 * (ring)))
#define EDMA_REG_TXDESC_BA2(ring)	   (0x1014 + (0x1000 * (ring)))
#define EDMA_REG_TXCMPL_BA(ring)	   (0x79000 + (0x1000 * (ring)))
#define EDMA_REG_TXCMPL_RING_SIZE(ring)	   (0x7900c + (0x1000 * (ring)))
#define EDMA_REG_TXCMPL_CTRL(ring)	   (0x79014 + (0x1000 * (ring)))
#define EDMA_REG_TX_INT_CTRL(ring)	   (0x9900c + (0x1000 * (ring)))
#define EDMA_REG_TXDESC2CMPL_MAP_0	   0x8c
#define EDMA_REG_RXDESC_INT_MASK(ring)	   (0x59004 + (0x1000 * (ring)))
#define EDMA_REG_MISC_INT_MASK		   0x60
#define EDMA_REG_LOOPBACK_CTRL		   0x58
#define EDMA_REG_RXFILL_CONS_IDX(ring)	   (0x29008 + 0x1000 * (ring))
#define EDMA_REG_RXFILL_BUFFER1_SIZE(ring) (0x29010 + 0x1000 * (ring))
#define EDMA_REG_RXFILL_FC_THRE(ring)	   (0x29014 + 0x1000 * (ring))
#define EDMA_REG_RXFILL_UGT_THRE(ring)	   (0x29018 + 0x1000 * (ring))
#define EDMA_REG_RXFILL_DISABLE(ring)	   (0x29020 + 0x1000 * (ring))
#define EDMA_REG_RXFILL_DISABLE_DONE(ring) (0x29024 + 0x1000 * (ring))
#define EDMA_REG_RXFILL_INT_MASK(ring)	   (0x31004 + 0x1000 * (ring))
#define EDMA_REG_RXDESC_FC_THRE(ring)	   (0x39010 + 0x1000 * (ring))
#define EDMA_REG_RXDESC_DISABLE(ring)	   (0x39020 + 0x1000 * (ring))
#define EDMA_REG_RXDESC_DISABLE_DONE(ring) (0x39024 + 0x1000 * (ring))
#define EDMA_REG_TXCMPL_UGT_THRE(ring)	   (0x79010 + 0x1000 * (ring))
#define EDMA_REG_TX_MOD_TIMER(ring)	   (0x99008 + 0x1000 * (ring))
#define EDMA_REG_TX_INT_MASK(ring)	   (0x99004 + 0x1000 * (ring))

/* descriptors */

typedef struct
{
  u32 buffer_address;
  u16 _reserved_1_0_15;
  u16 buffer_size;
  u32 opaque_low;
  u32 opaque_high;
} edma_rxfill_desc_t;

typedef union
{
  u32 as_u32[8];
  u64 as_u64[4];
  struct
  {
    /* word 0 */
    u32 buffer_address;

    /* word 1 */
    u32 buffer_address_hi : 8;
    u32 _reserved_1_8_9 : 2;
    u32 fake_mac : 1;
    u32 _reserved_1_11 : 1;
    u32 cpu_code_valid : 1;
    u32 _reserved_1_13_15 : 3;
    u32 service_code : 9;
    u32 acl_idx_valid : 1;
    u32 int_pri : 4;
    u32 more : 1;
    u32 _reserved_1_31 : 1;

    /* word 2 */
    u32 opaque_low;

    /* word 3 */
    u32 opaque_high;

    /* word 4 */
    u32 source_port_id : 12;
    u32 source_type : 4;
    u32 destination_port_id : 12;
    u32 destination_type : 4;

    /* word 5 */
    u32 packet_length : 16;
    u32 cpu_code : 10;
    u32 _reserved_5_26_31 : 6;

    /* word 6 */
    u32 data_offset : 12;
    u32 l4_checksum_status : 1;
    u32 l3_checksum_status : 1;
    u32 _reserved_6_14_31 : 18;

    /* word 7 */
    u32 _reserved_7_0_11 : 12;
    u32 pid : 4;
    u32 l3_offset : 8;
    u32 _reserved_7_24_31 : 8;
  };
} edma_rx_desc_t;

typedef union
{
  u32 as_u32[8];
  u64 as_u64[4];
  struct
  {
    /* word 0 */
    u32 timestamp_lo;

    /* word 1 */
    u32 timestamp_hi : 8;
    u32 _reserved_1_8_31 : 24;

    /* word 2 */
    u32 qos_tag;

    /* word 3 */
    u32 flow_idx : 20;
    u32 flow_idx_valid : 1;
    u32 _reserved_3_22 : 1;
    u32 timestamp_valid : 1;
    u32 _reserved_3_24_31 : 8;

    /* word 4 */
    u32 secondary_packet_offsets;

    /* word 5 */
    u32 _reserved_5;

    /* word 6 */
    u32 _reserved_6;

    /* word 7 */
    u32 _reserved_7;
  };
} edma_rx_sec_desc_t;

typedef union
{
  u32 as_u32[8];
  u64 as_u64[4];
  vec128_t v128[2];
  struct
  {
    /* word 0 */
    u32 buffer_address;

    /* word 1 */
    u32 buffer_address_hi : 8;
    u32 _reserved_1_8_9 : 2;
    u32 fake_mac : 1;
    u32 timestamp_tag_enable : 1;
    u32 _reserved_1_12_15 : 4;
    u32 service_code : 9;
    u32 int_pri_valid : 1;
    u32 int_pri : 4;
    u32 more : 1;
    u32 _reserved_1_31 : 1;

    /* word 2 */
    u32 opaque_low;

    /* word 3 */
    u32 opaque_high;

    /* word 4 */
    u32 source_port_id : 12;
    u32 source_type : 4;
    u32 destination_port_id : 12;
    u32 destination_type : 4;

    /* word 5 */
    u32 data_length : 17;
    u32 _reserved_5_17 : 1;
    u32 pool_id : 6;
    u32 tso_enable : 1;
    u32 ip_checksum_enable : 1;
    u32 l4_checksum_mode : 2;
    u32 _reserved_5_28_30 : 3;
    u32 advanced_offload : 1;

    /* word 6 */
    union
    {
      struct
      {
	u32 data_offset : 12;
	u32 _reserved_6_12_15 : 4;
	u32 mss : 16;
      };
      struct
      {
	u32 _reserved_6_0_15 : 16;
	u32 timestamp_tag : 10;
	u32 _reserved_6_26 : 1;
	u32 timestamp_enable : 1;
	u32 _reserved_6_28_31 : 4;
      };
    };

    /* word 7 */
    u32 _reserved_7;
  };
} edma_tx_desc_t;

typedef union
{
  u32 as_u32[8];
  u64 as_u64[4];
  struct
  {
    u32 _reserved_0;
    u32 _reserved_1;
    u32 _reserved_2;
    u32 _reserved_3;
    u32 _reserved_4;
    u32 _reserved_5;
    u32 _reserved_6;
    u32 _reserved_7;
  };
} edma_tx_sec_desc_t;

typedef union
{
  u32 as_u32[4];
  u64 as_u64[2];
  struct
  {
    /* word 0 */
    u32 opaque_low;

    /* word 1 */
    u32 opaque_high;

    /* word 2 */
    u32 pool_id : 6;
    u32 _reserved_2_6_29 : 24;
    u32 more : 1;
    u32 _reserved_2_31 : 1;

    /* word 3 */
    u32 error : 23;
    u32 _reserved_3_23_31 : 9;
  };
} edma_txcmpl_desc_t;

STATIC_ASSERT_SIZEOF (edma_rxfill_desc_t, 16);

STATIC_ASSERT_SIZEOF (edma_rx_desc_t, 32);

STATIC_ASSERT_SIZEOF (edma_rx_sec_desc_t, 32);

STATIC_ASSERT_SIZEOF (edma_tx_desc_t, 32);

STATIC_ASSERT_SIZEOF (edma_tx_sec_desc_t, 32);

STATIC_ASSERT_SIZEOF (edma_txcmpl_desc_t, 16);
