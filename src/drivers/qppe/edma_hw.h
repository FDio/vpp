/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>

#define PPE_CLOCK_RATE			   353000000
#define EDMA_RESET_DELAY_US		   100
#define EDMA_BASE_OFFSET		   0xb00000
#define EDMA_REG_MAS_CTRL_ADDR		   0x0
#define EDMA_REG_PORT_CTRL_ADDR		   0x4
#define EDMA_REG_RXFILL_BA(ring)	   (0x29000 + (0x1000 * (ring)))
#define EDMA_REG_RXFILL_PROD_IDX(ring)	   (0x29004 + (0x1000 * (ring)))
#define EDMA_REG_RXFILL_RING_SIZE(ring)	   (0x2900c + (0x1000 * (ring)))
#define EDMA_REG_RXFILL_RING_EN(ring)	   (0x2901c + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_BA(ring)	   (0x39000 + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_PROD_IDX(ring)	   (0x39004 + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_CONS_IDX(ring)	   (0x39008 + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_PREHEADER_BA(ring) (0x39028 + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_RING_SIZE(ring)	   (0x3900c + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_UGT_THRE(ring)	   (0x39014 + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_CTRL(ring)	   (0x39018 + (0x1000 * (ring)))
/* per-ring block confirmed against this chip's actual EDMA revision
 * (edma_v2, used by the ipq95xx SoC family per the vendor SDK's build
 * selection, also matching mainline's qcom_ppe driver) - NOT edma_v1. */
#define EDMA_REG_RXDESC_INT_STAT(ring) (0x59000 + (0x1000 * (ring)))
#define EDMA_REG_RXDESC_INT_MASK(ring) (0x59004 + (0x1000 * (ring)))
#define EDMA_REG_RX_MOD_TIMER(ring)    (0x59008 + (0x1000 * (ring)))
#define EDMA_REG_RX_INT_CTRL(ring)     (0x5900c + (0x1000 * (ring)))
/* global (not per-ring) EDMA error status/mask, same base block as
 * EDMA_REG_MAS_CTRL_ADDR/PORT_CTRL_ADDR above. Bits include
 * RX_DESC_FIFO_FULL and RX_ERR_BUF_SIZE. */
#define EDMA_REG_MISC_INT_STAT 0x5c
#define EDMA_REG_MISC_INT_MASK 0x60
/* per-descriptor-ring hardware self-test loopback: bit x loops TX
 * descriptor ring x directly back to its own RX side inside EDMA,
 * bypassing the physical MAC entirely. qppe has never touched this
 * register; read-only for now, to check whether any bit is set. */
#define EDMA_REG_LOOPBACK_CTRL	     0x58
#define EDMA_REG_RXDESC2FILL_MAP_0   0x14
#define EDMA_REG_QID2RID_TABLE(qid)  (0xb9000 + (0x4 * ((qid) / 4)))
#define PPE_REG_RING_Q_MAP_TBL(ring) (0x42a000 + (0x40 * (ring)))
#define EDMA_CPU_PORT_ID	     0
/* PPE virtual ports start at 64; physical ports never reach that high. */
#define EDMA_VP_BASE			  64
#define EDMA_RING_Q_MAP_WORDS		  10
#define EDMA_RX_QUEUE_ID_COUNT		  32
#define EDMA_QID2RID_WORD_COUNT		  (EDMA_RX_QUEUE_ID_COUNT / 4)
#define PPE_CPU_MCAST_QUEUE_START	  256
#define PPE_CPU_MCAST_QUEUE_COUNT	  16
#define PPE_CPU_MCAST_QUEUES_PER_PROFILE  (PPE_CPU_MCAST_QUEUE_COUNT / EDMA_RX_RING_COUNT)
#define EDMA_REG_RX_RING_INDEX_MASK	  0x1f
#define EDMA_RX_PROD_CONS_MASK		  0xffff
#define EDMA_QID2RID_WORD(q0, q1, q2, q3) ((q0) | ((q1) << 8) | ((q2) << 16) | ((q3) << 24))
#define EDMA_RX_QUEUES_PER_RING		  8
#define EDMA_RXFILL_RING_PRODUCER_START	  0
#define EDMA_RXFILL_RING_START		  4
#define EDMA_RXDESC_RING_START		  20
#define EDMA_RX_RING_COUNT		  4
#define EDMA_RX_NE_INT_EN		  0x2
/* RX descriptor write-back mitigation timer/packet-count threshold, per the
 * vendor SDK's edma_v2 driver and mainline's qcom_ppe driver (both agree):
 * without these, completed descriptors stay in EDMA's internal write-back
 * FIFO and never reach the visible ring. */
#define EDMA_RX_MITIGATION_TIMER_US 25
#define EDMA_RX_MITIGATION_PKT_CNT  16
#define EDMA_CYCLE_PER_TIMER_UNIT   128
#define EDMA_RX_MOD_TIMER_VALUE                                                                    \
  (EDMA_RX_MITIGATION_TIMER_US * (PPE_CLOCK_RATE / 1000000) / EDMA_CYCLE_PER_TIMER_UNIT)
#define EDMA_REG_TXDESC_BA(ring)	    (0x1000 + (0x1000 * (ring)))
#define EDMA_REG_TXDESC_PROD_IDX(ring)	    (0x1004 + (0x1000 * (ring)))
#define EDMA_REG_TXDESC_CONS_IDX(ring)	    (0x1008 + (0x1000 * (ring)))
#define EDMA_REG_TXDESC_RING_SIZE(ring)	    (0x100c + (0x1000 * (ring)))
#define EDMA_REG_TXDESC_CTRL(ring)	    (0x1010 + (0x1000 * (ring)))
#define EDMA_REG_TXDESC_BA2(ring)	    (0x1014 + (0x1000 * (ring)))
#define EDMA_REG_TXCMPL_BA(ring)	    (0x79000 + (0x1000 * (ring)))
#define EDMA_REG_TXCMPL_PROD_IDX(ring)	    (0x79004 + (0x1000 * (ring)))
#define EDMA_REG_TXCMPL_CONS_IDX(ring)	    (0x79008 + (0x1000 * (ring)))
#define EDMA_REG_TXCMPL_RING_SIZE(ring)	    (0x7900c + (0x1000 * (ring)))
#define EDMA_REG_TXCMPL_CTRL(ring)	    (0x79014 + (0x1000 * (ring)))
#define EDMA_REG_TX_INT_CTRL(ring)	    (0x9900c + (0x1000 * (ring)))
#define EDMA_REG_TXDESC2CMPL_MAP_0	    0x8c
#define EDMA_TXDESC2CMPL_MAP_RINGS_PER_WORD 6
#define EDMA_TXDESC2CMPL_MAP_RING_BITS	    5
#define EDMA_TX_RING_COUNT		    4
#define EDMA_TXDESC_RING_START		    8
#define EDMA_TXCMPL_RING_START		    8
#define EDMA_TXCMPL_RETMODE_OPAQUE	    0
#define EDMA_TX_NE_INT_EN		    0x2
#define EDMA_TX_PROD_CONS_MASK		    0xffff
/* service code 1 is reserved by this driver to bypass switch processing for
 * CPU-originated frames sent through EDMA's TX ring. */
#define EDMA_SC_BYPASS_ID 1

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

#define EDMA_RX_SOURCE_TYPE_PORT_ID  2
#define EDMA_RX_SOURCE_TYPE_GEM_PORT 0

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

    /* word 1: bits 16-29 (service_code, acl_idx_valid, int_pri below) are instead read
     * as a single 14-bit ACL index when acl_idx_valid is set. */
    u32 buffer_address_hi : 8;
    u32 _unparsed_1_8_9 : 2;
    u32 fake_mac : 1;
    u32 _unparsed_1_11 : 1;
    u32 cpu_code_valid : 1;
    u32 _unparsed_1_13_15 : 3;
    u32 service_code : 9;
    u32 acl_idx_valid : 1;
    u32 int_pri : 4;
    u32 more : 1;
    u32 _unparsed_1_31 : 1;

    /* word 2 */
    u32 opaque_low;

    /* word 3 */
    u32 opaque_high;

    /* word 4 */
    u32 source_port_id : 12;
    u32 source_type : 4;
    u32 destination_port_id : 12;
    u32 destination_type : 4;

    /* word 5: for WiFi-sourced traffic the top byte (bits 24-31) is instead read as a
     * WiFi QoS value, overlapping the top 2 bits of cpu_code. */
    u32 packet_length : 16;
    u32 cpu_code : 10;
    u32 _unparsed_5_26_31 : 6;

    /* word 6: vendor struct comment names this word "hash value, check sum status";
     * only the checksum status bits have documented accessors, so the hash value
     * sub-range is left unparsed rather than guessed at. */
    u32 data_offset : 12;
    u32 l4_checksum_status : 1;
    u32 l3_checksum_status : 1;
    u32 _unparsed_6_14_31 : 18;

    /* word 7 */
    u32 _unparsed_7_0_11 : 12;
    /* pid is a packet-format identifier used for checksum handling (0x0-0x3 = IPv4
     * variants, bit 2 set = IPv6), not a priority value. */
    u32 pid : 4;
    u32 l3_offset : 8;
    u32 _unparsed_7_24_31 : 8;
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
    u32 _unparsed_1_8_31 : 24;

    /* word 2: vendor struct comment names this word "QoS tag"; no bit-level accessor
     * is documented for it. */
    u32 qos_tag;

    /* word 3 */
    u32 flow_idx : 20;
    u32 flow_idx_valid : 1;
    u32 _unparsed_3_22 : 1;
    u32 timestamp_valid : 1;
    u32 _unparsed_3_24_31 : 8;

    /* word 4: vendor struct comment names this word "secondary packet offsets"; no
     * bit-level accessor is documented for it. */
    u32 secondary_packet_offsets;

    /* word 5: vendor struct comment names this word "multicast bit, checksum"; no
     * bit-level accessor is documented for it. */
    u32 _unparsed_5;

    /* word 6: vendor struct comment names this word "SVLAN, CVLAN"; no bit-level
     * accessor is documented for it. */
    u32 _unparsed_6;

    /* word 7: vendor struct comment names this word "secondary SVLAN, CVLAN"; no
     * bit-level accessor is documented for it. */
    u32 _unparsed_7;
  };
} edma_rx_sec_desc_t;

#define EDMA_TX_DST_PORT_TYPE 2

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
    u32 _unparsed_1_8_15 : 8;
    u32 service_code : 9;
    u32 _unparsed_1_25_29 : 5;
    u32 more : 1;
    u32 _unparsed_1_31 : 1;

    /* word 2 */
    u32 opaque_low;

    /* word 3 */
    u32 opaque_high;

    /* word 4 */
    u32 _unparsed_4_0_15 : 16;
    u32 destination_port_id : 12;
    u32 destination_type : 4;

    /* word 5 */
    u32 data_length : 17;
    u32 _unparsed_5_17 : 1;
    u32 pool_id : 6;
    u32 tso_enable : 1;
    u32 ip_checksum_enable : 1;
    u32 l4_checksum_mode : 2;
    u32 _unparsed_5_28_30 : 3;
    u32 advanced_offload : 1;

    /* word 6: vendor struct comment names this word "MSS/hash_value/PTP tag, data
     * offset"; only the MSS sub-range has a documented accessor. */
    u32 _unparsed_6_0_15 : 16;
    u32 mss : 16;

    /* word 7: vendor struct comment names this word "L4/L3 offset, PROT type, L2
     * type, CVLAN/SVLAN tag, service code"; no bit-level accessor beyond
     * word1.service_code (above) is documented for it. */
    u32 _unparsed_7;
  };
} edma_tx_desc_t;

typedef union
{
  u32 as_u32[8];
  u64 as_u64[4];
  struct
  {
    /* word 0: vendor struct comment names this word "reserved". */
    u32 _unparsed_0;

    /* word 1: vendor struct comment names this word "custom csum offset, payload
     * offset, TTL/NAT action"; no bit-level accessor is documented for it. */
    u32 _unparsed_1;

    /* word 2: vendor struct comment names this word "NAPT translated port, DSCP
     * value, TTL value"; no bit-level accessor is documented for it. */
    u32 _unparsed_2;

    /* word 3: vendor struct comment names this word "flow index value and valid
     * flag"; no bit-level accessor is documented for it. */
    u32 _unparsed_3;

    /* word 4: vendor struct comment names this word "reserved". */
    u32 _unparsed_4;

    /* word 5: vendor struct comment names this word "reserved". */
    u32 _unparsed_5;

    /* word 6: vendor struct comment names this word "CVLAN/SVLAN command"; no
     * bit-level accessor is documented for it. */
    u32 _unparsed_6;

    /* word 7: vendor struct comment names this word "CVLAN/SVLAN tag value"; no
     * bit-level accessor is documented for it. */
    u32 _unparsed_7;
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

    /* word 2: vendor struct comment names this word "more fragment, transmit ring
     * id, pool id"; only the pool id and more-fragment bits have documented
     * accessors, so the transmit-ring-id sub-range is left unparsed. */
    u32 pool_id : 6;
    u32 _unparsed_2_6_29 : 24;
    u32 more : 1;
    u32 _unparsed_2_31 : 1;

    /* word 3 */
    u32 error : 23;
    u32 _unparsed_3_23_31 : 9;
  };
} edma_txcmpl_desc_t;

STATIC_ASSERT_SIZEOF (edma_rxfill_desc_t, 16);
STATIC_ASSERT_SIZEOF (edma_rx_desc_t, 32);
STATIC_ASSERT_SIZEOF (edma_rx_sec_desc_t, 32);
STATIC_ASSERT_SIZEOF (edma_tx_desc_t, 32);
STATIC_ASSERT_SIZEOF (edma_tx_sec_desc_t, 32);
STATIC_ASSERT_SIZEOF (edma_txcmpl_desc_t, 16);
