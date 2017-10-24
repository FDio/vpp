/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */

#ifndef included_ixge_h
#define included_ixge_h

#include <vnet/vnet.h>
#include <vlib/pci/pci.h>
#include <vlib/i2c.h>
#include <vnet/ethernet/sfp.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

typedef volatile struct
{
  /* [31:7] 128 byte aligned. */
  u32 descriptor_address[2];
  u32 n_descriptor_bytes;

  /* [5] rx/tx descriptor dca enable
     [6] rx packet head dca enable
     [7] rx packet tail dca enable
     [9] rx/tx descriptor relaxed order
     [11] rx/tx descriptor write back relaxed order
     [13] rx/tx data write/read relaxed order
     [15] rx head data write relaxed order
     [31:24] apic id for cpu's cache. */
  u32 dca_control;

  u32 head_index;

  /* [4:0] tail buffer size (in 1k byte units)
     [13:8] head buffer size (in 64 byte units)
     [24:22] lo free descriptors threshold (units of 64 descriptors)
     [27:25] descriptor type 0 = legacy, 1 = advanced one buffer (e.g. tail),
     2 = advanced header splitting (head + tail), 5 = advanced header
     splitting (head only).
     [28] drop if no descriptors available. */
  u32 rx_split_control;

  u32 tail_index;
    CLIB_PAD_FROM_TO (0x1c, 0x28);

  /* [7:0] rx/tx prefetch threshold
     [15:8] rx/tx host threshold
     [24:16] rx/tx write back threshold
     [25] rx/tx enable
     [26] tx descriptor writeback flush
     [30] rx strip vlan enable */
  u32 control;

  u32 rx_coallesce_control;

  union
  {
    struct
    {
      /* packets bytes lo hi */
      u32 stats[3];

      u32 unused;
    } rx;

    struct
    {
      u32 unused[2];

      /* [0] enables head write back. */
      u32 head_index_write_back_address[2];
    } tx;
  };
} ixge_dma_regs_t;

/* Only advanced descriptors are supported. */
typedef struct
{
  u64 tail_address;
  u64 head_address;
} ixge_rx_to_hw_descriptor_t;

typedef struct
{
  u32 status[3];
  u16 n_packet_bytes_this_descriptor;
  u16 vlan_tag;
} ixge_rx_from_hw_descriptor_t;

#define IXGE_RX_DESCRIPTOR_STATUS0_IS_LAYER2 (1 << (4 + 11))
/* Valid if not layer2. */
#define IXGE_RX_DESCRIPTOR_STATUS0_IS_IP4 (1 << (4 + 0))
#define IXGE_RX_DESCRIPTOR_STATUS0_IS_IP4_EXT (1 << (4 + 1))
#define IXGE_RX_DESCRIPTOR_STATUS0_IS_IP6 (1 << (4 + 2))
#define IXGE_RX_DESCRIPTOR_STATUS0_IS_IP6_EXT (1 << (4 + 3))
#define IXGE_RX_DESCRIPTOR_STATUS0_IS_TCP (1 << (4 + 4))
#define IXGE_RX_DESCRIPTOR_STATUS0_IS_UDP (1 << (4 + 5))
#define IXGE_RX_DESCRIPTOR_STATUS0_L3_OFFSET(s) (((s) >> 21) & 0x3ff)

#define IXGE_RX_DESCRIPTOR_STATUS2_IS_OWNED_BY_SOFTWARE (1 << (0 + 0))
#define IXGE_RX_DESCRIPTOR_STATUS2_IS_END_OF_PACKET (1 << (0 + 1))
#define IXGE_RX_DESCRIPTOR_STATUS2_IS_VLAN (1 << (0 + 3))
#define IXGE_RX_DESCRIPTOR_STATUS2_IS_UDP_CHECKSUMMED (1 << (0 + 4))
#define IXGE_RX_DESCRIPTOR_STATUS2_IS_TCP_CHECKSUMMED (1 << (0 + 5))
#define IXGE_RX_DESCRIPTOR_STATUS2_IS_IP4_CHECKSUMMED (1 << (0 + 6))
#define IXGE_RX_DESCRIPTOR_STATUS2_NOT_UNICAST (1 << (0 + 7))
#define IXGE_RX_DESCRIPTOR_STATUS2_IS_DOUBLE_VLAN (1 << (0 + 9))
#define IXGE_RX_DESCRIPTOR_STATUS2_UDP_CHECKSUM_ERROR (1 << (0 + 10))
#define IXGE_RX_DESCRIPTOR_STATUS2_ETHERNET_ERROR (1 << (20 + 9))
#define IXGE_RX_DESCRIPTOR_STATUS2_TCP_CHECKSUM_ERROR (1 << (20 + 10))
#define IXGE_RX_DESCRIPTOR_STATUS2_IP4_CHECKSUM_ERROR (1 << (20 + 11))

/* For layer2 packets stats0 bottom 3 bits give ether type index from filter. */
#define IXGE_RX_DESCRIPTOR_STATUS0_LAYER2_ETHERNET_TYPE(s) ((s) & 7)

typedef struct
{
  u64 buffer_address;
  u16 n_bytes_this_buffer;
  u16 status0;
  u32 status1;
#define IXGE_TX_DESCRIPTOR_STATUS0_ADVANCED (3 << 4)
#define IXGE_TX_DESCRIPTOR_STATUS0_IS_ADVANCED (1 << (8 + 5))
#define IXGE_TX_DESCRIPTOR_STATUS0_LOG2_REPORT_STATUS (8 + 3)
#define IXGE_TX_DESCRIPTOR_STATUS0_REPORT_STATUS (1 << IXGE_TX_DESCRIPTOR_STATUS0_LOG2_REPORT_STATUS)
#define IXGE_TX_DESCRIPTOR_STATUS0_INSERT_FCS (1 << (8 + 1))
#define IXGE_TX_DESCRIPTOR_STATUS0_LOG2_IS_END_OF_PACKET (8 + 0)
#define IXGE_TX_DESCRIPTOR_STATUS0_IS_END_OF_PACKET (1 << IXGE_TX_DESCRIPTOR_STATUS0_LOG2_IS_END_OF_PACKET)
#define IXGE_TX_DESCRIPTOR_STATUS1_DONE (1 << 0)
#define IXGE_TX_DESCRIPTOR_STATUS1_CONTEXT(i) (/* valid */ (1 << 7) | ((i) << 4))
#define IXGE_TX_DESCRIPTOR_STATUS1_IPSEC_OFFLOAD (1 << (8 + 2))
#define IXGE_TX_DESCRIPTOR_STATUS1_INSERT_TCP_UDP_CHECKSUM (1 << (8 + 1))
#define IXGE_TX_DESCRIPTOR_STATUS1_INSERT_IP4_CHECKSUM (1 << (8 + 0))
#define IXGE_TX_DESCRIPTOR_STATUS0_N_BYTES_THIS_BUFFER(l) ((l) << 0)
#define IXGE_TX_DESCRIPTOR_STATUS1_N_BYTES_IN_PACKET(l) ((l) << 14)
} ixge_tx_descriptor_t;

typedef struct
{
  struct
  {
    u8 checksum_start_offset;
    u8 checksum_insert_offset;
    u16 checksum_end_offset;
  } ip, tcp;
  u32 status0;

  u8 status1;

  /* Byte offset after UDP/TCP header. */
  u8 payload_offset;

  u16 max_tcp_segment_size;
} __attribute__ ((packed)) ixge_tx_context_descriptor_t;

typedef union
{
  ixge_rx_to_hw_descriptor_t rx_to_hw;
  ixge_rx_from_hw_descriptor_t rx_from_hw;
  ixge_tx_descriptor_t tx;
  u32x4 as_u32x4;
} ixge_descriptor_t;

typedef volatile struct
{
  /* [2] pcie master disable
     [3] mac reset
     [26] global device reset */
  u32 control;
  u32 control_alias;
  /* [3:2] device id (0 or 1 for dual port chips)
     [7] link is up
     [17:10] num vfs
     [18] io active
     [19] pcie master enable status */
  u32 status_read_only;
    CLIB_PAD_FROM_TO (0xc, 0x18);
  /* [14] pf reset done
     [17] relaxed ordering disable
     [26] extended vlan enable
     [28] driver loaded */
  u32 extended_control;
    CLIB_PAD_FROM_TO (0x1c, 0x20);

  /* software definable pins.
     sdp_data [7:0]
     sdp_is_output [15:8]
     sdp_is_native [23:16]
     sdp_function [31:24].
   */
  u32 sdp_control;
    CLIB_PAD_FROM_TO (0x24, 0x28);

  /* [0] i2c clock in
     [1] i2c clock out
     [2] i2c data in
     [3] i2c data out */
  u32 i2c_control;
    CLIB_PAD_FROM_TO (0x2c, 0x4c);
  u32 tcp_timer;

    CLIB_PAD_FROM_TO (0x50, 0x200);

  u32 led_control;

    CLIB_PAD_FROM_TO (0x204, 0x600);
  u32 core_spare;
    CLIB_PAD_FROM_TO (0x604, 0x700);

  struct
  {
    u32 vflr_events_clear[4];
    u32 mailbox_interrupt_status[4];
    u32 mailbox_interrupt_enable[4];
      CLIB_PAD_FROM_TO (0x730, 0x800);
  } pf_foo;

  struct
  {
    u32 status_write_1_to_clear;
      CLIB_PAD_FROM_TO (0x804, 0x808);
    u32 status_write_1_to_set;
      CLIB_PAD_FROM_TO (0x80c, 0x810);
    u32 status_auto_clear_enable;
      CLIB_PAD_FROM_TO (0x814, 0x820);

    /* [11:3] minimum inter-interrupt interval
       (2e-6 units; 20e-6 units for fast ethernet).
       [15] low-latency interrupt moderation enable
       [20:16] low-latency interrupt credit
       [27:21] interval counter
       [31] write disable for credit and counter (write only). */
    u32 throttle0[24];

    u32 enable_write_1_to_set;
      CLIB_PAD_FROM_TO (0x884, 0x888);
    u32 enable_write_1_to_clear;
      CLIB_PAD_FROM_TO (0x88c, 0x890);
    u32 enable_auto_clear;
    u32 msi_to_eitr_select;
    /* [3:0] spd 0-3 interrupt detection enable
       [4] msi-x enable
       [5] other clear disable (makes other bits in status not clear on read)
       etc. */
    u32 control;
      CLIB_PAD_FROM_TO (0x89c, 0x900);

    /* Defines interrupt mapping for 128 rx + 128 tx queues.
       64 x 4 8 bit entries.
       For register [i]:
       [5:0] bit in interrupt status for rx queue 2*i + 0
       [7] valid bit
       [13:8] bit for tx queue 2*i + 0
       [15] valid bit
       similar for rx 2*i + 1 and tx 2*i + 1. */
    u32 queue_mapping[64];

    /* tcp timer [7:0] and other interrupts [15:8] */
    u32 misc_mapping;
      CLIB_PAD_FROM_TO (0xa04, 0xa90);

    /* 64 interrupts determined by mappings. */
    u32 status1_write_1_to_clear[4];
    u32 enable1_write_1_to_set[4];
    u32 enable1_write_1_to_clear[4];
      CLIB_PAD_FROM_TO (0xac0, 0xad0);
    u32 status1_enable_auto_clear[4];
      CLIB_PAD_FROM_TO (0xae0, 0x1000);
  } interrupt;

  ixge_dma_regs_t rx_dma0[64];

    CLIB_PAD_FROM_TO (0x2000, 0x2140);
  u32 dcb_rx_packet_plane_t4_config[8];
  u32 dcb_rx_packet_plane_t4_status[8];
    CLIB_PAD_FROM_TO (0x2180, 0x2300);

  /* reg i defines mapping for 4 rx queues starting at 4*i + 0. */
  u32 rx_queue_stats_mapping[32];
  u32 rx_queue_stats_control;

    CLIB_PAD_FROM_TO (0x2384, 0x2410);
  u32 fc_user_descriptor_ptr[2];
  u32 fc_buffer_control;
    CLIB_PAD_FROM_TO (0x241c, 0x2420);
  u32 fc_rx_dma;
    CLIB_PAD_FROM_TO (0x2424, 0x2430);
  u32 dcb_packet_plane_control;
    CLIB_PAD_FROM_TO (0x2434, 0x2f00);

  u32 rx_dma_control;
  u32 pf_queue_drop_enable;
    CLIB_PAD_FROM_TO (0x2f08, 0x2f20);
  u32 rx_dma_descriptor_cache_config;
    CLIB_PAD_FROM_TO (0x2f24, 0x3000);

  /* 1 bit. */
  u32 rx_enable;
    CLIB_PAD_FROM_TO (0x3004, 0x3008);
  /* [15:0] ether type (little endian)
     [31:16] opcode (big endian) */
  u32 flow_control_control;
    CLIB_PAD_FROM_TO (0x300c, 0x3020);
  /* 3 bit traffic class for each of 8 priorities. */
  u32 rx_priority_to_traffic_class;
    CLIB_PAD_FROM_TO (0x3024, 0x3028);
  u32 rx_coallesce_data_buffer_control;
    CLIB_PAD_FROM_TO (0x302c, 0x3190);
  u32 rx_packet_buffer_flush_detect;
    CLIB_PAD_FROM_TO (0x3194, 0x3200);
  u32 flow_control_tx_timers[4];	/* 2 timer values */
    CLIB_PAD_FROM_TO (0x3210, 0x3220);
  u32 flow_control_rx_threshold_lo[8];
    CLIB_PAD_FROM_TO (0x3240, 0x3260);
  u32 flow_control_rx_threshold_hi[8];
    CLIB_PAD_FROM_TO (0x3280, 0x32a0);
  u32 flow_control_refresh_threshold;
    CLIB_PAD_FROM_TO (0x32a4, 0x3c00);
  /* For each of 8 traffic classes (units of bytes). */
  u32 rx_packet_buffer_size[8];
    CLIB_PAD_FROM_TO (0x3c20, 0x3d00);
  u32 flow_control_config;
    CLIB_PAD_FROM_TO (0x3d04, 0x4200);

  struct
  {
    u32 pcs_config;
      CLIB_PAD_FROM_TO (0x4204, 0x4208);
    u32 link_control;
    u32 link_status;
    u32 pcs_debug[2];
    u32 auto_negotiation;
    u32 link_partner_ability;
    u32 auto_negotiation_tx_next_page;
    u32 auto_negotiation_link_partner_next_page;
      CLIB_PAD_FROM_TO (0x4228, 0x4240);
  } gige_mac;

  struct
  {
    /* [0] tx crc enable
       [2] enable frames up to max frame size register [31:16]
       [10] pad frames < 64 bytes if specified by user
       [15] loopback enable
       [16] mdc hi speed
       [17] turn off mdc between mdio packets */
    u32 control;

    /* [5] rx symbol error (all bits clear on read)
       [6] rx illegal symbol
       [7] rx idle error
       [8] rx local fault
       [9] rx remote fault */
    u32 status;

    u32 pause_and_pace_control;
      CLIB_PAD_FROM_TO (0x424c, 0x425c);
    u32 phy_command;
    u32 phy_data;
      CLIB_PAD_FROM_TO (0x4264, 0x4268);

    /* [31:16] max frame size in bytes. */
    u32 rx_max_frame_size;
      CLIB_PAD_FROM_TO (0x426c, 0x4288);

    /* [0]
       [2] pcs receive link up? (latch lo)
       [7] local fault
       [1]
       [0] pcs 10g base r capable
       [1] pcs 10g base x capable
       [2] pcs 10g base w capable
       [10] rx local fault
       [11] tx local fault
       [15:14] 2 => device present at this address (else not present) */
    u32 xgxs_status[2];

    u32 base_x_pcs_status;

    /* [0] pass unrecognized flow control frames
       [1] discard pause frames
       [2] rx priority flow control enable (only in dcb mode)
       [3] rx flow control enable. */
    u32 flow_control;

    /* [3:0] tx lanes change polarity
       [7:4] rx lanes change polarity
       [11:8] swizzle tx lanes
       [15:12] swizzle rx lanes
       4 x 2 bit tx lane swap
       4 x 2 bit rx lane swap. */
    u32 serdes_control;

    u32 fifo_control;

    /* [0] force link up
       [1] autoneg ack2 bit to transmit
       [6:2] autoneg selector field to transmit
       [8:7] 10g pma/pmd type 0 => xaui, 1 kx4, 2 cx4
       [9] 1g pma/pmd type 0 => sfi, 1 => kx/bx
       [10] disable 10g on without main power
       [11] restart autoneg on transition to dx power state
       [12] restart autoneg
       [15:13] link mode:
       0 => 1g no autoneg
       1 => 10g kx4 parallel link no autoneg
       2 => 1g bx autoneg
       3 => 10g sfi serdes
       4 => kx4/kx/kr
       5 => xgmii 1g/100m
       6 => kx4/kx/kr 1g an
       7 kx4/kx/kr sgmii.
       [16] kr support
       [17] fec requested
       [18] fec ability
       etc. */
    u32 auto_negotiation_control;

    /* [0] signal detect 1g/100m
       [1] fec signal detect
       [2] 10g serial pcs fec block lock
       [3] 10g serial high error rate
       [4] 10g serial pcs block lock
       [5] kx/kx4/kr autoneg next page received
       [6] kx/kx4/kr backplane autoneg next page received
       [7] link status clear to read
       [11:8] 10g signal detect (4 lanes) (for serial just lane 0)
       [12] 10g serial signal detect
       [16:13] 10g parallel lane sync status
       [17] 10g parallel align status
       [18] 1g sync status
       [19] kx/kx4/kr backplane autoneg is idle
       [20] 1g autoneg enabled
       [21] 1g pcs enabled for sgmii
       [22] 10g xgxs enabled
       [23] 10g serial fec enabled (forward error detection)
       [24] 10g kr pcs enabled
       [25] sgmii enabled
       [27:26] mac link mode
       0 => 1g
       1 => 10g parallel
       2 => 10g serial
       3 => autoneg
       [29:28] link speed
       1 => 100m
       2 => 1g
       3 => 10g
       [30] link is up
       [31] kx/kx4/kr backplane autoneg completed successfully. */
    u32 link_status;

    /* [17:16] pma/pmd for 10g serial
       0 => kr, 2 => sfi
       [18] disable dme pages */
    u32 auto_negotiation_control2;

      CLIB_PAD_FROM_TO (0x42ac, 0x42b0);
    u32 link_partner_ability[2];
      CLIB_PAD_FROM_TO (0x42b8, 0x42d0);
    u32 manageability_control;
    u32 link_partner_next_page[2];
      CLIB_PAD_FROM_TO (0x42dc, 0x42e0);
    u32 kr_pcs_control;
    u32 kr_pcs_status;
    u32 fec_status[2];
      CLIB_PAD_FROM_TO (0x42f0, 0x4314);
    u32 sgmii_control;
      CLIB_PAD_FROM_TO (0x4318, 0x4324);
    u32 link_status2;
      CLIB_PAD_FROM_TO (0x4328, 0x4900);
  } xge_mac;

  u32 tx_dcb_control;
  u32 tx_dcb_descriptor_plane_queue_select;
  u32 tx_dcb_descriptor_plane_t1_config;
  u32 tx_dcb_descriptor_plane_t1_status;
    CLIB_PAD_FROM_TO (0x4910, 0x4950);

  /* For each TC in units of 1k bytes. */
  u32 tx_packet_buffer_thresholds[8];
    CLIB_PAD_FROM_TO (0x4970, 0x4980);
  struct
  {
    u32 mmw;
    u32 config;
    u32 status;
    u32 rate_drift;
  } dcb_tx_rate_scheduler;
    CLIB_PAD_FROM_TO (0x4990, 0x4a80);
  u32 tx_dma_control;
    CLIB_PAD_FROM_TO (0x4a84, 0x4a88);
  u32 tx_dma_tcp_flags_control[2];
    CLIB_PAD_FROM_TO (0x4a90, 0x4b00);
  u32 pf_mailbox[64];
    CLIB_PAD_FROM_TO (0x4c00, 0x5000);

  /* RX */
  u32 checksum_control;
    CLIB_PAD_FROM_TO (0x5004, 0x5008);
  u32 rx_filter_control;
    CLIB_PAD_FROM_TO (0x500c, 0x5010);
  u32 management_vlan_tag[8];
  u32 management_udp_tcp_ports[8];
    CLIB_PAD_FROM_TO (0x5050, 0x5078);
  /* little endian. */
  u32 extended_vlan_ether_type;
    CLIB_PAD_FROM_TO (0x507c, 0x5080);
  /* [1] store/dma bad packets
     [8] accept all multicast
     [9] accept all unicast
     [10] accept all broadcast. */
  u32 filter_control;
    CLIB_PAD_FROM_TO (0x5084, 0x5088);
  /* [15:0] vlan ethernet type (0x8100) little endian
     [28] cfi bit expected
     [29] drop packets with unexpected cfi bit
     [30] vlan filter enable. */
  u32 vlan_control;
    CLIB_PAD_FROM_TO (0x508c, 0x5090);
  /* [1:0] hi bit of ethernet address for 12 bit index into multicast table
     0 => 47, 1 => 46, 2 => 45, 3 => 43.
     [2] enable multicast filter
   */
  u32 multicast_control;
    CLIB_PAD_FROM_TO (0x5094, 0x5100);
  u32 fcoe_rx_control;
    CLIB_PAD_FROM_TO (0x5104, 0x5108);
  u32 fc_flt_context;
    CLIB_PAD_FROM_TO (0x510c, 0x5110);
  u32 fc_filter_control;
    CLIB_PAD_FROM_TO (0x5114, 0x5120);
  u32 rx_message_type_lo;
    CLIB_PAD_FROM_TO (0x5124, 0x5128);
  /* [15:0] ethernet type (little endian)
     [18:16] matche pri in vlan tag
     [19] priority match enable
     [25:20] virtualization pool
     [26] pool enable
     [27] is fcoe
     [30] ieee 1588 timestamp enable
     [31] filter enable.
     (See ethernet_type_queue_select.) */
  u32 ethernet_type_queue_filter[8];
    CLIB_PAD_FROM_TO (0x5148, 0x5160);
  /* [7:0] l2 ethernet type and
     [15:8] l2 ethernet type or */
  u32 management_decision_filters1[8];
  u32 vf_vm_tx_switch_loopback_enable[2];
  u32 rx_time_sync_control;
    CLIB_PAD_FROM_TO (0x518c, 0x5190);
  u32 management_ethernet_type_filters[4];
  u32 rx_timestamp_attributes_lo;
  u32 rx_timestamp_hi;
  u32 rx_timestamp_attributes_hi;
    CLIB_PAD_FROM_TO (0x51ac, 0x51b0);
  u32 pf_virtual_control;
    CLIB_PAD_FROM_TO (0x51b4, 0x51d8);
  u32 fc_offset_parameter;
    CLIB_PAD_FROM_TO (0x51dc, 0x51e0);
  u32 vf_rx_enable[2];
  u32 rx_timestamp_lo;
    CLIB_PAD_FROM_TO (0x51ec, 0x5200);
  /* 12 bits determined by multicast_control
     lookup bits in this vector. */
  u32 multicast_enable[128];

  /* [0] ethernet address [31:0]
     [1] [15:0] ethernet address [47:32]
     [31] valid bit.
     Index 0 is read from eeprom after reset. */
  u32 rx_ethernet_address0[16][2];

    CLIB_PAD_FROM_TO (0x5480, 0x5800);
  u32 wake_up_control;
    CLIB_PAD_FROM_TO (0x5804, 0x5808);
  u32 wake_up_filter_control;
    CLIB_PAD_FROM_TO (0x580c, 0x5818);
  u32 multiple_rx_queue_command_82598;
    CLIB_PAD_FROM_TO (0x581c, 0x5820);
  u32 management_control;
  u32 management_filter_control;
    CLIB_PAD_FROM_TO (0x5828, 0x5838);
  u32 wake_up_ip4_address_valid;
    CLIB_PAD_FROM_TO (0x583c, 0x5840);
  u32 wake_up_ip4_address_table[4];
  u32 management_control_to_host;
    CLIB_PAD_FROM_TO (0x5854, 0x5880);
  u32 wake_up_ip6_address_table[4];

  /* unicast_and broadcast_and vlan_and ip_address_and
     etc. */
  u32 management_decision_filters[8];

  u32 management_ip4_or_ip6_address_filters[4][4];
    CLIB_PAD_FROM_TO (0x58f0, 0x5900);
  u32 wake_up_packet_length;
    CLIB_PAD_FROM_TO (0x5904, 0x5910);
  u32 management_ethernet_address_filters[4][2];
    CLIB_PAD_FROM_TO (0x5930, 0x5a00);
  u32 wake_up_packet_memory[32];
    CLIB_PAD_FROM_TO (0x5a80, 0x5c00);
  u32 redirection_table_82598[32];
  u32 rss_random_keys_82598[10];
    CLIB_PAD_FROM_TO (0x5ca8, 0x6000);

  ixge_dma_regs_t tx_dma[128];

  u32 pf_vm_vlan_insert[64];
  u32 tx_dma_tcp_max_alloc_size_requests;
    CLIB_PAD_FROM_TO (0x8104, 0x8110);
  u32 vf_tx_enable[2];
    CLIB_PAD_FROM_TO (0x8118, 0x8120);
  /* [0] dcb mode enable
     [1] virtualization mode enable
     [3:2] number of tcs/qs per pool. */
  u32 multiple_tx_queues_command;
    CLIB_PAD_FROM_TO (0x8124, 0x8200);
  u32 pf_vf_anti_spoof[8];
  u32 pf_dma_tx_switch_control;
    CLIB_PAD_FROM_TO (0x8224, 0x82e0);
  u32 tx_strict_low_latency_queues[4];
    CLIB_PAD_FROM_TO (0x82f0, 0x8600);
  u32 tx_queue_stats_mapping_82599[32];
  u32 tx_queue_packet_counts[32];
  u32 tx_queue_byte_counts[32][2];

  struct
  {
    u32 control;
    u32 status;
    u32 buffer_almost_full;
      CLIB_PAD_FROM_TO (0x880c, 0x8810);
    u32 buffer_min_ifg;
      CLIB_PAD_FROM_TO (0x8814, 0x8900);
  } tx_security;

  struct
  {
    u32 index;
    u32 salt;
    u32 key[4];
      CLIB_PAD_FROM_TO (0x8918, 0x8a00);
  } tx_ipsec;

  struct
  {
    u32 capabilities;
    u32 control;
    u32 tx_sci[2];
    u32 sa;
    u32 sa_pn[2];
    u32 key[2][4];
    /* untagged packets, encrypted packets, protected packets,
       encrypted bytes, protected bytes */
    u32 stats[5];
      CLIB_PAD_FROM_TO (0x8a50, 0x8c00);
  } tx_link_security;

  struct
  {
    u32 control;
    u32 timestamp_value[2];
    u32 system_time[2];
    u32 increment_attributes;
    u32 time_adjustment_offset[2];
    u32 aux_control;
    u32 target_time[2][2];
      CLIB_PAD_FROM_TO (0x8c34, 0x8c3c);
    u32 aux_time_stamp[2][2];
      CLIB_PAD_FROM_TO (0x8c4c, 0x8d00);
  } tx_timesync;

  struct
  {
    u32 control;
    u32 status;
      CLIB_PAD_FROM_TO (0x8d08, 0x8e00);
  } rx_security;

  struct
  {
    u32 index;
    u32 ip_address[4];
    u32 spi;
    u32 ip_index;
    u32 key[4];
    u32 salt;
    u32 mode;
      CLIB_PAD_FROM_TO (0x8e34, 0x8f00);
  } rx_ipsec;

  struct
  {
    u32 capabilities;
    u32 control;
    u32 sci[2];
    u32 sa[2];
    u32 sa_pn[2];
    u32 key[2][4];
    /* see datasheet */
    u32 stats[17];
      CLIB_PAD_FROM_TO (0x8f84, 0x9000);
  } rx_link_security;

  /* 4 wake up, 2 management, 2 wake up. */
  u32 flexible_filters[8][16][4];
    CLIB_PAD_FROM_TO (0x9800, 0xa000);

  /* 4096 bits. */
  u32 vlan_filter[128];

  /* [0] ethernet address [31:0]
     [1] [15:0] ethernet address [47:32]
     [31] valid bit.
     Index 0 is read from eeprom after reset. */
  u32 rx_ethernet_address1[128][2];

  /* select one of 64 pools for each rx address. */
  u32 rx_ethernet_address_pool_select[128][2];
    CLIB_PAD_FROM_TO (0xaa00, 0xc800);
  u32 tx_priority_to_traffic_class;
    CLIB_PAD_FROM_TO (0xc804, 0xcc00);

  /* In bytes units of 1k.  Total packet buffer is 160k. */
  u32 tx_packet_buffer_size[8];

    CLIB_PAD_FROM_TO (0xcc20, 0xcd10);
  u32 tx_manageability_tc_mapping;
    CLIB_PAD_FROM_TO (0xcd14, 0xcd20);
  u32 dcb_tx_packet_plane_t2_config[8];
  u32 dcb_tx_packet_plane_t2_status[8];
    CLIB_PAD_FROM_TO (0xcd60, 0xce00);

  u32 tx_flow_control_status;
    CLIB_PAD_FROM_TO (0xce04, 0xd000);

  ixge_dma_regs_t rx_dma1[64];

  struct
  {
    /* Bigendian ip4 src/dst address. */
    u32 src_address[128];
    u32 dst_address[128];

    /* TCP/UDP ports [15:0] src [31:16] dst; bigendian. */
    u32 tcp_udp_port[128];

    /* [1:0] protocol tcp, udp, sctp, other
       [4:2] match priority (highest wins)
       [13:8] pool
       [25] src address match disable
       [26] dst address match disable
       [27] src port match disable
       [28] dst port match disable
       [29] protocol match disable
       [30] pool match disable
       [31] enable. */
    u32 control[128];

    /* [12] size bypass
       [19:13] must be 0x80
       [20] low-latency interrupt
       [27:21] rx queue. */
    u32 interrupt[128];
  } ip4_filters;

    CLIB_PAD_FROM_TO (0xea00, 0xeb00);
  /* 4 bit rss output index indexed by 7 bit hash.
     128 8 bit fields = 32 registers. */
  u32 redirection_table_82599[32];

  u32 rss_random_key_82599[10];
    CLIB_PAD_FROM_TO (0xeba8, 0xec00);
  /* [15:0] reserved
     [22:16] rx queue index
     [29] low-latency interrupt on match
     [31] enable */
  u32 ethernet_type_queue_select[8];
    CLIB_PAD_FROM_TO (0xec20, 0xec30);
  u32 syn_packet_queue_filter;
    CLIB_PAD_FROM_TO (0xec34, 0xec60);
  u32 immediate_interrupt_rx_vlan_priority;
    CLIB_PAD_FROM_TO (0xec64, 0xec70);
  u32 rss_queues_per_traffic_class;
    CLIB_PAD_FROM_TO (0xec74, 0xec90);
  u32 lli_size_threshold;
    CLIB_PAD_FROM_TO (0xec94, 0xed00);

  struct
  {
    u32 control;
      CLIB_PAD_FROM_TO (0xed04, 0xed10);
    u32 table[8];
      CLIB_PAD_FROM_TO (0xed30, 0xee00);
  } fcoe_redirection;

  struct
  {
    /* [1:0] packet buffer allocation 0 => disabled, else 64k*2^(f-1)
       [3] packet buffer initialization done
       [4] perfetch match mode
       [5] report status in rss field of rx descriptors
       [7] report status always
       [14:8] drop queue
       [20:16] flex 2 byte packet offset (units of 2 bytes)
       [27:24] max linked list length
       [31:28] full threshold. */
    u32 control;
      CLIB_PAD_FROM_TO (0xee04, 0xee0c);

    u32 data[8];

    /* [1:0] 0 => no action, 1 => add, 2 => remove, 3 => query.
       [2] valid filter found by query command
       [3] filter update override
       [4] ip6 adress table
       [6:5] l4 protocol reserved, udp, tcp, sctp
       [7] is ip6
       [8] clear head/tail
       [9] packet drop action
       [10] matched packet generates low-latency interrupt
       [11] last in linked list
       [12] collision
       [15] rx queue enable
       [22:16] rx queue
       [29:24] pool. */
    u32 command;

      CLIB_PAD_FROM_TO (0xee30, 0xee3c);
    /* ip4 dst/src address, tcp ports, udp ports.
       set bits mean bit is ignored. */
    u32 ip4_masks[4];
    u32 filter_length;
    u32 usage_stats;
    u32 failed_usage_stats;
    u32 filters_match_stats;
    u32 filters_miss_stats;
      CLIB_PAD_FROM_TO (0xee60, 0xee68);
    /* Lookup, signature. */
    u32 hash_keys[2];
    /* [15:0] ip6 src address 1 bit per byte
       [31:16] ip6 dst address. */
    u32 ip6_mask;
    /* [0] vlan id
       [1] vlan priority
       [2] pool
       [3] ip protocol
       [4] flex
       [5] dst ip6. */
    u32 other_mask;
      CLIB_PAD_FROM_TO (0xee78, 0xf000);
  } flow_director;

  struct
  {
    u32 l2_control[64];
    u32 vlan_pool_filter[64];
    u32 vlan_pool_filter_bitmap[128];
    u32 dst_ethernet_address[128];
    u32 mirror_rule[4];
    u32 mirror_rule_vlan[8];
    u32 mirror_rule_pool[8];
      CLIB_PAD_FROM_TO (0xf650, 0x10010);
  } pf_bar;

  u32 eeprom_flash_control;
  /* [0] start
     [1] done
     [15:2] address
     [31:16] read data. */
  u32 eeprom_read;
    CLIB_PAD_FROM_TO (0x10018, 0x1001c);
  u32 flash_access;
    CLIB_PAD_FROM_TO (0x10020, 0x10114);
  u32 flash_data;
  u32 flash_control;
  u32 flash_read_data;
    CLIB_PAD_FROM_TO (0x10120, 0x1013c);
  u32 flash_opcode;
  u32 software_semaphore;
    CLIB_PAD_FROM_TO (0x10144, 0x10148);
  u32 firmware_semaphore;
    CLIB_PAD_FROM_TO (0x1014c, 0x10160);
  u32 software_firmware_sync;
    CLIB_PAD_FROM_TO (0x10164, 0x10200);
  u32 general_rx_control;
    CLIB_PAD_FROM_TO (0x10204, 0x11000);

  struct
  {
    u32 control;
      CLIB_PAD_FROM_TO (0x11004, 0x11010);
    /* [3:0] enable counters
       [7:4] leaky bucket counter mode
       [29] reset
       [30] stop
       [31] start. */
    u32 counter_control;
    /* [7:0],[15:8],[23:16],[31:24] event for counters 0-3.
       event codes:
       0x0 bad tlp
       0x10 reqs that reached timeout
       etc. */
    u32 counter_event;
      CLIB_PAD_FROM_TO (0x11018, 0x11020);
    u32 counters_clear_on_read[4];
    u32 counter_config[4];
    struct
    {
      u32 address;
      u32 data;
    } indirect_access;
      CLIB_PAD_FROM_TO (0x11048, 0x11050);
    u32 extended_control;
      CLIB_PAD_FROM_TO (0x11054, 0x11064);
    u32 mirrored_revision_id;
      CLIB_PAD_FROM_TO (0x11068, 0x11070);
    u32 dca_requester_id_information;

    /* [0] global disable
       [4:1] mode: 0 => legacy, 1 => dca 1.0. */
    u32 dca_control;
      CLIB_PAD_FROM_TO (0x11078, 0x110b0);
    /* [0] pci completion abort
       [1] unsupported i/o address
       [2] wrong byte enable
       [3] pci timeout */
    u32 pcie_interrupt_status;
      CLIB_PAD_FROM_TO (0x110b4, 0x110b8);
    u32 pcie_interrupt_enable;
      CLIB_PAD_FROM_TO (0x110bc, 0x110c0);
    u32 msi_x_pba_clear[8];
      CLIB_PAD_FROM_TO (0x110e0, 0x12300);
  } pcie;

  u32 interrupt_throttle1[128 - 24];
    CLIB_PAD_FROM_TO (0x124a0, 0x14f00);

  u32 core_analog_config;
    CLIB_PAD_FROM_TO (0x14f04, 0x14f10);
  u32 core_common_config;
    CLIB_PAD_FROM_TO (0x14f14, 0x15f14);

  u32 link_sec_software_firmware_interface;
} ixge_regs_t;

typedef union
{
  struct
  {
    /* Addresses bigendian. */
    union
    {
      struct
      {
	ip6_address_t src_address;
	u32 unused[1];
      } ip6;
      struct
      {
	u32 unused[3];
	ip4_address_t src_address, dst_address;
      } ip4;
    };

    /* [15:0] src port (little endian).
       [31:16] dst port. */
    u32 tcp_udp_ports;

    /* [15:0] vlan (cfi bit set to 0).
       [31:16] flex bytes.  bigendian. */
    u32 vlan_and_flex_word;

    /* [14:0] hash
       [15] bucket valid
       [31:16] signature (signature filers)/sw-index (perfect match). */
    u32 hash;
  };

  u32 as_u32[8];
} ixge_flow_director_key_t;

always_inline void
ixge_throttle_queue_interrupt (ixge_regs_t * r,
			       u32 queue_interrupt_index,
			       f64 inter_interrupt_interval_in_secs)
{
  volatile u32 *tr =
    (queue_interrupt_index < ARRAY_LEN (r->interrupt.throttle0)
     ? &r->interrupt.throttle0[queue_interrupt_index]
     : &r->interrupt_throttle1[queue_interrupt_index]);
  ASSERT (queue_interrupt_index < 128);
  u32 v;
  i32 i, mask = (1 << 9) - 1;

  i = flt_round_nearest (inter_interrupt_interval_in_secs / 2e-6);
  i = i < 1 ? 1 : i;
  i = i >= mask ? mask : i;

  v = tr[0];
  v &= ~(mask << 3);
  v |= i << 3;
  tr[0] = v;
}

#define foreach_ixge_counter				\
  _ (0x40d0, rx_total_packets)				\
  _64 (0x40c0, rx_total_bytes)				\
  _ (0x41b0, rx_good_packets_before_filtering)		\
  _64 (0x41b4, rx_good_bytes_before_filtering)		\
  _ (0x2f50, rx_dma_good_packets)			\
  _64 (0x2f54, rx_dma_good_bytes)			\
  _ (0x2f5c, rx_dma_duplicated_good_packets)		\
  _64 (0x2f60, rx_dma_duplicated_good_bytes)		\
  _ (0x2f68, rx_dma_good_loopback_packets)		\
  _64 (0x2f6c, rx_dma_good_loopback_bytes)		\
  _ (0x2f74, rx_dma_good_duplicated_loopback_packets)	\
  _64 (0x2f78, rx_dma_good_duplicated_loopback_bytes)	\
  _ (0x4074, rx_good_packets)				\
  _64 (0x4088, rx_good_bytes)				\
  _ (0x407c, rx_multicast_packets)			\
  _ (0x4078, rx_broadcast_packets)			\
  _ (0x405c, rx_64_byte_packets)			\
  _ (0x4060, rx_65_127_byte_packets)			\
  _ (0x4064, rx_128_255_byte_packets)			\
  _ (0x4068, rx_256_511_byte_packets)			\
  _ (0x406c, rx_512_1023_byte_packets)			\
  _ (0x4070, rx_gt_1023_byte_packets)			\
  _ (0x4000, rx_crc_errors)				\
  _ (0x4120, rx_ip_checksum_errors)			\
  _ (0x4004, rx_illegal_symbol_errors)			\
  _ (0x4008, rx_error_symbol_errors)			\
  _ (0x4034, rx_mac_local_faults)			\
  _ (0x4038, rx_mac_remote_faults)			\
  _ (0x4040, rx_length_errors)				\
  _ (0x41a4, rx_xons)					\
  _ (0x41a8, rx_xoffs)					\
  _ (0x40a4, rx_undersize_packets)			\
  _ (0x40a8, rx_fragments)				\
  _ (0x40ac, rx_oversize_packets)			\
  _ (0x40b0, rx_jabbers)				\
  _ (0x40b4, rx_management_packets)			\
  _ (0x40b8, rx_management_drops)			\
  _ (0x3fa0, rx_missed_packets_pool_0)			\
  _ (0x40d4, tx_total_packets)				\
  _ (0x4080, tx_good_packets)				\
  _64 (0x4090, tx_good_bytes)				\
  _ (0x40f0, tx_multicast_packets)			\
  _ (0x40f4, tx_broadcast_packets)			\
  _ (0x87a0, tx_dma_good_packets)			\
  _64 (0x87a4, tx_dma_good_bytes)			\
  _ (0x40d8, tx_64_byte_packets)			\
  _ (0x40dc, tx_65_127_byte_packets)			\
  _ (0x40e0, tx_128_255_byte_packets)			\
  _ (0x40e4, tx_256_511_byte_packets)			\
  _ (0x40e8, tx_512_1023_byte_packets)			\
  _ (0x40ec, tx_gt_1023_byte_packets)			\
  _ (0x4010, tx_undersize_drops)			\
  _ (0x8780, switch_security_violation_packets)		\
  _ (0x5118, fc_crc_errors)				\
  _ (0x241c, fc_rx_drops)				\
  _ (0x2424, fc_last_error_count)			\
  _ (0x2428, fcoe_rx_packets)				\
  _ (0x242c, fcoe_rx_dwords)				\
  _ (0x8784, fcoe_tx_packets)				\
  _ (0x8788, fcoe_tx_dwords)				\
  _ (0x1030, queue_0_rx_count)				\
  _ (0x1430, queue_0_drop_count)			\
  _ (0x1070, queue_1_rx_count)				\
  _ (0x1470, queue_1_drop_count)			\
  _ (0x10b0, queue_2_rx_count)				\
  _ (0x14b0, queue_2_drop_count)			\
  _ (0x10f0, queue_3_rx_count)				\
  _ (0x14f0, queue_3_drop_count)			\
  _ (0x1130, queue_4_rx_count)				\
  _ (0x1530, queue_4_drop_count)			\
  _ (0x1170, queue_5_rx_count)				\
  _ (0x1570, queue_5_drop_count)			\
  _ (0x11b0, queue_6_rx_count)				\
  _ (0x15b0, queue_6_drop_count)			\
  _ (0x11f0, queue_7_rx_count)				\
  _ (0x15f0, queue_7_drop_count)			\
  _ (0x1230, queue_8_rx_count)				\
  _ (0x1630, queue_8_drop_count)			\
  _ (0x1270, queue_9_rx_count)				\
  _ (0x1270, queue_9_drop_count)




typedef enum
{
#define _(a,f) IXGE_COUNTER_##f,
#define _64(a,f) _(a,f)
  foreach_ixge_counter
#undef _
#undef _64
    IXGE_N_COUNTER,
} ixge_counter_type_t;

typedef struct
{
  u32 mdio_address;

  /* 32 bit ID read from ID registers. */
  u32 id;
} ixge_phy_t;

typedef struct
{
  /* Cache aligned descriptors. */
  ixge_descriptor_t *descriptors;

  /* Number of descriptors in table. */
  u32 n_descriptors;

  /* Software head and tail pointers into descriptor ring. */
  u32 head_index, tail_index;

  /* Index into dma_queues vector. */
  u32 queue_index;

  /* Buffer indices corresponding to each active descriptor. */
  u32 *descriptor_buffer_indices;

  union
  {
    struct
    {
      u32 *volatile head_index_write_back;

      u32 n_buffers_on_ring;
    } tx;

    struct
    {
      /* Buffer indices to use to replenish each descriptor. */
      u32 *replenish_buffer_indices;

      vlib_node_runtime_t *node;
      u32 next_index;

      u32 saved_start_of_packet_buffer_index;

      u32 saved_start_of_packet_next_index;
      u32 saved_last_buffer_index;

      u32 is_start_of_packet;

      u32 n_descriptors_done_total;

      u32 n_descriptors_done_this_call;

      u32 n_bytes;
    } rx;
  };
} ixge_dma_queue_t;

#define foreach_ixge_pci_device_id		\
  _ (82598, 0x10b6)				\
  _ (82598_bx, 0x1508)				\
  _ (82598af_dual_port, 0x10c6)			\
  _ (82598af_single_port, 0x10c7)		\
  _ (82598at, 0x10c8)				\
  _ (82598at2, 0x150b)				\
  _ (82598eb_sfp_lom, 0x10db)			\
  _ (82598eb_cx4, 0x10dd)			\
  _ (82598_cx4_dual_port, 0x10ec)		\
  _ (82598_da_dual_port, 0x10f1)		\
  _ (82598_sr_dual_port_em, 0x10e1)		\
  _ (82598eb_xf_lr, 0x10f4)			\
  _ (82599_kx4, 0x10f7)				\
  _ (82599_kx4_mezz, 0x1514)			\
  _ (82599_kr, 0x1517)				\
  _ (82599_combo_backplane, 0x10f8)		\
  _ (82599_cx4, 0x10f9)				\
  _ (82599_sfp, 0x10fb)				\
  _ (82599_backplane_fcoe, 0x152a)		\
  _ (82599_sfp_fcoe, 0x1529)			\
  _ (82599_sfp_em, 0x1507)			\
  _ (82599_xaui_lom, 0x10fc)			\
  _ (82599_t3_lom, 0x151c)			\
  _ (x540t, 0x1528)

typedef enum
{
#define _(f,n) IXGE_##f = n,
  foreach_ixge_pci_device_id
#undef _
} ixge_pci_device_id_t;

typedef struct
{
  /* registers */
  ixge_regs_t *regs;

  /* Specific next index when using dynamic redirection */
  u32 per_interface_next_index;

  /* PCI bus info. */
  vlib_pci_device_t pci_device;

  /* From PCI config space header. */
  ixge_pci_device_id_t device_id;

  u16 device_index;

  /* 0 or 1. */
  u16 pci_function;

  /* VLIB interface for this instance. */
  u32 vlib_hw_if_index, vlib_sw_if_index;

  ixge_dma_queue_t *dma_queues[VLIB_N_RX_TX];

  /* Phy index (0 or 1) and address on MDI bus. */
  u32 phy_index;
  ixge_phy_t phys[2];

  /* Value of link_status register at last link change. */
  u32 link_status_at_last_link_change;

  i2c_bus_t i2c_bus;
  sfp_eeprom_t sfp_eeprom;

  /* Counters. */
  u64 counters[IXGE_N_COUNTER], counters_last_clear[IXGE_N_COUNTER];
} ixge_device_t;

typedef struct
{
  vlib_main_t *vlib_main;

  /* Vector of devices. */
  ixge_device_t *devices;

  /* Descriptor ring sizes. */
  u32 n_descriptors[VLIB_N_RX_TX];

  /* RX buffer size.  Must be at least 1k; will be rounded to
     next largest 1k size. */
  u32 n_bytes_in_rx_buffer;

  u32 n_descriptors_per_cache_line;

  u32 vlib_buffer_free_list_index;

  u32 process_node_index;

  /* Template and mask for initializing/validating TX descriptors. */
  ixge_tx_descriptor_t tx_descriptor_template, tx_descriptor_template_mask;

  /* Vector of buffers for which TX is done and can be freed. */
  u32 *tx_buffers_pending_free;

  u32 *rx_buffers_to_add;

  f64 time_last_stats_update;

  vlib_physmem_region_index_t physmem_region;
} ixge_main_t;

extern ixge_main_t ixge_main;
extern vnet_device_class_t ixge_device_class;

typedef enum
{
  IXGE_RX_NEXT_IP4_INPUT,
  IXGE_RX_NEXT_IP6_INPUT,
  IXGE_RX_NEXT_ETHERNET_INPUT,
  IXGE_RX_NEXT_DROP,
  IXGE_RX_N_NEXT,
} ixge_rx_next_t;

void ixge_set_next_node (ixge_rx_next_t, char *);

#endif /* included_ixge_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
