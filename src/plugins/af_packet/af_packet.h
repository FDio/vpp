/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/*
 * af_packet.h - linux kernel packet interface header file
 */

#include <linux/if_packet.h>

#include <vppinfra/lock.h>
#include <vlib/log.h>

typedef struct tpacket_block_desc block_desc_t;
typedef struct tpacket_req tpacket_req_t;
typedef struct tpacket_req3 tpacket_req3_t;
typedef struct tpacket2_hdr tpacket2_hdr_t;
typedef struct tpacket3_hdr tpacket3_hdr_t;

typedef union _tpacket_req_u
{
  tpacket_req_t req;
  tpacket_req3_t req3;
} tpacket_req_u_t;

typedef enum
{
  AF_PACKET_IF_MODE_ETHERNET = 1,
  AF_PACKET_IF_MODE_IP = 2
} af_packet_if_mode_t;

typedef enum
{
  AF_PACKET_IF_FLAGS_QDISC_BYPASS = 1,
  AF_PACKET_IF_FLAGS_CKSUM_GSO = 2,
  AF_PACKET_IF_FLAGS_FANOUT = 4,
  AF_PACKET_IF_FLAGS_VERSION_2 = 8,
} af_packet_if_flags_t;

#define foreach_af_packet_offload_flag                                        \
  _ (RXCKSUM, 0, "rx checksum")                                               \
  _ (TXCKSUM, 1, "tx checksum")                                               \
  _ (SG, 2, "scatter-gather")                                                 \
  _ (TSO, 3, "tcp segmentation offload")                                      \
  _ (UFO, 4, "udp fragmentation offload")                                     \
  _ (GSO, 5, "generic segmentation offload")                                  \
  _ (GRO, 6, "generic receive offload")

typedef enum
{
#define _(o, n, s) AF_PACKET_OFFLOAD_FLAG_##o = (1 << n),
  foreach_af_packet_offload_flag
#undef _
} af_packet_offload_flag_t;

#define AF_PACKET_OFFLOAD_FLAG_MASK                                           \
  (AF_PACKET_OFFLOAD_FLAG_RXCKSUM | AF_PACKET_OFFLOAD_FLAG_TXCKSUM |          \
   AF_PACKET_OFFLOAD_FLAG_SG | AF_PACKET_OFFLOAD_FLAG_TSO |                   \
   AF_PACKET_OFFLOAD_FLAG_UFO | AF_PACKET_OFFLOAD_FLAG_GSO |                  \
   AF_PACKET_OFFLOAD_FLAG_GRO)

typedef struct
{
  u32 sw_if_index;
  u8 host_if_name[64];
} af_packet_if_detail_t;

typedef struct
{
  u8 *ring_start_addr;
  u32 ring_size;
} af_packet_ring_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lockp;
  int fd;
  union
  {
    tpacket_req_u_t *rx_req;
    tpacket_req_u_t *tx_req;
  };

  union
  {
    u8 **rx_ring;
    u8 **tx_ring;
  };

  union
  {
    u32 next_rx_block;
    u32 next_rx_frame;
    u32 next_tx_frame;
  };

  u16 queue_id;
  u32 queue_index;

  u32 clib_file_index;

  u32 rx_frame_offset;
  u16 num_rx_pkts;
  u8 is_rx_pending;
  u8 is_tx_pending;
  vnet_hw_if_rx_mode mode;
} af_packet_queue_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 hw_if_index;
  u32 sw_if_index;
  u32 per_interface_next_index;
  af_packet_if_mode_t mode;
  u8 is_admin_up;
  u8 is_cksum_gso_enabled;
  u8 version;
  af_packet_queue_t *rx_queues;
  af_packet_queue_t *tx_queues;

  u8 num_rxqs;
  u8 num_txqs;

  u8 *host_if_name;
  int host_if_index;

  u32 host_mtu;
  u32 dev_instance;

  af_packet_ring_t *rings;
  u8 is_qdisc_bypass_enabled;
  u8 is_fanout_enabled;
  int *fds;
  af_packet_offload_flag_t host_interface_oflags;
} af_packet_if_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  af_packet_if_t *interfaces;

  u32 polling_count;
  /* rx buffer cache */
  u32 **rx_buffers;

  /* hash of host interface names */
  mhash_t if_index_by_host_if_name;

  /** log class */
  vlib_log_class_t log_class;
} af_packet_main_t;

typedef struct
{
  u8 *host_if_name;
  u8 *hw_addr;
  u32 rx_frame_size;
  u32 tx_frame_size;
  u32 rx_frames_per_block;
  u32 tx_frames_per_block;
  u8 num_rxqs;
  u8 num_txqs;
  u8 is_v2;
  af_packet_if_mode_t mode;
  af_packet_if_flags_t flags;

  /* return */
  u32 sw_if_index;
} af_packet_create_if_arg_t;

extern af_packet_main_t af_packet_main;
extern vnet_device_class_t af_packet_device_class;
extern vlib_node_registration_t af_packet_input_node;

int af_packet_create_if (af_packet_create_if_arg_t *arg);
int af_packet_delete_if (u8 *host_if_name);
int af_packet_set_l4_cksum_offload (u32 sw_if_index, u8 set);
int af_packet_enable_disable_qdisc_bypass (u32 sw_if_index, u8 enable_disable);
int af_packet_dump_ifs (af_packet_if_detail_t ** out_af_packet_ifs);
u32 af_packet_get_if_capabilities (u8 *host_if_name);

format_function_t format_af_packet_device_name;

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
