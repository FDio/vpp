/*
 *------------------------------------------------------------------
 * Copyright (c) 2023 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _IDPF_VIRTCHNL_H_
#define _IDPF_VIRTCHNL_H_

#include <idpf/virtchnl2_lan_desc.h>

#define foreach_virtchnl2_status                                              \
  _ (0, SUCCESS)                                                              \
  _ (-5, ERR_PARAM)                                                           \
  _ (-38, ERR_OPCODE_MISMATCH)

typedef enum
{
#define _(v, n) VIRTCHNL2_STATUS_##n = v,
  foreach_virtchnl2_status
#undef _
} virtchnl2_status_t;

#define foreach_virtchnl2_op                                                  \
  _ (0, UNKNOWN)                                                              \
  _ (1, VERSION)                                                              \
  _ (500, GET_CAPS)                                                           \
  _ (501, CREATE_VPORT)                                                       \
  _ (502, DESTROY_VPORT)                                                      \
  _ (503, ENABLE_VPORT)                                                       \
  _ (504, DISABLE_VPORT)                                                      \
  _ (505, CONFIG_TX_QUEUES)                                                   \
  _ (506, CONFIG_RX_QUEUES)                                                   \
  _ (507, ENABLE_QUEUES)                                                      \
  _ (508, DISABLE_QUEUES)                                                     \
  _ (509, ADD_QUEUES)                                                         \
  _ (510, DEL_QUEUES)                                                         \
  _ (511, MAP_QUEUE_VECTOR)                                                   \
  _ (512, UNMAP_QUEUE_VECTOR)                                                 \
  _ (513, GET_RSS_KEY)                                                        \
  _ (514, SET_RSS_KEY)                                                        \
  _ (515, GET_RSS_LUT)                                                        \
  _ (516, SET_RSS_LUT)                                                        \
  _ (517, GET_RSS_HASH)                                                       \
  _ (518, SET_RSS_HASH)                                                       \
  _ (519, SET_SRIOV_VFS)                                                      \
  _ (520, ALLOC_VECTORS)                                                      \
  _ (521, DEALLOC_VECTORS)                                                    \
  _ (522, EVENT)                                                              \
  _ (523, GET_STATS)                                                          \
  _ (524, RESET_VF)                                                           \
  _ (526, GET_PTYPE_INFO)                                                     \
  _ (532, CREATE_ADI)                                                         \
  _ (533, DESTROY_ADI)                                                        \
  _ (534, LOOPBACK)                                                           \
  _ (535, ADD_MAC_ADDR)                                                       \
  _ (536, DEL_MAC_ADDR)                                                       \
  _ (537, CONFIG_PROMISCUOUS_MODE)

typedef enum
{
#define _(v, n) VIRTCHNL2_OP_##n = v,
  foreach_virtchnl2_op
#undef _
} virtchnl2_op_t;

/* VIRTCHNL2_VPORT_TYPE
 * Type of virtual port
 */
#define foreach_virtchnl2_vport_type                                          \
  _ (0, DEFAULT)                                                              \
  _ (1, SRIOV)                                                                \
  _ (2, SIOV)                                                                 \
  _ (3, SUBDEV)                                                               \
  _ (4, MNG)

typedef enum
{
#define _(v, n) VIRTCHNL2_VPORT_TYPE_##n = v,
  foreach_virtchnl2_vport_type
#undef _
} virtchnl2_vport_type_t;

/* VIRTCHNL2_QUEUE_MODEL
 * Type of queue model
 */
#define VIRTCHNL2_QUEUE_MODEL_SINGLE 0
#define VIRTCHNL2_QUEUE_MODEL_SPLIT  1

#define foreach_idpf_checksum_cap_flag                                        \
  _ (0, TX_CSUM_L3_IPV4, "tx-csum-l3-ipv4")                                   \
  _ (1, TX_CSUM_L4_IPV4_TCP, "tx-csum-l4-ipv4-tcp")                           \
  _ (2, TX_CSUM_L4_IPV4_UDP, "tx-csum-l4-ipv4-udp")                           \
  _ (3, TX_CSUM_L4_IPV4_SCTP, "tx-csum-l4-ipv4-sctp")                         \
  _ (4, TX_CSUM_L4_IPV6_TCP, "tx-csum-l4-ipv6-tcp")                           \
  _ (5, TX_CSUM_L4_IPV6_UDP, "tx-csum-l4-ipv6-udp")                           \
  _ (6, TX_CSUM_L4_IPV6_SCTP, "tx-csum-l4-ipv6-sctp")                         \
  _ (7, TX_CSUM_GENERIC, "tx-csum-generic")                                   \
  _ (8, RX_CSUM_L3_IPV4, "rx-csum-l3-ipv4")                                   \
  _ (9, RX_CSUM_L4_IPV4_TCP, "rx-csum-l4-ipv4-tcp")                           \
  _ (10, RX_CSUM_L4_IPV4_UDP, "rx-csum-l4-ipv4-udp")                          \
  _ (11, RX_CSUM_L4_IPV4_SCTP, "rx-csum-l4-ipv4-sctp")                        \
  _ (12, RX_CSUM_L4_IPV6_TCP, "rx-csum-l4-ipv6-tcp")                          \
  _ (13, RX_CSUM_L4_IPV6_UDP, "rx-csum-l4-ipv6-udp")                          \
  _ (14, RX_CSUM_L4_IPV6_SCTP, "rx-csum-l4-ipv6-sctp")                        \
  _ (15, RX_CSUM_GENERIC, "rx-csum-generic")                                  \
  _ (16, TX_CSUM_L3_SINGLE_TUNNEL, "tx-csum-l3-single-tunnel")                \
  _ (17, TX_CSUM_L3_DOUBLE_TUNNEL, "tx-csum-l3-double-tunnel")                \
  _ (18, RX_CSUM_L3_SINGLE_TUNNEL, "rx-csum-l3-single-tunnel")                \
  _ (19, RX_CSUM_L3_DOUBLE_TUNNEL, "rx-csum-l3-double-tunnel")                \
  _ (20, TX_CSUM_L4_SINGLE_TUNNEL, "tx-csum-l4-single-tunnel")                \
  _ (21, TX_CSUM_L4_DOUBLE_TUNNEL, "tx-csum-l4-double-tunnel")                \
  _ (22, RX_CSUM_L4_SINGLE_TUNNEL, "rx-csum-l4-single-tunnel")                \
  _ (23, RX_CSUM_L4_DOUBLE_TUNNEL, "rx-csum-l4-double-tunnel")

typedef enum
{
#define _(a, b, c) VIRTCHNL2_CAP_##b = (1 << a),
  foreach_idpf_checksum_cap_flag
#undef _
} idpf_checksum_cap_flag_t;

#define foreach_idpf_seg_cap_flag                                             \
  _ (0, IPV4_TCP, "ipv4-tcp")                                                 \
  _ (1, IPV4_UDP, "ipv4-udp")                                                 \
  _ (2, IPV4_SCTP, "ipv4-sctp")                                               \
  _ (3, IPV6_TCP, "ipv6-tcp")                                                 \
  _ (4, IPV6_UDP, "ipv6-udp")                                                 \
  _ (5, IPV6_SCTP, "ipv6-sctp")                                               \
  _ (6, GENERIC, "generic")                                                   \
  _ (7, TX_SINGLE_TUNNEL, "tx-single-tunnel")                                 \
  _ (8, TX_DOUBLE_TUNNEL, "tx-double-tunnel")

typedef enum
{
#define _(a, b, c) VIRTCHNL2_CAP_SEG_##b = (1 << a),
  foreach_idpf_seg_cap_flag
#undef _
} idpf_seg_cap_flag_t;

#define foreach_idpf_rss_cap_flag                                             \
  _ (0, IPV4_TCP, "ipv4-tcp")                                                 \
  _ (1, IPV4_UDP, "ipv4-udp")                                                 \
  _ (2, IPV4_SCTP, "ipv4-sctp")                                               \
  _ (3, IPV4_OTHER, "ipv4-other")                                             \
  _ (4, IPV6_TCP, "ipv6-tcp")                                                 \
  _ (5, IPV6_UDP, "ipv6-udp")                                                 \
  _ (6, IPV6_SCTP, "ipv6-sctp")                                               \
  _ (7, IPV6_OTHER, "ipv6-other")                                             \
  _ (8, IPV4_AH, "ipv4-ah")                                                   \
  _ (9, IPV4_ESP, "ipv4-esp")                                                 \
  _ (10, IPV4_AH_ESP, "ipv4-ah-esp")                                          \
  _ (11, IPV6_AH, "ipv6-ah")                                                  \
  _ (12, IPV6_ESP, "ipv6-esp")                                                \
  _ (13, IPV6_AH_ESP, "ipv6-ah-esp")

typedef enum
{
#define _(a, b, c) VIRTCHNL2_CAP_RSS_##b = (1 << a),
  foreach_idpf_rss_cap_flag
#undef _
} idpf_rss_cap_flag_t;

#define foreach_idpf_hsplit_cap_flag                                          \
  _ (0, AT_L2, "at-l2")                                                       \
  _ (1, AT_L3, "at-l3")                                                       \
  _ (2, AT_L4V4, "at-l4v4")                                                   \
  _ (3, AT_L4V6, "at-l4v6")

typedef enum
{
#define _(a, b, c) VIRTCHNL2_CAP_RX_HSPLIT_##b = (1 << a),
  foreach_idpf_hsplit_cap_flag
#undef _
} idpf_hsplit_cap_flag_t;

#define foreach_idpf_rsc_cap_flag                                             \
  _ (0, IPV4_TCP, "ipv4-tcp")                                                 \
  _ (1, IPV4_SCTP, "ipv4-sctp")                                               \
  _ (2, IPV6_TCP, "ipv6-tcp")                                                 \
  _ (3, IPV6_SCTP, "ipv6-sctp")

typedef enum
{
#define _(a, b, c) VIRTCHNL2_CAP_RSC_##b = (1 << a),
  foreach_idpf_rsc_cap_flag
#undef _
} idpf_rsc_cap_flag_t;

#define foreach_idpf_other_cap_flag                                           \
  _ (0, RDMA, "rdma")                                                         \
  _ (1, SRIOV, "sriov")                                                       \
  _ (2, MACFILTER, "macfilter")                                               \
  _ (3, FLOW_DIRECTOR, "flow-director")                                       \
  _ (4, SPLITQ_QSCHED, "spliteq-qsched")                                      \
  _ (5, CRC, "crc")                                                           \
  _ (6, ADQ, "adq")                                                           \
  _ (7, WB_ON_ITR, "wb-on-itr")                                               \
  _ (8, PROMISC, "promisc")                                                   \
  _ (9, LINK_SPEED, "link-speed")                                             \
  _ (10, INLINE_IPSEC, "inline-ipsec")                                        \
  _ (11, LARGE_NUM_QUEUES, "large-num-queues")                                \
  _ (12, VLAN, "vlan")                                                        \
  _ (13, PTP, "ptp")                                                          \
  _ (15, ADV_RSS, "adv-rss")                                                  \
  _ (16, FDIR, "fdir")                                                        \
  _ (17, RX_FLEX_DESC, "rx-flex-desc")                                        \
  _ (18, PTYPE, "ptype")                                                      \
  _ (19, LOOPBACK, "loopback")                                                \
  _ (20, OEM, "oem")

typedef enum
{
#define _(a, b, c) VIRTCHNL2_CAP_##b = (1 << a),
  foreach_idpf_other_cap_flag
#undef _
} idpf_other_cap_flag_t;

#define VIRTCHNL2_TXQ_SCHED_MODE_QUEUE 0
#define VIRTCHNL2_TXQ_SCHED_MODE_FLOW  1

#define VIRTCHNL2_TXQ_ENABLE_MISS_COMPL BIT (0)

#define VIRTCHNL2_RDMA_CPF 0
#define VIRTCHNL2_NVME_CPF 1
#define VIRTCHNL2_ATE_CPF  2
#define VIRTCHNL2_LCE_CPF  3

#define VIRTCHNL2_RXQ_RSC		   BIT (0)
#define VIRTCHNL2_RXQ_HDR_SPLIT		   BIT (1)
#define VIRTCHNL2_RXQ_IMMEDIATE_WRITE_BACK BIT (2)
#define VIRTCHNL2_RX_DESC_SIZE_16BYTE	   BIT (3)
#define VIRTCHNL2_RX_DESC_SIZE_32BYTE	   BIT (4)

#define foreach_virtchnl2_rss_alg                                             \
  _ (0, TOEPLITZ_ASYMMETRIC)                                                  \
  _ (1, R_ASYMMETRIC)                                                         \
  _ (2, TOEPLITZ_SYMMETRIC)                                                   \
  _ (3, XOR_SYMMETRIC)

typedef enum
{
#define _(v, n) VIRTCHNL2_RSS_ALG_##n = v,
  foreach_virtchnl2_rss_alg
#undef _
} virtchnl2_rss_alg_t;

#define foreach_virtchnl2_event                                               \
  _ (0, UNKNOWN)                                                              \
  _ (1, LINK_CHANGE)                                                          \
  _ (2, START_RESET_ADI)                                                      \
  _ (3, FINISH_RESET_ADI)

typedef enum
{
#define _(v, n) VIRTCHNL2_EVENT_##n = v,
  foreach_virtchnl2_event
#undef _
} virtchnl2_event_name_t;

#define foreach_idpf_queue_type                                               \
  _ (0, TX)                                                                   \
  _ (1, RX)                                                                   \
  _ (2, TX_COMPLETION)                                                        \
  _ (3, RX_BUFFER)                                                            \
  _ (4, CONFIG_TX)                                                            \
  _ (5, CONFIG_RX)                                                            \
  _ (6, P2P_TX)                                                               \
  _ (7, P2P_RX)                                                               \
  _ (8, P2P_TX_COMPLETION)                                                    \
  _ (9, P2P_RX_BUFFER)                                                        \
  _ (10, MBX_TX)                                                              \
  _ (11, MBX_RX)

typedef enum
{
#define _(v, n) VIRTCHNL2_QUEUE_TYPE_##n = v,
  foreach_idpf_queue_type
#undef _
} idpf_queue_type_t;

#define foreach_virtchnl2_itr_idx                                             \
  _ (0, 0)                                                                    \
  _ (1, 1)                                                                    \
  _ (2, 2)                                                                    \
  _ (3, NO_ITR)

typedef enum
{
#define _(v, n) VIRTCHNL2_ITR_IDX_##n = v,
  foreach_virtchnl2_itr_idx
#undef _
} virtchnl2_itr_idx_t;

#define VIRTCHNL2_MAC_ADDR_PRIMARY 1
#define VIRTCHNL2_MAC_ADDR_EXTRA   2

#define VIRTCHNL2_UNICAST_PROMISC   BIT (0)
#define VIRTCHNL2_MULTICAST_PROMISC BIT (1)

#define foreach_virtchnl2_proto_hdr                                           \
  _ (0, ANY)                                                                  \
  _ (1, PRE_MAC)                                                              \
  _ (2, MAC)                                                                  \
  _ (3, POST_MAC)                                                             \
  _ (4, ETHERTYPE)                                                            \
  _ (5, VLAN)                                                                 \
  _ (6, SVLAN)                                                                \
  _ (7, CVLAN)                                                                \
  _ (8, MPLS)                                                                 \
  _ (9, UMPLS)                                                                \
  _ (10, MMPLS)                                                               \
  _ (11, PTP)                                                                 \
  _ (12, CTRL)                                                                \
  _ (13, LLDP)                                                                \
  _ (14, ARP)                                                                 \
  _ (15, ECP)                                                                 \
  _ (16, EAPOL)                                                               \
  _ (17, PPPOD)                                                               \
  _ (18, PPPOE)                                                               \
  _ (19, IPV4)                                                                \
  _ (20, IPV4_FRAG)                                                           \
  _ (21, IPV6)                                                                \
  _ (22, IPV6_FRAG)                                                           \
  _ (23, IPV6_EH)                                                             \
  _ (24, UDP)                                                                 \
  _ (25, TCP)                                                                 \
  _ (26, SCTP)                                                                \
  _ (27, ICMP)                                                                \
  _ (28, ICMPV6)                                                              \
  _ (29, IGMP)                                                                \
  _ (30, AH)                                                                  \
  _ (31, ESP)                                                                 \
  _ (32, IKE)                                                                 \
  _ (33, NATT_KEEP)                                                           \
  _ (34, PAY)                                                                 \
  _ (35, L2TPV2)                                                              \
  _ (36, L2TPV2_CONTROL)                                                      \
  _ (37, L2TPV3)                                                              \
  _ (38, GTP)                                                                 \
  _ (39, GTP_EH)                                                              \
  _ (40, GTPCV2)                                                              \
  _ (41, GTPC_TEID)                                                           \
  _ (42, GTPU)                                                                \
  _ (43, GTPU_UL)                                                             \
  _ (44, GTPU_DL)                                                             \
  _ (45, ECPRI)                                                               \
  _ (46, VRRP)                                                                \
  _ (47, OSPF)                                                                \
  _ (48, TUN)                                                                 \
  _ (49, GRE)                                                                 \
  _ (50, NVGRE)                                                               \
  _ (51, VXLAN)                                                               \
  _ (52, VXLAN_GPE)                                                           \
  _ (53, GENEVE)                                                              \
  _ (54, NSH)                                                                 \
  _ (55, QUIC)                                                                \
  _ (56, PFCP)                                                                \
  _ (57, PFCP_NODE)                                                           \
  _ (58, PFCP_SESSION)                                                        \
  _ (59, RTP)                                                                 \
  _ (60, ROCE)                                                                \
  _ (61, ROCEV1)                                                              \
  _ (62, ROCEV2)                                                              \
  _ (65535, NO_PROTO)

typedef enum
{
#define _(v, n) VIRTCHNL2_PROTO_HDR_##n = v,
  foreach_virtchnl2_proto_hdr
#undef _
} virtchnl2_proto_hdr_t;

#define VIRTCHNL2_VERSION_MAJOR_2 2
#define VIRTCHNL2_VERSION_MINOR_0 0

typedef struct
{
  u32 major;
  u32 minor;
} virtchnl2_version_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_version_info_t, 8);

typedef struct
{
  u32 csum_caps;
  u32 seg_caps;
  u32 hsplit_caps;
  u32 rsc_caps;
  u64 rss_caps;
  u64 other_caps;

  u32 mailbox_dyn_ctl;
  u16 mailbox_vector_id;
  u16 num_allocated_vectors;

  u16 max_rx_q;
  u16 max_tx_q;
  u16 max_rx_bufq;
  u16 max_tx_complq;

  u16 max_sriov_vfs;

  u16 max_vports;
  u16 default_num_vports;

  u16 max_tx_hdr_size;

  u8 max_sg_bufs_per_tx_pkt;

  u8 itr_idx_map;

  u16 pad1;

  u16 oem_cp_ver_major;
  u16 oem_cp_ver_minor;
  u32 device_type;

  u8 reserved[12];
} virtchnl2_get_capabilities_t;

STATIC_ASSERT_SIZEOF (virtchnl2_get_capabilities_t, 80);

typedef struct
{
  /* see VIRTCHNL2_QUEUE_TYPE definitions */
  u32 type;
  u32 start_queue_id;
  u32 num_queues;
  u32 pad;

  /* Queue tail register offset and spacing provided by CP */
  u64 qtail_reg_start;
  u32 qtail_reg_spacing;

  u8 reserved[4];
} virtchnl2_queue_reg_chunk_t;

STATIC_ASSERT_SIZEOF (virtchnl2_queue_reg_chunk_t, 32);

/* structure to specify several chunks of contiguous queues */
typedef struct
{
  u16 num_chunks;
  u8 reserved[6];
  virtchnl2_queue_reg_chunk_t chunks[1];
} virtchnl2_queue_reg_chunks_t;

STATIC_ASSERT_SIZEOF (virtchnl2_queue_reg_chunks_t, 40);

#define VIRTCHNL2_ETH_LENGTH_OF_ADDRESS 6

typedef struct
{
  u16 vport_type;
  u16 txq_model;
  u16 rxq_model;
  u16 num_tx_q;
  u16 num_tx_complq;
  u16 num_rx_q;
  u16 num_rx_bufq;
  u16 default_rx_q;
  u16 vport_index;

  u16 max_mtu;
  u32 vport_id;
  u8 default_mac_addr[VIRTCHNL2_ETH_LENGTH_OF_ADDRESS];
  u16 pad;
  u64 rx_desc_ids;
  u64 tx_desc_ids;

#define MAX_Q_REGIONS 16
  u32 max_qs_per_qregion[MAX_Q_REGIONS];
  u32 qregion_total_qs;
  u16 qregion_type;
  u16 pad2;

  u32 rss_algorithm;
  u16 rss_key_size;
  u16 rss_lut_size;

  u32 rx_split_pos;

  u8 reserved[20];
  virtchnl2_queue_reg_chunks_t chunks;
} virtchnl2_create_vport_t;

STATIC_ASSERT_SIZEOF (virtchnl2_create_vport_t, 192);

typedef struct
{
  u32 vport_id;
  u8 reserved[4];
} virtchnl2_vport_t;

STATIC_ASSERT_SIZEOF (virtchnl2_vport_t, 8);

typedef struct
{
  u64 dma_ring_addr;
  u32 type;
  u32 queue_id;
  u16 relative_queue_id;
  u16 model;
  u16 sched_mode;
  u16 qflags;
  u16 ring_len;

  u16 tx_compl_queue_id;
  u16 peer_type;
  u16 peer_rx_queue_id;

  u16 qregion_id;
  u8 pad[2];

  u32 egress_pasid;
  u32 egress_hdr_pasid;
  u32 egress_buf_pasid;

  u8 reserved[8];
} virtchnl2_txq_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_txq_info_t, 56);

typedef struct
{
  u32 vport_id;
  u16 num_qinfo;

  u8 reserved[10];
  virtchnl2_txq_info_t qinfo[1];
} virtchnl2_config_tx_queues_t;

STATIC_ASSERT_SIZEOF (virtchnl2_config_tx_queues_t, 72);

/* Receive queue config info */
typedef struct
{
  u64 desc_ids;
  u64 dma_ring_addr;

  u32 type;
  u32 queue_id;

  u16 model;

  u16 hdr_buffer_size;
  u32 data_buffer_size;
  u32 max_pkt_size;

  u16 ring_len;
  u8 buffer_notif_stride;
  u8 pad[1];

  u64 dma_head_wb_addr;

  u16 qflags;

  u16 rx_buffer_low_watermark;

  u16 rx_bufq1_id;
  u16 rx_bufq2_id;
  u8 bufq2_ena;
  u8 pad2;

  u16 qregion_id;

  u32 ingress_pasid;
  u32 ingress_hdr_pasid;
  u32 ingress_buf_pasid;

  u8 reserved[16];
} virtchnl2_rxq_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_rxq_info_t, 88);

typedef struct
{
  u32 vport_id;
  u16 num_qinfo;

  u8 reserved[18];
  virtchnl2_rxq_info_t qinfo[1];
} virtchnl2_config_rx_queues_t;

STATIC_ASSERT_SIZEOF (virtchnl2_config_rx_queues_t, 112);

typedef struct
{
  u32 vport_id;
  u16 num_tx_q;
  u16 num_tx_complq;
  u16 num_rx_q;
  u16 num_rx_bufq;
  u8 reserved[4];
  virtchnl2_queue_reg_chunks_t chunks;
} virtchnl2_add_queues_t;

STATIC_ASSERT_SIZEOF (virtchnl2_add_queues_t, 56);

typedef struct
{
  u16 start_vector_id;
  u16 start_evv_id;
  u16 num_vectors;
  u16 pad1;

  u32 dynctl_reg_start;
  u32 dynctl_reg_spacing;

  u32 itrn_reg_start;
  u32 itrn_reg_spacing;
  u8 reserved[8];
} virtchnl2_vector_chunk_t;

STATIC_ASSERT_SIZEOF (virtchnl2_vector_chunk_t, 32);

typedef struct
{
  u16 num_vchunks;
  u8 reserved[14];
  virtchnl2_vector_chunk_t vchunks[1];
} virtchnl2_vector_chunks_t;

STATIC_ASSERT_SIZEOF (virtchnl2_vector_chunks_t, 48);

typedef struct
{
  u16 num_vectors;
  u8 reserved[14];
  virtchnl2_vector_chunks_t vchunks;
} virtchnl2_alloc_vectors_t;

STATIC_ASSERT_SIZEOF (virtchnl2_alloc_vectors_t, 64);

typedef struct
{
  u32 vport_id;
  u16 lut_entries_start;
  u16 lut_entries;
  u8 reserved[4];
  u32 lut[1]; /* RSS lookup table */
} virtchnl2_rss_lut_t;

STATIC_ASSERT_SIZEOF (virtchnl2_rss_lut_t, 16);

typedef struct
{
  /* Packet Type Groups bitmap */
  u64 ptype_groups;
  u32 vport_id;
  u8 reserved[4];
} virtchnl2_rss_hash_t;

STATIC_ASSERT_SIZEOF (virtchnl2_rss_hash_t, 16);

typedef struct
{
  u16 num_vfs;
  u16 pad;
} virtchnl2_sriov_vfs_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_sriov_vfs_info_t, 4);

typedef struct
{
  u32 pasid;
  u16 mbx_id;
  u16 mbx_vec_id;
  u16 adi_id;
  u8 reserved[64];
  u8 pad[6];
  virtchnl2_queue_reg_chunks_t chunks;
  virtchnl2_vector_chunks_t vchunks;
} virtchnl2_create_adi_t;

STATIC_ASSERT_SIZEOF (virtchnl2_create_adi_t, 168);

typedef struct
{
  u16 adi_id;
  u8 reserved[2];
} virtchnl2_destroy_adi_t;

STATIC_ASSERT_SIZEOF (virtchnl2_destroy_adi_t, 4);

typedef struct
{
  u16 ptype_id_10;
  u8 ptype_id_8;
  u8 proto_id_count;
  u16 pad;
  u16 proto_id[1];
} virtchnl2_ptype_t;

STATIC_ASSERT_SIZEOF (virtchnl2_ptype_t, 8);

typedef struct
{
  u16 start_ptype_id;
  u16 num_ptypes;
  u32 pad;
  virtchnl2_ptype_t ptype[1];
} virtchnl2_get_ptype_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_get_ptype_info_t, 16);

typedef struct
{
  u32 vport_id;
  u8 pad[4];

  u64 rx_bytes;
  u64 rx_unicast;
  u64 rx_multicast;
  u64 rx_broadcast;
  u64 rx_discards;
  u64 rx_errors;
  u64 rx_unknown_protocol;
  u64 tx_bytes;
  u64 tx_unicast;
  u64 tx_multicast;
  u64 tx_broadcast;
  u64 tx_discards;
  u64 tx_errors;
  u64 rx_invalid_frame_length;
  u64 rx_overflow_drop;
} virtchnl2_vport_stats_t;

STATIC_ASSERT_SIZEOF (virtchnl2_vport_stats_t, 128);

typedef struct
{
  u32 event;
  u32 link_speed;
  u32 vport_id;
  u8 link_status;
  u8 pad[1];
  u16 adi_id;
} virtchnl2_event_t;

STATIC_ASSERT_SIZEOF (virtchnl2_event_t, 16);

typedef struct
{
  u32 vport_id;
  u16 key_len;
  u8 pad;
  u8 key[1];
} virtchnl2_rss_key_t;

STATIC_ASSERT_SIZEOF (virtchnl2_rss_key_t, 8);

typedef struct
{
  u32 type;
  u32 start_queue_id;
  u32 num_queues;
  u8 reserved[4];
} virtchnl2_queue_chunk_t;

STATIC_ASSERT_SIZEOF (virtchnl2_queue_chunk_t, 16);

typedef struct
{
  u16 num_chunks;
  u8 reserved[6];
  virtchnl2_queue_chunk_t chunks[1];
} virtchnl2_queue_chunks_t;

STATIC_ASSERT_SIZEOF (virtchnl2_queue_chunks_t, 24);

typedef struct
{
  u32 vport_id;
  u8 reserved[4];
  virtchnl2_queue_chunks_t chunks;
} virtchnl2_del_ena_dis_queues_t;

STATIC_ASSERT_SIZEOF (virtchnl2_del_ena_dis_queues_t, 32);

typedef struct
{
  u32 queue_id;
  u16 vector_id;
  u8 pad[2];

  u32 itr_idx;

  u32 queue_type;
  u8 reserved[8];
} virtchnl2_queue_vector_t;

STATIC_ASSERT_SIZEOF (virtchnl2_queue_vector_t, 24);

typedef struct
{
  u32 vport_id;
  u16 num_qv_maps;
  u8 pad[10];
  virtchnl2_queue_vector_t qv_maps[1];
} virtchnl2_queue_vector_maps_t;

STATIC_ASSERT_SIZEOF (virtchnl2_queue_vector_maps_t, 40);

typedef struct
{
  u32 vport_id;
  u8 enable;
  u8 pad[3];
} virtchnl2_loopback_t;

STATIC_ASSERT_SIZEOF (virtchnl2_loopback_t, 8);

typedef struct
{
  u8 addr[VIRTCHNL2_ETH_LENGTH_OF_ADDRESS];
  u8 type;
  u8 pad;
} virtchnl2_mac_addr_t;

STATIC_ASSERT_SIZEOF (virtchnl2_mac_addr_t, 8);

typedef struct
{
  u32 vport_id;
  u16 num_mac_addr;
  u8 pad[2];
  virtchnl2_mac_addr_t mac_addr_list[1];
} virtchnl2_mac_addr_list_t;

STATIC_ASSERT_SIZEOF (virtchnl2_mac_addr_list_t, 16);

typedef struct
{
  u32 vport_id;
  u16 flags;
  u8 pad[2];
} virtchnl2_promisc_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_promisc_info_t, 8);

#endif /* _IDPF_VIRTCHNL_H_ */
