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

/* New major set of opcodes introduced and so leaving room for
 * old misc opcodes to be added in future. Also these opcodes may only
 * be used if both the PF and VF have successfully negotiated the
 * VIRTCHNL version as 2.0 during VIRTCHNL22_OP_VERSION exchange.
 */
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

/* VIRTCHNL2_SEGMENTATION_OFFLOAD_CAPS
 * Segmentation offload capability flags
 */
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

/* VIRTCHNL2_RSS_FLOW_TYPE_CAPS
 * Receive Side Scaling Flow type capability flags
 */
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

/* VIRTCHNL2_HEADER_SPLIT_CAPS
 * Header split capability flags
 */
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

/* VIRTCHNL2_RSC_OFFLOAD_CAPS
 * Receive Side Coalescing offload capability flags
 */
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

/* VIRTCHNL2_OTHER_CAPS
 * Other capability flags
 * SPLITQ_QSCHED: Queue based scheduling using split queue model
 * TX_VLAN: VLAN tag insertion
 * RX_VLAN: VLAN tag stripping
 */
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

/* VIRTCHNL2_TXQ_SCHED_MODE
 * Transmit Queue Scheduling Modes - Queue mode is the legacy mode i.e. inorder
 * completions where descriptors and buffers are completed at the same time.
 * Flow scheduling mode allows for out of order packet processing where
 * descriptors are cleaned in order, but buffers can be completed out of order.
 */
#define VIRTCHNL2_TXQ_SCHED_MODE_QUEUE 0
#define VIRTCHNL2_TXQ_SCHED_MODE_FLOW  1

/* VIRTCHNL2_TXQ_FLAGS
 * Transmit Queue feature flags
 *
 * Enable rule miss completion type; packet completion for a packet
 * sent on exception path; only relevant in flow scheduling mode
 */
#define VIRTCHNL2_TXQ_ENABLE_MISS_COMPL BIT (0)

/* VIRTCHNL2_PEER_TYPE
 * Transmit mailbox peer type
 */
#define VIRTCHNL2_RDMA_CPF 0
#define VIRTCHNL2_NVME_CPF 1
#define VIRTCHNL2_ATE_CPF  2
#define VIRTCHNL2_LCE_CPF  3

/* VIRTCHNL2_RXQ_FLAGS
 * Receive Queue Feature flags
 */
#define VIRTCHNL2_RXQ_RSC		   BIT (0)
#define VIRTCHNL2_RXQ_HDR_SPLIT		   BIT (1)
#define VIRTCHNL2_RXQ_IMMEDIATE_WRITE_BACK BIT (2)
#define VIRTCHNL2_RX_DESC_SIZE_16BYTE	   BIT (3)
#define VIRTCHNL2_RX_DESC_SIZE_32BYTE	   BIT (4)

/* VIRTCHNL2_RSS_ALGORITHM
 * Type of RSS algorithm
 */
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

/* VIRTCHNL2_EVENT_CODES
 * Type of event
 */
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

/* VIRTCHNL2_QUEUE_TYPE
 * Transmit and Receive queue types are valid in legacy as well as split queue
 * models. With Split Queue model, 2 additional types are introduced -
 * TX_COMPLETION and RX_BUFFER. In split queue model, receive  corresponds to
 * the queue where hardware posts completions.
 */
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

/* VIRTCHNL2_ITR_IDX
 * Virtchannel interrupt throttling rate index
 */
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

/* VIRTCHNL2_MAC_TYPE
 * VIRTCHNL2_MAC_ADDR_PRIMARY
 * PF/VF driver should set @type to VIRTCHNL2_MAC_ADDR_PRIMARY for the
 * primary/device unicast MAC address filter for VIRTCHNL2_OP_ADD_MAC_ADDR and
 * VIRTCHNL2_OP_DEL_MAC_ADDR. This allows for the underlying control plane
 * function to accurately track the MAC address and for VM/function reset.
 *
 * VIRTCHNL2_MAC_ADDR_EXTRA
 * PF/VF driver should set @type to VIRTCHNL2_MAC_ADDR_EXTRA for any extra
 * unicast and/or multicast filters that are being added/deleted via
 * VIRTCHNL2_OP_ADD_MAC_ADDR/VIRTCHNL2_OP_DEL_MAC_ADDR respectively.
 */
#define VIRTCHNL2_MAC_ADDR_PRIMARY 1
#define VIRTCHNL2_MAC_ADDR_EXTRA   2

/* VIRTCHNL2_PROMISC_FLAGS
 * Flags used for promiscuous mode
 */
#define VIRTCHNL2_UNICAST_PROMISC   BIT (0)
#define VIRTCHNL2_MULTICAST_PROMISC BIT (1)

/* VIRTCHNL2_PROTO_HDR_TYPE
 * Protocol header type within a packet segment. A segment consists of one or
 * more protocol headers that make up a logical group of protocol headers. Each
 * logical group of protocol headers encapsulates or is encapsulated using/by
 * tunneling or encapsulation protocols for network virtualization.
 */
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

/* VIRTCHNL2_OP_VERSION
 * VF posts its version number to the CP. CP responds with its version number
 * in the same format, along with a return code.
 * If there is a major version mismatch, then the VF cannot operate.
 * If there is a minor version mismatch, then the VF can operate but should
 * add a warning to the system log.
 *
 * This version opcode  MUST always be specified as == 1, regardless of other
 * changes in the API. The CP must always respond to this message without
 * error regardless of version mismatch.
 */
typedef struct
{
  u32 major;
  u32 minor;
} virtchnl2_version_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_version_info_t, 8);

/* VIRTCHNL2_OP_GET_CAPS
 * Dataplane driver sends this message to CP to negotiate capabilities and
 * provides a virtchnl2_get_capabilities structure with its desired
 * capabilities, max_sriov_vfs and num_allocated_vectors.
 * CP responds with a virtchnl2_get_capabilities structure updated
 * with allowed capabilities and the other fields as below.
 * If PF sets max_sriov_vfs as 0, CP will respond with max number of VFs
 * that can be created by this PF. For any other value 'n', CP responds
 * with max_sriov_vfs set to min(n, x) where x is the max number of VFs
 * allowed by CP's policy. max_sriov_vfs is not applicable for VFs.
 * If dataplane driver sets num_allocated_vectors as 0, CP will respond with 1
 * which is default vector associated with the default mailbox. For any other
 * value 'n', CP responds with a value <= n based on the CP's policy of
 * max number of vectors for a PF.
 * CP will respond with the vector ID of mailbox allocated to the PF in
 * mailbox_vector_id and the number of itr index registers in itr_idx_map.
 * It also responds with default number of vports that the dataplane driver
 * should comeup with in default_num_vports and maximum number of vports that
 * can be supported in max_vports
 */
typedef struct
{
  /* see VIRTCHNL2_CHECKSUM_OFFLOAD_CAPS definitions */
  u32 csum_caps;

  /* see VIRTCHNL2_SEGMENTATION_OFFLOAD_CAPS definitions */
  u32 seg_caps;

  /* see VIRTCHNL2_HEADER_SPLIT_CAPS definitions */
  u32 hsplit_caps;

  /* see VIRTCHNL2_RSC_OFFLOAD_CAPS definitions */
  u32 rsc_caps;

  /* see VIRTCHNL2_RSS_FLOW_TYPE_CAPS definitions  */
  u64 rss_caps;

  /* see VIRTCHNL2_OTHER_CAPS definitions  */
  u64 other_caps;

  /* DYN_CTL register offset and vector id for mailbox provided by CP */
  u32 mailbox_dyn_ctl;
  u16 mailbox_vector_id;
  /* Maximum number of allocated vectors for the device */
  u16 num_allocated_vectors;

  /* Maximum number of queues that can be supported */
  u16 max_rx_q;
  u16 max_tx_q;
  u16 max_rx_bufq;
  u16 max_tx_complq;

  /* The PF sends the maximum VFs it is requesting. The CP responds with
   * the maximum VFs granted.
   */
  u16 max_sriov_vfs;

  /* maximum number of vports that can be supported */
  u16 max_vports;
  /* default number of vports driver should allocate on load */
  u16 default_num_vports;

  /* Max header length hardware can parse/checksum, in bytes */
  u16 max_tx_hdr_size;

  /* Max number of scatter gather buffers that can be sent per transmit
   * packet without needing to be linearized
   */
  u8 max_sg_bufs_per_tx_pkt;

  /* see VIRTCHNL2_ITR_IDX definition */
  u8 itr_idx_map;

  u16 pad1;

  /* version of Control Plane that is running */
  u16 oem_cp_ver_major;
  u16 oem_cp_ver_minor;
  /* see VIRTCHNL2_DEVICE_TYPE definitions */
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

/* VIRTCHNL2_OP_CREATE_VPORT
 * PF sends this message to CP to create a vport by filling in required
 * fields of virtchnl2_create_vport structure.
 * CP responds with the updated virtchnl2_create_vport structure containing the
 * necessary fields followed by chunks which in turn will have an array of
 * num_chunks entries of virtchnl2_queue_chunk structures.
 */
typedef struct
{
  /* PF/VF populates the following fields on request */
  /* see VIRTCHNL2_VPORT_TYPE definitions */
  u16 vport_type;

  /* see VIRTCHNL2_QUEUE_MODEL definitions */
  u16 txq_model;

  /* see VIRTCHNL2_QUEUE_MODEL definitions */
  u16 rxq_model;
  u16 num_tx_q;
  /* valid only if txq_model is split queue */
  u16 num_tx_complq;
  u16 num_rx_q;
  /* valid only if rxq_model is split queue */
  u16 num_rx_bufq;
  /* relative receive queue index to be used as default */
  u16 default_rx_q;
  /* used to align PF and CP in case of default multiple vports, it is
   * filled by the PF and CP returns the same value, to enable the driver
   * to support multiple asynchronous parallel CREATE_VPORT requests and
   * associate a response to a specific request
   */
  u16 vport_index;

  /* CP populates the following fields on response */
  u16 max_mtu;
  u32 vport_id;
  u8 default_mac_addr[VIRTCHNL2_ETH_LENGTH_OF_ADDRESS];
  u16 pad;
  /* see VIRTCHNL2_RX_DESC_IDS definitions */
  u64 rx_desc_ids;
  /* see VIRTCHNL2_TX_DESC_IDS definitions */
  u64 tx_desc_ids;

#define MAX_Q_REGIONS 16
  u32 max_qs_per_qregion[MAX_Q_REGIONS];
  u32 qregion_total_qs;
  u16 qregion_type;
  u16 pad2;

  /* see VIRTCHNL2_RSS_ALGORITHM definitions */
  u32 rss_algorithm;
  u16 rss_key_size;
  u16 rss_lut_size;

  /* see VIRTCHNL2_HEADER_SPLIT_CAPS definitions */
  u32 rx_split_pos;

  u8 reserved[20];
  virtchnl2_queue_reg_chunks_t chunks;
} virtchnl2_create_vport_t;

STATIC_ASSERT_SIZEOF (virtchnl2_create_vport_t, 192);

/* VIRTCHNL2_OP_DESTROY_VPORT
 * VIRTCHNL2_OP_ENABLE_VPORT
 * VIRTCHNL2_OP_DISABLE_VPORT
 * PF sends this message to CP to destroy, enable or disable a vport by filling
 * in the vport_id in virtchnl2_vport structure.
 * CP responds with the status of the requested operation.
 */
typedef struct
{
  u32 vport_id;
  u8 reserved[4];
} virtchnl2_vport_t;

STATIC_ASSERT_SIZEOF (virtchnl2_vport_t, 8);

/* Transmit queue config info */
typedef struct
{
  u64 dma_ring_addr;

  /* see VIRTCHNL2_QUEUE_TYPE definitions */
  u32 type;

  u32 queue_id;
  /* valid only if queue model is split and type is transmit queue. Used
   * in many to one mapping of transmit queues to completion queue
   */
  u16 relative_queue_id;

  /* see VIRTCHNL2_QUEUE_MODEL definitions */
  u16 model;

  /* see VIRTCHNL2_TXQ_SCHED_MODE definitions */
  u16 sched_mode;

  /* see VIRTCHNL2_TXQ_FLAGS definitions */
  u16 qflags;
  u16 ring_len;

  /* valid only if queue model is split and type is transmit queue */
  u16 tx_compl_queue_id;
  /* valid only if queue type is VIRTCHNL2_QUEUE_TYPE_MAILBOX_TX */
  /* see VIRTCHNL2_PEER_TYPE definitions */
  u16 peer_type;
  /* valid only if queue type is CONFIG_TX and used to deliver messages
   * for the respective CONFIG_TX queue
   */
  u16 peer_rx_queue_id;

  /* value ranges from 0 to 15 */
  u16 qregion_id;
  u8 pad[2];

  /* Egress pasid is used for SIOV use case */
  u32 egress_pasid;
  u32 egress_hdr_pasid;
  u32 egress_buf_pasid;

  u8 reserved[8];
} virtchnl2_txq_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_txq_info_t, 56);

/* VIRTCHNL2_OP_CONFIG_TX_QUEUES
 * PF sends this message to set up parameters for one or more transmit queues.
 * This message contains an array of num_qinfo instances of virtchnl2_txq_info
 * structures. CP configures requested queues and returns a status code. If
 * num_qinfo specified is greater than the number of queues associated with the
 * vport, an error is returned and no queues are configured.
 */
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
  /* see VIRTCHNL2_RX_DESC_IDS definitions */
  u64 desc_ids;
  u64 dma_ring_addr;

  /* see VIRTCHNL2_QUEUE_TYPE definitions */
  u32 type;
  u32 queue_id;

  /* see QUEUE_MODEL definitions */
  u16 model;

  u16 hdr_buffer_size;
  u32 data_buffer_size;
  u32 max_pkt_size;

  u16 ring_len;
  u8 buffer_notif_stride;
  u8 pad[1];

  /* Applicable only for receive buffer queues */
  u64 dma_head_wb_addr;

  /* Applicable only for receive completion queues */
  /* see VIRTCHNL2_RXQ_FLAGS definitions */
  u16 qflags;

  u16 rx_buffer_low_watermark;

  /* valid only in split queue model */
  u16 rx_bufq1_id;
  /* valid only in split queue model */
  u16 rx_bufq2_id;
  /* it indicates if there is a second buffer, rx_bufq2_id is valid only
   * if this field is set
   */
  u8 bufq2_ena;
  u8 pad2;

  /* value ranges from 0 to 15 */
  u16 qregion_id;

  /* Ingress pasid is used for SIOV use case */
  u32 ingress_pasid;
  u32 ingress_hdr_pasid;
  u32 ingress_buf_pasid;

  u8 reserved[16];
} virtchnl2_rxq_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_rxq_info_t, 88);

/* VIRTCHNL2_OP_CONFIG_RX_QUEUES
 * PF sends this message to set up parameters for one or more receive queues.
 * This message contains an array of num_qinfo instances of virtchnl2_rxq_info
 * structures. CP configures requested queues and returns a status code.
 * If the number of queues specified is greater than the number of queues
 * associated with the vport, an error is returned and no queues are
 * configured.
 */
typedef struct
{
  u32 vport_id;
  u16 num_qinfo;

  u8 reserved[18];
  virtchnl2_rxq_info_t qinfo[1];
} virtchnl2_config_rx_queues_t;

STATIC_ASSERT_SIZEOF (virtchnl2_config_rx_queues_t, 112);

/* VIRTCHNL2_OP_ADD_QUEUES
 * PF sends this message to request additional transmit/receive queues beyond
 * the ones that were assigned via CREATE_VPORT request. virtchnl2_add_queues
 * structure is used to specify the number of each type of queues.
 * CP responds with the same structure with the actual number of queues
 * assigned followed by num_chunks of virtchnl2_queue_chunk structures.
 */
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

/* Structure to specify a chunk of contiguous interrupt vectors */
typedef struct
{
  u16 start_vector_id;
  u16 start_evv_id;
  u16 num_vectors;
  u16 pad1;

  /* Register offsets and spacing provided by CP.
   * dynamic control registers are used for enabling/disabling/re-enabling
   * interrupts and updating interrupt rates in the hotpath. Any changes
   * to interrupt rates in the dynamic control registers will be reflected
   * in the interrupt throttling rate registers.
   * itrn registers are used to update interrupt rates for specific
   * interrupt indices without modifying the state of the interrupt.
   */
  u32 dynctl_reg_start;
  u32 dynctl_reg_spacing;

  u32 itrn_reg_start;
  u32 itrn_reg_spacing;
  u8 reserved[8];
} virtchnl2_vector_chunk_t;

STATIC_ASSERT_SIZEOF (virtchnl2_vector_chunk_t, 32);

/* Structure to specify several chunks of contiguous interrupt vectors */
typedef struct
{
  u16 num_vchunks;
  u8 reserved[14];
  virtchnl2_vector_chunk_t vchunks[1];
} virtchnl2_vector_chunks_t;

STATIC_ASSERT_SIZEOF (virtchnl2_vector_chunks_t, 48);

/* VIRTCHNL2_OP_ALLOC_VECTORS
 * PF sends this message to request additional interrupt vectors beyond the
 * ones that were assigned via GET_CAPS request. virtchnl2_alloc_vectors
 * structure is used to specify the number of vectors requested. CP responds
 * with the same structure with the actual number of vectors assigned followed
 * by virtchnl2_vector_chunks structure identifying the vector ids.
 */
typedef struct
{
  u16 num_vectors;
  u8 reserved[14];
  virtchnl2_vector_chunks_t vchunks;
} virtchnl2_alloc_vectors_t;

STATIC_ASSERT_SIZEOF (virtchnl2_alloc_vectors_t, 64);

/* VIRTCHNL2_OP_DEALLOC_VECTORS
 * PF sends this message to release the vectors.
 * PF sends virtchnl2_vector_chunks struct to specify the vectors it is giving
 * away. CP performs requested action and returns status.
 */

/* VIRTCHNL2_OP_GET_RSS_LUT
 * VIRTCHNL2_OP_SET_RSS_LUT
 * PF sends this message to get or set RSS lookup table. Only supported if
 * both PF and CP drivers set the VIRTCHNL2_CAP_RSS bit during configuration
 * negotiation. Uses the virtchnl2_rss_lut structure
 */
typedef struct
{
  u32 vport_id;
  u16 lut_entries_start;
  u16 lut_entries;
  u8 reserved[4];
  u32 lut[1]; /* RSS lookup table */
} virtchnl2_rss_lut_t;

STATIC_ASSERT_SIZEOF (virtchnl2_rss_lut_t, 16);

/* VIRTCHNL2_OP_GET_RSS_KEY
 * PF sends this message to get RSS key. Only supported if both PF and CP
 * drivers set the VIRTCHNL2_CAP_RSS bit during configuration negotiation. Uses
 * the virtchnl2_rss_key structure
 */

/* VIRTCHNL2_OP_GET_RSS_HASH
 * VIRTCHNL2_OP_SET_RSS_HASH
 * PF sends these messages to get and set the hash filter enable bits for RSS.
 * By default, the CP sets these to all possible traffic types that the
 * hardware supports. The PF can query this value if it wants to change the
 * traffic types that are hashed by the hardware.
 * Only supported if both PF and CP drivers set the VIRTCHNL2_CAP_RSS bit
 * during configuration negotiation.
 */
typedef struct
{
  /* Packet Type Groups bitmap */
  u64 ptype_groups;
  u32 vport_id;
  u8 reserved[4];
} virtchnl2_rss_hash_t;

STATIC_ASSERT_SIZEOF (virtchnl2_rss_hash_t, 16);

/* VIRTCHNL2_OP_SET_SRIOV_VFS
 * This message is used to set number of SRIOV VFs to be created. The actual
 * allocation of resources for the VFs in terms of vport, queues and interrupts
 * is done by CP. When this call completes, the APF driver calls
 * pci_enable_sriov to let the OS instantiate the SRIOV PCIE devices.
 * The number of VFs set to 0 will destroy all the VFs of this function.
 */

typedef struct
{
  u16 num_vfs;
  u16 pad;
} virtchnl2_sriov_vfs_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_sriov_vfs_info_t, 4);

/* VIRTCHNL2_OP_CREATE_ADI
 * PF sends this message to CP to create ADI by filling in required
 * fields of virtchnl2_create_adi structure.
 * CP responds with the updated virtchnl2_create_adi structure containing the
 * necessary fields followed by chunks which in turn will have an array of
 * num_chunks entries of virtchnl2_queue_chunk structures.
 */
typedef struct
{
  /* PF sends PASID to CP */
  u32 pasid;
  /*
   * mbx_id is set to 1 by PF when requesting CP to provide HW mailbox
   * id else it is set to 0 by PF
   */
  u16 mbx_id;
  /* PF sends mailbox vector id to CP */
  u16 mbx_vec_id;
  /* CP populates ADI id */
  u16 adi_id;
  u8 reserved[64];
  u8 pad[6];
  /* CP populates queue chunks */
  virtchnl2_queue_reg_chunks_t chunks;
  /* PF sends vector chunks to CP */
  virtchnl2_vector_chunks_t vchunks;
} virtchnl2_create_adi_t;

STATIC_ASSERT_SIZEOF (virtchnl2_create_adi_t, 168);

/* VIRTCHNL2_OP_DESTROY_ADI
 * PF sends this message to CP to destroy ADI by filling
 * in the adi_id in virtchnl2_destropy_adi structure.
 * CP responds with the status of the requested operation.
 */
typedef struct
{
  u16 adi_id;
  u8 reserved[2];
} virtchnl2_destroy_adi_t;

STATIC_ASSERT_SIZEOF (virtchnl2_destroy_adi_t, 4);

/* Based on the descriptor type the PF supports, CP fills ptype_id_10 or
 * ptype_id_8 for flex and base descriptor respectively. If ptype_id_10 value
 * is set to 0xFFFF, PF should consider this ptype as dummy one and it is the
 * last ptype.
 */
typedef struct
{
  u16 ptype_id_10;
  u8 ptype_id_8;
  /* number of protocol ids the packet supports, maximum of 32
   * protocol ids are supported
   */
  u8 proto_id_count;
  u16 pad;
  /* proto_id_count decides the allocation of protocol id array */
  /* see VIRTCHNL2_PROTO_HDR_TYPE */
  u16 proto_id[1];
} virtchnl2_ptype_t;

STATIC_ASSERT_SIZEOF (virtchnl2_ptype_t, 8);

/* VIRTCHNL2_OP_GET_PTYPE_INFO
 * PF sends this message to CP to get all supported packet types. It does by
 * filling in start_ptype_id and num_ptypes. Depending on descriptor type the
 * PF supports, it sets num_ptypes to 1024 (10-bit ptype) for flex descriptor
 * and 256 (8-bit ptype) for base descriptor support. CP responds back to PF by
 * populating start_ptype_id, num_ptypes and array of ptypes. If all ptypes
 * doesn't fit into one mailbox buffer, CP splits ptype info into multiple
 * messages, where each message will have the start ptype id, number of ptypes
 * sent in that message and the ptype array itself. When CP is done updating
 * all ptype information it extracted from the package (number of ptypes
 * extracted might be less than what PF expects), it will append a dummy ptype
 * (which has 'ptype_id_10' of 'struct virtchnl2_ptype' as 0xFFFF) to the ptype
 * array. PF is expected to receive multiple VIRTCHNL2_OP_GET_PTYPE_INFO
 * messages.
 */
typedef struct
{
  u16 start_ptype_id;
  u16 num_ptypes;
  u32 pad;
  virtchnl2_ptype_t ptype[1];
} virtchnl2_get_ptype_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_get_ptype_info_t, 16);

/* VIRTCHNL2_OP_GET_STATS
 * PF/VF sends this message to CP to get the update stats by specifying the
 * vport_id. CP responds with stats in struct virtchnl2_vport_stats.
 */
typedef struct
{
  u32 vport_id;
  u8 pad[4];

  u64 rx_bytes;	    /* received bytes */
  u64 rx_unicast;   /* received unicast pkts */
  u64 rx_multicast; /* received multicast pkts */
  u64 rx_broadcast; /* received broadcast pkts */
  u64 rx_discards;
  u64 rx_errors;
  u64 rx_unknown_protocol;
  u64 tx_bytes;	    /* transmitted bytes */
  u64 tx_unicast;   /* transmitted unicast pkts */
  u64 tx_multicast; /* transmitted multicast pkts */
  u64 tx_broadcast; /* transmitted broadcast pkts */
  u64 tx_discards;
  u64 tx_errors;
  u64 rx_invalid_frame_length;
  u64 rx_overflow_drop;
} virtchnl2_vport_stats_t;

STATIC_ASSERT_SIZEOF (virtchnl2_vport_stats_t, 128);

/* VIRTCHNL2_OP_EVENT
 * CP sends this message to inform the PF/VF driver of events that may affect
 * it. No direct response is expected from the driver, though it may generate
 * other messages in response to this one.
 */
typedef struct
{
  /* see VIRTCHNL2_EVENT_CODES definitions */
  u32 event;
  /* link_speed provided in Mbps */
  u32 link_speed;
  u32 vport_id;
  u8 link_status;
  u8 pad[1];
  /* CP sends reset notification to PF with corresponding ADI ID */
  u16 adi_id;
} virtchnl2_event_t;

STATIC_ASSERT_SIZEOF (virtchnl2_event_t, 16);

/* VIRTCHNL2_OP_GET_RSS_KEY
 * VIRTCHNL2_OP_SET_RSS_KEY
 * PF/VF sends this message to get or set RSS key. Only supported if both
 * PF/VF and CP drivers set the VIRTCHNL2_CAP_RSS bit during configuration
 * negotiation. Uses the virtchnl2_rss_key structure
 */
typedef struct
{
  u32 vport_id;
  u16 key_len;
  u8 pad;
  u8 key[1]; /* RSS hash key, packed bytes */
} virtchnl2_rss_key_t;

STATIC_ASSERT_SIZEOF (virtchnl2_rss_key_t, 8);

/* structure to specify a chunk of contiguous queues */
typedef struct
{
  /* see VIRTCHNL2_QUEUE_TYPE definitions */
  u32 type;
  u32 start_queue_id;
  u32 num_queues;
  u8 reserved[4];
} virtchnl2_queue_chunk_t;

STATIC_ASSERT_SIZEOF (virtchnl2_queue_chunk_t, 16);

/* structure to specify several chunks of contiguous queues */
typedef struct
{
  u16 num_chunks;
  u8 reserved[6];
  virtchnl2_queue_chunk_t chunks[1];
} virtchnl2_queue_chunks_t;

STATIC_ASSERT_SIZEOF (virtchnl2_queue_chunks_t, 24);

/* VIRTCHNL2_OP_ENABLE_QUEUES
 * VIRTCHNL2_OP_DISABLE_QUEUES
 * VIRTCHNL2_OP_DEL_QUEUES
 *
 * PF sends these messages to enable, disable or delete queues specified in
 * chunks. PF sends virtchnl2_del_ena_dis_queues struct to specify the queues
 * to be enabled/disabled/deleted. Also applicable to single queue receive or
 * transmit. CP performs requested action and returns status.
 */
typedef struct
{
  u32 vport_id;
  u8 reserved[4];
  virtchnl2_queue_chunks_t chunks;
} virtchnl2_del_ena_dis_queues_t;

STATIC_ASSERT_SIZEOF (virtchnl2_del_ena_dis_queues_t, 32);

/* Queue to vector mapping */
typedef struct
{
  u32 queue_id;
  u16 vector_id;
  u8 pad[2];

  /* see VIRTCHNL2_ITR_IDX definitions */
  u32 itr_idx;

  /* see VIRTCHNL2_QUEUE_TYPE definitions */
  u32 queue_type;
  u8 reserved[8];
} virtchnl2_queue_vector_t;

STATIC_ASSERT_SIZEOF (virtchnl2_queue_vector_t, 24);

/* VIRTCHNL2_OP_MAP_QUEUE_VECTOR
 * VIRTCHNL2_OP_UNMAP_QUEUE_VECTOR
 *
 * PF sends this message to map or unmap queues to vectors and interrupt
 * throttling rate index registers. External data buffer contains
 * virtchnl2_queue_vector_maps structure that contains num_qv_maps of
 * virtchnl2_queue_vector structures. CP maps the requested queue vector maps
 * after validating the queue and vector ids and returns a status code.
 */
typedef struct
{
  u32 vport_id;
  u16 num_qv_maps;
  u8 pad[10];
  virtchnl2_queue_vector_t qv_maps[1];
} virtchnl2_queue_vector_maps_t;

STATIC_ASSERT_SIZEOF (virtchnl2_queue_vector_maps_t, 40);

/* VIRTCHNL2_OP_LOOPBACK
 *
 * PF/VF sends this message to transition to/from the loopback state. Setting
 * the 'enable' to 1 enables the loopback state and setting 'enable' to 0
 * disables it. CP configures the state to loopback and returns status.
 */
typedef struct
{
  u32 vport_id;
  u8 enable;
  u8 pad[3];
} virtchnl2_loopback_t;

STATIC_ASSERT_SIZEOF (virtchnl2_loopback_t, 8);

/* structure to specify each MAC address */
typedef struct
{
  u8 addr[VIRTCHNL2_ETH_LENGTH_OF_ADDRESS];
  /* see VIRTCHNL2_MAC_TYPE definitions */
  u8 type;
  u8 pad;
} virtchnl2_mac_addr_t;

STATIC_ASSERT_SIZEOF (virtchnl2_mac_addr_t, 8);

/* VIRTCHNL2_OP_ADD_MAC_ADDR
 * VIRTCHNL2_OP_DEL_MAC_ADDR
 *
 * PF/VF driver uses this structure to send list of MAC addresses to be
 * added/deleted to the CP where as CP performs the action and returns the
 * status.
 */
typedef struct
{
  u32 vport_id;
  u16 num_mac_addr;
  u8 pad[2];
  virtchnl2_mac_addr_t mac_addr_list[1];
} virtchnl2_mac_addr_list_t;

STATIC_ASSERT_SIZEOF (virtchnl2_mac_addr_list_t, 16);

/* VIRTCHNL2_OP_CONFIG_PROMISCUOUS_MODE
 *
 * PF/VF sends vport id and flags to the CP where as CP performs the action
 * and returns the status.
 */
typedef struct
{
  u32 vport_id;
  /* see VIRTCHNL2_PROMISC_FLAGS definitions */
  u16 flags;
  u8 pad[2];
} virtchnl2_promisc_info_t;

STATIC_ASSERT_SIZEOF (virtchnl2_promisc_info_t, 8);

#endif /* _IDPF_VIRTCHNL_H_ */
