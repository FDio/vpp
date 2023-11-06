/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _IIAVF_VIRTCHNL_H_
#define _IIAVF_VIRTCHNL_H_

#define VIRTCHNL_VERSION_MAJOR 1
#define VIRTCHNL_VERSION_MINOR 1

#define foreach_iavf_promisc_flags                                            \
  _ (0, UNICAST_PROMISC, "unicast")                                           \
  _ (1, MULTICAST_PROMISC, "multicast")

enum
{
#define _(a, b, c) FLAG_VF_##b = (1 << a),
  foreach_iavf_promisc_flags
#undef _
};

#define IAVF_VFINT_DYN_CTLN(x) (0x00003800 + (0x4 * x))
#define IAVF_VFINT_ICR0	       0x00004800
#define IAVF_VFINT_ICR0_ENA1   0x00005000
#define IAVF_VFINT_DYN_CTL0    0x00005C00
#define IAVF_ARQBAH	       0x00006000
#define IAVF_ATQH	       0x00006400
#define IAVF_ATQLEN	       0x00006800
#define IAVF_ARQBAL	       0x00006C00
#define IAVF_ARQT	       0x00007000
#define IAVF_ARQH	       0x00007400
#define IAVF_ATQBAH	       0x00007800
#define IAVF_ATQBAL	       0x00007C00
#define IAVF_ARQLEN	       0x00008000
#define IAVF_ATQT	       0x00008400
#define IAVF_VFGEN_RSTAT       0x00008800
#define IAVF_QTX_TAIL(q)       (0x00000000 + (0x4 * q))
#define IAVF_QRX_TAIL(q)       (0x00002000 + (0x4 * q))

#define foreach_virtchnl_op                                                   \
  _ (0, UNKNOWN)                                                              \
  _ (1, VERSION)                                                              \
  _ (2, RESET_VF)                                                             \
  _ (3, GET_VF_RESOURCES)                                                     \
  _ (4, CONFIG_TX_QUEUE)                                                      \
  _ (5, CONFIG_RX_QUEUE)                                                      \
  _ (6, CONFIG_VSI_QUEUES)                                                    \
  _ (7, CONFIG_IRQ_MAP)                                                       \
  _ (8, ENABLE_QUEUES)                                                        \
  _ (9, DISABLE_QUEUES)                                                       \
  _ (10, ADD_ETH_ADDR)                                                        \
  _ (11, DEL_ETH_ADDR)                                                        \
  _ (12, ADD_VLAN)                                                            \
  _ (13, DEL_VLAN)                                                            \
  _ (14, CONFIG_PROMISCUOUS_MODE)                                             \
  _ (15, GET_STATS)                                                           \
  _ (16, RSVD)                                                                \
  _ (17, EVENT)                                                               \
  _ (18, UNDEF_18)                                                            \
  _ (19, UNDEF_19)                                                            \
  _ (20, IWARP)                                                               \
  _ (21, CONFIG_IWARP_IRQ_MAP)                                                \
  _ (22, RELEASE_IWARP_IRQ_MAP)                                               \
  _ (23, CONFIG_RSS_KEY)                                                      \
  _ (24, CONFIG_RSS_LUT)                                                      \
  _ (25, GET_RSS_HENA_CAPS)                                                   \
  _ (26, SET_RSS_HENA)                                                        \
  _ (27, ENABLE_VLAN_STRIPPING)                                               \
  _ (28, DISABLE_VLAN_STRIPPING)                                              \
  _ (29, REQUEST_QUEUES)                                                      \
  _ (30, ENABLE_CHANNELS)                                                     \
  _ (31, DISABLE_CHANNELS)                                                    \
  _ (32, ADD_CLOUD_FILTER)                                                    \
  _ (33, DEL_CLOUD_FILTER)                                                    \
  _ (45, ADD_RSS_CFG)                                                         \
  _ (46, DEL_RSS_CFG)                                                         \
  _ (47, ADD_FDIR_FILTER)                                                     \
  _ (48, DEL_FDIR_FILTER)                                                     \
  _ (49, QUERY_FDIR_FILTER)                                                   \
  _ (50, GET_MAX_RSS_QREGION)                                                 \
  _ (51, GET_OFFLOAD_VLAN_V2_CAPS)                                            \
  _ (52, ADD_VLAN_V2)                                                         \
  _ (53, DEL_VLAN_V2)                                                         \
  _ (54, ENABLE_VLAN_STRIPPING_V2)                                            \
  _ (55, DISABLE_VLAN_STRIPPING_V2)                                           \
  _ (56, ENABLE_VLAN_INSERTION_V2)                                            \
  _ (57, DISABLE_VLAN_INSERTION_V2)                                           \
  _ (58, ENABLE_VLAN_FILTERING_V2)                                            \
  _ (59, DISABLE_VLAN_FILTERING_V2)                                           \
  _ (107, ENABLE_QUEUES_V2)                                                   \
  _ (108, DISABLE_QUEUES_V2)                                                  \
  _ (111, MAP_QUEUE_VECTOR)

typedef enum
{
#define _(v, n) VIRTCHNL_OP_##n = v,
  foreach_virtchnl_op
#undef _
    VIRTCHNL_N_OPS,
} virtchnl_op_t;

#define foreach_virtchnl_status                                               \
  _ (0, SUCCESS)                                                              \
  _ (-5, ERR_PARAM)                                                           \
  _ (-18, ERR_NO_MEMORY)                                                      \
  _ (-38, ERR_OPCODE_MISMATCH)                                                \
  _ (-39, ERR_CQP_COMPL_ERROR)                                                \
  _ (-40, ERR_INVALID_VF_ID)                                                  \
  _ (-53, ERR_ADMIN_QUEUE_ERROR)                                              \
  _ (-64, NOT_SUPPORTED)

typedef enum
{
#define _(a, b) VIRTCHNL_STATUS_##b = a,
  foreach_virtchnl_status
#undef _
} virtchnl_status_t;

#define foreach_iavf_vf_cap_flag                                              \
  _ (0, OFFLOAD_L2, "l2")                                                     \
  _ (1, OFFLOAD_IWARP, "iwarp")                                               \
  _ (2, OFFLOAD_RSVD, "rsvd")                                                 \
  _ (3, OFFLOAD_RSS_AQ, "rss-aq")                                             \
  _ (4, OFFLOAD_RSS_REG, "rss-reg")                                           \
  _ (5, OFFLOAD_WB_ON_ITR, "wb-on-itr")                                       \
  _ (6, OFFLOAD_REQ_QUEUES, "req-queues")                                     \
  _ (7, CAP_ADV_LINK_SPEED, "adv-link-speed")                                 \
  _ (9, LARGE_NUM_QPAIRS, "large-num-qpairs")                                 \
  _ (15, OFFLOAD_VLAN_V2, "vlan-v2")                                          \
  _ (16, OFFLOAD_VLAN, "vlan")                                                \
  _ (17, OFFLOAD_RX_POLLING, "rx-polling")                                    \
  _ (18, OFFLOAD_RSS_PCTYPE_V2, "rss-pctype-v2")                              \
  _ (19, OFFLOAD_RSS_PF, "rss-pf")                                            \
  _ (20, OFFLOAD_ENCAP, "encap")                                              \
  _ (21, OFFLOAD_ENCAP_CSUM, "encap-csum")                                    \
  _ (22, OFFLOAD_RX_ENCAP_CSUM, "rx-encap-csum")                              \
  _ (23, OFFLOAD_ADQ, "offload-adq")                                          \
  _ (24, OFFLOAD_ADQ_v2, "offload-adq-v2")                                    \
  _ (25, OFFLOAD_USO, "offload-uso")                                          \
  _ (26, OFFLOAD_RX_FLEX_DESC, "offload-rx-flex-desc")                        \
  _ (27, OFFLOAD_ADV_RSS_PF, "offload-adv-rss-pf")                            \
  _ (28, OFFLOAD_FDIR_PF, "offload-fdir-pf")                                  \
  _ (30, CAP_DCF, "dcf")

typedef enum
{
#define _(a, b, c) VIRTCHNL_VF_##b = (1 << a),
  foreach_iavf_vf_cap_flag
#undef _
} iavf_vf_cap_flag_t;

typedef enum
{
  VIRTCHNL_VSI_TYPE_INVALID = 0,
  VIRTCHNL_VSI_SRIOV = 6,
} virtchnl_vsi_type_t;

typedef enum
{
  VIRTCHNL_VFR_INPROGRESS = 0,
  VIRTCHNL_VFR_COMPLETED,
  VIRTCHNL_VFR_VFACTIVE,
} virtchnl_vfr_states_t;

typedef struct
{
  u16 vsi_id;
  u16 num_queue_pairs;
  virtchnl_vsi_type_t vsi_type;
  u16 qset_handle;
  u8 default_mac_addr[6];
} virtchnl_vsi_resource_t;

typedef struct
{
  u16 num_vsis;
  u16 num_queue_pairs;
  u16 max_vectors;
  u16 max_mtu;
  u32 vf_cap_flags;
  u32 rss_key_size;
  u32 rss_lut_size;
  virtchnl_vsi_resource_t vsi_res[1];
} virtchnl_vf_resource_t;

#define foreach_virtchnl_event_code                                           \
  _ (0, UNKNOWN)                                                              \
  _ (1, LINK_CHANGE)                                                          \
  _ (2, RESET_IMPENDING)                                                      \
  _ (3, PF_DRIVER_CLOSE)

typedef enum
{
#define _(a, b) VIRTCHNL_EVENT_##b = (a),
  foreach_virtchnl_event_code
#undef _
} virtchnl_event_codes_t;

#define foreach_virtchnl_link_speed                                           \
  _ (0, 2_5GB, "2.5 Gbps")                                                    \
  _ (1, 100MB, "100 Mbps")                                                    \
  _ (2, 1GB, "1 Gbps")                                                        \
  _ (3, 10GB, "10 Gbps")                                                      \
  _ (4, 40GB, "40 Gbps")                                                      \
  _ (5, 20GB, "20 Gbps")                                                      \
  _ (6, 25GB, "25 Gbps")                                                      \
  _ (7, 5GB, "5 Gbps")

typedef enum
{
  VIRTCHNL_LINK_SPEED_UNKNOWN = 0,
#define _(a, b, c) VIRTCHNL_LINK_SPEED_##b = (1 << a),
  foreach_virtchnl_link_speed
#undef _
} virtchnl_link_speed_t;

typedef struct
{
  virtchnl_event_codes_t event;
  union
  {
    struct
    {
      virtchnl_link_speed_t link_speed;
      u8 link_status;
    } link_event;
    struct
    {
      u32 link_speed;
      u8 link_status;
    } link_event_adv;
  } event_data;
  int severity;
} virtchnl_pf_event_t;

STATIC_ASSERT_SIZEOF (virtchnl_pf_event_t, 16);

typedef struct
{
  u32 major;
  u32 minor;
} virtchnl_version_info_t;

#define foreach_iavf_aq_desc_flag                                             \
  _ (1, dd)                                                                   \
  _ (1, cmp)                                                                  \
  _ (1, err)                                                                  \
  _ (1, vfe)                                                                  \
  _ (5, reserved)                                                             \
  _ (1, lb)                                                                   \
  _ (1, rd)                                                                   \
  _ (1, vfc)                                                                  \
  _ (1, buf)                                                                  \
  _ (1, si)                                                                   \
  _ (1, ie)                                                                   \
  _ (1, fe)

typedef union
{
  struct
  {
#define _(n, s) u16 s : n;
    foreach_iavf_aq_desc_flag
#undef _
  };
  u16 as_u16;
} iavf_aq_desc_flags_t;

STATIC_ASSERT_SIZEOF (iavf_aq_desc_flags_t, 2);

typedef enum
{
  IIAVF_AQ_DESC_OP_QUEUE_SHUTDOWN = 0x0003,
  IIAVF_AQ_DESC_OP_SEND_TO_PF = 0x0801,
  IIAVF_AQ_DESC_OP_MESSAGE_FROM_PF = 0x0802,
} __clib_packed iavf_aq_desc_op_t;

#define foreach_iavf_aq_desc_retval                                           \
  _ (0, OK)                                                                   \
  _ (1, EPERM)                                                                \
  _ (2, ENOENT)                                                               \
  _ (3, ESRCH)                                                                \
  _ (4, EINTR)                                                                \
  _ (5, EIO)                                                                  \
  _ (6, ENXIO)                                                                \
  _ (7, E2BIG)                                                                \
  _ (8, EAGAIN)                                                               \
  _ (9, ENOMEM)                                                               \
  _ (10, EACCES)                                                              \
  _ (11, EFAULT)                                                              \
  _ (12, EBUSY)                                                               \
  _ (13, EEXIST)                                                              \
  _ (14, EINVAL)                                                              \
  _ (15, ENOTTY)                                                              \
  _ (16, ENOSPC)                                                              \
  _ (17, ENOSYS)                                                              \
  _ (18, ERANGE)                                                              \
  _ (19, EFLUSHED)                                                            \
  _ (20, BAD_ADDR)                                                            \
  _ (21, EMODE)                                                               \
  _ (22, EFBIG)                                                               \
  _ (23, ESBCOMP)                                                             \
  _ (24, ENOSEC)                                                              \
  _ (25, EBADSIG)                                                             \
  _ (26, ESVN)                                                                \
  _ (27, EBADMAN)                                                             \
  _ (28, EBADBUF)                                                             \
  _ (29, EACCES_BMCU)

typedef enum
{
#define _(a, b) IIAVF_AQ_DESC_RETVAL_##b = a,
  foreach_iavf_aq_desc_retval
#undef _
} __clib_packed iavf_aq_desc_retval_t;

typedef struct
{
  iavf_aq_desc_flags_t flags;
  iavf_aq_desc_op_t opcode;
  u16 datalen;
  u16 retval;
  union
  {
    u32 cookie_hi;
    virtchnl_op_t v_opcode;
  };
  union
  {
    u32 cookie_lo;
    virtchnl_status_t v_retval;
  };
  union
  {
    u8 driver_unloading : 1;
    u32 param0;
  };
  u32 param1;
  union
  {
    u32 param2;
    u32 addr_hi;
  };
  union
  {
    u32 param3;
    u32 addr_lo;
  };
} iavf_aq_desc_t;

STATIC_ASSERT_SIZEOF (iavf_aq_desc_t, 32);

typedef struct
{
  u16 vsi_id;
  u16 queue_id;
  u16 ring_len;
  u64 dma_ring_addr;
  u64 dma_headwb_addr;
} virtchnl_txq_info_t;

STATIC_ASSERT_SIZEOF (virtchnl_txq_info_t, 24);

typedef struct
{
  u16 vsi_id;
  u16 queue_id;
  u32 ring_len;
  u16 hdr_size;
  u16 splithdr_enabled;
  u32 databuffer_size;
  u32 max_pkt_size;
  u8 crc_disable;
  u8 rxdid;
  u8 pad[2];
  u64 dma_ring_addr;
  i32 rx_split_pos;
  u32 pad2;
} virtchnl_rxq_info_t;

STATIC_ASSERT_SIZEOF (virtchnl_rxq_info_t, 40);

typedef struct
{
  virtchnl_txq_info_t txq;
  virtchnl_rxq_info_t rxq;
} virtchnl_queue_pair_info_t;

STATIC_ASSERT_SIZEOF (virtchnl_queue_pair_info_t, 64);

typedef struct
{
  u16 vsi_id;
  u16 num_queue_pairs;
  u32 pad;
  virtchnl_queue_pair_info_t qpair[1];
} virtchnl_vsi_queue_config_info_t;

STATIC_ASSERT_SIZEOF (virtchnl_vsi_queue_config_info_t, 72);

typedef struct
{
  u16 vsi_id;
  u16 pad;
  u32 rx_queues;
  u32 tx_queues;
} virtchnl_queue_select_t;

STATIC_ASSERT_SIZEOF (virtchnl_queue_select_t, 12);

typedef struct
{
  u16 vsi_id;
  u16 vector_id;
  u16 rxq_map;
  u16 txq_map;
  u16 rxitr_idx;
  u16 txitr_idx;
} virtchnl_vector_map_t;

typedef struct
{
  u16 num_vectors;
  virtchnl_vector_map_t vecmap[1];
} virtchnl_irq_map_info_t;

STATIC_ASSERT_SIZEOF (virtchnl_irq_map_info_t, 14);

typedef struct
{
  u8 addr[6];
  union
  {
    struct
    {
      u8 primary : 1;
      u8 extra : 1;
    };
    u8 type;
  };
  u8 pad[1];
} virtchnl_ether_addr_t;

typedef struct
{
  u16 vsi_id;
  u16 num_elements;
  virtchnl_ether_addr_t list[1];
} virtchnl_ether_addr_list_t;

#define foreach_virtchnl_eth_stats                                            \
  _ (rx_bytes)                                                                \
  _ (rx_unicast)                                                              \
  _ (rx_multicast)                                                            \
  _ (rx_broadcast)                                                            \
  _ (rx_discards)                                                             \
  _ (rx_unknown_protocol)                                                     \
  _ (tx_bytes)                                                                \
  _ (tx_unicast)                                                              \
  _ (tx_multicast)                                                            \
  _ (tx_broadcast)                                                            \
  _ (tx_discards)                                                             \
  _ (tx_errors)

typedef struct
{
#define _(s) u64 s;
  foreach_virtchnl_eth_stats
#undef _
} virtchnl_eth_stats_t;

typedef struct
{
  u16 vsi_id;
  u16 key_len;
  u8 key[1];
} virtchnl_rss_key_t;

STATIC_ASSERT_SIZEOF (virtchnl_rss_key_t, 6);

typedef struct
{
  u16 vsi_id;
  u16 lut_entries;
  u8 lut[1];
} virtchnl_rss_lut_t;

STATIC_ASSERT_SIZEOF (virtchnl_rss_lut_t, 6);

/* VIRTCHNL_OP_REQUEST_QUEUES */
typedef struct
{
  u16 num_queue_pairs;
} virtchnl_vf_res_request_t;

typedef struct
{
  u32 outer;
  u32 inner;
} virtchnl_vlan_supported_caps_t;

typedef struct
{
  virtchnl_vlan_supported_caps_t filtering_support;
  u32 ethertype_init;
  u16 max_filters;
  u8 pad[2];
} virtchnl_vlan_filtering_caps_t;

typedef struct virtchnl_vlan_offload_caps
{
  virtchnl_vlan_supported_caps_t stripping_support;
  virtchnl_vlan_supported_caps_t insertion_support;
  u32 ethertype_init;
  u8 ethertype_match;
  u8 pad[3];
} virtchnl_vlan_offload_caps_t;

typedef struct
{
  virtchnl_vlan_filtering_caps_t filtering;
  virtchnl_vlan_offload_caps_t offloads;
} virtchnl_vlan_caps_t;

#define foreach_virtchnl_vlan_support_bit                                     \
  _ (0, ETHERTYPE_8100, "dot1Q")                                              \
  _ (1, ETHERTYPE_88A8, "dot1AD")                                             \
  _ (2, ETHERTYPE_9100, "QinQ")                                               \
  _ (8, TAG_LOCATION_L2TAG1, "l2tag1")                                        \
  _ (9, TAG_LOCATION_L2TAG2, "l2tag2")                                        \
  _ (10, TAG_LOCATION_L2TAG2_2, "l2tag2_2")                                   \
  _ (24, PRIO, "prio")                                                        \
  _ (28, FILTER_MASK, "filter-mask")                                          \
  _ (29, ETHERTYPE_AND, "etype-and")                                          \
  _ (30, ETHERTYPE_XOR, "etype-xor")                                          \
  _ (31, TOGGLE, "toggle")

typedef enum
{
  VIRTCHNL_VLAN_UNSUPPORTED = 0,
#define _(a, b, c) VIRTCHNL_VLAN_##b = (1 << a),
  foreach_virtchnl_vlan_support_bit
#undef _
} virtchnl_vlan_support_caps_t;

typedef struct
{
  u32 outer_ethertype_setting;
  u32 inner_ethertype_setting;
  u16 vport_id;
  u8 pad[6];
} virtchnl_vlan_setting_t;

typedef struct
{
  u16 vsi_id;
  union
  {
    struct
    {
      u16 unicast_promisc : 1;
      u16 multicast_promisc : 1;
    };
    u16 flags;
  };
} virtchnl_promisc_info_t;

STATIC_ASSERT_SIZEOF (virtchnl_promisc_info_t, 4);

#endif /* IAVF_VIRTCHNL_H */
