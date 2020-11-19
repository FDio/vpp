/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef _AVF_VIRTCHNL_H_
#define _AVF_VIRTCHNL_H_

#define VIRTCHNL_VERSION_MAJOR 1
#define VIRTCHNL_VERSION_MINOR 1

#define foreach_avf_promisc_flags \
  _(0, UNICAST_PROMISC, "unicast") \
  _(1, MULTICAST_PROMISC, "multicast")

enum
{
#define _(a, b, c) FLAG_VF_ ##b = (1 << a),
  foreach_avf_promisc_flags
#undef _
};

#define AVFINT_DYN_CTLN(x)  (0x00003800 + (0x4 * x))
#define AVFINT_ICR0         0x00004800
#define AVFINT_ICR0_ENA1    0x00005000
#define AVFINT_DYN_CTL0     0x00005C00
#define AVF_ARQBAH          0x00006000
#define AVF_ATQH            0x00006400
#define AVF_ATQLEN          0x00006800
#define AVF_ARQBAL          0x00006C00
#define AVF_ARQT            0x00007000
#define AVF_ARQH            0x00007400
#define AVF_ATQBAH          0x00007800
#define AVF_ATQBAL          0x00007C00
#define AVF_ARQLEN          0x00008000
#define AVF_ATQT            0x00008400
#define AVFGEN_RSTAT        0x00008800
#define AVF_QTX_TAIL(q)     (0x00000000 + (0x4 * q))
#define AVF_QRX_TAIL(q)     (0x00002000 + (0x4 * q))

#define AVF_AQ_F_DD  (1 << 0)
#define AVF_AQ_F_CMP (1 << 1)
#define AVF_AQ_F_ERR (1 << 2)
#define AVF_AQ_F_VFE (1 << 3)
#define AVF_AQ_F_LB  (1 << 9)
#define AVF_AQ_F_RD  (1 << 10)
#define AVF_AQ_F_VFC (1 << 11)
#define AVF_AQ_F_BUF (1 << 12)
#define AVF_AQ_F_SI  (1 << 13)
#define AVF_AQ_F_EI  (1 << 14)
#define AVF_AQ_F_FE  (1 << 15)


#define foreach_virtchnl_op \
  _(0, UNKNOWN)					\
  _(1, VERSION)					\
  _(2, RESET_VF)				\
  _(3, GET_VF_RESOURCES)			\
  _(4, CONFIG_TX_QUEUE)				\
  _(5, CONFIG_RX_QUEUE)				\
  _(6, CONFIG_VSI_QUEUES)			\
  _(7, CONFIG_IRQ_MAP)				\
  _(8, ENABLE_QUEUES)				\
  _(9, DISABLE_QUEUES)				\
  _(10, ADD_ETH_ADDR)				\
  _(11, DEL_ETH_ADDR)				\
  _(12, ADD_VLAN)				\
  _(13, DEL_VLAN)				\
  _(14, CONFIG_PROMISCUOUS_MODE)		\
  _(15, GET_STATS)				\
  _(16, RSVD)					\
  _(17, EVENT)					\
  _(18, UNDEF_18)				\
  _(19, UNDEF_19)				\
  _(20, IWARP)					\
  _(21, CONFIG_IWARP_IRQ_MAP)			\
  _(22, RELEASE_IWARP_IRQ_MAP)			\
  _(23, CONFIG_RSS_KEY)				\
  _(24, CONFIG_RSS_LUT)				\
  _(25, GET_RSS_HENA_CAPS)			\
  _(26, SET_RSS_HENA)				\
  _(27, ENABLE_VLAN_STRIPPING)			\
  _(28, DISABLE_VLAN_STRIPPING)			\
  _(29, REQUEST_QUEUES)				\
  _(30, ENABLE_CHANNELS)			\
  _(31, DISABLE_CHANNELS)			\
  _(32, ADD_CLOUD_FILTER)			\
  _(33, DEL_CLOUD_FILTER)			\
  _(44, GET_SUPPORTED_RXDIDS) 			\
  _(47, ADD_FDIR_FILTER) 			\
  _(48, DEL_FDIR_FILTER) 			\
  _(49, QUERY_FDIR_FILTER)

typedef enum
{
#define _(v,n) VIRTCHNL_OP_##n = v,
  foreach_virtchnl_op
#undef _
    VIRTCHNL_N_OPS,
} virtchnl_ops_t;

typedef enum
{
  VIRTCHNL_STATUS_SUCCESS = 0,
  VIRTCHNL_STATUS_ERR_PARAM = -5,
  VIRTCHNL_STATUS_ERR_NO_MEMORY = -18,
  VIRTCHNL_STATUS_ERR_OPCODE_MISMATCH = -38,
  VIRTCHNL_STATUS_ERR_CQP_COMPL_ERROR = -39,
  VIRTCHNL_STATUS_ERR_INVALID_VF_ID = -40,
  VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR = -53,
  VIRTCHNL_STATUS_NOT_SUPPORTED = -64,
} virtchnl_status_code_t;

#define foreach_avf_vf_cap_flag \
  _( 0, OFFLOAD_L2, "l2") \
  _( 1, OFFLOAD_IWARP, "iwarp") \
  _( 2, OFFLOAD_RSVD, "rsvd") \
  _( 3, OFFLOAD_RSS_AQ, "rss-aq") \
  _( 4, OFFLOAD_RSS_REG, "rss-reg") \
  _( 5, OFFLOAD_WB_ON_ITR, "wb-on-itr") \
  _( 6, OFFLOAD_REQ_QUEUES, "req-queues") \
  _( 7, CAP_ADV_LINK_SPEED, "adv-link-speed") \
  _(16, OFFLOAD_VLAN, "vlan") \
  _(17, OFFLOAD_RX_POLLING, "rx-polling") \
  _(18, OFFLOAD_RSS_PCTYPE_V2, "rss-pctype-v2") \
  _(19, OFFLOAD_RSS_PF, "rss-pf") \
  _(20, OFFLOAD_ENCAP, "encap") \
  _(21, OFFLOAD_ENCAP_CSUM, "encap-csum") \
  _(22, OFFLOAD_RX_ENCAP_CSUM, "rx-encap-csum") \
  _(23, OFFLOAD_ADQ, "offload-adq")	\
  _(27, OFFLOAD_ADV_RSS_PF, "offload-adv-rss-pf") \
  _(28, OFFLOAD_FDIR_PF, "offload-fdir-pf")

typedef enum
{
#define _(a, b, c) VIRTCHNL_VF_##b = (1 << a),
  foreach_avf_vf_cap_flag
#undef _
} avf_vf_cap_flag_t;

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
  u32 vf_offload_flags;
  u32 rss_key_size;
  u32 rss_lut_size;
  virtchnl_vsi_resource_t vsi_res[1];
} virtchnl_vf_resource_t;

#define foreach_virtchnl_event_code \
  _(0, UNKNOWN)				\
  _(1, LINK_CHANGE)			\
  _(2, RESET_IMPENDING)			\
  _(3, PF_DRIVER_CLOSE)

typedef enum
{
#define _(a,b) VIRTCHNL_EVENT_##b = (a),
  foreach_virtchnl_event_code
#undef _
} virtchnl_event_codes_t;

#define foreach_virtchnl_link_speed \
  _(0, 2_5GB, "2.5 Gbps")		\
  _(1, 100MB, "100 Mbps")		\
  _(2, 1GB, "1 Gbps")			\
  _(3, 10GB, "10 Gbps")			\
  _(4, 40GB, "40 Gbps")			\
  _(5, 20GB, "20 Gbps")			\
  _(6, 25GB, "25 Gbps")			\
  _(7, 5GB, "5 Gbps")

typedef enum
{
  VIRTCHNL_LINK_SPEED_UNKNOWN = 0,
#define _(a,b,c) VIRTCHNL_LINK_SPEED_##b = (1 << a),
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

typedef struct
{
  u16 flags;
  u16 opcode;
  u16 datalen;
  u16 retval;
  union
  {
    u32 cookie_hi;
    virtchnl_ops_t v_opcode;
  };
  union
  {
    u32 cookie_lo;
    virtchnl_status_code_t v_retval;
  };
  u32 param0;
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
} avf_aq_desc_t;

STATIC_ASSERT_SIZEOF (avf_aq_desc_t, 32);

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
  u32 pad1;
  u64 dma_ring_addr;
  int rx_split_pos;
  u32 pad2;
} virtchnl_rxq_info_t;

STATIC_ASSERT_SIZEOF (virtchnl_rxq_info_t, 40);

typedef struct
{
  virtchnl_txq_info_t txq;
  virtchnl_rxq_info_t rxq;
} virtchnl_queue_pair_info_t;

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
  u8 pad[2];
} virtchnl_ether_addr_t;

typedef struct
{
  u16 vsi_id;
  u16 num_elements;
  virtchnl_ether_addr_t list[1];
} virtchnl_ether_addr_list_t;

#define foreach_virtchnl_eth_stats \
  _(rx_bytes)		\
  _(rx_unicast)		\
  _(rx_multicast)	\
  _(rx_broadcast)	\
  _(rx_discards)	\
  _(rx_unknown_protocol)\
  _(tx_bytes)		\
  _(tx_unicast)		\
  _(tx_multicast)	\
  _(tx_broadcast)	\
  _(tx_discards)	\
  _(tx_errors)

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

#endif /* AVF_VIRTCHNL_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
