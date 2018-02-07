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

#define VIRTCHNL_VERSION_MAJOR 1
#define VIRTCHNL_VERSION_MINOR 1


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
#define VFINT_DYN_CTL0      0x00005C00
#define AVF_QRX_TAIL(q)     (0x00002000 + 0x4 * q)

#define AVF_AQ_FLAG_DD  (1 << 0)
#define AVF_AQ_FLAG_CMP (1 << 1)
#define AVF_AQ_FLAG_ERR (1 << 2)
#define AVF_AQ_FLAG_VFE (1 << 3)
#define AVF_AQ_FLAG_LB  (1 << 9)
#define AVF_AQ_FLAG_RD  (1 << 10)
#define AVF_AQ_FLAG_VFC (1 << 11)
#define AVF_AQ_FLAG_BUF (1 << 12)
#define AVF_AQ_FLAG_SI  (1 << 13)
#define AVF_AQ_FLAG_EI  (1 << 14)
#define AVF_AQ_FLAG_FE  (1 << 15)

typedef enum
{
  VIRTCHNL_OP_UNKNOWN = 0,
  VIRTCHNL_OP_VERSION = 1,
  VIRTCHNL_OP_RESET_VF = 2,
  VIRTCHNL_OP_GET_VF_RESOURCES = 3,
  VIRTCHNL_OP_CONFIG_TX_QUEUE = 4,
  VIRTCHNL_OP_CONFIG_RX_QUEUE = 5,
  VIRTCHNL_OP_CONFIG_VSI_QUEUES = 6,
  VIRTCHNL_OP_ENABLE_QUEUES = 8,
  VIRTCHNL_OP_DISABLE_QUEUES = 9,
  VIRTCHNL_OP_GET_STATS = 15,
  VIRTCHNL_OP_EVENT = 17,
} virtchnl_ops_t;

typedef enum
{
  VIRTCHNL_STATUS_SUCCESS = 0,
  VIRTCHNL_ERR_PARAM = -5,
  VIRTCHNL_STATUS_ERR_OPCODE_MISMATCH = -38,
  VIRTCHNL_STATUS_ERR_CQP_COMPL_ERROR = -39,
  VIRTCHNL_STATUS_ERR_INVALID_VF_ID = -40,
  VIRTCHNL_STATUS_NOT_SUPPORTED = -64,
} virtchnl_status_code_t;

typedef enum
{
  VIRTCHNL_VSI_TYPE_INVALID = 0,
  VIRTCHNL_VSI_SRIOV = 6,
} virtchnl_vsi_type_t;

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

typedef enum
{
  VIRTCHNL_EVENT_UNKNOWN = 0,
  VIRTCHNL_EVENT_LINK_CHANGE,
  VIRTCHNL_EVENT_RESET_IMPENDING,
  VIRTCHNL_EVENT_PF_DRIVER_CLOSE,
} virtchnl_event_codes_t;

#define VIRTCHNL_LINK_SPEED_100MB_SHIFT 0x1
#define VIRTCHNL_LINK_SPEED_1000MB_SHIFT 0x2
#define VIRTCHNL_LINK_SPEED_10GB_SHIFT 0x3
#define VIRTCHNL_LINK_SPEED_40GB_SHIFT 0x4
#define VIRTCHNL_LINK_SPEED_20GB_SHIFT 0x5
#define VIRTCHNL_LINK_SPEED_25GB_SHIFT 0x6

#define BIT(x) (1 << x)
typedef enum
{
  VIRTCHNL_LINK_SPEED_UNKNOWN = 0,
  VIRTCHNL_LINK_SPEED_100MB = BIT (VIRTCHNL_LINK_SPEED_100MB_SHIFT),
  VIRTCHNL_LINK_SPEED_1GB = BIT (VIRTCHNL_LINK_SPEED_1000MB_SHIFT),
  VIRTCHNL_LINK_SPEED_10GB = BIT (VIRTCHNL_LINK_SPEED_10GB_SHIFT),
  VIRTCHNL_LINK_SPEED_40GB = BIT (VIRTCHNL_LINK_SPEED_40GB_SHIFT),
  VIRTCHNL_LINK_SPEED_20GB = BIT (VIRTCHNL_LINK_SPEED_20GB_SHIFT),
  VIRTCHNL_LINK_SPEED_25GB = BIT (VIRTCHNL_LINK_SPEED_25GB_SHIFT),
} virtchnl_link_speed_t;

typedef struct
{
  virtchnl_event_codes_t event;
  union
  {
    struct
    {
      virtchnl_link_speed_t link_speed;
      int link_status;
    } link_event;
  } event_data;
  int severity;
} virtchnl_pf_event_t;


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
  u32 param[2];
  u32 addr_hi;
  u32 addr_lo;
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
  u64 rx_bytes;
  u64 rx_unicast;
  u64 rx_multicast;
  u64 rx_broadcast;
  u64 rx_discards;
  u64 rx_unknown_protocol;
  u64 tx_bytes;
  u64 tx_unicast;
  u64 tx_multicast;
  u64 tx_broadcast;
  u64 tx_discards;
  u64 tx_errors;
} virtchnl_eth_stats_t;
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
