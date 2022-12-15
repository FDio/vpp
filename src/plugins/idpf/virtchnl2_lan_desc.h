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

#ifndef _IDPF_VIRTCHNL_LAN_DESC_H_
#define _IDPF_VIRTCHNL_LAN_DESC_H_

/* VIRTCHNL2_TX_DESC_IDS
 * Transmit descriptor ID flags
 */
#define foreach_idpf_txdid                                                    \
  _ (0, DATA)                                                                 \
  _ (1, CTX)                                                                  \
  _ (2, REINJECT_CTX)                                                         \
  _ (3, FLEX_DATA)                                                            \
  _ (4, FLEX_CTX)                                                             \
  _ (5, FLEX_TSO_CTX)                                                         \
  _ (6, FLEX_TSYN_L2TAG1)                                                     \
  _ (7, FLEX_L2TAG1_L2TAG2)                                                   \
  _ (8, FLEX_TSO_L2TAG2_PARSTAG_CTX)                                          \
  _ (9, FLEX_HOSTSPLIT_SA_TSO_CTX)                                            \
  _ (10, FLEX_HOSTSPLIT_SA_CTX)                                               \
  _ (11, FLEX_L2TAG2_CTX)                                                     \
  _ (12, FLEX_FLOW_SCHED)                                                     \
  _ (13, FLEX_HOSTSPLIT_TSO_CTX)                                              \
  _ (14, FLEX_HOSTSPLIT_CTX)                                                  \
  _ (15, DESC_DONE)

typedef enum
{
#define _(a, b) VIRTCHNL2_TXDID_##b = (1 << a),
  foreach_idpf_txdid
#undef _
} idpf_txdid_t;

/* VIRTCHNL2_RX_DESC_IDS
 * Receive descriptor IDs (range from 0 to 63)
 */
#define foreach_virtchnl2_rxdid                                               \
  _ (0, 0_16B_BASE)                                                           \
  _ (1, 1_32B_BASE)                                                           \
  _ (2, 2_FLEX_SPLITQ)                                                        \
  _ (2, 2_FLEX_SQ_NIC)                                                        \
  _ (3, 3_FLEX_SQ_SW)                                                         \
  _ (4, 4_FLEX_SQ_NIC_VEB)                                                    \
  _ (5, 5_FLEX_SQ_NIC_ACL)                                                    \
  _ (6, 6_FLEX_SQ_NIC_2)                                                      \
  _ (7, 7_HW_RSVD)                                                            \
  _ (16, 16_COMMS_GENERIC)                                                    \
  _ (17, 17_COMMS_AUX_VLAN)                                                   \
  _ (18, 18_COMMS_AUX_IPV4)                                                   \
  _ (19, 19_COMMS_AUX_IPV6)                                                   \
  _ (20, 20_COMMS_AUX_FLOW)                                                   \
  _ (21, 21_COMMS_AUX_TCP)

typedef enum
{
#define _(v, n) VIRTCHNL2_RXDID_##n = v,
  foreach_virtchnl2_rxdid
#undef _
} virtchnl2_rxdid_t;

/* VIRTCHNL2_RX_DESC_ID_BITMASKS
 * Receive descriptor ID bitmasks
 */
#define VIRTCHNL2_RXDID_0_16B_BASE_M	BIT (VIRTCHNL2_RXDID_0_16B_BASE)
#define VIRTCHNL2_RXDID_1_32B_BASE_M	BIT (VIRTCHNL2_RXDID_1_32B_BASE)
#define VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M BIT (VIRTCHNL2_RXDID_2_FLEX_SPLITQ)
#define VIRTCHNL2_RXDID_2_FLEX_SQ_NIC_M BIT (VIRTCHNL2_RXDID_2_FLEX_SQ_NIC)
#define VIRTCHNL2_RXDID_3_FLEX_SQ_SW_M	BIT (VIRTCHNL2_RXDID_3_FLEX_SQ_SW)
#define VIRTCHNL2_RXDID_4_FLEX_SQ_NIC_VEB_M                                   \
  BIT (VIRTCHNL2_RXDID_4_FLEX_SQ_NIC_VEB)
#define VIRTCHNL2_RXDID_5_FLEX_SQ_NIC_ACL_M                                   \
  BIT (VIRTCHNL2_RXDID_5_FLEX_SQ_NIC_ACL)
#define VIRTCHNL2_RXDID_6_FLEX_SQ_NIC_2_M BIT (VIRTCHNL2_RXDID_6_FLEX_SQ_NIC_2)
#define VIRTCHNL2_RXDID_7_HW_RSVD_M	  BIT (VIRTCHNL2_RXDID_7_HW_RSVD)
/* 9 through 15 are reserved */
#define VIRTCHNL2_RXDID_16_COMMS_GENERIC_M                                    \
  BIT (VIRTCHNL2_RXDID_16_COMMS_GENERIC)
#define VIRTCHNL2_RXDID_17_COMMS_AUX_VLAN_M                                   \
  BIT (VIRTCHNL2_RXDID_17_COMMS_AUX_VLAN)
#define VIRTCHNL2_RXDID_18_COMMS_AUX_IPV4_M                                   \
  BIT (VIRTCHNL2_RXDID_18_COMMS_AUX_IPV4)
#define VIRTCHNL2_RXDID_19_COMMS_AUX_IPV6_M                                   \
  BIT (VIRTCHNL2_RXDID_19_COMMS_AUX_IPV6)
#define VIRTCHNL2_RXDID_20_COMMS_AUX_FLOW_M                                   \
  BIT (VIRTCHNL2_RXDID_20_COMMS_AUX_FLOW)
#define VIRTCHNL2_RXDID_21_COMMS_AUX_TCP_M                                    \
  BIT (VIRTCHNL2_RXDID_21_COMMS_AUX_TCP)
/* 22 through 63 are reserved */

/* Rx */
/* For splitq virtchnl2_rx_flex_desc_adv desc members */
#define VIRTCHNL2_RX_FLEX_DESC_ADV_RXDID_S 0
#define VIRTCHNL2_RX_FLEX_DESC_ADV_RXDID_M                                    \
  MAKEMASK (0xFUL, VIRTCHNL2_RX_FLEX_DESC_ADV_RXDID_S)
#define VIRTCHNL2_RX_FLEX_DESC_ADV_PTYPE_S 0
#define VIRTCHNL2_RX_FLEX_DESC_ADV_PTYPE_M                                    \
  MAKEMASK (0x3FFUL, VIRTCHNL2_RX_FLEX_DESC_ADV_PTYPE_S)
#define VIRTCHNL2_RX_FLEX_DESC_ADV_UMBCAST_S 10
#define VIRTCHNL2_RX_FLEX_DESC_ADV_UMBCAST_M                                  \
  MAKEMASK (0x3UL, VIRTCHNL2_RX_FLEX_DESC_ADV_UMBCAST_S)
#define VIRTCHNL2_RX_FLEX_DESC_ADV_FF0_S 12
#define VIRTCHNL2_RX_FLEX_DESC_ADV_FF0_M                                      \
  MAKEMASK (0xFUL, VIRTCHNL2_RX_FLEX_DESC_ADV_FF0_S)
#define VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_PBUF_S 0
#define VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_PBUF_M                                 \
  MAKEMASK (0x3FFFUL, VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_PBUF_S)
#define VIRTCHNL2_RX_FLEX_DESC_ADV_GEN_S 14
#define VIRTCHNL2_RX_FLEX_DESC_ADV_GEN_M                                      \
  BIT_ULL (VIRTCHNL2_RX_FLEX_DESC_ADV_GEN_S)
#define VIRTCHNL2_RX_FLEX_DESC_ADV_BUFQ_ID_S 15
#define VIRTCHNL2_RX_FLEX_DESC_ADV_BUFQ_ID_M                                  \
  BIT_ULL (VIRTCHNL2_RX_FLEX_DESC_ADV_BUFQ_ID_S)
#define VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_HDR_S 0
#define VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_HDR_M                                  \
  MAKEMASK (0x3FFUL, VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_HDR_S)
#define VIRTCHNL2_RX_FLEX_DESC_ADV_RSC_S 10
#define VIRTCHNL2_RX_FLEX_DESC_ADV_RSC_M                                      \
  BIT_ULL (VIRTCHNL2_RX_FLEX_DESC_ADV_RSC_S)
#define VIRTCHNL2_RX_FLEX_DESC_ADV_SPH_S 11
#define VIRTCHNL2_RX_FLEX_DESC_ADV_SPH_M                                      \
  BIT_ULL (VIRTCHNL2_RX_FLEX_DESC_ADV_SPH_S)
#define VIRTCHNL2_RX_FLEX_DESC_ADV_MISS_S 12
#define VIRTCHNL2_RX_FLEX_DESC_ADV_MISS_M                                     \
  BIT_ULL (VIRTCHNL2_RX_FLEX_DESC_ADV_MISS_S)
#define VIRTCHNL2_RX_FLEX_DESC_ADV_FF1_S 13
#define VIRTCHNL2_RX_FLEX_DESC_ADV_FF1_M                                      \
  MAKEMASK (0x7UL, VIRTCHNL2_RX_FLEX_DESC_ADV_FF1_M)

#define foreach_virtchnl2_rx_flex_desc_adv_status0_qw1                        \
  _ (0, DD_S)                                                                 \
  _ (1, EOF_S)                                                                \
  _ (2, HBO_S)                                                                \
  _ (3, L3L4P_S)                                                              \
  _ (4, XSUM_IPE_S)                                                           \
  _ (5, XSUM_L4E_S)                                                           \
  _ (6, XSUM_EIPE_S)                                                          \
  _ (7, XSUM_EUDPE_S)

typedef enum
{
#define _(v, n) VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_##n = v,
  foreach_virtchnl2_rx_flex_desc_adv_status0_qw1
#undef _
} virtchnl2_rx_flex_desc_adv_status0_qw1_t;

#define foreach_virtchnl2_rx_flex_desc_adv_status0_qw0                        \
  _ (0, LPBK_S)                                                               \
  _ (1, IPV6EXADD_S)                                                          \
  _ (2, RXE_S)                                                                \
  _ (3, CRCP_S)                                                               \
  _ (4, RSS_VALID_S)                                                          \
  _ (5, L2TAG1P_S)                                                            \
  _ (6, XTRMD0_VALID_S)                                                       \
  _ (7, XTRMD1_VALID_S)                                                       \
  _ (8, LAST)

typedef enum
{
#define _(v, n) VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_##n = v,
  foreach_virtchnl2_rx_flex_desc_adv_status0_qw0
#undef _
} virtchnl2_rx_flex_desc_adv_status0_qw0_t;

#define foreach_virtchnl2_rx_flex_desc_adv_status1                            \
  _ (0, RSVD_S)                                                               \
  _ (2, ATRAEFAIL_S)                                                          \
  _ (3, L2TAG2P_S)                                                            \
  _ (4, XTRMD2_VALID_S)                                                       \
  _ (5, XTRMD3_VALID_S)                                                       \
  _ (6, XTRMD4_VALID_S)                                                       \
  _ (7, XTRMD5_VALID_S)                                                       \
  _ (8, LAST)

typedef enum
{
#define _(v, n) VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS1_##n = v,
  foreach_virtchnl2_rx_flex_desc_adv_status1
#undef _
} virtchnl2_rx_flex_desc_adv_status1_t;

#define VIRTCHNL2_RX_FLEX_DESC_PTYPE_S 0
#define VIRTCHNL2_RX_FLEX_DESC_PTYPE_M                                        \
  MAKEMASK (0x3FFUL, VIRTCHNL2_RX_FLEX_DESC_PTYPE_S) /* 10 bits */

#define VIRTCHNL2_RX_FLEX_DESC_PKT_LEN_S 0
#define VIRTCHNL2_RX_FLEX_DESC_PKT_LEN_M                                      \
  MAKEMASK (0x3FFFUL, VIRTCHNL2_RX_FLEX_DESC_PKT_LEN_S) /* 14 bits */

#define foreach_virtchnl2_rx_flex_desc_status0                                \
  _ (0, DD_S)                                                                 \
  _ (1, EOF_S)                                                                \
  _ (2, HBO_S)                                                                \
  _ (3, L3L4P_S)                                                              \
  _ (4, XSUM_IPE_S)                                                           \
  _ (5, XSUM_L4E_S)                                                           \
  _ (6, XSUM_EIPE_S)                                                          \
  _ (7, XSUM_EUDPE_S)                                                         \
  _ (8, LPBK_S)                                                               \
  _ (9, IPV6EXADD_S)                                                          \
  _ (10, RXE_S)                                                               \
  _ (11, CRCP_S)                                                              \
  _ (12, RSS_VALID_S)                                                         \
  _ (13, L2TAG1P_S)                                                           \
  _ (14, XTRMD0_VALID_S)                                                      \
  _ (15, XTRMD1_VALID_S)                                                      \
  _ (16, LAST)

typedef enum
{
#define _(v, n) VIRTCHNL2_RX_FLEX_DESC_STATUS0_##n = v,
  foreach_virtchnl2_rx_flex_desc_status0
#undef _
} virtchnl2_rx_flex_desc_status0_t;

#define foreach_virtchnl2_rx_flex_desc_status1                                \
  _ (0, CPM_S)                                                                \
  _ (4, NAT_S)                                                                \
  _ (5, CRYPTO_S)                                                             \
  _ (11, L2TAG2P_S)                                                           \
  _ (12, XTRMD2_VALID_S)                                                      \
  _ (13, XTRMD3_VALID_S)                                                      \
  _ (14, XTRMD4_VALID_S)                                                      \
  _ (15, XTRMD5_VALID_S)                                                      \
  _ (16, LAST)

typedef enum
{
#define _(v, n) VIRTCHNL2_RX_FLEX_DESC_STATUS1_##n = v,
  foreach_virtchnl2_rx_flex_desc_status1
#undef _
} virtchnl2_rx_flex_desc_status1_t;

#define VIRTCHNL2_RX_BASE_DESC_QW1_LEN_SPH_S 63
#define VIRTCHNL2_RX_BASE_DESC_QW1_LEN_SPH_M                                  \
  BIT_ULL (VIRTCHNL2_RX_BASE_DESC_QW1_LEN_SPH_S)
#define VIRTCHNL2_RX_BASE_DESC_QW1_LEN_HBUF_S 52
#define VIRTCHNL2_RX_BASE_DESC_QW1_LEN_HBUF_M                                 \
  MAKEMASK (0x7FFULL, VIRTCHNL2_RX_BASE_DESC_QW1_LEN_HBUF_S)
#define VIRTCHNL2_RX_BASE_DESC_QW1_LEN_PBUF_S 38
#define VIRTCHNL2_RX_BASE_DESC_QW1_LEN_PBUF_M                                 \
  MAKEMASK (0x3FFFULL, VIRTCHNL2_RX_BASE_DESC_QW1_LEN_PBUF_S)
#define VIRTCHNL2_RX_BASE_DESC_QW1_PTYPE_S 30
#define VIRTCHNL2_RX_BASE_DESC_QW1_PTYPE_M                                    \
  MAKEMASK (0xFFULL, VIRTCHNL2_RX_BASE_DESC_QW1_PTYPE_S)
#define VIRTCHNL2_RX_BASE_DESC_QW1_ERROR_S 19
#define VIRTCHNL2_RX_BASE_DESC_QW1_ERROR_M                                    \
  MAKEMASK (0xFFUL, VIRTCHNL2_RX_BASE_DESC_QW1_ERROR_S)
#define VIRTCHNL2_RX_BASE_DESC_QW1_STATUS_S 0
#define VIRTCHNL2_RX_BASE_DESC_QW1_STATUS_M                                   \
  MAKEMASK (0x7FFFFUL, VIRTCHNL2_RX_BASE_DESC_QW1_STATUS_S)

#define foreach_virtchnl2_rx_base_desc_status                                 \
  _ (0, DD_S)                                                                 \
  _ (1, EOF_S)                                                                \
  _ (2, L2TAG1P_S)                                                            \
  _ (3, L3L4P_S)                                                              \
  _ (4, CRCP_S)                                                               \
  _ (5, RSVD_S)                                                               \
  _ (8, EXT_UDP_0_S)                                                          \
  _ (9, UMBCAST_S)                                                            \
  _ (11, FLM_S)                                                               \
  _ (12, FLTSTAT_S)                                                           \
  _ (14, LPBK_S)                                                              \
  _ (15, IPV6EXADD_S)                                                         \
  _ (16, RSVD1_S)                                                             \
  _ (18, INT_UDP_0_S)                                                         \
  _ (19, LAST)

typedef enum
{
#define _(v, n) VIRTCHNL2_RX_BASE_DESC_STATUS_##n = v,
  foreach_virtchnl2_rx_base_desc_status
#undef _
} virtchnl2_rx_base_desc_status_t;

#define VIRTCHNL2_RX_BASE_DESC_EXT_STATUS_L2TAG2P_S 0

#define foreach_virtchnl2_rx_base_desc_error                                  \
  _ (0, RXE_S)                                                                \
  _ (1, ATRAEFAIL_S)                                                          \
  _ (2, HBO_S)                                                                \
  _ (3, L3L4E_S)                                                              \
  _ (3, IPE_S)                                                                \
  _ (4, L4E_S)                                                                \
  _ (5, EIPE_S)                                                               \
  _ (6, OVERSIZE_S)                                                           \
  _ (7, PPRS_S)

typedef enum
{
#define _(v, n) VIRTCHNL2_RX_BASE_DESC_ERROR_##n = v,
  foreach_virtchnl2_rx_base_desc_error
#undef _
} virtchnl2_rx_base_desc_error_t;

#define foreach_virtchnl2_rx_base_desc_fltstat                                \
  _ (0, NO_DATA)                                                              \
  _ (1, FD_ID)                                                                \
  _ (2, RSV)                                                                  \
  _ (3, RSS_HASH)

typedef enum
{
#define _(v, n) VIRTCHNL2_RX_BASE_DESC_FLTSTAT_##n = v,
  foreach_virtchnl2_rx_base_desc_fltstat
#undef _
} virtchnl2_rx_base_desc_fltstat_t;

/* Receive Descriptors */
/* splitq buf
 |                                       16|                   0|
 ----------------------------------------------------------------
 | RSV                                     | Buffer ID          |
 ----------------------------------------------------------------
 | Rx packet buffer adresss                                     |
 ----------------------------------------------------------------
 | Rx header buffer adresss                                     |
 ----------------------------------------------------------------
 | RSV                                                          |
 ----------------------------------------------------------------
 |                                                             0|
 */
typedef struct
{
  struct
  {
    u16 buf_id;
    u16 rsvd0;
    u32 rsvd1;
  } qword0;
  u64 pkt_addr;
  u64 hdr_addr;
  u64 rsvd2;
} virtchnl2_splitq_rx_buf_desc_t;

typedef struct
{
  u64 pkt_addr;
  u64 hdr_addr;
  u64 rsvd1;
  u64 rsvd2;
} virtchnl2_singleq_rx_buf_desc_t;

union virtchnl2_rx_buf_desc
{
  virtchnl2_singleq_rx_buf_desc_t read;
  virtchnl2_splitq_rx_buf_desc_t split_rd;
};

typedef struct
{
  struct
  {
    struct
    {
      u16 mirroring_status;
      u16 l2tag1;
    } lo_dword;
    union
    {
      u32 rss;
      u32 fd_id;
    } hi_dword;
  } qword0;
  struct
  {
    u64 status_error_ptype_len;
  } qword1;
  struct
  {
    u16 ext_status;
    u16 rsvd;
    u16 l2tag2_1;
    u16 l2tag2_2;
  } qword2;
  struct
  {
    u32 reserved;
    u32 fd_id;
  } qword3;
} virtchnl2_singleq_base_rx_desc_t;

typedef struct
{
  /* Qword 0 */
  u8 rxdid;
  u8 mir_id_umb_cast;
  u16 ptype_flex_flags0;
  u16 pkt_len;
  u16 hdr_len_sph_flex_flags1;

  /* Qword 1 */
  u16 status_error0;
  u16 l2tag1;
  u16 flex_meta0;
  u16 flex_meta1;

  /* Qword 2 */
  u16 status_error1;
  u8 flex_flags2;
  u8 time_stamp_low;
  u16 l2tag2_1st;
  u16 l2tag2_2nd;

  /* Qword 3 */
  u16 flex_meta2;
  u16 flex_meta3;
  union
  {
    struct
    {
      u16 flex_meta4;
      u16 flex_meta5;
    } flex;
    u32 ts_high;
  } flex_ts;
} virtchnl2_rx_flex_desc_t;

typedef struct
{
  /* Qword 0 */
  u8 rxdid;
  u8 mir_id_umb_cast;
  u16 ptype_flex_flags0;
  u16 pkt_len;
  u16 hdr_len_sph_flex_flags1;

  /* Qword 1 */
  u16 status_error0;
  u16 l2tag1;
  u32 rss_hash;

  /* Qword 2 */
  u16 status_error1;
  u8 flexi_flags2;
  u8 ts_low;
  u16 l2tag2_1st;
  u16 l2tag2_2nd;

  /* Qword 3 */
  u32 flow_id;
  union
  {
    struct
    {
      u16 rsvd;
      u16 flow_id_ipv6;
    } flex;
    u32 ts_high;
  } flex_ts;
} virtchnl2_rx_flex_desc_nic_t;

typedef struct
{
  /* Qword 0 */
  u8 rxdid;
  u8 mir_id_umb_cast;
  u16 ptype_flex_flags0;
  u16 pkt_len;
  u16 hdr_len_sph_flex_flags1;

  /* Qword 1 */
  u16 status_error0;
  u16 l2tag1;
  u16 src_vsi;
  u16 flex_md1_rsvd;

  /* Qword 2 */
  u16 status_error1;
  u8 flex_flags2;
  u8 ts_low;
  u16 l2tag2_1st;
  u16 l2tag2_2nd;

  /* Qword 3 */
  u32 rsvd;
  u32 ts_high;
} virtchnl2_rx_flex_desc_sw_t;

typedef struct
{
  /* Qword 0 */
  u8 rxdid;
  u8 mir_id_umb_cast;
  u16 ptype_flex_flags0;
  u16 pkt_len;
  u16 hdr_len_sph_flex_flags1;

  /* Qword 1 */
  u16 status_error0;
  u16 l2tag1;
  u32 rss_hash;

  /* Qword 2 */
  u16 status_error1;
  u8 flexi_flags2;
  u8 ts_low;
  u16 l2tag2_1st;
  u16 l2tag2_2nd;

  /* Qword 3 */
  u16 flow_id;
  u16 src_vsi;
  union
  {
    struct
    {
      u16 rsvd;
      u16 flow_id_ipv6;
    } flex;
    u32 ts_high;
  } flex_ts;
} virtchnl2_rx_flex_desc_nic_2_t;

typedef struct
{
  /* Qword 0 */
  u8 rxdid_ucast;
  u8 status_err0_qw0;
  u16 ptype_err_fflags0;
  u16 pktlen_gen_bufq_id;
  u16 hdrlen_flags;

  /* Qword 1 */
  u8 status_err0_qw1;
  u8 status_err1;
  u8 fflags1;
  u8 ts_low;
  u16 fmd0;
  u16 fmd1;
  /* Qword 2 */
  u16 fmd2;
  u8 fflags2;
  u8 hash3;
  u16 fmd3;
  u16 fmd4;
  /* Qword 3 */
  u16 fmd5;
  u16 fmd6;
  u16 fmd7_0;
  u16 fmd7_1;
} virtchnl2_rx_flex_desc_adv_t;

typedef struct
{
  /* Qword 0 */
  u8 rxdid_ucast;
  u8 status_err0_qw0;
  u16 ptype_err_fflags0;
  u16 pktlen_gen_bufq_id;
  u16 hdrlen_flags;

  /* Qword 1 */
  u8 status_err0_qw1;
  u8 status_err1;
  u8 fflags1;
  u8 ts_low;
  u16 buf_id;
  union
  {
    u16 raw_cs;
    u16 l2tag1;
    u16 rscseglen;
  } misc;
  /* Qword 2 */
  u16 hash1;
  union
  {
    u8 fflags2;
    u8 mirrorid;
    u8 hash2;
  } ff2_mirrid_hash2;
  u8 hash3;
  u16 l2tag2;
  u16 fmd4;
  /* Qword 3 */
  u16 l2tag1;
  u16 fmd6;
  u32 ts_high;
} virtchnl2_rx_flex_desc_adv_nic_3_t;

typedef union
{
  virtchnl2_singleq_rx_buf_desc_t read;
  virtchnl2_singleq_base_rx_desc_t base_wb;
  virtchnl2_rx_flex_desc_t flex_wb;
  virtchnl2_rx_flex_desc_nic_t flex_nic_wb;
  virtchnl2_rx_flex_desc_sw_t flex_sw_wb;
  virtchnl2_rx_flex_desc_nic_2_t flex_nic_2_wb;
  virtchnl2_rx_flex_desc_adv_t flex_adv_wb;
  virtchnl2_rx_flex_desc_adv_nic_3_t flex_adv_nic_3_wb;
  u64 qword[4];
} virtchnl2_rx_desc_t;

#endif /* _IDPF_VIRTCHNL_LAN_DESC_H_ */
