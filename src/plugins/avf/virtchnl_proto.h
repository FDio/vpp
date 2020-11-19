/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Intel and/or its affiliates.
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

#ifndef _VIRTCHNL_PROTO_H_
#define _VIRTCHNL_PROTO_H_

#define BIT(a) (1UL << (a))
#define BIT_ULL(a) (1ULL << (a))

enum virthnl_adv_ops
{
  VIRTCHNL_ADV_OP_ADD_FDIR_FILTER = 0,
  VIRTCHNL_ADV_OP_DEL_FDIR_FILTER,
  VIRTCHNL_ADV_OP_QUERY_FDIR_FILTER,
  VIRTCHNL_ADV_OP_MAX
};

/* IAVF ethernet frame types */
#define IAVF_ETHER_TYPE_IPV4 0x0800 /**< IPv4 Protocol. */
#define IAVF_ETHER_TYPE_IPV6 0x86DD /**< IPv6 Protocol. */

#define VIRTCHNL_MAX_NUM_PROTO_HDRS 32
#define PROTO_HDR_SHIFT 5
#define PROTO_HDR_FIELD_START(proto_hdr_type) \
  (proto_hdr_type << PROTO_HDR_SHIFT)
#define PROTO_HDR_FIELD_MASK ((1UL << PROTO_HDR_SHIFT) - 1)

/* VF use these macros to configure each protocol header.
 * Specify which protocol headers and protocol header fields base on
 * virtchnl_proto_hdr_type and virtchnl_proto_hdr_field.
 * @param hdr: a struct of virtchnl_proto_hdr
 * @param hdr_type: ETH/IPV4/TCP, etc
 * @param field: SRC/DST/TEID/SPI, etc
 */
#define VIRTCHNL_ADD_PROTO_HDR_FIELD(hdr, field) \
  ((hdr)->field_selector |= BIT ((field)&PROTO_HDR_FIELD_MASK))
#define VIRTCHNL_DEL_PROTO_HDR_FIELD(hdr, field) \
  ((hdr)->field_selector &= ~BIT ((field)&PROTO_HDR_FIELD_MASK))
#define VIRTCHNL_TEST_PROTO_HDR_FIELD(hdr, val) \
  ((hdr)->field_selector & BIT ((val)&PROTO_HDR_FIELD_MASK))
#define VIRTCHNL_GET_PROTO_HDR_FIELD(hdr) ((hdr)->field_selector)

#define VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, hdr_type, field) \
  (VIRTCHNL_ADD_PROTO_HDR_FIELD (hdr, VIRTCHNL_PROTO_HDR_##hdr_type##_##field))
#define VIRTCHNL_DEL_PROTO_HDR_FIELD_BIT(hdr, hdr_type, field) \
  (VIRTCHNL_DEL_PROTO_HDR_FIELD (hdr, VIRTCHNL_PROTO_HDR_##hdr_type##_##field))

#define VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, hdr_type) \
  ((hdr)->type = VIRTCHNL_PROTO_HDR_##hdr_type)
#define VIRTCHNL_GET_PROTO_HDR_TYPE(hdr) (((hdr)->type) >> PROTO_HDR_SHIFT)
#define VIRTCHNL_TEST_PROTO_HDR_TYPE(hdr, val) \
  ((hdr)->type == ((val) >> PROTO_HDR_SHIFT))
#define VIRTCHNL_TEST_PROTO_HDR(hdr, val)     \
  (VIRTCHNL_TEST_PROTO_HDR_TYPE (hdr, val) && \
   VIRTCHNL_TEST_PROTO_HDR_FIELD (hdr, val))

/* protocol */

#define IAVF_PROT_MAC_INNER (1ULL << 1)
#define IAVF_PROT_MAC_OUTER (1ULL << 2)
#define IAVF_PROT_VLAN_INNER (1ULL << 3)
#define IAVF_PROT_VLAN_OUTER (1ULL << 4)
#define IAVF_PROT_IPV4_INNER (1ULL << 5)
#define IAVF_PROT_IPV4_OUTER (1ULL << 6)
#define IAVF_PROT_IPV6_INNER (1ULL << 7)
#define IAVF_PROT_IPV6_OUTER (1ULL << 8)
#define IAVF_PROT_TCP_INNER (1ULL << 9)
#define IAVF_PROT_TCP_OUTER (1ULL << 10)
#define IAVF_PROT_UDP_INNER (1ULL << 11)
#define IAVF_PROT_UDP_OUTER (1ULL << 12)
#define IAVF_PROT_SCTP_INNER (1ULL << 13)
#define IAVF_PROT_SCTP_OUTER (1ULL << 14)
#define IAVF_PROT_ICMP4_INNER (1ULL << 15)
#define IAVF_PROT_ICMP4_OUTER (1ULL << 16)
#define IAVF_PROT_ICMP6_INNER (1ULL << 17)
#define IAVF_PROT_ICMP6_OUTER (1ULL << 18)
#define IAVF_PROT_VXLAN (1ULL << 19)
#define IAVF_PROT_NVGRE (1ULL << 20)
#define IAVF_PROT_GTPU (1ULL << 21)
#define IAVF_PROT_ESP (1ULL << 22)
#define IAVF_PROT_AH (1ULL << 23)
#define IAVF_PROT_L2TPV3OIP (1ULL << 24)
#define IAVF_PROT_PFCP (1ULL << 25)

/* field */

#define IAVF_SMAC (1ULL << 63)
#define IAVF_DMAC (1ULL << 62)
#define IAVF_ETHERTYPE (1ULL << 61)
#define IAVF_IP_SRC (1ULL << 60)
#define IAVF_IP_DST (1ULL << 59)
#define IAVF_IP_PROTO (1ULL << 58)
#define IAVF_IP_TTL (1ULL << 57)
#define IAVF_IP_TOS (1ULL << 56)
#define IAVF_SPORT (1ULL << 55)
#define IAVF_DPORT (1ULL << 54)
#define IAVF_ICMP_TYPE (1ULL << 53)
#define IAVF_ICMP_CODE (1ULL << 52)
#define IAVF_VXLAN_VNI (1ULL << 51)
#define IAVF_NVGRE_TNI (1ULL << 50)
#define IAVF_GTPU_TEID (1ULL << 49)
#define IAVF_GTPU_QFI (1ULL << 48)
#define IAVF_ESP_SPI (1ULL << 47)
#define IAVF_AH_SPI (1ULL << 46)
#define IAVF_L2TPV3OIP_SESSION_ID (1ULL << 45)
#define IAVF_PFCP_S_FIELD (1ULL << 44)
#define IAVF_PFCP_SEID (1ULL << 43)

/* input set */

#define IAVF_INSET_NONE 0ULL

/* non-tunnel */

#define IAVF_INSET_SMAC (IAVF_PROT_MAC_OUTER | IAVF_SMAC)
#define IAVF_INSET_DMAC (IAVF_PROT_MAC_OUTER | IAVF_DMAC)
#define IAVF_INSET_VLAN_INNER (IAVF_PROT_VLAN_INNER)
#define IAVF_INSET_VLAN_OUTER (IAVF_PROT_VLAN_OUTER)
#define IAVF_INSET_ETHERTYPE (IAVF_ETHERTYPE)

#define IAVF_INSET_IPV4_SRC (IAVF_PROT_IPV4_OUTER | IAVF_IP_SRC)
#define IAVF_INSET_IPV4_DST (IAVF_PROT_IPV4_OUTER | IAVF_IP_DST)
#define IAVF_INSET_IPV4_TOS (IAVF_PROT_IPV4_OUTER | IAVF_IP_TOS)
#define IAVF_INSET_IPV4_PROTO (IAVF_PROT_IPV4_OUTER | IAVF_IP_PROTO)
#define IAVF_INSET_IPV4_TTL (IAVF_PROT_IPV4_OUTER | IAVF_IP_TTL)
#define IAVF_INSET_IPV6_SRC (IAVF_PROT_IPV6_OUTER | IAVF_IP_SRC)
#define IAVF_INSET_IPV6_DST (IAVF_PROT_IPV6_OUTER | IAVF_IP_DST)
#define IAVF_INSET_IPV6_NEXT_HDR (IAVF_PROT_IPV6_OUTER | IAVF_IP_PROTO)
#define IAVF_INSET_IPV6_HOP_LIMIT (IAVF_PROT_IPV6_OUTER | IAVF_IP_TTL)
#define IAVF_INSET_IPV6_TC (IAVF_PROT_IPV6_OUTER | IAVF_IP_TOS)

#define IAVF_INSET_TCP_SRC_PORT (IAVF_PROT_TCP_OUTER | IAVF_SPORT)
#define IAVF_INSET_TCP_DST_PORT (IAVF_PROT_TCP_OUTER | IAVF_DPORT)
#define IAVF_INSET_UDP_SRC_PORT (IAVF_PROT_UDP_OUTER | IAVF_SPORT)
#define IAVF_INSET_UDP_DST_PORT (IAVF_PROT_UDP_OUTER | IAVF_DPORT)
#define IAVF_INSET_SCTP_SRC_PORT (IAVF_PROT_SCTP_OUTER | IAVF_SPORT)
#define IAVF_INSET_SCTP_DST_PORT (IAVF_PROT_SCTP_OUTER | IAVF_DPORT)
#define IAVF_INSET_ICMP4_SRC_PORT (IAVF_PROT_ICMP4_OUTER | IAVF_SPORT)
#define IAVF_INSET_ICMP4_DST_PORT (IAVF_PROT_ICMP4_OUTER | IAVF_DPORT)
#define IAVF_INSET_ICMP6_SRC_PORT (IAVF_PROT_ICMP6_OUTER | IAVF_SPORT)
#define IAVF_INSET_ICMP6_DST_PORT (IAVF_PROT_ICMP6_OUTER | IAVF_DPORT)
#define IAVF_INSET_ICMP4_TYPE (IAVF_PROT_ICMP4_OUTER | IAVF_ICMP_TYPE)
#define IAVF_INSET_ICMP4_CODE (IAVF_PROT_ICMP4_OUTER | IAVF_ICMP_CODE)
#define IAVF_INSET_ICMP6_TYPE (IAVF_PROT_ICMP6_OUTER | IAVF_ICMP_TYPE)
#define IAVF_INSET_ICMP6_CODE (IAVF_PROT_ICMP6_OUTER | IAVF_ICMP_CODE)
#define IAVF_INSET_GTPU_TEID (IAVF_PROT_GTPU | IAVF_GTPU_TEID)
#define IAVF_INSET_GTPU_QFI (IAVF_PROT_GTPU | IAVF_GTPU_QFI)
#define IAVF_INSET_ESP_SPI (IAVF_PROT_ESP | IAVF_ESP_SPI)
#define IAVF_INSET_AH_SPI (IAVF_PROT_AH | IAVF_AH_SPI)
#define IAVF_INSET_L2TPV3OIP_SESSION_ID \
  (IAVF_PROT_L2TPV3OIP | IAVF_L2TPV3OIP_SESSION_ID)
#define IAVF_INSET_PFCP_S_FIELD (IAVF_PROT_PFCP | IAVF_PFCP_S_FIELD)
#define IAVF_INSET_PFCP_SEID \
  (IAVF_PROT_PFCP | IAVF_PFCP_S_FIELD | IAVF_PFCP_SEID)

/* Protocol header type within a packet segment. A segment consists of one or
 * more protocol headers that make up a logical group of protocol headers. Each
 * logical group of protocol headers encapsulates or is encapsulated using/by
 * tunneling or encapsulation protocols for network virtualization.
 */
enum virtchnl_proto_hdr_type
{
  VIRTCHNL_PROTO_HDR_NONE,
  VIRTCHNL_PROTO_HDR_ETH,
  VIRTCHNL_PROTO_HDR_S_VLAN,
  VIRTCHNL_PROTO_HDR_C_VLAN,
  VIRTCHNL_PROTO_HDR_IPV4,
  VIRTCHNL_PROTO_HDR_IPV6,
  VIRTCHNL_PROTO_HDR_TCP,
  VIRTCHNL_PROTO_HDR_UDP,
  VIRTCHNL_PROTO_HDR_SCTP,
  VIRTCHNL_PROTO_HDR_GTPU_IP,
  VIRTCHNL_PROTO_HDR_GTPU_EH,
  VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_DWN,
  VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_UP,
  VIRTCHNL_PROTO_HDR_PPPOE,
  VIRTCHNL_PROTO_HDR_L2TPV3,
  VIRTCHNL_PROTO_HDR_ESP,
  VIRTCHNL_PROTO_HDR_AH,
  VIRTCHNL_PROTO_HDR_PFCP,
};

/* Protocol header field within a protocol header. */
enum virtchnl_proto_hdr_field
{
  /* ETHER */
  VIRTCHNL_PROTO_HDR_ETH_SRC = PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_ETH),
  VIRTCHNL_PROTO_HDR_ETH_DST,
  VIRTCHNL_PROTO_HDR_ETH_ETHERTYPE,
  /* S-VLAN */
  VIRTCHNL_PROTO_HDR_S_VLAN_ID =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_S_VLAN),
  /* C-VLAN */
  VIRTCHNL_PROTO_HDR_C_VLAN_ID =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_C_VLAN),
  /* IPV4 */
  VIRTCHNL_PROTO_HDR_IPV4_SRC =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_IPV4),
  VIRTCHNL_PROTO_HDR_IPV4_DST,
  VIRTCHNL_PROTO_HDR_IPV4_DSCP,
  VIRTCHNL_PROTO_HDR_IPV4_TTL,
  VIRTCHNL_PROTO_HDR_IPV4_PROT,
  /* IPV6 */
  VIRTCHNL_PROTO_HDR_IPV6_SRC =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_IPV6),
  VIRTCHNL_PROTO_HDR_IPV6_DST,
  VIRTCHNL_PROTO_HDR_IPV6_TC,
  VIRTCHNL_PROTO_HDR_IPV6_HOP_LIMIT,
  VIRTCHNL_PROTO_HDR_IPV6_PROT,
  /* TCP */
  VIRTCHNL_PROTO_HDR_TCP_SRC_PORT =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_TCP),
  VIRTCHNL_PROTO_HDR_TCP_DST_PORT,
  /* UDP */
  VIRTCHNL_PROTO_HDR_UDP_SRC_PORT =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_UDP),
  VIRTCHNL_PROTO_HDR_UDP_DST_PORT,
  /* SCTP */
  VIRTCHNL_PROTO_HDR_SCTP_SRC_PORT =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_SCTP),
  VIRTCHNL_PROTO_HDR_SCTP_DST_PORT,
  /* GTPU_IP */
  VIRTCHNL_PROTO_HDR_GTPU_IP_TEID =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_GTPU_IP),
  /* GTPU_EH */
  VIRTCHNL_PROTO_HDR_GTPU_EH_PDU =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_GTPU_EH),
  VIRTCHNL_PROTO_HDR_GTPU_EH_QFI,
  /* PPPOE */
  VIRTCHNL_PROTO_HDR_PPPOE_SESS_ID =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_PPPOE),
  /* L2TPV3 */
  VIRTCHNL_PROTO_HDR_L2TPV3_SESS_ID =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_L2TPV3),
  /* ESP */
  VIRTCHNL_PROTO_HDR_ESP_SPI = PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_ESP),
  /* AH */
  VIRTCHNL_PROTO_HDR_AH_SPI = PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_AH),
  /* PFCP */
  VIRTCHNL_PROTO_HDR_PFCP_S_FIELD =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_PFCP),
  VIRTCHNL_PROTO_HDR_PFCP_SEID,
};

/* virtual channel op handler */
typedef int (*iavf_fdir_vc_op_t) (void *vc_hdl, enum virthnl_adv_ops vc_op,
				  void *in, u32 in_len, void *out,
				  u32 out_len);

/* virtual channel context object */
struct iavf_fdir_vc_ctx
{
  void *vc_hdl;			/* virtual channel handler */
  iavf_fdir_vc_op_t vc_op;
};

#endif /* _VIRTCHNL_PROTO_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
