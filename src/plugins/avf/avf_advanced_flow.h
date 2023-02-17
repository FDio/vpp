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

#ifndef _AVF_ADVANCED_FLOW_H_
#define _AVF_ADVANCED_FLOW_H_

#define AVF_SUCCESS (0)
#define AVF_FAILURE (-1)

#define BIT(a)	   (1UL << (a))
#define BIT_ULL(a) (1ULL << (a))

/* These macros are used to generate compilation errors if a structure/union
 * is not exactly the correct length. It gives a divide by zero error if the
 * structure/union is not of the correct size, otherwise it creates an enum
 * that is never used.
 */
#define VIRTCHNL_CHECK_STRUCT_LEN(n, X)                                       \
  enum virtchnl_static_assert_enum_##X                                        \
  {                                                                           \
    virtchnl_static_assert_##X = (n) / ((sizeof (struct X) == (n)) ? 1 : 0)   \
  }
#define VIRTCHNL_CHECK_UNION_LEN(n, X)                                        \
  enum virtchnl_static_asset_enum_##X                                         \
  {                                                                           \
    virtchnl_static_assert_##X = (n) / ((sizeof (union X) == (n)) ? 1 : 0)    \
  }

/* AVF ethernet frame types */
#define AVF_ETHER_TYPE_IPV4 0x0800 /**< IPv4 Protocol. */
#define AVF_ETHER_TYPE_IPV6 0x86DD /**< IPv6 Protocol. */

#define VIRTCHNL_MAX_NUM_PROTO_HDRS 32
#define VIRTCHNL_MAX_SIZE_GEN_PACKET 1024
#define PROTO_HDR_SHIFT		    5
#define PROTO_HDR_FIELD_START(proto_hdr_type)                                 \
  (proto_hdr_type << PROTO_HDR_SHIFT)
#define PROTO_HDR_FIELD_MASK ((1UL << PROTO_HDR_SHIFT) - 1)

/* VF use these macros to configure each protocol header.
 * Specify which protocol headers and protocol header fields base on
 * virtchnl_proto_hdr_type and virtchnl_proto_hdr_field.
 * @param hdr: a struct of virtchnl_proto_hdr
 * @param hdr_type: ETH/IPV4/TCP, etc
 * @param field: SRC/DST/TEID/SPI, etc
 */
#define VIRTCHNL_ADD_PROTO_HDR_FIELD(hdr, field)                              \
  ((hdr)->field_selector |= BIT ((field) &PROTO_HDR_FIELD_MASK))
#define VIRTCHNL_DEL_PROTO_HDR_FIELD(hdr, field)                              \
  ((hdr)->field_selector &= ~BIT ((field) &PROTO_HDR_FIELD_MASK))
#define VIRTCHNL_TEST_PROTO_HDR_FIELD(hdr, val)                               \
  ((hdr)->field_selector & BIT ((val) &PROTO_HDR_FIELD_MASK))
#define VIRTCHNL_GET_PROTO_HDR_FIELD(hdr) ((hdr)->field_selector)

#define VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, hdr_type, field)                \
  (VIRTCHNL_ADD_PROTO_HDR_FIELD (hdr, VIRTCHNL_PROTO_HDR_##hdr_type##_##field))
#define VIRTCHNL_DEL_PROTO_HDR_FIELD_BIT(hdr, hdr_type, field)                \
  (VIRTCHNL_DEL_PROTO_HDR_FIELD (hdr, VIRTCHNL_PROTO_HDR_##hdr_type##_##field))

#define VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, hdr_type)                            \
  ((hdr)->type = VIRTCHNL_PROTO_HDR_##hdr_type)
#define VIRTCHNL_GET_PROTO_HDR_TYPE(hdr) (((hdr)->type) >> PROTO_HDR_SHIFT)
#define VIRTCHNL_TEST_PROTO_HDR_TYPE(hdr, val)                                \
  ((hdr)->type == ((val) >> PROTO_HDR_SHIFT))
#define VIRTCHNL_TEST_PROTO_HDR(hdr, val)                                     \
  (VIRTCHNL_TEST_PROTO_HDR_TYPE (hdr, val) &&                                 \
   VIRTCHNL_TEST_PROTO_HDR_FIELD (hdr, val))

/* protocol */

#define AVF_PROT_MAC_INNER   (1ULL << 1)
#define AVF_PROT_MAC_OUTER   (1ULL << 2)
#define AVF_PROT_VLAN_INNER  (1ULL << 3)
#define AVF_PROT_VLAN_OUTER  (1ULL << 4)
#define AVF_PROT_IPV4_INNER  (1ULL << 5)
#define AVF_PROT_IPV4_OUTER  (1ULL << 6)
#define AVF_PROT_IPV6_INNER  (1ULL << 7)
#define AVF_PROT_IPV6_OUTER  (1ULL << 8)
#define AVF_PROT_TCP_INNER   (1ULL << 9)
#define AVF_PROT_TCP_OUTER   (1ULL << 10)
#define AVF_PROT_UDP_INNER   (1ULL << 11)
#define AVF_PROT_UDP_OUTER   (1ULL << 12)
#define AVF_PROT_SCTP_INNER  (1ULL << 13)
#define AVF_PROT_SCTP_OUTER  (1ULL << 14)
#define AVF_PROT_ICMP4_INNER (1ULL << 15)
#define AVF_PROT_ICMP4_OUTER (1ULL << 16)
#define AVF_PROT_ICMP6_INNER (1ULL << 17)
#define AVF_PROT_ICMP6_OUTER (1ULL << 18)
#define AVF_PROT_VXLAN	     (1ULL << 19)
#define AVF_PROT_NVGRE	     (1ULL << 20)
#define AVF_PROT_GTPU	     (1ULL << 21)
#define AVF_PROT_ESP	     (1ULL << 22)
#define AVF_PROT_AH	     (1ULL << 23)
#define AVF_PROT_L2TPV3OIP   (1ULL << 24)
#define AVF_PROT_PFCP	     (1ULL << 25)

/* field */

#define AVF_SMAC		 (1ULL << 63)
#define AVF_DMAC		 (1ULL << 62)
#define AVF_ETHERTYPE		 (1ULL << 61)
#define AVF_IP_SRC		 (1ULL << 60)
#define AVF_IP_DST		 (1ULL << 59)
#define AVF_IP_PROTO		 (1ULL << 58)
#define AVF_IP_TTL		 (1ULL << 57)
#define AVF_IP_TOS		 (1ULL << 56)
#define AVF_SPORT		 (1ULL << 55)
#define AVF_DPORT		 (1ULL << 54)
#define AVF_ICMP_TYPE		 (1ULL << 53)
#define AVF_ICMP_CODE		 (1ULL << 52)
#define AVF_VXLAN_VNI		 (1ULL << 51)
#define AVF_NVGRE_TNI		 (1ULL << 50)
#define AVF_GTPU_TEID		 (1ULL << 49)
#define AVF_GTPU_QFI		 (1ULL << 48)
#define AVF_ESP_SPI		 (1ULL << 47)
#define AVF_AH_SPI		 (1ULL << 46)
#define AVF_L2TPV3OIP_SESSION_ID (1ULL << 45)
#define AVF_PFCP_S_FIELD	 (1ULL << 44)
#define AVF_PFCP_SEID		 (1ULL << 43)

/* input set */

#define AVF_INSET_NONE 0ULL

/* non-tunnel */

#define AVF_INSET_SMAC	     (AVF_PROT_MAC_OUTER | AVF_SMAC)
#define AVF_INSET_DMAC	     (AVF_PROT_MAC_OUTER | AVF_DMAC)
#define AVF_INSET_VLAN_INNER (AVF_PROT_VLAN_INNER)
#define AVF_INSET_VLAN_OUTER (AVF_PROT_VLAN_OUTER)
#define AVF_INSET_ETHERTYPE  (AVF_ETHERTYPE)

#define AVF_INSET_IPV4_SRC	 (AVF_PROT_IPV4_OUTER | AVF_IP_SRC)
#define AVF_INSET_IPV4_DST	 (AVF_PROT_IPV4_OUTER | AVF_IP_DST)
#define AVF_INSET_IPV4_TOS	 (AVF_PROT_IPV4_OUTER | AVF_IP_TOS)
#define AVF_INSET_IPV4_PROTO	 (AVF_PROT_IPV4_OUTER | AVF_IP_PROTO)
#define AVF_INSET_IPV4_TTL	 (AVF_PROT_IPV4_OUTER | AVF_IP_TTL)
#define AVF_INSET_IPV6_SRC	 (AVF_PROT_IPV6_OUTER | AVF_IP_SRC)
#define AVF_INSET_IPV6_DST	 (AVF_PROT_IPV6_OUTER | AVF_IP_DST)
#define AVF_INSET_IPV6_NEXT_HDR	 (AVF_PROT_IPV6_OUTER | AVF_IP_PROTO)
#define AVF_INSET_IPV6_HOP_LIMIT (AVF_PROT_IPV6_OUTER | AVF_IP_TTL)
#define AVF_INSET_IPV6_TC	 (AVF_PROT_IPV6_OUTER | AVF_IP_TOS)

#define AVF_INSET_TCP_SRC_PORT	 (AVF_PROT_TCP_OUTER | AVF_SPORT)
#define AVF_INSET_TCP_DST_PORT	 (AVF_PROT_TCP_OUTER | AVF_DPORT)
#define AVF_INSET_UDP_SRC_PORT	 (AVF_PROT_UDP_OUTER | AVF_SPORT)
#define AVF_INSET_UDP_DST_PORT	 (AVF_PROT_UDP_OUTER | AVF_DPORT)
#define AVF_INSET_SCTP_SRC_PORT	 (AVF_PROT_SCTP_OUTER | AVF_SPORT)
#define AVF_INSET_SCTP_DST_PORT	 (AVF_PROT_SCTP_OUTER | AVF_DPORT)
#define AVF_INSET_ICMP4_SRC_PORT (AVF_PROT_ICMP4_OUTER | AVF_SPORT)
#define AVF_INSET_ICMP4_DST_PORT (AVF_PROT_ICMP4_OUTER | AVF_DPORT)
#define AVF_INSET_ICMP6_SRC_PORT (AVF_PROT_ICMP6_OUTER | AVF_SPORT)
#define AVF_INSET_ICMP6_DST_PORT (AVF_PROT_ICMP6_OUTER | AVF_DPORT)
#define AVF_INSET_ICMP4_TYPE	 (AVF_PROT_ICMP4_OUTER | AVF_ICMP_TYPE)
#define AVF_INSET_ICMP4_CODE	 (AVF_PROT_ICMP4_OUTER | AVF_ICMP_CODE)
#define AVF_INSET_ICMP6_TYPE	 (AVF_PROT_ICMP6_OUTER | AVF_ICMP_TYPE)
#define AVF_INSET_ICMP6_CODE	 (AVF_PROT_ICMP6_OUTER | AVF_ICMP_CODE)
#define AVF_INSET_GTPU_TEID	 (AVF_PROT_GTPU | AVF_GTPU_TEID)
#define AVF_INSET_GTPU_QFI	 (AVF_PROT_GTPU | AVF_GTPU_QFI)
#define AVF_INSET_ESP_SPI	 (AVF_PROT_ESP | AVF_ESP_SPI)
#define AVF_INSET_AH_SPI	 (AVF_PROT_AH | AVF_AH_SPI)
#define AVF_INSET_L2TPV3OIP_SESSION_ID                                        \
  (AVF_PROT_L2TPV3OIP | AVF_L2TPV3OIP_SESSION_ID)
#define AVF_INSET_PFCP_S_FIELD (AVF_PROT_PFCP | AVF_PFCP_S_FIELD)
#define AVF_INSET_PFCP_SEID    (AVF_PROT_PFCP | AVF_PFCP_S_FIELD | AVF_PFCP_SEID)

#define AVF_ETH_RSS_IPV4	       BIT_ULL (2)
#define AVF_ETH_RSS_FRAG_IPV4	       BIT_ULL (3)
#define AVF_ETH_RSS_NONFRAG_IPV4_TCP   BIT_ULL (4)
#define AVF_ETH_RSS_NONFRAG_IPV4_UDP   BIT_ULL (5)
#define AVF_ETH_RSS_NONFRAG_IPV4_SCTP  BIT_ULL (6)
#define AVF_ETH_RSS_NONFRAG_IPV4_OTHER BIT_ULL (7)
#define AVF_ETH_RSS_IPV6	       BIT_ULL (8)
#define AVF_ETH_RSS_FRAG_IPV6	       BIT_ULL (9)
#define AVF_ETH_RSS_NONFRAG_IPV6_TCP   BIT_ULL (10)
#define AVF_ETH_RSS_NONFRAG_IPV6_UDP   BIT_ULL (11)
#define AVF_ETH_RSS_NONFRAG_IPV6_SCTP  BIT_ULL (12)
#define AVF_ETH_RSS_NONFRAG_IPV6_OTHER BIT_ULL (13)
#define AVF_ETH_RSS_L2_PAYLOAD	       BIT_ULL (14)
#define AVF_ETH_RSS_IPV6_EX	       BIT_ULL (15)
#define AVF_ETH_RSS_IPV6_TCP_EX	       BIT_ULL (16)
#define AVF_ETH_RSS_IPV6_UDP_EX	       BIT_ULL (17)
#define AVF_ETH_RSS_PORT	       BIT_ULL (18)
#define AVF_ETH_RSS_VXLAN	       BIT_ULL (19)
#define AVF_ETH_RSS_GENEVE	       BIT_ULL (20)
#define AVF_ETH_RSS_NVGRE	       BIT_ULL (21)
#define AVF_ETH_RSS_GTPU	       BIT_ULL (23)
#define AVF_ETH_RSS_ETH		       BIT_ULL (24)
#define AVF_ETH_RSS_S_VLAN	       BIT_ULL (25)
#define AVF_ETH_RSS_C_VLAN	       BIT_ULL (26)
#define AVF_ETH_RSS_ESP		       BIT_ULL (27)
#define AVF_ETH_RSS_AH		       BIT_ULL (28)
#define AVF_ETH_RSS_L2TPV3	       BIT_ULL (29)
#define AVF_ETH_RSS_PFCP	       BIT_ULL (30)
#define AVF_ETH_RSS_PPPOE	       BIT_ULL (31)
#define AVF_ETH_RSS_ECPRI	       BIT_ULL (32)
#define AVF_ETH_RSS_MPLS	       BIT_ULL (33)
#define AVF_ETH_RSS_IPV4_CHKSUM	       BIT_ULL (34)
#define AVF_ETH_RSS_L4_CHKSUM	       BIT_ULL (35)
#define AVF_ETH_RSS_L2TPV2	       BIT_ULL (36)
#define AVF_ETH_RSS_L3_SRC_ONLY	       BIT_ULL (63)
#define AVF_ETH_RSS_L3_DST_ONLY	       BIT_ULL (62)
#define AVF_ETH_RSS_L4_SRC_ONLY	       BIT_ULL (61)
#define AVF_ETH_RSS_L4_DST_ONLY	       BIT_ULL (60)
#define AVF_ETH_RSS_L2_SRC_ONLY	       BIT_ULL (59)
#define AVF_ETH_RSS_L2_DST_ONLY	       BIT_ULL (58)
#define AVF_ETH_RSS_L3_PRE32	       BIT_ULL (57)
#define AVF_ETH_RSS_L3_PRE40	       BIT_ULL (56)
#define AVF_ETH_RSS_L3_PRE48	       BIT_ULL (55)
#define AVF_ETH_RSS_L3_PRE56	       BIT_ULL (54)
#define AVF_ETH_RSS_L3_PRE64	       BIT_ULL (53)
#define AVF_ETH_RSS_L3_PRE96	       BIT_ULL (52)

#define foreach_avf_rss_hf                                                    \
  _ (0, AVF_ETH_RSS_FRAG_IPV4, "ipv4-frag")                                   \
  _ (1, AVF_ETH_RSS_NONFRAG_IPV4_TCP, "ipv4-tcp")                             \
  _ (2, AVF_ETH_RSS_NONFRAG_IPV4_UDP, "ipv4-udp")                             \
  _ (3, AVF_ETH_RSS_NONFRAG_IPV4_SCTP, "ipv4-sctp")                           \
  _ (4, AVF_ETH_RSS_NONFRAG_IPV4_OTHER, "ipv4-other")                         \
  _ (5, AVF_ETH_RSS_IPV4, "ipv4")                                             \
  _ (6, AVF_ETH_RSS_IPV6_TCP_EX, "ipv6-tcp-ex")                               \
  _ (7, AVF_ETH_RSS_IPV6_UDP_EX, "ipv6-udp-ex")                               \
  _ (8, AVF_ETH_RSS_FRAG_IPV6, "ipv6-frag")                                   \
  _ (9, AVF_ETH_RSS_NONFRAG_IPV6_TCP, "ipv6-tcp")                             \
  _ (10, AVF_ETH_RSS_NONFRAG_IPV6_UDP, "ipv6-udp")                            \
  _ (11, AVF_ETH_RSS_NONFRAG_IPV6_SCTP, "ipv6-sctp")                          \
  _ (12, AVF_ETH_RSS_NONFRAG_IPV6_OTHER, "ipv6-other")                        \
  _ (13, AVF_ETH_RSS_IPV6_EX, "ipv6-ex")                                      \
  _ (14, AVF_ETH_RSS_IPV6, "ipv6")                                            \
  _ (15, AVF_ETH_RSS_L2_PAYLOAD, "l2-payload")                                \
  _ (16, AVF_ETH_RSS_PORT, "port")                                            \
  _ (17, AVF_ETH_RSS_VXLAN, "vxlan")                                          \
  _ (18, AVF_ETH_RSS_GENEVE, "geneve")                                        \
  _ (19, AVF_ETH_RSS_NVGRE, "nvgre")                                          \
  _ (20, AVF_ETH_RSS_GTPU, "gtpu")                                            \
  _ (21, AVF_ETH_RSS_ESP, "esp")                                              \
  _ (60, AVF_ETH_RSS_L4_DST_ONLY, "l4-dst-only")                              \
  _ (61, AVF_ETH_RSS_L4_SRC_ONLY, "l4-src-only")                              \
  _ (62, AVF_ETH_RSS_L3_DST_ONLY, "l3-dst-only")                              \
  _ (63, AVF_ETH_RSS_L3_SRC_ONLY, "l3-src-only")

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
  VIRTCHNL_PROTO_HDR_GTPC,
  VIRTCHNL_PROTO_HDR_ECPRI,
  VIRTCHNL_PROTO_HDR_L2TPV2,
  VIRTCHNL_PROTO_HDR_PPP,
  /* IPv4 and IPv6 Fragment header types are only associated to
   * VIRTCHNL_PROTO_HDR_IPV4 and VIRTCHNL_PROTO_HDR_IPV6 respectively,
   * cannot be used independently.
   */
  VIRTCHNL_PROTO_HDR_IPV4_FRAG,
  VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG,
  VIRTCHNL_PROTO_HDR_GRE,
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
  VIRTCHNL_PROTO_HDR_IPV4_CHKSUM,
  /* IPV6 */
  VIRTCHNL_PROTO_HDR_IPV6_SRC =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_IPV6),
  VIRTCHNL_PROTO_HDR_IPV6_DST,
  VIRTCHNL_PROTO_HDR_IPV6_TC,
  VIRTCHNL_PROTO_HDR_IPV6_HOP_LIMIT,
  VIRTCHNL_PROTO_HDR_IPV6_PROT,
  /* IPV6 Prefix */
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX32_SRC,
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX32_DST,
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX40_SRC,
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX40_DST,
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX48_SRC,
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX48_DST,
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX56_SRC,
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX56_DST,
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX64_SRC,
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX64_DST,
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX96_SRC,
  VIRTCHNL_PROTO_HDR_IPV6_PREFIX96_DST,
  /* TCP */
  VIRTCHNL_PROTO_HDR_TCP_SRC_PORT =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_TCP),
  VIRTCHNL_PROTO_HDR_TCP_DST_PORT,
  VIRTCHNL_PROTO_HDR_TCP_CHKSUM,
  /* UDP */
  VIRTCHNL_PROTO_HDR_UDP_SRC_PORT =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_UDP),
  VIRTCHNL_PROTO_HDR_UDP_DST_PORT,
  VIRTCHNL_PROTO_HDR_UDP_CHKSUM,
  /* SCTP */
  VIRTCHNL_PROTO_HDR_SCTP_SRC_PORT =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_SCTP),
  VIRTCHNL_PROTO_HDR_SCTP_DST_PORT,
  VIRTCHNL_PROTO_HDR_SCTP_CHKSUM,
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
  /* GTPC */
  VIRTCHNL_PROTO_HDR_GTPC_TEID =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_GTPC),
  /* ECPRI */
  VIRTCHNL_PROTO_HDR_ECPRI_MSG_TYPE =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_ECPRI),
  VIRTCHNL_PROTO_HDR_ECPRI_PC_RTC_ID,
  /* IPv4 Dummy Fragment */
  VIRTCHNL_PROTO_HDR_IPV4_FRAG_PKID =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_IPV4_FRAG),
  /* IPv6 Extension Fragment */
  VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG_PKID =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG),
  /* GTPU_DWN/UP */
  VIRTCHNL_PROTO_HDR_GTPU_DWN_QFI =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_DWN),
  VIRTCHNL_PROTO_HDR_GTPU_UP_QFI =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_GTPU_EH_PDU_UP),
  /* L2TPv2 */
  VIRTCHNL_PROTO_HDR_L2TPV2_SESS_ID =
    PROTO_HDR_FIELD_START (VIRTCHNL_PROTO_HDR_L2TPV2),
  VIRTCHNL_PROTO_HDR_L2TPV2_LEN_SESS_ID,
};

struct virtchnl_proto_hdr
{
  enum virtchnl_proto_hdr_type type;
  u32 field_selector; /* a bit mask to select field for header type */
  u8 buffer[64];
  /**
   * binary buffer in network order for specific header type.
   * For example, if type = VIRTCHNL_PROTO_HDR_IPV4, a IPv4
   * header is expected to be copied into the buffer.
   */
};

VIRTCHNL_CHECK_STRUCT_LEN (72, virtchnl_proto_hdr);

struct virtchnl_proto_hdrs
{
  u8 tunnel_level;
  /**
   * specify where protocol header start from. Must be 0 when sending a generic
   * packet request. 0 - from the outer layer 1 - from the first inner layer 2
   *- from the second inner layer
   * ....
   **/
  int count;
  /**
   * the proto layers must < VIRTCHNL_MAX_NUM_PROTO_HDRS.
   * Must be 0 when sending a generic packet request.
   **/
  union
  {
    struct virtchnl_proto_hdr proto_hdr[VIRTCHNL_MAX_NUM_PROTO_HDRS];
    struct
    {
      u16 pkt_len;
      u8 spec[VIRTCHNL_MAX_SIZE_GEN_PACKET];
      u8 mask[VIRTCHNL_MAX_SIZE_GEN_PACKET];
    } raw;
  };
};

VIRTCHNL_CHECK_STRUCT_LEN (2312, virtchnl_proto_hdrs);

/* VIRTCHNL_OP_CONFIG_RSS_KEY
 * VIRTCHNL_OP_CONFIG_RSS_LUT
 * VF sends these messages to configure RSS. Only supported if both PF
 * and VF drivers set the VIRTCHNL_VF_OFFLOAD_RSS_PF bit during
 * configuration negotiation. If this is the case, then the RSS fields in
 * the VF resource struct are valid.
 * Both the key and LUT are initialized to 0 by the PF, meaning that
 * RSS is effectively disabled until set up by the VF.
 */
struct virtchnl_rss_key
{
  u16 vsi_id;
  u16 key_len;
  u8 key[1]; /* RSS hash key, packed bytes */
};

VIRTCHNL_CHECK_STRUCT_LEN (6, virtchnl_rss_key);

struct virtchnl_rss_lut
{
  u16 vsi_id;
  u16 lut_entries;
  u8 lut[1]; /* RSS lookup table */
};

VIRTCHNL_CHECK_STRUCT_LEN (6, virtchnl_rss_lut);

/* VIRTCHNL_OP_GET_RSS_HENA_CAPS
 * VIRTCHNL_OP_SET_RSS_HENA
 * VF sends these messages to get and set the hash filter enable bits for RSS.
 * By default, the PF sets these to all possible traffic types that the
 * hardware supports. The VF can query this value if it wants to change the
 * traffic types that are hashed by the hardware.
 */
struct virtchnl_rss_hena
{
  u64 hena;
};

VIRTCHNL_CHECK_STRUCT_LEN (8, virtchnl_rss_hena);

/* Type of RSS algorithm */
enum virtchnl_rss_algorithm
{
  VIRTCHNL_RSS_ALG_TOEPLITZ_ASYMMETRIC = 0,
  VIRTCHNL_RSS_ALG_XOR_ASYMMETRIC = 1,
  VIRTCHNL_RSS_ALG_TOEPLITZ_SYMMETRIC = 2,
  VIRTCHNL_RSS_ALG_XOR_SYMMETRIC = 3,
};

struct virtchnl_rss_cfg
{
  struct virtchnl_proto_hdrs proto_hdrs;     /* protocol headers */
  enum virtchnl_rss_algorithm rss_algorithm; /* rss algorithm type */
  u8 reserved[128];			     /* reserve for future */
};

VIRTCHNL_CHECK_STRUCT_LEN (2444, virtchnl_rss_cfg);

struct avf_pattern_match_item
{
  enum avf_flow_item_type *pattern_list;
  u64 input_set_mask;
  void *meta;
};

enum avf_flow_item_type
{
  AVF_FLOW_ITEM_TYPE_END,
  AVF_FLOW_ITEM_TYPE_VOID,
  AVF_FLOW_ITEM_TYPE_INVERT,
  AVF_FLOW_ITEM_TYPE_ANY,
  AVF_FLOW_ITEM_TYPE_PORT_ID,
  AVF_FLOW_ITEM_TYPE_RAW,
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_ICMP,
  AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_SCTP,
  AVF_FLOW_ITEM_TYPE_VXLAN,
  AVF_FLOW_ITEM_TYPE_E_TAG,
  AVF_FLOW_ITEM_TYPE_NVGRE,
  AVF_FLOW_ITEM_TYPE_MPLS,
  AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_FUZZY,
  AVF_FLOW_ITEM_TYPE_GTP,
  AVF_FLOW_ITEM_TYPE_GTPC,
  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_ESP,
  AVF_FLOW_ITEM_TYPE_GENEVE,
  AVF_FLOW_ITEM_TYPE_VXLAN_GPE,
  AVF_FLOW_ITEM_TYPE_ARP_ETH_IPV4,
  AVF_FLOW_ITEM_TYPE_IPV6_EXT,
  AVF_FLOW_ITEM_TYPE_ICMP6,
  AVF_FLOW_ITEM_TYPE_ICMP6_ND_NS,
  AVF_FLOW_ITEM_TYPE_ICMP6_ND_NA,
  AVF_FLOW_ITEM_TYPE_ICMP6_ND_OPT,
  AVF_FLOW_ITEM_TYPE_ICMP6_ND_OPT_SLA_ETH,
  AVF_FLOW_ITEM_TYPE_ICMP6_ND_OPT_TLA_ETH,
  AVF_FLOW_ITEM_TYPE_MARK,
  AVF_FLOW_ITEM_TYPE_META,
  AVF_FLOW_ITEM_TYPE_GRE_KEY,
  AVF_FLOW_ITEM_TYPE_GTP_PSC,
  AVF_FLOW_ITEM_TYPE_PPPOES,
  AVF_FLOW_ITEM_TYPE_PPPOED,
  AVF_FLOW_ITEM_TYPE_PPPOE_PROTO_ID,
  AVF_FLOW_ITEM_TYPE_NSH,
  AVF_FLOW_ITEM_TYPE_IGMP,
  AVF_FLOW_ITEM_TYPE_AH,
  AVF_FLOW_ITEM_TYPE_HIGIG2,
  AVF_FLOW_ITEM_TYPE_TAG,
  AVF_FLOW_ITEM_TYPE_L2TPV3OIP,
  AVF_FLOW_ITEM_TYPE_PFCP,
  AVF_FLOW_ITEM_TYPE_ECPRI,
  AVF_FLOW_ITEM_TYPE_IPV6_FRAG_EXT,
  AVF_FLOW_ITEM_TYPE_GENEVE_OPT,
  AVF_FLOW_ITEM_TYPE_INTEGRITY,
  AVF_FLOW_ITEM_TYPE_CONNTRACK,
  AVF_FLOW_ITEM_TYPE_PORT_REPRESENTOR,
  AVF_FLOW_ITEM_TYPE_REPRESENTED_PORT,
  AVF_FLOW_ITEM_TYPE_FLEX,
  AVF_FLOW_ITEM_TYPE_L2TPV2,
  AVF_FLOW_ITEM_TYPE_PPP,
  AVF_FLOW_ITEM_TYPE_GRE_OPTION,
  AVF_FLOW_ITEM_TYPE_MACSEC,
  AVF_FLOW_ITEM_TYPE_METER_COLOR,
};

enum avf_flow_action_type
{
  AVF_FLOW_ACTION_TYPE_END,
  AVF_FLOW_ACTION_TYPE_VOID,
  AVF_FLOW_ACTION_TYPE_PASSTHRU,
  AVF_FLOW_ACTION_TYPE_JUMP,
  AVF_FLOW_ACTION_TYPE_MARK,
  AVF_FLOW_ACTION_TYPE_FLAG,
  AVF_FLOW_ACTION_TYPE_QUEUE,
  AVF_FLOW_ACTION_TYPE_DROP,
  AVF_FLOW_ACTION_TYPE_COUNT,
  AVF_FLOW_ACTION_TYPE_RSS,
  AVF_FLOW_ACTION_TYPE_PF,
  AVF_FLOW_ACTION_TYPE_VF,
  AVF_FLOW_ACTION_TYPE_PORT_ID,
  AVF_FLOW_ACTION_TYPE_METER,
  AVF_FLOW_ACTION_TYPE_SECURITY,
  AVF_FLOW_ACTION_TYPE_OF_DEC_NW_TTL,
  AVF_FLOW_ACTION_TYPE_OF_POP_VLAN,
  AVF_FLOW_ACTION_TYPE_OF_PUSH_VLAN,
  AVF_FLOW_ACTION_TYPE_OF_SET_VLAN_VID,
  AVF_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP,
  AVF_FLOW_ACTION_TYPE_OF_POP_MPLS,
  AVF_FLOW_ACTION_TYPE_OF_PUSH_MPLS,
  AVF_FLOW_ACTION_TYPE_VXLAN_ENCAP,
  AVF_FLOW_ACTION_TYPE_VXLAN_DECAP,
  AVF_FLOW_ACTION_TYPE_NVGRE_ENCAP,
  AVF_FLOW_ACTION_TYPE_NVGRE_DECAP,
  AVF_FLOW_ACTION_TYPE_RAW_ENCAP,
  AVF_FLOW_ACTION_TYPE_RAW_DECAP,
  AVF_FLOW_ACTION_TYPE_SET_IPV4_SRC,
  AVF_FLOW_ACTION_TYPE_SET_IPV4_DST,
  AVF_FLOW_ACTION_TYPE_SET_IPV6_SRC,
  AVF_FLOW_ACTION_TYPE_SET_IPV6_DST,
  AVF_FLOW_ACTION_TYPE_SET_TP_SRC,
  AVF_FLOW_ACTION_TYPE_SET_TP_DST,
  AVF_FLOW_ACTION_TYPE_MAC_SWAP,
  AVF_FLOW_ACTION_TYPE_DEC_TTL,
  AVF_FLOW_ACTION_TYPE_SET_TTL,
  AVF_FLOW_ACTION_TYPE_SET_MAC_SRC,
  AVF_FLOW_ACTION_TYPE_SET_MAC_DST,
  AVF_FLOW_ACTION_TYPE_INC_TCP_SEQ,
  AVF_FLOW_ACTION_TYPE_DEC_TCP_SEQ,
  AVF_FLOW_ACTION_TYPE_INC_TCP_ACK,
  AVF_FLOW_ACTION_TYPE_DEC_TCP_ACK,
  AVF_FLOW_ACTION_TYPE_SET_TAG,
  AVF_FLOW_ACTION_TYPE_SET_META,
  AVF_FLOW_ACTION_TYPE_SET_IPV4_DSCP,
  AVF_FLOW_ACTION_TYPE_SET_IPV6_DSCP,
  AVF_FLOW_ACTION_TYPE_AGE,
  AVF_FLOW_ACTION_TYPE_SAMPLE,
  AVF_FLOW_ACTION_TYPE_SHARED,
  AVF_FLOW_ACTION_TYPE_MODIFY_FIELD,
  AVF_FLOW_ACTION_TYPE_INDIRECT,
  AVF_FLOW_ACTION_TYPE_CONNTRACK,
  AVF_FLOW_ACTION_TYPE_METER_COLOR,
  AVF_FLOW_ACTION_TYPE_PORT_REPRESENTOR,
  AVF_FLOW_ACTION_TYPE_REPRESENTED_PORT,
  AVF_FLOW_ACTION_TYPE_METER_MARK,
  AVF_FLOW_ACTION_TYPE_SEND_TO_KERNEL,
};

enum virtchnl_action
{
  /* action types */
  VIRTCHNL_ACTION_DROP = 0,
  VIRTCHNL_ACTION_TC_REDIRECT,
  VIRTCHNL_ACTION_PASSTHRU,
  VIRTCHNL_ACTION_QUEUE,
  VIRTCHNL_ACTION_Q_REGION,
  VIRTCHNL_ACTION_MARK,
  VIRTCHNL_ACTION_COUNT,
  VIRTCHNL_ACTION_NONE,
};

/* action configuration for FDIR */
struct virtchnl_filter_action
{
  enum virtchnl_action type;
  union
  {
    /* used for queue and qgroup action */
    struct
    {
      u16 index;
      u8 region;
    } queue;
    /* used for count action */
    struct
    {
      /* share counter ID with other flow rules */
      u8 shared;
      u32 id; /* counter ID */
    } count;
    /* used for mark action */
    u32 mark_id;
    u8 reserve[32];
  } act_conf;
};

VIRTCHNL_CHECK_STRUCT_LEN (36, virtchnl_filter_action);

#define VIRTCHNL_MAX_NUM_ACTIONS 8

struct virtchnl_filter_action_set
{
  /* action number must be less then VIRTCHNL_MAX_NUM_ACTIONS */
  int count;
  struct virtchnl_filter_action actions[VIRTCHNL_MAX_NUM_ACTIONS];
};

VIRTCHNL_CHECK_STRUCT_LEN (292, virtchnl_filter_action_set);

/* pattern and action for FDIR rule */
struct virtchnl_fdir_rule
{
  struct virtchnl_proto_hdrs proto_hdrs;
  struct virtchnl_filter_action_set action_set;
};

VIRTCHNL_CHECK_STRUCT_LEN (2604, virtchnl_fdir_rule);

/* query information to retrieve fdir rule counters.
 * PF will fill out this structure to reset counter.
 */
struct virtchnl_fdir_query_info
{
  u32 match_packets_valid : 1;
  u32 match_bytes_valid : 1;
  u32 reserved : 30; /* Reserved, must be zero. */
  u32 pad;
  u64 matched_packets; /* Number of packets for this rule. */
  u64 matched_bytes;   /* Number of bytes through this rule. */
};

VIRTCHNL_CHECK_STRUCT_LEN (24, virtchnl_fdir_query_info);

/* Status returned to VF after VF requests FDIR commands
 * VIRTCHNL_FDIR_SUCCESS
 * VF FDIR related request is successfully done by PF
 * The request can be OP_ADD/DEL/QUERY_FDIR_FILTER.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_NORESOURCE
 * OP_ADD_FDIR_FILTER request is failed due to no Hardware resource.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_EXIST
 * OP_ADD_FDIR_FILTER request is failed due to the rule is already existed.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_CONFLICT
 * OP_ADD_FDIR_FILTER request is failed due to conflict with existing rule.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_NONEXIST
 * OP_DEL_FDIR_FILTER request is failed due to this rule doesn't exist.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_INVALID
 * OP_ADD_FDIR_FILTER request is failed due to parameters validation
 * or HW doesn't support.
 *
 * VIRTCHNL_FDIR_FAILURE_RULE_TIMEOUT
 * OP_ADD/DEL_FDIR_FILTER request is failed due to timing out
 * for programming.
 *
 * VIRTCHNL_FDIR_FAILURE_QUERY_INVALID
 * OP_QUERY_FDIR_FILTER request is failed due to parameters validation,
 * for example, VF query counter of a rule who has no counter action.
 */
enum virtchnl_fdir_prgm_status
{
  VIRTCHNL_FDIR_SUCCESS = 0,
  VIRTCHNL_FDIR_FAILURE_RULE_NORESOURCE,
  VIRTCHNL_FDIR_FAILURE_RULE_EXIST,
  VIRTCHNL_FDIR_FAILURE_RULE_CONFLICT,
  VIRTCHNL_FDIR_FAILURE_RULE_NONEXIST,
  VIRTCHNL_FDIR_FAILURE_RULE_INVALID,
  VIRTCHNL_FDIR_FAILURE_RULE_TIMEOUT,
  VIRTCHNL_FDIR_FAILURE_QUERY_INVALID,
  VIRTCHNL_FDIR_FAILURE_MAX,
};

/* VIRTCHNL_OP_ADD_FDIR_FILTER
 * VF sends this request to PF by filling out vsi_id,
 * validate_only and rule_cfg. PF will return flow_id
 * if the request is successfully done and return add_status to VF.
 */
struct virtchnl_fdir_add
{
  u16 vsi_id; /* INPUT */
  /*
   * 1 for validating a fdir rule, 0 for creating a fdir rule.
   * Validate and create share one ops: VIRTCHNL_OP_ADD_FDIR_FILTER.
   */
  u16 validate_only;			 /* INPUT */
  u32 flow_id;				 /* OUTPUT */
  struct virtchnl_fdir_rule rule_cfg;	 /* INPUT */
  enum virtchnl_fdir_prgm_status status; /* OUTPUT */
};

VIRTCHNL_CHECK_STRUCT_LEN (2616, virtchnl_fdir_add);

/* VIRTCHNL_OP_DEL_FDIR_FILTER
 * VF sends this request to PF by filling out vsi_id
 * and flow_id. PF will return del_status to VF.
 */
struct virtchnl_fdir_del
{
  u16 vsi_id; /* INPUT */
  u16 pad;
  u32 flow_id;				 /* INPUT */
  enum virtchnl_fdir_prgm_status status; /* OUTPUT */
};

VIRTCHNL_CHECK_STRUCT_LEN (12, virtchnl_fdir_del);

/* VIRTCHNL_OP_QUERY_FDIR_FILTER
 * VF sends this request to PF by filling out vsi_id,
 * flow_id and reset_counter. PF will return query_info
 * and query_status to VF.
 */
struct virtchnl_fdir_query
{
  u16 vsi_id; /* INPUT */
  u16 pad1[3];
  u32 flow_id;				      /* INPUT */
  u32 reset_counter : 1;		      /* INPUT */
  struct virtchnl_fdir_query_info query_info; /* OUTPUT */
  enum virtchnl_fdir_prgm_status status;      /* OUTPUT */
  u32 pad2;
};

VIRTCHNL_CHECK_STRUCT_LEN (48, virtchnl_fdir_query);

/**
 * Those headers used temporary, maybe OS packet
 * definition can replace. Add flow error, pattern
 * and action definition.
 */

/**
 * Verbose error types.
 *
 * Most of them provide the type of the object referenced by struct
 * rte_flow_error.cause.
 */
enum avf_flow_error_type
{
  AVF_FLOW_ERROR_TYPE_NONE,	     /**< No error. */
  AVF_FLOW_ERROR_TYPE_UNSPECIFIED,   /**< Cause unspecified. */
  AVF_FLOW_ERROR_TYPE_HANDLE,	     /**< Flow rule (handle). */
  AVF_FLOW_ERROR_TYPE_ATTR_GROUP,    /**< Group field. */
  AVF_FLOW_ERROR_TYPE_ATTR_PRIORITY, /**< Priority field. */
  AVF_FLOW_ERROR_TYPE_ATTR_INGRESS,  /**< Ingress field. */
  AVF_FLOW_ERROR_TYPE_ATTR_EGRESS,   /**< Egress field. */
  AVF_FLOW_ERROR_TYPE_ATTR_TRANSFER, /**< Transfer field. */
  AVF_FLOW_ERROR_TYPE_ATTR,	     /**< Attributes structure. */
  AVF_FLOW_ERROR_TYPE_ITEM_NUM,	     /**< Pattern length. */
  AVF_FLOW_ERROR_TYPE_ITEM_SPEC,     /**< Item specification. */
  AVF_FLOW_ERROR_TYPE_ITEM_LAST,     /**< Item specification range. */
  AVF_FLOW_ERROR_TYPE_ITEM_MASK,     /**< Item specification mask. */
  AVF_FLOW_ERROR_TYPE_ITEM,	     /**< Specific pattern item. */
  AVF_FLOW_ERROR_TYPE_ACTION_NUM,    /**< Number of actions. */
  AVF_FLOW_ERROR_TYPE_ACTION_CONF,   /**< Action configuration. */
  AVF_FLOW_ERROR_TYPE_ACTION,	     /**< Specific action. */
};

/**
 * Verbose error structure definition.
 * Both cause and message may be NULL regardless of the error type.
 */
struct avf_flow_error
{
  enum avf_flow_error_type type; /**< Cause field and error types. */
  const void *cause;		 /**< Object responsible for the error. */
  const char *message;		 /**< Human-readable error message. */
};

#define AVF_ETHER_ADDR_LEN 6
struct avf_ether_addr
{
  u8 addr_bytes[AVF_ETHER_ADDR_LEN]; /**< Addr bytes in tx order */
} __attribute__ ((__aligned__ (2)));

struct avf_flow_eth_hdr
{
  struct avf_ether_addr dst; /**< Destination MAC. */
  struct avf_ether_addr src; /**< Source MAC. */
  u16 type;		     /**< EtherType or TPID. */
};

/**
 * IPv4 Header
 */
struct avf_ipv4_hdr
{
  u8 version_ihl;      /**< version and header length */
  u8 type_of_service;  /**< type of service */
  u16 total_length;    /**< length of packet */
  u16 packet_id;       /**< packet ID */
  u16 fragment_offset; /**< fragmentation offset */
  u8 time_to_live;     /**< time to live */
  u8 next_proto_id;    /**< protocol ID */
  u16 hdr_checksum;    /**< header checksum */
  u32 src_addr;	       /**< source address */
  u32 dst_addr;	       /**< destination address */
} __attribute__ ((__packed__));

/**
 * IPv6 Header
 */
struct avf_ipv6_hdr
{
  u32 vtc_flow;	   /**< IP version, traffic class & flow label. */
  u16 payload_len; /**< IP packet length - includes header size */
  u8 proto;	   /**< Protocol, next header. */
  u8 hop_limits;   /**< Hop limits. */
  u8 src_addr[16]; /**< IP address of source host. */
  u8 dst_addr[16]; /**< IP address of destination host(s). */
} __attribute__ ((__packed__));

/**
 * TCP Header
 */
struct avf_tcp_hdr
{
  u16 src_port; /**< TCP source port. */
  u16 dst_port; /**< TCP destination port. */
  u32 sent_seq; /**< TX data sequence number. */
  u32 recv_ack; /**< RX data acknowledgment sequence number. */
  u8 data_off;	/**< Data offset. */
  u8 tcp_flags; /**< TCP flags */
  u16 rx_win;	/**< RX flow control window. */
  u16 cksum;	/**< TCP checksum. */
  u16 tcp_urp;	/**< TCP urgent pointer, if any. */
} __attribute__ ((__packed__));

/**
 * UDP Header
 */
struct avf_udp_hdr
{
  u16 src_port;	   /**< UDP source port. */
  u16 dst_port;	   /**< UDP destination port. */
  u16 dgram_len;   /**< UDP datagram length */
  u16 dgram_cksum; /**< UDP datagram checksum */
} __attribute__ ((__packed__));

/**
 * Match IP Authentication Header (AH), RFC 4302
 */
struct avf_ah_hdr
{
  u32 next_hdr : 8;
  u32 payload_len : 8;
  u32 reserved : 16;
  u32 spi;
  u32 seq_num;
};

/**
 * ESP Header
 */
struct avf_esp_hdr
{
  u32 spi; /**< Security Parameters Index */
  u32 seq; /**< packet sequence number */
} __attribute__ ((__packed__));

/**
 * Match PFCP Header
 */
struct avf_pfcp_hdr
{
  u8 s_field;
  u8 msg_type;
  u16 msg_len;
  u64 seid;
};

/**
 * Matches a L2TPv3 over IP header.
 */
struct avf_l2tpv3oip_hdr
{
  u32 session_id; /**< Session ID. */
};

/**
 * Matches a GTP PDU extension header with type 0x85.
 */
struct avf_gtp_psc_hdr
{
  u8 pdu_type; /**< PDU type. */
  u8 qfi;      /**< QoS flow identifier. */
};

/**
 * Matches a GTPv1 header.
 */
struct avf_gtp_hdr
{
  /**
   * Version (3b), protocol type (1b), reserved (1b),
   * Extension header flag (1b),
   * Sequence number flag (1b),
   * N-PDU number flag (1b).
   */
  u8 v_pt_rsv_flags;
  u8 msg_type; /**< Message type. */
  u16 msg_len; /**< Message length. */
  u32 teid;    /**< Tunnel endpoint identifier. */
};

/**
 * SCTP Header
 */
struct avf_sctp_hdr
{
  u16 src_port; /**< Source port. */
  u16 dst_port; /**< Destin port. */
  u32 tag;	/**< Validation tag. */
  u32 cksum;	/**< Checksum. */
} __attribute__ ((__packed__));

/**
 * Hash function types.
 */
enum avf_eth_hash_function
{
  AVF_ETH_HASH_FUNCTION_DEFAULT = 0,
  AVF_ETH_HASH_FUNCTION_TOEPLITZ,   /**< Toeplitz */
  AVF_ETH_HASH_FUNCTION_SIMPLE_XOR, /**< Simple XOR */
  /**
   * Symmetric Toeplitz: src, dst will be replaced by
   * xor(src, dst). For the case with src/dst only,
   * src or dst address will xor with zero pair.
   */
  AVF_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ,
  AVF_ETH_HASH_FUNCTION_MAX,
};

struct avf_flow_action_rss
{
  enum avf_eth_hash_function func; /**< RSS hash function to apply. */

  u32 level;
  u64 types;	    /**< Specific RSS hash types (see ETH_RSS_*). */
  u32 key_len;	    /**< Hash key length in bytes. */
  u32 queue_num;    /**< Number of entries in @p queue. */
  const u8 *key;    /**< Hash key. */
  const u16 *queue; /**< Queue indices to use. */
};

struct avf_flow_action_queue
{
  u16 index; /**< Queue index to use. */
};

struct avf_flow_action_mark
{
  u32 id; /**< Integer value to return with packets. */
};

struct avf_flow_action
{
  enum avf_flow_action_type type; /**< Action type. */
  const void *conf;	     /**< Pointer to action configuration object. */
};

struct avf_flow_item
{
  enum avf_flow_item_type type; /**< Item type. */
  const void *spec; /**< Pointer to item specification structure. */
  const void *mask; /**< Bit-mask applied to spec and last. */
  int is_generic;   /* indicate if this item is for a generic flow pattern. */
};

struct avf_fdir_conf
{
  struct virtchnl_fdir_add add_fltr;
  struct virtchnl_fdir_del del_fltr;
  u64 input_set;
  u32 flow_id;
  u32 mark_flag;
  u32 vsi;
  u32 nb_rx_queues;
};

enum virthnl_adv_ops
{
  VIRTCHNL_ADV_OP_ADD_FDIR_FILTER = 0,
  VIRTCHNL_ADV_OP_DEL_FDIR_FILTER,
  VIRTCHNL_ADV_OP_QUERY_FDIR_FILTER,
  VIRTCHNL_ADV_OP_ADD_RSS_CFG,
  VIRTCHNL_ADV_OP_DEL_RSS_CFG,
  VIRTCHNL_ADV_OP_MAX
};

/* virtual channel op handler */
typedef int (*avf_flow_vc_op_t) (void *vc_hdl, enum virthnl_adv_ops vc_op,
				 void *in, u32 in_len, void *out, u32 out_len);

/* virtual channel context object */
struct avf_flow_vc_ctx
{
  void *vc_hdl; /* virtual channel handler */
  avf_flow_vc_op_t vc_op;
};

/**
 * Create a rule cfg object.
 *
 * @param rcfg
 * 	created rule cfg object.
 * @param tunnel
 * 	tunnel level where protocol header start from
 * 	0 from moster outer layer.
 * 	1 from first inner layer.
 * 	2 form second inner layer.
 * 	...
 * @param vsi
 * 	avf vsi id
 *
 * @param nrxq
 * 	the rx queue number of the avf
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int avf_fdir_rcfg_create (struct avf_fdir_conf **rcfg, int tunnel_level,
			  u16 vsi, u16 nrxq);

/**
 * Destroy a rule cfg object.
 *
 * @param rcfg
 * 	the cfg object to destroy.
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int avf_fdir_rcfg_destroy (struct avf_fdir_conf *rcfg);

/**
 * Set match potocol header on specific layer, it will overwrite is already be
 * set.
 *
 * @param rcfg
 * 	the rule cfg object
 * @param layer
 * 	layer of the protocol header.
 * @param hdr
 * 	protocol header type.
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int avf_fdir_rcfg_set_hdr (struct avf_fdir_conf *rcfg, int layer,
			   enum virtchnl_proto_hdr_type hdr);

/**
 * Set a match field on specific protocol layer, if any match field already be
 * set on this layer, it will be overwritten.
 *
 * @param rcfg
 * 	the rule cfg object
 * @param layer
 * 	layer of the protocol header.
 * @param item
 * 	flow item
 * @param error
 *	save error cause
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int avf_fdir_rcfg_set_field (struct avf_fdir_conf *rcfg, int layer,
			     struct avf_flow_item *item,
			     struct avf_flow_error *error);

/**
 * Set action as to queue(group), conflict with drop action.
 *
 * @param rcfg
 * 	rule cfg object
 * @param queue
 * 	queue id.
 * @param size
 *	queue group size, must be 2^n. 1 means only to single queue.
 * @param act_idx
 * 	action index
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int avf_fdir_rcfg_act_queue (struct avf_fdir_conf *rcfg, int queue, int size,
			     int act_idx);

/**
 * Set action as to queue group, conflict with drop action.
 *
 * @param rcfg
 * 	the rule cfg object
 * @param act
 * 	flow actions
 * @param act_idx
 * 	action index
 * @error
 *	save error cause
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int avf_fdir_parse_action_qregion (struct avf_fdir_conf *rcfg,
				   const struct avf_flow_action *act,
				   int act_idx, struct avf_flow_error *error);

/**
 * Set action as as drop, conflict with to queue(gropu) action.
 *
 * @param rcfg
 * 	the rule cfg object
 * @param act_idx
 * 	action index
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int avf_fdir_rcfg_act_drop (struct avf_fdir_conf *rcfg, int act_idx);

/**
 * Set action as mark, it can co-exist with to queue(group) or drop action.
 *
 * @param rcfg
 * 	the rule cfg object
 * @param mark
 * 	a 32 bit flow mark
 * @param act_idx
 * 	action index
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int avf_fdir_rcfg_act_mark (struct avf_fdir_conf *rcfg, const u32 mark,
			    int act_idx);

/**
 * Validate a flow rule cfg, check with PF driver if the rule cfg is supportted
 *or not.
 *
 * @param ctx
 *	 virtual channel context
 * @param rcfg
 * 	the rule cfg object.
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int avf_fdir_rcfg_validate (struct avf_flow_vc_ctx *ctx,
			    struct avf_fdir_conf *rcfg);

/**
 * Create a flow rule, a FDIR rule is expected to be programmed into hardware
 *if return success.
 *
 * @param ctx
 *	 virtual channel context
 * @param rcfg
 * 	rule cfg object.
 *
 * @return
 * 	0 = successfule.
 * 	< 0 = failure.
 */
int avf_fdir_rule_create (struct avf_flow_vc_ctx *ctx,
			  struct avf_fdir_conf *rcfg);

/**
 * Destroy a flow rule.
 *
 * @param ctx
 *	 virtual channel context
 * @param rcfg
 * 	the rule cfg object.
 *
 * @return
 * 	0 = successfule.
 * 	< 0 = failure.
 */
int avf_fdir_rule_destroy (struct avf_flow_vc_ctx *ctx,
			   struct avf_fdir_conf *rcfg);

/*
 * Parse avf patterns and set pattern fields.
 *
 * @param rcfg
 * 	flow config
 * @param avf_items
 * 	pattern items
 * @param error
 * 	save error cause
 *
 * @return
 *	0 = successful.
 *	< 0 = failure
 */
int avf_fdir_parse_pattern (struct avf_fdir_conf *rcfg,
			    struct avf_flow_item avf_items[],
			    struct avf_flow_error *error);

/*
 * Parse avf patterns for generic flow and set pattern fields.
 *
 * @param rcfg
 * 	flow config
 * @param avf_items
 * 	pattern items
 * @param error
 * 	save error cause
 *
 * @return
 *	0 = successful.
 *	< 0 = failure
 */
int avf_fdir_parse_generic_pattern (struct avf_fdir_conf *rcfg,
				    struct avf_flow_item avf_items[],
				    struct avf_flow_error *error);

/*
 * Parse flow actions, set actions.
 *
 * @param actions
 * 	flow actions
 * @param rcfg
 * 	flow config
 * @param error
 * 	save error cause
 *
 * @return
 *  0 = successful.
 *  < 0 = failure
 */
int avf_fdir_parse_action (const struct avf_flow_action actions[],
			   struct avf_fdir_conf *rcfg,
			   struct avf_flow_error *error);

/*
 * Parse flow patterns and rss actions, set rss config.
 *
 * @param avf_items
 * 	flow pattern
 * @param avf_actions
 *  flow actions
 * @param rss_cfg
 * 	rss config
 * @param error
 * 	save error cause
 *
 * @return
 *  0 = successful.
 *  < 0 = failure
 */
int avf_rss_parse_pattern_action (struct avf_flow_item avf_items[],
				  struct avf_flow_action avf_actions[],
				  struct virtchnl_rss_cfg *rss_cfg,
				  struct avf_flow_error *error);

/**
 * Create a RSS rule cfg object.
 *
 * @param rss_cfg
 * 	created rule cfg object.
 * @param tunnel
 * 	tunnel level where protocol header start from
 * 	0 from moster outer layer.
 * 	1 from first inner layer.
 * 	2 form second inner layer.
 *  Must be 0 for generic flow.
 *
 * @return
 * 	0 = successful.
 * 	< 0 = failure.
 */
int avf_rss_cfg_create (struct virtchnl_rss_cfg **rss_cfg, int tunnel_level);

int avf_rss_rcfg_destroy (struct virtchnl_rss_cfg *rss_cfg);

/**
 * Create a RSS flow rule
 *
 * @param ctx
 *	 virtual channel context
 * @param rss_cfg
 * 	rule cfg object.
 *
 * @return
 * 	0 = successfule.
 * 	< 0 = failure.
 */
int avf_rss_rule_create (struct avf_flow_vc_ctx *ctx,
			 struct virtchnl_rss_cfg *rss_cfg);

/**
 * Destroy a RSS flow rule
 *
 * @param ctx
 *	 virtual channel context
 * @param rss_cfg
 * 	rule cfg object.
 *
 * @return
 * 	0 = successfule.
 * 	< 0 = failure.
 */
int avf_rss_rule_destroy (struct avf_flow_vc_ctx *ctx,
			  struct virtchnl_rss_cfg *rss_cfg);

/**
 * Parse generic flow pattern to get spec and mask
 *
 * @param item
 *	flow item
 * @param pkt_buf
 * 	spec buffer.
 * @param msk_buf
 * 	mask buffer .
 * @param spec_len
 * 	length of spec.
 */
void avf_parse_generic_pattern (struct avf_flow_item *item, u8 *pkt_buf,
				u8 *msk_buf, u16 spec_len);

/**
 * Initialize flow error structure.
 *
 * @param[out] error
 *   Pointer to flow error structure (may be NULL).
 * @param code
 *   Related error code
 * @param type
 *   Cause field and error types.
 * @param cause
 *   Object responsible for the error.
 * @param message
 *   Human-readable error message.
 *
 * @return
 *   Negative error code (errno value)
 */
int avf_flow_error_set (struct avf_flow_error *error, int code,
			enum avf_flow_error_type type, const void *cause,
			const char *message);

/*
 * decode the error number to Verbose error string
 *
 * @param err_no
 *  error number
 *
 * @return
 *  Verbose error string
 */
char *avf_fdir_prgm_error_decode (int err_no);

#endif /* _AVF_ADVANCED_FLOW_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
