/*
 *------------------------------------------------------------------
 * Copyright (c) 2022 Intel and/or its affiliates.
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

#include <vppinfra/mem.h>
#include "avf_advanced_flow.h"

#define AVF_PHINT_NONE	      0
#define AVF_PHINT_GTPU	      BIT_ULL (0)
#define AVF_PHINT_GTPU_EH     BIT_ULL (1)
#define AVF_PHINT_GTPU_EH_DWN BIT_ULL (2)
#define AVF_PHINT_GTPU_EH_UP  BIT_ULL (3)
#define AVF_PHINT_OUTER_IPV4  BIT_ULL (4)
#define AVF_PHINT_OUTER_IPV6  BIT_ULL (5)
#define AVF_PHINT_GRE	      BIT_ULL (6)
/* the second IP header of GTPoGRE */
#define AVF_PHINT_MID_IPV4 BIT_ULL (7)
#define AVF_PHINT_MID_IPV6 BIT_ULL (8)
/* L2TPv2 */
#define AVF_PHINT_L2TPV2     BIT_ULL (9)
#define AVF_PHINT_L2TPV2_LEN BIT_ULL (10)
/* Raw */
#define AVF_PHINT_RAW BIT_ULL (11)

#define AVF_PHINT_GTPU_MSK                                                    \
  (AVF_PHINT_GTPU | AVF_PHINT_GTPU_EH | AVF_PHINT_GTPU_EH_DWN |               \
   AVF_PHINT_GTPU_EH_UP)

#define AVF_PHINT_LAYERS_MSK (AVF_PHINT_OUTER_IPV4 | AVF_PHINT_OUTER_IPV6)

#define AVF_GTPU_EH_DWNLINK 0
#define AVF_GTPU_EH_UPLINK  1

#define FIELD_SELECTOR(proto_hdr_field)                                       \
  (1UL << ((proto_hdr_field) &PROTO_HDR_FIELD_MASK))
#define BUFF_NOUSED 0

#define REFINE_PROTO_FLD(op, fld)                                             \
  VIRTCHNL_##op##_PROTO_HDR_FIELD (hdr, VIRTCHNL_PROTO_HDR_##fld)
#define REPALCE_PROTO_FLD(fld_1, fld_2)                                       \
  do                                                                          \
    {                                                                         \
      REFINE_PROTO_FLD (DEL, fld_1);                                          \
      REFINE_PROTO_FLD (ADD, fld_2);                                          \
    }                                                                         \
  while (0)

#define proto_hdr_eth                                                         \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_ETH,                                                   \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_ETH_SRC) |                           \
	FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_ETH_DST),                          \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_svlan                                                       \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_S_VLAN, FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_S_VLAN_ID), \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_cvlan                                                       \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_C_VLAN, FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_C_VLAN_ID), \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_ipv4                                                        \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_IPV4,                                                  \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_IPV4_SRC) |                          \
	FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_IPV4_DST),                         \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_ipv4_with_prot                                              \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_IPV4,                                                  \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_IPV4_SRC) |                          \
	FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_IPV4_DST) |                        \
	FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_IPV4_PROT),                        \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_ipv6                                                        \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_IPV6,                                                  \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_IPV6_SRC) |                          \
	FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_IPV6_DST),                         \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_ipv6_frag                                                   \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG,                                          \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG_PKID),                  \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_ipv6_with_prot                                              \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_IPV6,                                                  \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_IPV6_SRC) |                          \
	FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_IPV6_DST) |                        \
	FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_IPV6_PROT),                        \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_udp                                                         \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_UDP,                                                   \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_UDP_SRC_PORT) |                      \
	FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_UDP_DST_PORT),                     \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_tcp                                                         \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_TCP,                                                   \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_TCP_SRC_PORT) |                      \
	FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_TCP_DST_PORT),                     \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_sctp                                                        \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_SCTP,                                                  \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_SCTP_SRC_PORT) |                     \
	FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_SCTP_DST_PORT),                    \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_esp                                                         \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_ESP, FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_ESP_SPI),      \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_ah                                                          \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_AH, FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_AH_SPI),        \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_l2tpv3                                                      \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_L2TPV3,                                                \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_L2TPV3_SESS_ID),                     \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_pfcp                                                        \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_PFCP, FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_PFCP_SEID),   \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_gtpc                                                        \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_GTPC, 0, { BUFF_NOUSED }                               \
  }

#define proto_hdr_ecpri                                                       \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_ECPRI,                                                 \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_ECPRI_PC_RTC_ID),                    \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_l2tpv2                                                      \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_L2TPV2,                                                \
      FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_L2TPV2_SESS_ID) |                    \
	FIELD_SELECTOR (VIRTCHNL_PROTO_HDR_L2TPV2_LEN_SESS_ID),               \
    {                                                                         \
      BUFF_NOUSED                                                             \
    }                                                                         \
  }

#define proto_hdr_ppp                                                         \
  {                                                                           \
    VIRTCHNL_PROTO_HDR_PPP, 0, { BUFF_NOUSED }                                \
  }

#define TUNNEL_LEVEL_OUTER 0
#define TUNNEL_LEVEL_INNER 1

/* proto_hdrs template */
struct virtchnl_proto_hdrs outer_ipv4_tmplt = {
  TUNNEL_LEVEL_OUTER,
  4,
  { { proto_hdr_eth, proto_hdr_svlan, proto_hdr_cvlan, proto_hdr_ipv4 } }
};

struct virtchnl_proto_hdrs outer_ipv4_udp_tmplt = {
  TUNNEL_LEVEL_OUTER,
  5,
  { { proto_hdr_eth, proto_hdr_svlan, proto_hdr_cvlan,
      proto_hdr_ipv4_with_prot, proto_hdr_udp } }
};

struct virtchnl_proto_hdrs outer_ipv4_tcp_tmplt = {
  TUNNEL_LEVEL_OUTER,
  5,
  { { proto_hdr_eth, proto_hdr_svlan, proto_hdr_cvlan,
      proto_hdr_ipv4_with_prot, proto_hdr_tcp } }
};

struct virtchnl_proto_hdrs outer_ipv4_sctp_tmplt = {
  TUNNEL_LEVEL_OUTER,
  5,
  { { proto_hdr_eth, proto_hdr_svlan, proto_hdr_cvlan, proto_hdr_ipv4,
      proto_hdr_sctp } }
};

struct virtchnl_proto_hdrs outer_ipv6_tmplt = {
  TUNNEL_LEVEL_OUTER,
  4,
  { { proto_hdr_eth, proto_hdr_svlan, proto_hdr_cvlan, proto_hdr_ipv6 } }
};

struct virtchnl_proto_hdrs outer_ipv6_frag_tmplt = {
  TUNNEL_LEVEL_OUTER,
  5,
  { { proto_hdr_eth, proto_hdr_svlan, proto_hdr_cvlan, proto_hdr_ipv6,
      proto_hdr_ipv6_frag } }
};

struct virtchnl_proto_hdrs outer_ipv6_udp_tmplt = {
  TUNNEL_LEVEL_OUTER,
  5,
  { { proto_hdr_eth, proto_hdr_svlan, proto_hdr_cvlan,
      proto_hdr_ipv6_with_prot, proto_hdr_udp } }
};

struct virtchnl_proto_hdrs outer_ipv6_tcp_tmplt = {
  TUNNEL_LEVEL_OUTER,
  5,
  { { proto_hdr_eth, proto_hdr_svlan, proto_hdr_cvlan,
      proto_hdr_ipv6_with_prot, proto_hdr_tcp } }
};

struct virtchnl_proto_hdrs outer_ipv6_sctp_tmplt = {
  TUNNEL_LEVEL_OUTER,
  5,
  { { proto_hdr_eth, proto_hdr_svlan, proto_hdr_cvlan, proto_hdr_ipv6,
      proto_hdr_sctp } }
};

struct virtchnl_proto_hdrs inner_ipv4_tmplt = { TUNNEL_LEVEL_INNER,
						1,
						{ { proto_hdr_ipv4 } } };

struct virtchnl_proto_hdrs inner_ipv4_udp_tmplt = {
  TUNNEL_LEVEL_INNER, 2, { { proto_hdr_ipv4_with_prot, proto_hdr_udp } }
};

struct virtchnl_proto_hdrs inner_ipv4_tcp_tmplt = {
  TUNNEL_LEVEL_INNER, 2, { { proto_hdr_ipv4_with_prot, proto_hdr_tcp } }
};

struct virtchnl_proto_hdrs second_inner_ipv4_tmplt = {
  2, 1, { { proto_hdr_ipv4 } }
};

struct virtchnl_proto_hdrs second_inner_ipv4_udp_tmplt = {
  2, 2, { { proto_hdr_ipv4_with_prot, proto_hdr_udp } }
};

struct virtchnl_proto_hdrs second_inner_ipv4_tcp_tmplt = {
  2, 2, { { proto_hdr_ipv4_with_prot, proto_hdr_tcp } }
};

struct virtchnl_proto_hdrs second_inner_ipv6_tmplt = {
  2, 1, { { proto_hdr_ipv6 } }
};

struct virtchnl_proto_hdrs second_inner_ipv6_udp_tmplt = {
  2, 2, { { proto_hdr_ipv6_with_prot, proto_hdr_udp } }
};

struct virtchnl_proto_hdrs second_inner_ipv6_tcp_tmplt = {
  2, 2, { { proto_hdr_ipv6_with_prot, proto_hdr_tcp } }
};

struct virtchnl_proto_hdrs inner_ipv4_sctp_tmplt = {
  TUNNEL_LEVEL_INNER, 2, { { proto_hdr_ipv4, proto_hdr_sctp } }
};

struct virtchnl_proto_hdrs inner_ipv6_tmplt = { TUNNEL_LEVEL_INNER,
						1,
						{ { proto_hdr_ipv6 } } };

struct virtchnl_proto_hdrs inner_ipv6_udp_tmplt = {
  TUNNEL_LEVEL_INNER, 2, { { proto_hdr_ipv6_with_prot, proto_hdr_udp } }
};

struct virtchnl_proto_hdrs inner_ipv6_tcp_tmplt = {
  TUNNEL_LEVEL_INNER, 2, { { proto_hdr_ipv6_with_prot, proto_hdr_tcp } }
};

struct virtchnl_proto_hdrs inner_ipv6_sctp_tmplt = {
  TUNNEL_LEVEL_INNER, 2, { { proto_hdr_ipv6, proto_hdr_sctp } }
};

struct virtchnl_proto_hdrs ipv4_esp_tmplt = {
  TUNNEL_LEVEL_OUTER, 2, { { proto_hdr_ipv4, proto_hdr_esp } }
};

struct virtchnl_proto_hdrs ipv4_udp_esp_tmplt = {
  TUNNEL_LEVEL_OUTER, 3, { { proto_hdr_ipv4, proto_hdr_udp, proto_hdr_esp } }
};

struct virtchnl_proto_hdrs ipv4_ah_tmplt = {
  TUNNEL_LEVEL_OUTER, 2, { { proto_hdr_ipv4, proto_hdr_ah } }
};

struct virtchnl_proto_hdrs ipv6_esp_tmplt = {
  TUNNEL_LEVEL_OUTER, 2, { { proto_hdr_ipv6, proto_hdr_esp } }
};

struct virtchnl_proto_hdrs ipv6_udp_esp_tmplt = {
  TUNNEL_LEVEL_OUTER, 3, { { proto_hdr_ipv6, proto_hdr_udp, proto_hdr_esp } }
};

struct virtchnl_proto_hdrs ipv6_ah_tmplt = {
  TUNNEL_LEVEL_OUTER, 2, { { proto_hdr_ipv6, proto_hdr_ah } }
};

struct virtchnl_proto_hdrs ipv4_l2tpv3_tmplt = {
  TUNNEL_LEVEL_OUTER, 2, { { proto_hdr_ipv4, proto_hdr_l2tpv3 } }
};

struct virtchnl_proto_hdrs ipv6_l2tpv3_tmplt = {
  TUNNEL_LEVEL_OUTER, 2, { { proto_hdr_ipv6, proto_hdr_l2tpv3 } }
};

struct virtchnl_proto_hdrs ipv4_pfcp_tmplt = {
  TUNNEL_LEVEL_OUTER, 2, { { proto_hdr_ipv4, proto_hdr_pfcp } }
};

struct virtchnl_proto_hdrs ipv6_pfcp_tmplt = {
  TUNNEL_LEVEL_OUTER, 2, { { proto_hdr_ipv6, proto_hdr_pfcp } }
};

struct virtchnl_proto_hdrs ipv4_udp_gtpc_tmplt = {
  TUNNEL_LEVEL_OUTER, 3, { { proto_hdr_ipv4, proto_hdr_udp, proto_hdr_gtpc } }
};

struct virtchnl_proto_hdrs ipv6_udp_gtpc_tmplt = {
  TUNNEL_LEVEL_OUTER, 3, { { proto_hdr_ipv6, proto_hdr_udp, proto_hdr_gtpc } }
};

struct virtchnl_proto_hdrs eth_ecpri_tmplt = {
  TUNNEL_LEVEL_OUTER, 2, { { proto_hdr_eth, proto_hdr_ecpri } }
};

struct virtchnl_proto_hdrs ipv4_ecpri_tmplt = {
  TUNNEL_LEVEL_OUTER, 3, { { proto_hdr_ipv4, proto_hdr_udp, proto_hdr_ecpri } }
};

struct virtchnl_proto_hdrs udp_l2tpv2_ppp_ipv4_tmplt = {
  TUNNEL_LEVEL_INNER,
  3,
  { { proto_hdr_l2tpv2, proto_hdr_ppp, proto_hdr_ipv4 } }
};

struct virtchnl_proto_hdrs udp_l2tpv2_ppp_ipv6_tmplt = {
  TUNNEL_LEVEL_INNER,
  3,
  { { proto_hdr_l2tpv2, proto_hdr_ppp, proto_hdr_ipv6 } }
};

struct virtchnl_proto_hdrs udp_l2tpv2_ppp_ipv4_udp_tmplt = {
  TUNNEL_LEVEL_INNER,
  4,
  { { proto_hdr_l2tpv2, proto_hdr_ppp, proto_hdr_ipv4_with_prot,
      proto_hdr_udp } }
};

struct virtchnl_proto_hdrs udp_l2tpv2_ppp_ipv4_tcp_tmplt = {
  TUNNEL_LEVEL_INNER,
  4,
  { { proto_hdr_l2tpv2, proto_hdr_ppp, proto_hdr_ipv4_with_prot,
      proto_hdr_tcp } }
};

struct virtchnl_proto_hdrs udp_l2tpv2_ppp_ipv6_udp_tmplt = {
  TUNNEL_LEVEL_INNER,
  4,
  { { proto_hdr_l2tpv2, proto_hdr_ppp, proto_hdr_ipv6_with_prot,
      proto_hdr_udp } }
};

struct virtchnl_proto_hdrs udp_l2tpv2_ppp_ipv6_tcp_tmplt = {
  TUNNEL_LEVEL_INNER,
  4,
  { { proto_hdr_l2tpv2, proto_hdr_ppp, proto_hdr_ipv6_with_prot,
      proto_hdr_tcp } }

};

struct virtchnl_proto_hdrs ipv4_l2tpv2_tmplt = {
  TUNNEL_LEVEL_OUTER,
  4,
  { { proto_hdr_eth, proto_hdr_ipv4, proto_hdr_udp, proto_hdr_l2tpv2 } }
};

struct virtchnl_proto_hdrs ipv6_l2tpv2_tmplt = {
  TUNNEL_LEVEL_OUTER,
  4,
  { { proto_hdr_eth, proto_hdr_ipv6, proto_hdr_udp, proto_hdr_l2tpv2 } }
};

struct virtchnl_proto_hdrs ipv4_l2tpv2_ppp_tmplt = {
  TUNNEL_LEVEL_OUTER,
  5,
  { { proto_hdr_eth, proto_hdr_ipv4, proto_hdr_udp, proto_hdr_l2tpv2,
      proto_hdr_ppp } }
};

struct virtchnl_proto_hdrs ipv6_l2tpv2_ppp_tmplt = {
  TUNNEL_LEVEL_OUTER,
  5,
  { { proto_hdr_eth, proto_hdr_ipv6, proto_hdr_udp, proto_hdr_l2tpv2,
      proto_hdr_ppp } }
};

/* rss type super set */

#define AVF_INSET_NONE 0ULL

/* IPv4 outer */
#define AVF_RSS_TYPE_OUTER_IPV4                                               \
  (AVF_ETH_RSS_ETH | AVF_ETH_RSS_IPV4 | AVF_ETH_RSS_FRAG_IPV4 |               \
   AVF_ETH_RSS_IPV4_CHKSUM)
#define AVF_RSS_TYPE_OUTER_IPV4_UDP                                           \
  (AVF_RSS_TYPE_OUTER_IPV4 | AVF_ETH_RSS_NONFRAG_IPV4_UDP |                   \
   AVF_ETH_RSS_L4_CHKSUM)
#define AVF_RSS_TYPE_OUTER_IPV4_TCP                                           \
  (AVF_RSS_TYPE_OUTER_IPV4 | AVF_ETH_RSS_NONFRAG_IPV4_TCP |                   \
   AVF_ETH_RSS_L4_CHKSUM)
#define AVF_RSS_TYPE_OUTER_IPV4_SCTP                                          \
  (AVF_RSS_TYPE_OUTER_IPV4 | AVF_ETH_RSS_NONFRAG_IPV4_SCTP |                  \
   AVF_ETH_RSS_L4_CHKSUM)
/* IPv6 outer */
#define AVF_RSS_TYPE_OUTER_IPV6 (AVF_ETH_RSS_ETH | AVF_ETH_RSS_IPV6)
#define AVF_RSS_TYPE_OUTER_IPV6_FRAG                                          \
  (AVF_RSS_TYPE_OUTER_IPV6 | AVF_ETH_RSS_FRAG_IPV6)
#define AVF_RSS_TYPE_OUTER_IPV6_UDP                                           \
  (AVF_RSS_TYPE_OUTER_IPV6 | AVF_ETH_RSS_NONFRAG_IPV6_UDP |                   \
   AVF_ETH_RSS_L4_CHKSUM)
#define AVF_RSS_TYPE_OUTER_IPV6_TCP                                           \
  (AVF_RSS_TYPE_OUTER_IPV6 | AVF_ETH_RSS_NONFRAG_IPV6_TCP |                   \
   AVF_ETH_RSS_L4_CHKSUM)
#define AVF_RSS_TYPE_OUTER_IPV6_SCTP                                          \
  (AVF_RSS_TYPE_OUTER_IPV6 | AVF_ETH_RSS_NONFRAG_IPV6_SCTP |                  \
   AVF_ETH_RSS_L4_CHKSUM)
/* VLAN IPV4 */
#define AVF_RSS_TYPE_VLAN_IPV4                                                \
  (AVF_RSS_TYPE_OUTER_IPV4 | AVF_ETH_RSS_S_VLAN | AVF_ETH_RSS_C_VLAN)
#define AVF_RSS_TYPE_VLAN_IPV4_UDP                                            \
  (AVF_RSS_TYPE_OUTER_IPV4_UDP | AVF_ETH_RSS_S_VLAN | AVF_ETH_RSS_C_VLAN)
#define AVF_RSS_TYPE_VLAN_IPV4_TCP                                            \
  (AVF_RSS_TYPE_OUTER_IPV4_TCP | AVF_ETH_RSS_S_VLAN | AVF_ETH_RSS_C_VLAN)
#define AVF_RSS_TYPE_VLAN_IPV4_SCTP                                           \
  (AVF_RSS_TYPE_OUTER_IPV4_SCTP | AVF_ETH_RSS_S_VLAN | AVF_ETH_RSS_C_VLAN)
/* VLAN IPv6 */
#define AVF_RSS_TYPE_VLAN_IPV6                                                \
  (AVF_RSS_TYPE_OUTER_IPV6 | AVF_ETH_RSS_S_VLAN | AVF_ETH_RSS_C_VLAN)
#define AVF_RSS_TYPE_VLAN_IPV6_FRAG                                           \
  (AVF_RSS_TYPE_OUTER_IPV6_FRAG | AVF_ETH_RSS_S_VLAN | AVF_ETH_RSS_C_VLAN)
#define AVF_RSS_TYPE_VLAN_IPV6_UDP                                            \
  (AVF_RSS_TYPE_OUTER_IPV6_UDP | AVF_ETH_RSS_S_VLAN | AVF_ETH_RSS_C_VLAN)
#define AVF_RSS_TYPE_VLAN_IPV6_TCP                                            \
  (AVF_RSS_TYPE_OUTER_IPV6_TCP | AVF_ETH_RSS_S_VLAN | AVF_ETH_RSS_C_VLAN)
#define AVF_RSS_TYPE_VLAN_IPV6_SCTP                                           \
  (AVF_RSS_TYPE_OUTER_IPV6_SCTP | AVF_ETH_RSS_S_VLAN | AVF_ETH_RSS_C_VLAN)
/* IPv4 inner */
#define AVF_RSS_TYPE_INNER_IPV4 AVF_ETH_RSS_IPV4
#define AVF_RSS_TYPE_INNER_IPV4_UDP                                           \
  (AVF_ETH_RSS_IPV4 | AVF_ETH_RSS_NONFRAG_IPV4_UDP)
#define AVF_RSS_TYPE_INNER_IPV4_TCP                                           \
  (AVF_ETH_RSS_IPV4 | AVF_ETH_RSS_NONFRAG_IPV4_TCP)
#define AVF_RSS_TYPE_INNER_IPV4_SCTP                                          \
  (AVF_ETH_RSS_IPV4 | AVF_ETH_RSS_NONFRAG_IPV4_SCTP)
/* IPv6 inner */
#define AVF_RSS_TYPE_INNER_IPV6 AVF_ETH_RSS_IPV6
#define AVF_RSS_TYPE_INNER_IPV6_UDP                                           \
  (AVF_ETH_RSS_IPV6 | AVF_ETH_RSS_NONFRAG_IPV6_UDP)
#define AVF_RSS_TYPE_INNER_IPV6_TCP                                           \
  (AVF_ETH_RSS_IPV6 | AVF_ETH_RSS_NONFRAG_IPV6_TCP)
#define AVF_RSS_TYPE_INNER_IPV6_SCTP                                          \
  (AVF_ETH_RSS_IPV6 | AVF_ETH_RSS_NONFRAG_IPV6_SCTP)
/* GTPU IPv4 */
#define AVF_RSS_TYPE_GTPU_IPV4 (AVF_RSS_TYPE_INNER_IPV4 | AVF_ETH_RSS_GTPU)
#define AVF_RSS_TYPE_GTPU_IPV4_UDP                                            \
  (AVF_RSS_TYPE_INNER_IPV4_UDP | AVF_ETH_RSS_GTPU)
#define AVF_RSS_TYPE_GTPU_IPV4_TCP                                            \
  (AVF_RSS_TYPE_INNER_IPV4_TCP | AVF_ETH_RSS_GTPU)
/* GTPU IPv6 */
#define AVF_RSS_TYPE_GTPU_IPV6 (AVF_RSS_TYPE_INNER_IPV6 | AVF_ETH_RSS_GTPU)
#define AVF_RSS_TYPE_GTPU_IPV6_UDP                                            \
  (AVF_RSS_TYPE_INNER_IPV6_UDP | AVF_ETH_RSS_GTPU)
#define AVF_RSS_TYPE_GTPU_IPV6_TCP                                            \
  (AVF_RSS_TYPE_INNER_IPV6_TCP | AVF_ETH_RSS_GTPU)
/* ESP, AH, L2TPV3 and PFCP */
#define AVF_RSS_TYPE_IPV4_ESP	 (AVF_ETH_RSS_ESP | AVF_ETH_RSS_IPV4)
#define AVF_RSS_TYPE_IPV4_AH	 (AVF_ETH_RSS_AH | AVF_ETH_RSS_IPV4)
#define AVF_RSS_TYPE_IPV6_ESP	 (AVF_ETH_RSS_ESP | AVF_ETH_RSS_IPV6)
#define AVF_RSS_TYPE_IPV6_AH	 (AVF_ETH_RSS_AH | AVF_ETH_RSS_IPV6)
#define AVF_RSS_TYPE_IPV4_L2TPV3 (AVF_ETH_RSS_L2TPV3 | AVF_ETH_RSS_IPV4)
#define AVF_RSS_TYPE_IPV6_L2TPV3 (AVF_ETH_RSS_L2TPV3 | AVF_ETH_RSS_IPV6)
#define AVF_RSS_TYPE_IPV4_PFCP	 (AVF_ETH_RSS_PFCP | AVF_ETH_RSS_IPV4)
#define AVF_RSS_TYPE_IPV6_PFCP	 (AVF_ETH_RSS_PFCP | AVF_ETH_RSS_IPV6)

/* L2TPv2 */
#define AVF_RSS_TYPE_ETH_L2TPV2 (AVF_ETH_RSS_ETH | AVF_ETH_RSS_L2TPV2)

#define VALID_RSS_IPV4_L4                                                     \
  (AVF_ETH_RSS_NONFRAG_IPV4_UDP | AVF_ETH_RSS_NONFRAG_IPV4_TCP |              \
   AVF_ETH_RSS_NONFRAG_IPV4_SCTP)

#define VALID_RSS_IPV6_L4                                                     \
  (AVF_ETH_RSS_NONFRAG_IPV6_UDP | AVF_ETH_RSS_NONFRAG_IPV6_TCP |              \
   AVF_ETH_RSS_NONFRAG_IPV6_SCTP)

#define VALID_RSS_IPV4                                                        \
  (AVF_ETH_RSS_IPV4 | AVF_ETH_RSS_FRAG_IPV4 | VALID_RSS_IPV4_L4)
#define VALID_RSS_IPV6                                                        \
  (AVF_ETH_RSS_IPV6 | AVF_ETH_RSS_FRAG_IPV6 | VALID_RSS_IPV6_L4)
#define VALID_RSS_L3 (VALID_RSS_IPV4 | VALID_RSS_IPV6)
#define VALID_RSS_L4 (VALID_RSS_IPV4_L4 | VALID_RSS_IPV6_L4)

#define VALID_RSS_ATTR                                                        \
  (AVF_ETH_RSS_L3_SRC_ONLY | AVF_ETH_RSS_L3_DST_ONLY |                        \
   AVF_ETH_RSS_L4_SRC_ONLY | AVF_ETH_RSS_L4_DST_ONLY |                        \
   AVF_ETH_RSS_L2_SRC_ONLY | AVF_ETH_RSS_L2_DST_ONLY | AVF_ETH_RSS_L3_PRE64)

#define INVALID_RSS_ATTR                                                      \
  (AVF_ETH_RSS_L3_PRE32 | AVF_ETH_RSS_L3_PRE40 | AVF_ETH_RSS_L3_PRE48 |       \
   AVF_ETH_RSS_L3_PRE56 | AVF_ETH_RSS_L3_PRE96)

static u64 invalid_rss_comb[] = {
  AVF_ETH_RSS_IPV4 | AVF_ETH_RSS_NONFRAG_IPV4_UDP,
  AVF_ETH_RSS_IPV4 | AVF_ETH_RSS_NONFRAG_IPV4_TCP,
  AVF_ETH_RSS_IPV6 | AVF_ETH_RSS_NONFRAG_IPV6_UDP,
  AVF_ETH_RSS_IPV6 | AVF_ETH_RSS_NONFRAG_IPV6_TCP,
  AVF_ETH_RSS_L3_PRE32 | AVF_ETH_RSS_L3_PRE40 | AVF_ETH_RSS_L3_PRE48 |
    AVF_ETH_RSS_L3_PRE56 | AVF_ETH_RSS_L3_PRE96
};

struct rss_attr_type
{
  u64 attr;
  u64 type;
};

static struct rss_attr_type rss_attr_to_valid_type[] = {
  { AVF_ETH_RSS_L2_SRC_ONLY | AVF_ETH_RSS_L2_DST_ONLY, AVF_ETH_RSS_ETH },
  { AVF_ETH_RSS_L3_SRC_ONLY | AVF_ETH_RSS_L3_DST_ONLY, VALID_RSS_L3 },
  { AVF_ETH_RSS_L4_SRC_ONLY | AVF_ETH_RSS_L4_DST_ONLY, VALID_RSS_L4 },
  /* current ipv6 prefix only supports prefix 64 bits*/
  { AVF_ETH_RSS_L3_PRE64, VALID_RSS_IPV6 },
  { INVALID_RSS_ATTR, 0 }
};

/* raw */
enum avf_flow_item_type avf_pattern_raw[] = {
  AVF_FLOW_ITEM_TYPE_RAW,
  AVF_FLOW_ITEM_TYPE_END,
};

/* empty */
enum avf_flow_item_type avf_pattern_empty[] = {
  AVF_FLOW_ITEM_TYPE_END,
};

/* L2 */
enum avf_flow_item_type avf_pattern_ethertype[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_ethertype_vlan[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_ethertype_qinq[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_END,
};

/* ARP */
enum avf_flow_item_type avf_pattern_eth_arp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_ARP_ETH_IPV4,
  AVF_FLOW_ITEM_TYPE_END,
};

/* non-tunnel IPv4 */
enum avf_flow_item_type avf_pattern_eth_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_vlan_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_qinq_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_vlan_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH, AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_UDP, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_qinq_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_vlan_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH, AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_TCP, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_qinq_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_sctp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_SCTP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_vlan_ipv4_sctp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_SCTP, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_qinq_ipv4_sctp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_SCTP, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_icmp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_ICMP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_vlan_ipv4_icmp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_ICMP, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_qinq_ipv4_icmp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_ICMP, AVF_FLOW_ITEM_TYPE_END,
};

/* non-tunnel IPv6 */
enum avf_flow_item_type avf_pattern_eth_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_vlan_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_qinq_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_frag_ext[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_IPV6_FRAG_EXT,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_vlan_ipv6_frag_ext[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_IPV6_FRAG_EXT,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_qinq_ipv6_frag_ext[] = {
  AVF_FLOW_ITEM_TYPE_ETH,	    AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_VLAN,	    AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_IPV6_FRAG_EXT, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_vlan_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH, AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_UDP, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_qinq_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_vlan_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH, AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_TCP, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_qinq_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_sctp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_SCTP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_vlan_ipv6_sctp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_SCTP, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_qinq_ipv6_sctp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_SCTP, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_icmp6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_ICMP6,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_vlan_ipv6_icmp6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,   AVF_FLOW_ITEM_TYPE_VLAN, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_ICMP6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_qinq_ipv6_icmp6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_VLAN,  AVF_FLOW_ITEM_TYPE_VLAN,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_ICMP6, AVF_FLOW_ITEM_TYPE_END,
};

/* IPv4 GTPC */
enum avf_flow_item_type avf_pattern_eth_ipv4_gtpc[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPC, AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GTPU (EH) */
enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_eh[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_END,
};

/* IPv6 GTPC */
enum avf_flow_item_type avf_pattern_eth_ipv6_gtpc[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPC, AVF_FLOW_ITEM_TYPE_END,
};

/* IPV6 GTPU (EH) */
enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_eh[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GTPU IPv4 */
enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_ipv4_icmp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_ICMP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GRE IPv4 UDP GTPU IPv4*/
enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GRE IPv4 UDP GTPU IPv6*/
enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GRE IPv6 UDP GTPU IPv4*/
enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GRE IPv6 UDP GTPU IPv6*/
enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV6 GRE IPv4 UDP GTPU IPv4*/
enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GRE IPv4 UDP GTPU IPv6*/
enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV6 GRE IPv6 UDP GTPU IPv4*/
enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV6 GRE IPv6 UDP GTPU IPv6*/
enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GRE IPv4 UDP GTPU EH IPv4*/
enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GRE IPv4 UDP GTPU IPv6*/
enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GRE IPv6 UDP GTPU EH IPv4*/
enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GRE IPv6 UDP GTPU EH IPv6*/
enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_END,
};

/* IPV6 GRE IPv4 UDP GTPU EH IPv4*/
enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GRE IPv4 UDP GTPU EH IPv6*/
enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_END,
};

/* IPV6 GRE IPv6 UDP GTPU EH IPv4*/
enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV6 GRE IPv6 UDP GTPU EH IPv6*/
enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,     AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_GTPU,
  AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GTPU IPv6 */
enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_ipv6_icmp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_ICMP,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV6 GTPU IPv4 */
enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_ipv4_icmp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_ICMP,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV6 GTPU IPv6 */
enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_ipv6_icmp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_ICMP,
  AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GTPU EH IPv4 */
enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_eh_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_eh_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_eh_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_eh_ipv4_icmp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_ICMP, AVF_FLOW_ITEM_TYPE_END,
};

/* IPV4 GTPU EH IPv6 */
enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_eh_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_eh_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_eh_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gtpu_eh_ipv6_icmp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_ICMP, AVF_FLOW_ITEM_TYPE_END,
};

/* IPV6 GTPU EH IPv4 */
enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_eh_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_eh_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_eh_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_eh_ipv4_icmp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_ICMP, AVF_FLOW_ITEM_TYPE_END,
};

/* IPV6 GTPU EH IPv6 */
enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_eh_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_eh_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_eh_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gtpu_eh_ipv6_icmp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6,    AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_GTPU, AVF_FLOW_ITEM_TYPE_GTP_PSC, AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_ICMP, AVF_FLOW_ITEM_TYPE_END,
};

/* ESP */
enum avf_flow_item_type avf_pattern_eth_ipv4_esp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_ESP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_udp_esp[] = {
  AVF_FLOW_ITEM_TYPE_ETH, AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_ESP, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_esp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_ESP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_udp_esp[] = {
  AVF_FLOW_ITEM_TYPE_ETH, AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_ESP, AVF_FLOW_ITEM_TYPE_END,
};

/* AH */
enum avf_flow_item_type avf_pattern_eth_ipv4_ah[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_AH,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_ah[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_AH,
  AVF_FLOW_ITEM_TYPE_END,
};

/* L2TPV3 */
enum avf_flow_item_type avf_pattern_eth_ipv4_l2tpv3[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_L2TPV3OIP,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_l2tpv3[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_L2TPV3OIP,
  AVF_FLOW_ITEM_TYPE_END,
};

/* PFCP */
enum avf_flow_item_type avf_pattern_eth_ipv4_pfcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_PFCP, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_pfcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_PFCP, AVF_FLOW_ITEM_TYPE_END,
};

/* ECPRI */
enum avf_flow_item_type avf_pattern_eth_ecpri[] = {
  AVF_FLOW_ITEM_TYPE_ETH,
  AVF_FLOW_ITEM_TYPE_ECPRI,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_ecpri[] = {
  AVF_FLOW_ITEM_TYPE_ETH,   AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_ECPRI, AVF_FLOW_ITEM_TYPE_END,
};

/* GRE */
enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_gre_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_TCP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_gre_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_GRE,
  AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_udp_l2tpv2[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_udp_l2tpv2_ppp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_udp_l2tpv2[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_udp_l2tpv2_ppp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_END,
};

/* PPPoL2TPv2oUDP */
enum avf_flow_item_type avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_UDP,    AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_TCP,    AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_UDP,    AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV4, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_TCP,    AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv4[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv6[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv4_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_UDP,    AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv4_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV4,
  AVF_FLOW_ITEM_TYPE_TCP,    AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv6_udp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_UDP,    AVF_FLOW_ITEM_TYPE_END,
};

enum avf_flow_item_type avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv6_tcp[] = {
  AVF_FLOW_ITEM_TYPE_ETH,    AVF_FLOW_ITEM_TYPE_IPV6, AVF_FLOW_ITEM_TYPE_UDP,
  AVF_FLOW_ITEM_TYPE_L2TPV2, AVF_FLOW_ITEM_TYPE_PPP,  AVF_FLOW_ITEM_TYPE_IPV6,
  AVF_FLOW_ITEM_TYPE_TCP,    AVF_FLOW_ITEM_TYPE_END,
};

static struct avf_pattern_match_item avf_hash_pattern_list[] = {
  /* IPv4 */
  { avf_pattern_raw, AVF_INSET_NONE, NULL },
  { avf_pattern_eth_ipv4, AVF_RSS_TYPE_OUTER_IPV4, &outer_ipv4_tmplt },
  { avf_pattern_eth_ipv4_udp, AVF_RSS_TYPE_OUTER_IPV4_UDP,
    &outer_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv4_tcp, AVF_RSS_TYPE_OUTER_IPV4_TCP,
    &outer_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv4_sctp, AVF_RSS_TYPE_OUTER_IPV4_SCTP,
    &outer_ipv4_sctp_tmplt },
  { avf_pattern_eth_vlan_ipv4, AVF_RSS_TYPE_VLAN_IPV4, &outer_ipv4_tmplt },
  { avf_pattern_eth_vlan_ipv4_udp, AVF_RSS_TYPE_VLAN_IPV4_UDP,
    &outer_ipv4_udp_tmplt },
  { avf_pattern_eth_vlan_ipv4_tcp, AVF_RSS_TYPE_VLAN_IPV4_TCP,
    &outer_ipv4_tcp_tmplt },
  { avf_pattern_eth_vlan_ipv4_sctp, AVF_RSS_TYPE_VLAN_IPV4_SCTP,
    &outer_ipv4_sctp_tmplt },
  { avf_pattern_eth_ipv4_gtpu, AVF_ETH_RSS_IPV4, &outer_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv4_gtpu_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &inner_ipv4_tmplt },
  { avf_pattern_eth_ipv4_gtpu_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv4_gtpu_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv6_gtpu_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &inner_ipv4_tmplt },
  { avf_pattern_eth_ipv6_gtpu_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv6_gtpu_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv4_gtpu_eh_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &inner_ipv4_tmplt },
  { avf_pattern_eth_ipv4_gtpu_eh_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv4_gtpu_eh_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv6_gtpu_eh_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &inner_ipv4_tmplt },
  { avf_pattern_eth_ipv6_gtpu_eh_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv6_gtpu_eh_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &second_inner_ipv4_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &second_inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &second_inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &second_inner_ipv4_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &second_inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &second_inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &second_inner_ipv4_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &second_inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &second_inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &second_inner_ipv4_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &second_inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &second_inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &second_inner_ipv4_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &second_inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &second_inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &second_inner_ipv4_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &second_inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &second_inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &second_inner_ipv4_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &second_inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &second_inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv4, AVF_RSS_TYPE_GTPU_IPV4,
    &second_inner_ipv4_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv4_udp, AVF_RSS_TYPE_GTPU_IPV4_UDP,
    &second_inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv4_tcp, AVF_RSS_TYPE_GTPU_IPV4_TCP,
    &second_inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv4_esp, AVF_RSS_TYPE_IPV4_ESP, &ipv4_esp_tmplt },
  { avf_pattern_eth_ipv4_udp_esp, AVF_RSS_TYPE_IPV4_ESP, &ipv4_udp_esp_tmplt },
  { avf_pattern_eth_ipv4_ah, AVF_RSS_TYPE_IPV4_AH, &ipv4_ah_tmplt },
  { avf_pattern_eth_ipv4_l2tpv3, AVF_RSS_TYPE_IPV4_L2TPV3,
    &ipv4_l2tpv3_tmplt },
  { avf_pattern_eth_ipv4_pfcp, AVF_RSS_TYPE_IPV4_PFCP, &ipv4_pfcp_tmplt },
  { avf_pattern_eth_ipv4_gtpc, AVF_ETH_RSS_IPV4, &ipv4_udp_gtpc_tmplt },
  { avf_pattern_eth_ecpri, AVF_ETH_RSS_ECPRI, &eth_ecpri_tmplt },
  { avf_pattern_eth_ipv4_ecpri, AVF_ETH_RSS_ECPRI, &ipv4_ecpri_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4, AVF_RSS_TYPE_INNER_IPV4,
    &inner_ipv4_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4, AVF_RSS_TYPE_INNER_IPV4,
    &inner_ipv4_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_tcp, AVF_RSS_TYPE_INNER_IPV4_TCP,
    &inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_tcp, AVF_RSS_TYPE_INNER_IPV4_TCP,
    &inner_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_udp, AVF_RSS_TYPE_INNER_IPV4_UDP,
    &inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_udp, AVF_RSS_TYPE_INNER_IPV4_UDP,
    &inner_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv4_udp_l2tpv2, AVF_RSS_TYPE_ETH_L2TPV2,
    &ipv4_l2tpv2_tmplt },
  { avf_pattern_eth_ipv4_udp_l2tpv2_ppp, AVF_RSS_TYPE_ETH_L2TPV2,
    &ipv4_l2tpv2_ppp_tmplt },
  { avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv4, AVF_RSS_TYPE_INNER_IPV4,
    &udp_l2tpv2_ppp_ipv4_tmplt },
  { avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv4_udp, AVF_RSS_TYPE_INNER_IPV4_UDP,
    &udp_l2tpv2_ppp_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv4_tcp, AVF_RSS_TYPE_INNER_IPV4_TCP,
    &udp_l2tpv2_ppp_ipv4_tcp_tmplt },
  { avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv4, AVF_RSS_TYPE_INNER_IPV4,
    &udp_l2tpv2_ppp_ipv4_tmplt },
  { avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv4_udp, AVF_RSS_TYPE_INNER_IPV4_UDP,
    &udp_l2tpv2_ppp_ipv4_udp_tmplt },
  { avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv4_tcp, AVF_RSS_TYPE_INNER_IPV4_TCP,
    &udp_l2tpv2_ppp_ipv4_tcp_tmplt },

  /* IPv6 */
  { avf_pattern_eth_ipv6, AVF_RSS_TYPE_OUTER_IPV6, &outer_ipv6_tmplt },
  { avf_pattern_eth_ipv6_frag_ext, AVF_RSS_TYPE_OUTER_IPV6_FRAG,
    &outer_ipv6_frag_tmplt },
  { avf_pattern_eth_ipv6_udp, AVF_RSS_TYPE_OUTER_IPV6_UDP,
    &outer_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv6_tcp, AVF_RSS_TYPE_OUTER_IPV6_TCP,
    &outer_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv6_sctp, AVF_RSS_TYPE_OUTER_IPV6_SCTP,
    &outer_ipv6_sctp_tmplt },
  { avf_pattern_eth_vlan_ipv6, AVF_RSS_TYPE_VLAN_IPV6, &outer_ipv6_tmplt },
  { avf_pattern_eth_vlan_ipv6_frag_ext, AVF_RSS_TYPE_OUTER_IPV6_FRAG,
    &outer_ipv6_frag_tmplt },
  { avf_pattern_eth_vlan_ipv6_udp, AVF_RSS_TYPE_VLAN_IPV6_UDP,
    &outer_ipv6_udp_tmplt },
  { avf_pattern_eth_vlan_ipv6_tcp, AVF_RSS_TYPE_VLAN_IPV6_TCP,
    &outer_ipv6_tcp_tmplt },
  { avf_pattern_eth_vlan_ipv6_sctp, AVF_RSS_TYPE_VLAN_IPV6_SCTP,
    &outer_ipv6_sctp_tmplt },
  { avf_pattern_eth_ipv6_gtpu, AVF_ETH_RSS_IPV6, &outer_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv4_gtpu_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &inner_ipv6_tmplt },
  { avf_pattern_eth_ipv4_gtpu_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv4_gtpu_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv6_gtpu_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &inner_ipv6_tmplt },
  { avf_pattern_eth_ipv6_gtpu_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv6_gtpu_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv4_gtpu_eh_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &inner_ipv6_tmplt },
  { avf_pattern_eth_ipv4_gtpu_eh_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv4_gtpu_eh_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv6_gtpu_eh_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &inner_ipv6_tmplt },
  { avf_pattern_eth_ipv6_gtpu_eh_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv6_gtpu_eh_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &second_inner_ipv6_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &second_inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &second_inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &second_inner_ipv6_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &second_inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &second_inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &second_inner_ipv6_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &second_inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &second_inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &second_inner_ipv6_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &second_inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &second_inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &second_inner_ipv6_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &second_inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv4_gtpu_eh_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &second_inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &second_inner_ipv6_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &second_inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_gtpu_eh_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &second_inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &second_inner_ipv6_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &second_inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv4_gtpu_eh_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &second_inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv6, AVF_RSS_TYPE_GTPU_IPV6,
    &second_inner_ipv6_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv6_udp, AVF_RSS_TYPE_GTPU_IPV6_UDP,
    &second_inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_gtpu_eh_ipv6_tcp, AVF_RSS_TYPE_GTPU_IPV6_TCP,
    &second_inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv6_esp, AVF_RSS_TYPE_IPV6_ESP, &ipv6_esp_tmplt },
  { avf_pattern_eth_ipv6_udp_esp, AVF_RSS_TYPE_IPV6_ESP, &ipv6_udp_esp_tmplt },
  { avf_pattern_eth_ipv6_ah, AVF_RSS_TYPE_IPV6_AH, &ipv6_ah_tmplt },
  { avf_pattern_eth_ipv6_l2tpv3, AVF_RSS_TYPE_IPV6_L2TPV3,
    &ipv6_l2tpv3_tmplt },
  { avf_pattern_eth_ipv6_pfcp, AVF_RSS_TYPE_IPV6_PFCP, &ipv6_pfcp_tmplt },
  { avf_pattern_eth_ipv6_gtpc, AVF_ETH_RSS_IPV6, &ipv6_udp_gtpc_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6, AVF_RSS_TYPE_INNER_IPV6,
    &inner_ipv6_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6, AVF_RSS_TYPE_INNER_IPV6,
    &inner_ipv6_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_tcp, AVF_RSS_TYPE_INNER_IPV6_TCP,
    &inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_tcp, AVF_RSS_TYPE_INNER_IPV6_TCP,
    &inner_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv4_gre_ipv6_udp, AVF_RSS_TYPE_INNER_IPV6_UDP,
    &inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv6_gre_ipv6_udp, AVF_RSS_TYPE_INNER_IPV6_UDP,
    &inner_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv6_udp_l2tpv2, AVF_RSS_TYPE_ETH_L2TPV2,
    &ipv6_l2tpv2_tmplt },
  { avf_pattern_eth_ipv6_udp_l2tpv2_ppp, AVF_RSS_TYPE_ETH_L2TPV2,
    &ipv6_l2tpv2_ppp_tmplt },
  { avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv6, AVF_RSS_TYPE_INNER_IPV6,
    &udp_l2tpv2_ppp_ipv6_tmplt },
  { avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv6_udp, AVF_RSS_TYPE_INNER_IPV6_UDP,
    &udp_l2tpv2_ppp_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv4_udp_l2tpv2_ppp_ipv6_tcp, AVF_RSS_TYPE_INNER_IPV6_TCP,
    &udp_l2tpv2_ppp_ipv6_tcp_tmplt },
  { avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv6, AVF_RSS_TYPE_INNER_IPV6,
    &udp_l2tpv2_ppp_ipv6_tmplt },
  { avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv6_udp, AVF_RSS_TYPE_INNER_IPV6_UDP,
    &udp_l2tpv2_ppp_ipv6_udp_tmplt },
  { avf_pattern_eth_ipv6_udp_l2tpv2_ppp_ipv6_tcp, AVF_RSS_TYPE_INNER_IPV6_TCP,
    &udp_l2tpv2_ppp_ipv6_tcp_tmplt },

};

static inline u64
avf_eth_rss_hf_refine (u64 rss_hf)
{
  if ((rss_hf & AVF_ETH_RSS_L3_SRC_ONLY) && (rss_hf & AVF_ETH_RSS_L3_DST_ONLY))
    rss_hf &= ~(AVF_ETH_RSS_L3_SRC_ONLY | AVF_ETH_RSS_L3_DST_ONLY);

  if ((rss_hf & AVF_ETH_RSS_L4_SRC_ONLY) && (rss_hf & AVF_ETH_RSS_L4_DST_ONLY))
    rss_hf &= ~(AVF_ETH_RSS_L4_SRC_ONLY | AVF_ETH_RSS_L4_DST_ONLY);

  return rss_hf;
}

static int
avf_any_invalid_rss_type (enum avf_eth_hash_function rss_func, u64 rss_type,
			  u64 allow_rss_type)
{
  u32 i;

  /**
   * Check if l3/l4 SRC/DST_ONLY is set for SYMMETRIC_TOEPLITZ
   * hash function.
   */
  if (rss_func == AVF_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ)
    {
      if (rss_type & (AVF_ETH_RSS_L3_SRC_ONLY | AVF_ETH_RSS_L3_DST_ONLY |
		      AVF_ETH_RSS_L4_SRC_ONLY | AVF_ETH_RSS_L4_DST_ONLY))
	return 1;

      if (!(rss_type &
	    (AVF_ETH_RSS_IPV4 | AVF_ETH_RSS_IPV6 |
	     AVF_ETH_RSS_NONFRAG_IPV4_UDP | AVF_ETH_RSS_NONFRAG_IPV6_UDP |
	     AVF_ETH_RSS_NONFRAG_IPV4_TCP | AVF_ETH_RSS_NONFRAG_IPV6_TCP |
	     AVF_ETH_RSS_NONFRAG_IPV4_SCTP | AVF_ETH_RSS_NONFRAG_IPV6_SCTP)))
	return 1;
    }

  /* check invalid combination */
  for (i = 0; i < vec_len (invalid_rss_comb); i++)
    {
      if (__builtin_popcountll (rss_type & invalid_rss_comb[i]) > 1)
	return 1;
    }

  /* check invalid RSS attribute */
  for (i = 0; i < vec_len (rss_attr_to_valid_type); i++)
    {
      struct rss_attr_type *rat = &rss_attr_to_valid_type[i];

      if (rat->attr & rss_type && !(rat->type & rss_type))
	return 1;
    }

  /* check not allowed RSS type */
  rss_type &= ~VALID_RSS_ATTR;

  return ((rss_type & allow_rss_type) != rss_type);
}

int
avf_rss_cfg_create (struct virtchnl_rss_cfg **rss_cfg, int tunnel_level)
{
  *rss_cfg = clib_mem_alloc (sizeof (**rss_cfg));

  clib_memset (*rss_cfg, 0, sizeof (**rss_cfg));

  (*rss_cfg)->proto_hdrs.tunnel_level = tunnel_level;

  return 0;
}

int
avf_rss_rcfg_destroy (struct virtchnl_rss_cfg *rss_cfg)
{
  clib_mem_free (rss_cfg);

  return 0;
}

/* refine proto hdrs base on gtpu rss type */
static void
avf_refine_proto_hdrs_gtpu (struct virtchnl_proto_hdrs *proto_hdrs,
			    u64 rss_type)
{
  struct virtchnl_proto_hdr *hdr;
  int i;

  if (!(rss_type & AVF_ETH_RSS_GTPU))
    return;

  for (i = 0; i < proto_hdrs->count; i++)
    {
      hdr = &proto_hdrs->proto_hdr[i];
      switch (hdr->type)
	{
	case VIRTCHNL_PROTO_HDR_GTPU_IP:
	  REFINE_PROTO_FLD (ADD, GTPU_IP_TEID);
	  break;
	default:
	  break;
	}
    }
}

static void
avf_hash_add_fragment_hdr (struct virtchnl_proto_hdrs *hdrs, int layer)
{
  struct virtchnl_proto_hdr *hdr1;
  struct virtchnl_proto_hdr *hdr2;
  int i;

  if (layer < 0 || layer > hdrs->count)
    return;

  /* shift headers layer */
  for (i = hdrs->count; i >= layer; i--)
    {
      hdr1 = &hdrs->proto_hdr[i];
      hdr2 = &hdrs->proto_hdr[i - 1];
      *hdr1 = *hdr2;
    }

  /* adding dummy fragment header */
  hdr1 = &hdrs->proto_hdr[layer];
  VIRTCHNL_SET_PROTO_HDR_TYPE (hdr1, IPV4_FRAG);
  hdrs->count = ++layer;
}

/* refine proto hdrs base on l2, l3, l4 rss type */
static void
avf_refine_proto_hdrs_l234 (struct virtchnl_proto_hdrs *proto_hdrs,
			    u64 rss_type)
{
  struct virtchnl_proto_hdr *hdr;
  int i;

  for (i = 0; i < proto_hdrs->count; i++)
    {
      hdr = &proto_hdrs->proto_hdr[i];
      switch (hdr->type)
	{
	case VIRTCHNL_PROTO_HDR_ETH:
	  if (!(rss_type & AVF_ETH_RSS_ETH))
	    hdr->field_selector = 0;
	  else if (rss_type & AVF_ETH_RSS_L2_SRC_ONLY)
	    REFINE_PROTO_FLD (DEL, ETH_DST);
	  else if (rss_type & AVF_ETH_RSS_L2_DST_ONLY)
	    REFINE_PROTO_FLD (DEL, ETH_SRC);
	  break;
	case VIRTCHNL_PROTO_HDR_IPV4:
	  if (rss_type &
	      (AVF_ETH_RSS_IPV4 | AVF_ETH_RSS_FRAG_IPV4 |
	       AVF_ETH_RSS_NONFRAG_IPV4_UDP | AVF_ETH_RSS_NONFRAG_IPV4_TCP |
	       AVF_ETH_RSS_NONFRAG_IPV4_SCTP))
	    {
	      if (rss_type & AVF_ETH_RSS_FRAG_IPV4)
		{
		  avf_hash_add_fragment_hdr (proto_hdrs, i + 1);
		}
	      else if (rss_type & AVF_ETH_RSS_L3_SRC_ONLY)
		{
		  REFINE_PROTO_FLD (DEL, IPV4_DST);
		}
	      else if (rss_type & AVF_ETH_RSS_L3_DST_ONLY)
		{
		  REFINE_PROTO_FLD (DEL, IPV4_SRC);
		}
	      else if (rss_type &
		       (AVF_ETH_RSS_L4_SRC_ONLY | AVF_ETH_RSS_L4_DST_ONLY))
		{
		  REFINE_PROTO_FLD (DEL, IPV4_DST);
		  REFINE_PROTO_FLD (DEL, IPV4_SRC);
		}
	    }
	  else
	    {
	      hdr->field_selector = 0;
	    }

	  if (rss_type & AVF_ETH_RSS_IPV4_CHKSUM)
	    REFINE_PROTO_FLD (ADD, IPV4_CHKSUM);

	  break;
	case VIRTCHNL_PROTO_HDR_IPV4_FRAG:
	  if (rss_type &
	      (AVF_ETH_RSS_IPV4 | AVF_ETH_RSS_FRAG_IPV4 |
	       AVF_ETH_RSS_NONFRAG_IPV4_UDP | AVF_ETH_RSS_NONFRAG_IPV4_TCP |
	       AVF_ETH_RSS_NONFRAG_IPV4_SCTP))
	    {
	      if (rss_type & AVF_ETH_RSS_FRAG_IPV4)
		REFINE_PROTO_FLD (ADD, IPV4_FRAG_PKID);
	    }
	  else
	    {
	      hdr->field_selector = 0;
	    }

	  if (rss_type & AVF_ETH_RSS_IPV4_CHKSUM)
	    REFINE_PROTO_FLD (ADD, IPV4_CHKSUM);

	  break;
	case VIRTCHNL_PROTO_HDR_IPV6:
	  if (rss_type &
	      (AVF_ETH_RSS_IPV6 | AVF_ETH_RSS_FRAG_IPV6 |
	       AVF_ETH_RSS_NONFRAG_IPV6_UDP | AVF_ETH_RSS_NONFRAG_IPV6_TCP |
	       AVF_ETH_RSS_NONFRAG_IPV6_SCTP))
	    {
	      if (rss_type & AVF_ETH_RSS_L3_SRC_ONLY)
		{
		  REFINE_PROTO_FLD (DEL, IPV6_DST);
		}
	      else if (rss_type & AVF_ETH_RSS_L3_DST_ONLY)
		{
		  REFINE_PROTO_FLD (DEL, IPV6_SRC);
		}
	      else if (rss_type &
		       (AVF_ETH_RSS_L4_SRC_ONLY | AVF_ETH_RSS_L4_DST_ONLY))
		{
		  REFINE_PROTO_FLD (DEL, IPV6_DST);
		  REFINE_PROTO_FLD (DEL, IPV6_SRC);
		}
	    }
	  else
	    {
	      hdr->field_selector = 0;
	    }
	  if (rss_type & AVF_ETH_RSS_L3_PRE64)
	    {
	      if (REFINE_PROTO_FLD (TEST, IPV6_SRC))
		REPALCE_PROTO_FLD (IPV6_SRC, IPV6_PREFIX64_SRC);
	      if (REFINE_PROTO_FLD (TEST, IPV6_DST))
		REPALCE_PROTO_FLD (IPV6_DST, IPV6_PREFIX64_DST);
	    }
	  break;
	case VIRTCHNL_PROTO_HDR_IPV6_EH_FRAG:
	  if (rss_type & AVF_ETH_RSS_FRAG_IPV6)
	    REFINE_PROTO_FLD (ADD, IPV6_EH_FRAG_PKID);
	  else
	    hdr->field_selector = 0;

	  break;
	case VIRTCHNL_PROTO_HDR_UDP:
	  if (rss_type &
	      (AVF_ETH_RSS_NONFRAG_IPV4_UDP | AVF_ETH_RSS_NONFRAG_IPV6_UDP))
	    {
	      if (rss_type & AVF_ETH_RSS_L4_SRC_ONLY)
		REFINE_PROTO_FLD (DEL, UDP_DST_PORT);
	      else if (rss_type & AVF_ETH_RSS_L4_DST_ONLY)
		REFINE_PROTO_FLD (DEL, UDP_SRC_PORT);
	      else if (rss_type &
		       (AVF_ETH_RSS_L3_SRC_ONLY | AVF_ETH_RSS_L3_DST_ONLY))
		hdr->field_selector = 0;
	    }
	  else
	    {
	      hdr->field_selector = 0;
	    }

	  if (rss_type & AVF_ETH_RSS_L4_CHKSUM)
	    REFINE_PROTO_FLD (ADD, UDP_CHKSUM);
	  break;
	case VIRTCHNL_PROTO_HDR_TCP:
	  if (rss_type &
	      (AVF_ETH_RSS_NONFRAG_IPV4_TCP | AVF_ETH_RSS_NONFRAG_IPV6_TCP))
	    {
	      if (rss_type & AVF_ETH_RSS_L4_SRC_ONLY)
		REFINE_PROTO_FLD (DEL, TCP_DST_PORT);
	      else if (rss_type & AVF_ETH_RSS_L4_DST_ONLY)
		REFINE_PROTO_FLD (DEL, TCP_SRC_PORT);
	      else if (rss_type &
		       (AVF_ETH_RSS_L3_SRC_ONLY | AVF_ETH_RSS_L3_DST_ONLY))
		hdr->field_selector = 0;
	    }
	  else
	    {
	      hdr->field_selector = 0;
	    }

	  if (rss_type & AVF_ETH_RSS_L4_CHKSUM)
	    REFINE_PROTO_FLD (ADD, TCP_CHKSUM);
	  break;
	case VIRTCHNL_PROTO_HDR_SCTP:
	  if (rss_type &
	      (AVF_ETH_RSS_NONFRAG_IPV4_SCTP | AVF_ETH_RSS_NONFRAG_IPV6_SCTP))
	    {
	      if (rss_type & AVF_ETH_RSS_L4_SRC_ONLY)
		REFINE_PROTO_FLD (DEL, SCTP_DST_PORT);
	      else if (rss_type & AVF_ETH_RSS_L4_DST_ONLY)
		REFINE_PROTO_FLD (DEL, SCTP_SRC_PORT);
	      else if (rss_type &
		       (AVF_ETH_RSS_L3_SRC_ONLY | AVF_ETH_RSS_L3_DST_ONLY))
		hdr->field_selector = 0;
	    }
	  else
	    {
	      hdr->field_selector = 0;
	    }

	  if (rss_type & AVF_ETH_RSS_L4_CHKSUM)
	    REFINE_PROTO_FLD (ADD, SCTP_CHKSUM);
	  break;
	case VIRTCHNL_PROTO_HDR_S_VLAN:
	  if (!(rss_type & AVF_ETH_RSS_S_VLAN))
	    hdr->field_selector = 0;
	  break;
	case VIRTCHNL_PROTO_HDR_C_VLAN:
	  if (!(rss_type & AVF_ETH_RSS_C_VLAN))
	    hdr->field_selector = 0;
	  break;
	case VIRTCHNL_PROTO_HDR_L2TPV3:
	  if (!(rss_type & AVF_ETH_RSS_L2TPV3))
	    hdr->field_selector = 0;
	  break;
	case VIRTCHNL_PROTO_HDR_ESP:
	  if (!(rss_type & AVF_ETH_RSS_ESP))
	    hdr->field_selector = 0;
	  break;
	case VIRTCHNL_PROTO_HDR_AH:
	  if (!(rss_type & AVF_ETH_RSS_AH))
	    hdr->field_selector = 0;
	  break;
	case VIRTCHNL_PROTO_HDR_PFCP:
	  if (!(rss_type & AVF_ETH_RSS_PFCP))
	    hdr->field_selector = 0;
	  break;
	case VIRTCHNL_PROTO_HDR_ECPRI:
	  if (!(rss_type & AVF_ETH_RSS_ECPRI))
	    hdr->field_selector = 0;
	  break;
	case VIRTCHNL_PROTO_HDR_L2TPV2:
	  if (!(rss_type & AVF_ETH_RSS_L2TPV2))
	    hdr->field_selector = 0;
	  break;
	default:
	  break;
	}
    }
}

static void
avf_refine_proto_hdrs_by_pattern (struct virtchnl_proto_hdrs *proto_hdrs,
				  u64 phint)
{
  struct virtchnl_proto_hdr *hdr1;
  struct virtchnl_proto_hdr *hdr2;
  int i, shift_count = 1;
  int tun_lvl = proto_hdrs->tunnel_level;

  if (!(phint & AVF_PHINT_GTPU_MSK) && !(phint & AVF_PHINT_GRE))
    return;

  while (tun_lvl)
    {
      if (phint & AVF_PHINT_LAYERS_MSK)
	shift_count = 2;

      /* shift headers layer */
      for (i = proto_hdrs->count - 1 + shift_count; i > shift_count - 1; i--)
	{
	  hdr1 = &proto_hdrs->proto_hdr[i];
	  hdr2 = &proto_hdrs->proto_hdr[i - shift_count];
	  *hdr1 = *hdr2;
	}

      if (shift_count == 1)
	{
	  /* adding tunnel header at layer 0 */
	  hdr1 = &proto_hdrs->proto_hdr[0];
	}
      else
	{
	  /* adding tunnel header and outer ip header */
	  hdr1 = &proto_hdrs->proto_hdr[1];
	  hdr2 = &proto_hdrs->proto_hdr[0];
	  hdr2->field_selector = 0;
	  proto_hdrs->count++;
	  tun_lvl--;

	  if (tun_lvl == TUNNEL_LEVEL_OUTER)
	    {
	      if (phint & AVF_PHINT_OUTER_IPV4)
		VIRTCHNL_SET_PROTO_HDR_TYPE (hdr2, IPV4);
	      else if (phint & AVF_PHINT_OUTER_IPV6)
		VIRTCHNL_SET_PROTO_HDR_TYPE (hdr2, IPV6);
	    }
	  else if (tun_lvl == TUNNEL_LEVEL_INNER)
	    {
	      if (phint & AVF_PHINT_MID_IPV4)
		VIRTCHNL_SET_PROTO_HDR_TYPE (hdr2, IPV4);
	      else if (phint & AVF_PHINT_MID_IPV6)
		VIRTCHNL_SET_PROTO_HDR_TYPE (hdr2, IPV6);
	    }
	}

      hdr1->field_selector = 0;
      proto_hdrs->count++;

      if (phint & AVF_PHINT_GTPU_EH_DWN)
	VIRTCHNL_SET_PROTO_HDR_TYPE (hdr1, GTPU_EH_PDU_DWN);
      else if (phint & AVF_PHINT_GTPU_EH_UP)
	VIRTCHNL_SET_PROTO_HDR_TYPE (hdr1, GTPU_EH_PDU_UP);
      else if (phint & AVF_PHINT_GTPU_EH)
	VIRTCHNL_SET_PROTO_HDR_TYPE (hdr1, GTPU_EH);
      else if (phint & AVF_PHINT_GTPU)
	VIRTCHNL_SET_PROTO_HDR_TYPE (hdr1, GTPU_IP);

      if (phint & AVF_PHINT_GRE)
	{
	  if (phint & AVF_PHINT_GTPU)
	    {
	      /* if GTPoGRE, add GRE header at the outer tunnel  */
	      if (tun_lvl == TUNNEL_LEVEL_OUTER)
		VIRTCHNL_SET_PROTO_HDR_TYPE (hdr1, GRE);
	    }
	  else
	    {
	      VIRTCHNL_SET_PROTO_HDR_TYPE (hdr1, GRE);
	    }
	}
    }
  proto_hdrs->tunnel_level = tun_lvl;
}

static void
avf_refine_proto_hdrs (struct virtchnl_proto_hdrs *proto_hdrs, u64 rss_type,
		       u64 phint)
{
  avf_refine_proto_hdrs_l234 (proto_hdrs, rss_type);
  avf_refine_proto_hdrs_by_pattern (proto_hdrs, phint);
  avf_refine_proto_hdrs_gtpu (proto_hdrs, rss_type);
}

static int
avf_rss_parse_action (const struct avf_flow_action actions[],
		      struct virtchnl_rss_cfg *rss_cfg,
		      struct avf_pattern_match_item *match_item, u64 phint,
		      struct avf_flow_error *error)
{
  const struct avf_flow_action_rss *rss;
  const struct avf_flow_action *action;
  u64 rss_type;
  int ret;

  for (action = actions; action->type != AVF_FLOW_ACTION_TYPE_END; action++)
    {
      switch (action->type)
	{
	case AVF_FLOW_ACTION_TYPE_RSS:
	  rss = action->conf;

	  if (rss->func == AVF_ETH_HASH_FUNCTION_SIMPLE_XOR)
	    {
	      rss_cfg->rss_algorithm = VIRTCHNL_RSS_ALG_XOR_ASYMMETRIC;
	      ret = avf_flow_error_set (error, AVF_FAILURE,
					AVF_FLOW_ERROR_TYPE_ACTION, actions,
					"simple xor is not supported.");
	      return ret;
	    }
	  else if (rss->func == AVF_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ)
	    {
	      rss_cfg->rss_algorithm = VIRTCHNL_RSS_ALG_TOEPLITZ_SYMMETRIC;
	    }
	  else
	    {
	      rss_cfg->rss_algorithm = VIRTCHNL_RSS_ALG_TOEPLITZ_ASYMMETRIC;
	    }

	  if (rss->level)
	    return avf_flow_error_set (
	      error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION, actions,
	      "a nonzero RSS encapsulation level is not supported");

	  if (rss->key_len)
	    return avf_flow_error_set (
	      error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION, actions,
	      "a nonzero RSS key_len is not supported");

	  if (rss->queue_num)
	    return avf_flow_error_set (
	      error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION, actions,
	      "a non-NULL RSS queue is not supported");

	  if (phint == AVF_PHINT_RAW)
	    break;

	  rss_type = avf_eth_rss_hf_refine (rss->types);

	  if (avf_any_invalid_rss_type (rss->func, rss_type,
					match_item->input_set_mask))
	    return avf_flow_error_set (error, AVF_FAILURE,
				       AVF_FLOW_ERROR_TYPE_ACTION, actions,
				       "RSS type not supported");

	  memcpy (&rss_cfg->proto_hdrs, match_item->meta,
		  sizeof (struct virtchnl_proto_hdrs));

	  avf_refine_proto_hdrs (&rss_cfg->proto_hdrs, rss_type, phint);

	  break;

	default:
	  return avf_flow_error_set (error, AVF_FAILURE,
				     AVF_FLOW_ERROR_TYPE_ACTION, actions,
				     "Invalid action.");
	}
    }

  return 0;
}

static int
avf_rss_parse_generic_pattern (struct virtchnl_rss_cfg *rss_cfg,
			       struct avf_flow_item avf_items[],
			       struct avf_flow_error *error)
{
  struct avf_flow_item *item = avf_items;
  u8 *pkt_buf, *msk_buf;
  u16 spec_len, pkt_len;

  spec_len = clib_strnlen (item->spec, VIRTCHNL_MAX_SIZE_GEN_PACKET);
  pkt_len = spec_len / 2;

  pkt_buf = clib_mem_alloc (pkt_len);
  msk_buf = clib_mem_alloc (pkt_len);

  avf_parse_generic_pattern (item, pkt_buf, msk_buf, spec_len);

  clib_memcpy (rss_cfg->proto_hdrs.raw.spec, pkt_buf, pkt_len);
  clib_memcpy (rss_cfg->proto_hdrs.raw.mask, msk_buf, pkt_len);

  rss_cfg->proto_hdrs.count = 0;
  rss_cfg->proto_hdrs.tunnel_level = 0;
  rss_cfg->proto_hdrs.raw.pkt_len = pkt_len;

  clib_mem_free (pkt_buf);
  clib_mem_free (msk_buf);

  return 0;
}

/* Find the first VOID or non-VOID item pointer */
static const struct avf_flow_item *
avf_find_first_item (const struct avf_flow_item *item, int is_void)
{
  int is_find;

  while (item->type != AVF_FLOW_ITEM_TYPE_END)
    {
      if (is_void)
	is_find = item->type == AVF_FLOW_ITEM_TYPE_VOID;
      else
	is_find = item->type != AVF_FLOW_ITEM_TYPE_VOID;
      if (is_find)
	break;
      item++;
    }
  return item;
}

/* Skip all VOID items of the pattern */
static void
avf_pattern_skip_void_item (struct avf_flow_item *items,
			    const struct avf_flow_item *pattern)
{
  u32 cpy_count = 0;
  const struct avf_flow_item *pb = pattern, *pe = pattern;

  for (;;)
    {
      /* Find a non-void item first */
      pb = avf_find_first_item (pb, 0);
      if (pb->type == AVF_FLOW_ITEM_TYPE_END)
	{
	  pe = pb;
	  break;
	}

      /* Find a void item */
      pe = avf_find_first_item (pb + 1, 1);

      cpy_count = pe - pb;
      clib_memcpy (items, pb, sizeof (struct avf_flow_item) * cpy_count);

      items += cpy_count;

      if (pe->type == AVF_FLOW_ITEM_TYPE_END)
	break;

      pb = pe + 1;
    }
  /* Copy the END item. */
  clib_memcpy (items, pe, sizeof (struct avf_flow_item));
}

/* Check if the pattern matches a supported item type array */
static int
avf_match_pattern (enum avf_flow_item_type *item_array,
		   const struct avf_flow_item *pattern)
{
  const struct avf_flow_item *item = pattern;

  while ((*item_array == item->type) &&
	 (*item_array != AVF_FLOW_ITEM_TYPE_END))
    {
      item_array++;
      item++;
    }

  return (*item_array == AVF_FLOW_ITEM_TYPE_END &&
	  item->type == AVF_FLOW_ITEM_TYPE_END);
}

static int
avf_rss_search_pattern_match_item (const struct avf_flow_item pattern[],
				   struct avf_pattern_match_item **match_item,
				   struct avf_flow_error *error)
{
  u16 i = 0;
  struct avf_pattern_match_item *array = avf_hash_pattern_list;
  u32 array_len =
    sizeof (avf_hash_pattern_list) / sizeof (avf_hash_pattern_list[0]);
  /* need free by each filter */
  struct avf_flow_item *items; /* used for pattern without VOID items */
  u32 item_num = 0;	       /* non-void item number */

  /* Get the non-void item number of pattern */
  while ((pattern + i)->type != AVF_FLOW_ITEM_TYPE_END)
    {
      if ((pattern + i)->type != AVF_FLOW_ITEM_TYPE_VOID)
	item_num++;
      i++;
    }
  item_num++;

  items = clib_mem_alloc (item_num * sizeof (struct avf_flow_item));
  avf_pattern_skip_void_item (items, pattern);

  for (i = 0; i < array_len; i++)
    if (avf_match_pattern (array[i].pattern_list, items))
      {
	*match_item = &array[i];
	clib_mem_free (items);
	return 0;
      }
  avf_flow_error_set (error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ITEM, pattern,
		      "Unsupported pattern");

  *match_item = NULL;
  clib_mem_free (items);
  return -1;
}

static void
avf_rss_parse_pattern (const struct avf_flow_item pattern[], u64 *phint)
{
  const struct avf_flow_item *item = pattern;
  const struct avf_gtp_psc_hdr *psc;

  for (item = pattern; item->type != AVF_FLOW_ITEM_TYPE_END; item++)
    {

      switch (item->type)
	{
	case AVF_FLOW_ITEM_TYPE_RAW:
	  *phint |= AVF_PHINT_RAW;
	  break;
	case AVF_FLOW_ITEM_TYPE_IPV4:
	  if (!(*phint & AVF_PHINT_GTPU_MSK) && !(*phint & AVF_PHINT_GRE) &&
	      !(*phint & AVF_PHINT_L2TPV2))
	    *phint |= AVF_PHINT_OUTER_IPV4;
	  if ((*phint & AVF_PHINT_GRE) && !(*phint & AVF_PHINT_GTPU_MSK))
	    *phint |= AVF_PHINT_MID_IPV4;
	  break;
	case AVF_FLOW_ITEM_TYPE_IPV6:
	  if (!(*phint & AVF_PHINT_GTPU_MSK) && !(*phint & AVF_PHINT_GRE) &&
	      !(*phint & AVF_PHINT_L2TPV2))
	    *phint |= AVF_PHINT_OUTER_IPV6;
	  if ((*phint & AVF_PHINT_GRE) && !(*phint & AVF_PHINT_GTPU_MSK))
	    *phint |= AVF_PHINT_MID_IPV6;
	  break;
	case AVF_FLOW_ITEM_TYPE_GTPU:
	  *phint |= AVF_PHINT_GTPU;
	  break;
	case AVF_FLOW_ITEM_TYPE_GTP_PSC:
	  *phint |= AVF_PHINT_GTPU_EH;
	  psc = item->spec;
	  if (!psc)
	    break;
	  else if (psc->pdu_type == AVF_GTPU_EH_UPLINK)
	    *phint |= AVF_PHINT_GTPU_EH_UP;
	  else if (psc->pdu_type == AVF_GTPU_EH_DWNLINK)
	    *phint |= AVF_PHINT_GTPU_EH_DWN;
	  break;
	case AVF_FLOW_ITEM_TYPE_GRE:
	  *phint |= AVF_PHINT_GRE;
	  break;
	default:
	  break;
	}
    }
}

int
avf_rss_parse_pattern_action (struct avf_flow_item avf_items[],
			      struct avf_flow_action avf_actions[],
			      struct virtchnl_rss_cfg *rss_cfg,
			      struct avf_flow_error *error)
{
  struct avf_pattern_match_item *match_item = NULL;
  u64 pattern_hint = 0;
  int ret = 0;

  ret = avf_rss_search_pattern_match_item (avf_items, &match_item, error);
  if (ret)
    return ret;

  avf_rss_parse_pattern (avf_items, &pattern_hint);

  if (pattern_hint == AVF_PHINT_RAW)
    {
      ret = avf_rss_parse_generic_pattern (rss_cfg, avf_items, error);
      if (ret)
	return ret;
    }

  ret = avf_rss_parse_action (avf_actions, rss_cfg, match_item, pattern_hint,
			      error);
  return ret;
}

int
avf_rss_rule_create (struct avf_flow_vc_ctx *ctx,
		     struct virtchnl_rss_cfg *rss_cfg)
{
  int ret;

  ret = ctx->vc_op (ctx->vc_hdl, VIRTCHNL_ADV_OP_ADD_RSS_CFG, rss_cfg,
		    sizeof (*rss_cfg), 0, 0);

  return ret;
}

int
avf_rss_rule_destroy (struct avf_flow_vc_ctx *ctx,
		      struct virtchnl_rss_cfg *rss_cfg)
{
  int ret;

  ret = ctx->vc_op (ctx->vc_hdl, VIRTCHNL_ADV_OP_DEL_RSS_CFG, rss_cfg,
		    sizeof (*rss_cfg), 0, 0);

  return ret;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
