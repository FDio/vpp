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

#ifndef _IAVF_PKTS_H_
#define _IAVF_PKTS_H_

/**
 * This header file define packet structure which fdir will use,
 * also can use OS packet definition.
 */

struct iavf_flow_action_mark
{
  u32 id; /**< Integer value to return with packets. */
};

/**
 * Match IP Authentication Header (AH), RFC 4302
 */
struct iavf_ah_hdr
{
  u32 next_hdr:8;
  u32 payload_len:8;
  u32 reserved:16;
  u32 spi;
  u32 seq_num;
};

/**
 * ESP Header
 */
struct iavf_esp_hdr
{
  __be32 spi; /**< Security Parameters Index */
  __be32 seq; /**< packet sequence number */
} __avf_packed;

/**
 * Match PFCP Header
 */
struct iavf_pfcp_hdr
{
  u8 s_field;
  u8 msg_type;
  __be16 msg_len;
  __be64 seid;
};

/**
 * Matches a L2TPv3 over IP header.
 */
struct iavf_l2tpv3oip_hdr
{
  __be32 session_id; /**< Session ID. */
};

/**
 * Matches a GTP PDU extension header with type 0x85.
 */
struct iavf_gtp_psc_hdr
{
  u8 pdu_type; /**< PDU type. */
  u8 qfi;      /**< QoS flow identifier. */
};

/**
 * Matches a GTPv1 header.
 */
struct iavf_gtp_hdr
{
  /**
   * Version (3b), protocol type (1b), reserved (1b),
   * Extension header flag (1b),
   * Sequence number flag (1b),
   * N-PDU number flag (1b).
   */
  u8 v_pt_rsv_flags;
  u8 msg_type;	  /**< Message type. */
  __be16 msg_len; /**< Message length. */
  __be32 teid;	  /**< Tunnel endpoint identifier. */
};

/**
 * SCTP Header
 */
struct iavf_sctp_hdr
{
  __be16 src_port; /**< Source port. */
  __be16 dst_port; /**< Destin port. */
  __be32 tag;	   /**< Validation tag. */
  __be32 cksum;	   /**< Checksum. */
} __avf_packed;

/**
 * IPv4 Header
 */
struct iavf_ipv4_hdr
{
  u8 version_ihl;	  /**< version and header length */
  u8 type_of_service;	  /**< type of service */
  __be16 total_length;	  /**< length of packet */
  __be16 packet_id;	  /**< packet ID */
  __be16 fragment_offset; /**< fragmentation offset */
  u8 time_to_live;	  /**< time to live */
  u8 next_proto_id;	  /**< protocol ID */
  __be16 hdr_checksum;	  /**< header checksum */
  __be32 src_addr;	  /**< source address */
  __be32 dst_addr;	  /**< destination address */
} __avf_packed;

/**
 * TCP Header
 */
struct iavf_tcp_hdr
{
  __be16 src_port; /**< TCP source port. */
  __be16 dst_port; /**< TCP destination port. */
  __be32 sent_seq; /**< TX data sequence number. */
  __be32 recv_ack; /**< RX data acknowledgment sequence number. */
  u8 data_off;	   /**< Data offset. */
  u8 tcp_flags;	   /**< TCP flags */
  __be16 rx_win;   /**< RX flow control window. */
  __be16 cksum;	   /**< TCP checksum. */
  __be16 tcp_urp;  /**< TCP urgent pointer, if any. */
} __avf_packed;

/**
 * UDP Header
 */
struct iavf_udp_hdr
{
  __be16 src_port;    /**< UDP source port. */
  __be16 dst_port;    /**< UDP destination port. */
  __be16 dgram_len;   /**< UDP datagram length */
  __be16 dgram_cksum; /**< UDP datagram checksum */
} __avf_packed;

/**
 * IPv6 Header
 */
struct iavf_ipv6_hdr
{
  __be32 vtc_flow;    /**< IP version, traffic class & flow label. */
  __be16 payload_len; /**< IP packet length - includes header size */
  u8 proto;	      /**< Protocol, next header. */
  u8 hop_limits;      /**< Hop limits. */
  u8 src_addr[16];    /**< IP address of source host. */
  u8 dst_addr[16];    /**< IP address of destination host(s). */
} __avf_packed;

#define IAVF_ETHER_ADDR_LEN 6
struct iavf_ether_addr
{
  u8 addr_bytes[IAVF_ETHER_ADDR_LEN]; /**< Addr bytes in tx order */
} __avf_aligned (2);

struct iavf_flow_eth_hdr
{
  struct iavf_ether_addr dst; /**< Destination MAC. */
  struct iavf_ether_addr src; /**< Source MAC. */
  __be16 type;		      /**< EtherType or TPID. */
};

struct iavf_flow_gtp_psc_hdr
{
  u8 pdu_type; /**< PDU type. */
  u8 qfi;      /**< QoS flow identifier. */
};

struct iavf_flow_l2tpv3oip_hdr
{
  __be32 session_id; /**< Session ID. */
};

#endif /* _IAVF_PKTS_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
