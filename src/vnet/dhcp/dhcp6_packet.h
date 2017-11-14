#ifndef included_vnet_dhcp6_packet_h
#define included_vnet_dhcp6_packet_h

/*
 * DHCP packet format
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
 */
#include <vnet/ip/ip6_packet.h>

// #define DHCP_VRF_NAME_MAX_LEN L3VM_MAX_NAME_STR_LEN
// #define DHCPV6_MAX_VRF_NAME_LEN L3VM_MAX_NAME_STR_LEN
#define DHCP_MAX_RELAY_ADDR    16
#define PROTO_UDP 17
#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547
#define HOP_COUNT_LIMIT  32
#define DHCPV6_CISCO_ENT_NUM 9

/*
 * DHCPv6 message types
 */
typedef enum dhcpv6_msg_type_{
    DHCPV6_MSG_SOLICIT              = 1,
    DHCPV6_MSG_ADVERTISE            = 2,
    DHCPV6_MSG_REQUEST              = 3,
    DHCPV6_MSG_CONFIRM              = 4,
    DHCPV6_MSG_RENEW                = 5,
    DHCPV6_MSG_REBIND               = 6,
    DHCPV6_MSG_REPLY                = 7,
    DHCPV6_MSG_RELEASE              = 8,
    DHCPV6_MSG_DECLINE              = 9,
    DHCPV6_MSG_RECONFIGURE          = 10,
    DHCPV6_MSG_INFORMATION_REQUEST  = 11,
    DHCPV6_MSG_RELAY_FORW           = 12,
    DHCPV6_MSG_RELAY_REPL           = 13,
} dhcpv6_msg_type_t;

/*
 * DHCPv6 options types
 */
enum {
    DHCPV6_OPTION_CLIENTID      = 1,
    DHCPV6_OPTION_SERVERID      = 2,
    DHCPV6_OPTION_IA_NA         = 3,
    DHCPV6_OPTION_IA_TA         = 4,
    DHCPV6_OPTION_IAADDR        = 5,
    DHCPV6_OPTION_ORO           = 6,
    DHCPV6_OPTION_PREFERENCE    = 7,
    DHCPV6_OPTION_ELAPSED_TIME  = 8,
    DHCPV6_OPTION_RELAY_MSG     = 9,
    DHCPV6_OPTION_AUTH          = 11,
    DHCPV6_OPTION_UNICAST       = 12,
    DHCPV6_OPTION_STATUS_CODE   = 13,
    DHCPV6_OPTION_RAPID_COMMIT  = 14,
    DHCPV6_OPTION_USER_CLASS    = 15,
    DHCPV6_OPTION_VENDOR_CLASS  = 16,
    DHCPV6_OPTION_VENDOR_OPTS   = 17,
    DHCPV6_OPTION_INTERFACE_ID  = 18, // relay agent fills this
    DHCPV6_OPTION_RECONF_MSG    = 19,
    DHCPV6_OPTION_RECONF_ACCEPT = 20,
    DHCPV6_OPTION_REMOTEID      = 37, // relay agent fills this
    DHCPV6_OPTION_VSS      = 68, // relay agent fills this
    DHCPV6_OPTION_CLIENT_LINK_LAYER_ADDRESS = 79, 
    DHCPV6_OPTION_MAX
};

/*
* DHCPv6 status codes
 */
enum {
    DHCPV6_STATUS_SUCCESS       = 0,
    DHCPV6_STATUS_UNSPEC_FAIL   = 1,
    DHCPV6_STATUS_NOADDRS_AVAIL = 2,
    DHCPV6_STATUS_NO_BINDING    = 3,
    DHCPV6_STATUS_NOT_ONLINK    = 4,
    DHCPV6_STATUS_USE_MULTICAST = 5,
};

/*
 * DHCPv6 DUID types
 */
enum {
    DHCPV6_DUID_LLT =   1,  /* DUID Based on Link-layer Address Plus Time */
    DHCPV6_DUID_EN =    2,  /* DUID Based on Enterprise Number */
    DHCPV6_DUID_LL =    3,  /* DUID Based on Link-layer Address */
};

//Structure for DHCPv6 payload from client
typedef struct dhcpv6_hdr_ {
    union {
        u8 msg_type; //DHCP msg type
        u32 xid;     // transaction id
    }u;
    u8  data[0];
} dhcpv6_header_t;



typedef CLIB_PACKED (struct dhcpv6_relay_ctx_ {
    dhcpv6_header_t *pkt;
    u32  pkt_len;
    u32  dhcpv6_len; //DHCPv6 payload load
//    if_ordinal iod;
    u32 if_index;
    u32 ctx_id;
    char ctx_name[32+1];
    u8 dhcp_msg_type;
}) dhcpv6_relay_ctx_t;

//Structure for DHCPv6 RELAY-FORWARD and DHCPv6 RELAY-REPLY pkts
typedef CLIB_PACKED (struct dhcpv6_relay_hdr_ {
    u8           msg_type;
    u8           hop_count;
    ip6_address_t    link_addr;
    ip6_address_t    peer_addr;
    u8           data[0];
}) dhcpv6_relay_hdr_t;

typedef enum dhcp_stats_action_type_ {
    DHCP_STATS_ACTION_FORWARDED=1,
    DHCP_STATS_ACTION_RECEIVED,
    DHCP_STATS_ACTION_DROPPED
} dhcp_stats_action_type_t;
//Generic counters for a packet
typedef  struct dhcp_stats_counters_ {
    u64  rx_pkts; //counter for received pkts
    u64  tx_pkts; //counter for forwarded pkts
    u64  drops;   //counter for dropped pkts
} dhcp_stats_counters_t;


typedef enum dhcpv6_stats_drop_reason_ {
    DHCPV6_RELAY_PKT_DROP_RELAYDISABLE = 1,
    DHCPV6_RELAY_PKT_DROP_MAX_HOPS,
    DHCPV6_RELAY_PKT_DROP_VALIDATION_FAIL,
    DHCPV6_RELAY_PKT_DROP_UNKNOWN_OP_INTF,
    DHCPV6_RELAY_PKT_DROP_BAD_CONTEXT,
    DHCPV6_RELAY_PKT_DROP_OPT_INSERT_FAIL,
    DHCPV6_RELAY_PKT_DROP_REPLY_FROM_CLIENT,
} dhcpv6_stats_drop_reason_t;

typedef CLIB_PACKED (struct {
  u16 option;
  u16 length;
  u8 data[0];
}) dhcpv6_option_t;

typedef CLIB_PACKED (struct {
  dhcpv6_option_t opt;
  u32 int_idx;
}) dhcpv6_int_id_t;

typedef CLIB_PACKED (struct {
  dhcpv6_option_t opt;
  u8 vss_type;
  u8 data[0];
}) dhcpv6_vss_t;

typedef CLIB_PACKED (struct {
  dhcpv6_option_t opt;
  u32 ent_num;
  u32 rmt_id;
}) dhcpv6_rmt_id_t;

typedef CLIB_PACKED (struct {
  dhcpv6_option_t opt;
  u16 link_type;
  u8 data[6];  // data[0]:data[5]: MAC address
}) dhcpv6_client_mac_t;


#endif /* included_vnet_dhcp6_packet_h */
