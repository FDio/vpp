/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __included_ip6_hop_by_hop_packet_h__
#define __included_ip6_hop_by_hop_packet_h__

#define BIT_NONE            0x00
#define BIT_0               0x01
#define BIT_1               0x02
#define BIT_2               0x04
#define BIT_3               0x08
#define BIT_4               0x10
#define BIT_5               0x20
#define BIT_6               0x40
#define BIT_7               0x80
#define BIT_8               0x0100

typedef struct {
  /* Protocol for next header */
  u8 protocol;
  /*
   * Length of hop_by_hop header in 8 octet units, 
   * not including the first 8 octets
   */
  u8 length;
} ip6_hop_by_hop_header_t;

typedef struct {
  /* Option Type */
#define HBH_OPTION_TYPE_SKIP_UNKNOWN (0x0 << 6)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN (0x1 << 6)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN_ICMP (0x2 << 6)
#define HBH_OPTION_TYPE_DISCARD_UNKNOWN_ICMP_NOT_MCAST (0x3 << 6)
#define HBH_OPTION_TYPE_DATA_CHANGE_ENROUTE (1<<5)
#define HBH_OPTION_TYPE_MASK (0x1F)
  u8 type;
  /* Length in octets of the option data field */
  u8 length;
} ip6_hop_by_hop_option_t;

/* $$$$ IANA banana constants */
#define HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST 1
#define HBH_OPTION_TYPE_IOAM_PROOF_OF_WORK 2
#define HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE 3

/*
typedef struct {
  u32 ttl_node_id;
  u16 ingress_if;
  u16 egress_if;
  u32 timestamp;
  u32 app_data;
} ioam_trace_data_list_element_t;
*/

#define    BIT_TTL_NODEID       BIT_0
#define    BIT_ING_INTERFACE    BIT_1 
#define    BIT_EGR_INTERFACE    BIT_2 
#define    BIT_TIMESTAMP        BIT_3 
#define    BIT_APPDATA          BIT_4 
#define    TRACE_TYPE_MASK  (BIT_0 | BIT_1 | BIT_2 | BIT_3 | BIT_4)

/*
     0x00011111  iOAM-trace-type is 0x00011111 then the format of node
        data is:
  
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |     ingress_if_id             |         egress_if_id          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                           timestamp                           +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                            app_data                           |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  
*/
#define   TRACE_TYPE_IF_TS_APP   0x1f
typedef struct {
  u32 ttl_node_id;
  u16 ingress_if;
  u16 egress_if;
  u32 timestamp;
  u32 app_data;
} ioam_trace_if_ts_app_t;

/*
     0x00000111  iOAM-trace-type is 0x00000111 then the format is:
  
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |     ingress_if_id             |         egress_if_id          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  
*/

#define   TRACE_TYPE_IF   0x03
typedef struct {
  u32 ttl_node_id;
  u16 ingress_if;
  u16 egress_if;
} ioam_trace_if_t;

/*
     0x00001001  iOAM-trace-type is 0x00001001 then the format is:
  
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                           timestamp                           +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  
*/

#define   TRACE_TYPE_TS   0x09
typedef struct {
  u32 ttl_node_id;
  u32 timestamp;
} ioam_trace_ts_t;

/*
     0x00010001  iOAM-trace-type is 0x00010001 then the format is:
  
  
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                            app_data                           |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  
*/


#define   TRACE_TYPE_APP   0x11
typedef struct {
  u32 ttl_node_id;
  u32 app_data;
} ioam_trace_app_t;

/*
  
     0x00011001  iOAM-trace-type is 0x00011001 then the format is:
  
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                           timestamp                           +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                            app_data                           |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define   TRACE_TYPE_TS_APP   0x19
typedef struct {
  u32 ttl_node_id;
  u32 timestamp;
  u32 app_data;
} ioam_trace_ts_app_t;


typedef CLIB_PACKED(struct {
  ip6_hop_by_hop_option_t hdr;
  u8 ioam_trace_type;
  u8 data_list_elts_left;
  u32 elts[0]; /* Variable type. So keep it generic */
}) ioam_trace_option_t;

typedef CLIB_PACKED(struct {
  ip6_hop_by_hop_option_t hdr;
  u8 pow_type;
#define PROFILE_ID_MASK 0xF
  u8 reserved_profile_id; /* 4 bits reserved, 4 bits to carry profile id */
  u64 random;
  u64 cumulative;
}) ioam_pow_option_t;

typedef CLIB_PACKED(struct {
  ip6_hop_by_hop_option_t hdr;
  u8 e2e_type;
  u8 reserved;
  u32 e2e_data;
}) ioam_e2e_option_t;

#endif /* __included_ip6_hop_by_hop_packet_h__ */
