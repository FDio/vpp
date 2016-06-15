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
#ifndef __included_ip6_hop_by_hop_ioam_h__
#define __included_ip6_hop_by_hop_ioam_h__

#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>
#include <vnet/ip/ip.h>

#define IOAM_FLOW_TEMPLATE_ID    260
#define MAX_NODES  16
#define PPC_WINDOW_SIZE 2048

typedef CLIB_PACKED (struct {
  u16 ingress_if;
  u16 egress_if;
  u32 node_id;
}) ioam_path_map_t;

/* This structure is 64-byte aligned */
typedef CLIB_PACKED (struct {
  /* one cache line (64 bytes) */
  ip6_address_t src_addr; //Address of source originating flow
  ip6_address_t dst_addr; // Address of destination destined for
  u32 my_node_id;    // Egress VPP node id (this node id)
  u32 pkt_counter;   // Num of pkts within start and end timestamps
  u32 bytes_counter; // Num of bytes within start and end timestamps
  u32 sfc_id;        // Service fn chain id (a const value for now)
  u32 sfc_validated_count; // Number of packets validated (passes through the service chain) within the timestamps
  u32 sfc_invalidated_count; // Number of packets invalidated (failed through the service chain) within the timestamps
  u32 start_timestamp; // Timestamp since the collector started to monitor (unit in seconds since Jan 1 1970) (1433433271 for eg)
  u32 end_timestamp;  // End time stamp

  /* second cache line */
  u16 src_port;       // L4 Port of source originating the flow
  u16 dst_port;       // L4 Port of the destination 
  u16 protocol;       // Protocol field in the IPv6 header of the flow
  u16 num_nodes;      // Number of nodes
  u64 pad2[7];

  /* third cache line */
  ioam_path_map_t path[MAX_NODES];
}) ioam_ipfix_elts_t;

typedef struct {
  /* The current rewrite we're using */
  u8 * rewrite;

  /* Trace data processing callback */
  void *ioam_end_of_path_cb;
  /* Configuration data */
  /* Adjacency */
  ip6_address_t adj;
#define IOAM_HBYH_ADD  0
#define IOAM_HBYH_MOD  1
#define IOAM_HBYH_POP  2
  u8 ioam_flag;

  /* time scale transform. Joy. */
  u32 unix_time_0;
  f64 vlib_time_0;


  /* Trace option */
  u8 trace_type;
  u8 trace_option_elts;

  /* Configured node-id */
  u32 node_id;
  u32 app_data;

  /* PoW option */
  u8 has_pow_option;

#define PPC_NONE  0
#define PPC_ENCAP 1
#define PPC_DECAP 2
  u8 has_ppc_option;

#define TSP_SECONDS              0
#define TSP_MILLISECONDS         1
#define TSP_MICROSECONDS         2
#define TSP_NANOSECONDS          3
  /* Time stamp precision. This is enumerated to above four options */
  u32 trace_tsp;


  /* IOAM sessions used in decap node only */
  ioam_ipfix_elts_t * ioam_flows;
  
  /* Writer (only) lock for this table */
  volatile u32 * writer_lock;
  u8 ipfix_enabled;
  u8 enable_ipfix_ut;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} ip6_hop_by_hop_ioam_main_t;

/*
  Client: Option Aggregated Flow Statistics
  Exporter Format: NetFlow Version 9Template ID    : 260
  Source ID      : 0
  Record Size    : 204
  Template layout
  _____________________________________________________________________
  |                 Field                   |  Type | Offset |  Size  |
  ---------------------------------------------------------------------
  | ipv6 source address                     |    27 |     0  |    16  |
  | ipv6 destination address                |    28 |    16  |    16  |
  | iOAM my node-id                         |  5234 |    32  |     4  |
  | IOAM packet counter                     |  5237 |    36  |     4  |
  | IOAM byte count                         |  5238 |    40  |     4  |
  | iOAM sfc-id                             |  5277 |    44  |     4  |
  | iOAM sfc validated count                |  5278 |    48  |     4  |
  | iOAM sfc invalidated count              |  5279 |    52  |     4  |
  | start timestamp                         |  5235 |    56  |     4  |
  | end timestamp                           |  5236 |    60  |     4  |
  | transport source-port                   |     7 |    64  |     2  |
  | transport destination-port              |    11 |    66  |     2  |
  | ipv6 protocol filed                     |  5260 |    68  |     2  |
  | iOAM number of nodes                    |  5263 |    70  |     2  |
  | iOAM Path Map                           |  5262 |    72  |   132  |
  ---------------------------------------------------------------------         
*/

extern ip6_hop_by_hop_ioam_main_t ip6_hop_by_hop_ioam_main;

extern u8 * format_path_map(u8 * s, va_list * args);
extern clib_error_t *
ip6_ioam_trace_profile_set(u32 trace_option_elts, u32 trace_type, u32 node_id,
                           u32 app_data, int has_pow_option, u32 trace_tsp,
                           int has_e2e_option);
extern int ip6_ioam_set_destination (ip6_address_t *addr, u32 mask_width,
                  u32 vrf_id, int is_add, int is_pop, int is_none);

extern clib_error_t * clear_ioam_rewrite_fn(void);

static inline u8 is_zero_ip4_address (ip4_address_t *a)
{
  return (a->as_u32 == 0);
}

static inline void copy_ip6_address (ip6_address_t *dst, ip6_address_t *src)
{
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
}

static inline void set_zero_ip6_address (ip6_address_t *a)
{
  a->as_u64[0] = 0;
  a->as_u64[1] = 0;
}

static inline u8 cmp_ip6_address (ip6_address_t *a1, ip6_address_t *a2)
{
  return ((a1->as_u64[0] == a2->as_u64[0]) && (a1->as_u64[1] == a2->as_u64[1]));
}
static inline u8 is_zero_ip6_address (ip6_address_t *a)
{
  return ((a->as_u64[0] == 0) && (a->as_u64[1] == 0));
}

static inline ioam_ipfix_elts_t * get_ipfix_flow(u32 index)
{
  ioam_ipfix_elts_t *ipfix = 0;
  ip6_hop_by_hop_ioam_main_t * hm = &ip6_hop_by_hop_ioam_main;

  if (pool_is_free_index (hm->ioam_flows, index))
    return 0;

  ipfix = pool_elt_at_index (hm->ioam_flows, index);

  return ipfix;
}

void ioam_flow_add(vnet_classify_table_t * t, vnet_classify_entry_t * v);
void ioam_flow_del(vnet_classify_table_t * t, vnet_classify_entry_t * v);
extern ip6_hop_by_hop_ioam_main_t * hm;
#endif /* __included_ip6_hop_by_hop_ioam_h__ */
