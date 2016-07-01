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
#define MAX_FLOWS  16
#define PPC_WINDOW_SIZE 2048
#define PPC_WINDOW_ARRAY_SIZE 64 /* PPC_WINDOW_SIZE / 32 */
typedef struct ppc_bitmap_ {
    u32 window_size;
    u32 array_size;
    u32 mask;
    u32 pad;
    u64 highest;
    u64 array[PPC_WINDOW_ARRAY_SIZE];    /* Will be alloc to array_size */
} ppc_bitmap;

typedef struct ppc_rx_info_ {
    u64 rx_packets;
    u64 lost_packets;
    u64 reordered_packets;
    u64 dup_packets;
    u64 fnf_rx_packets;
    u64 fnf_lost_packets;
    u64 fnf_reordered_packets;
    u64 fnf_dup_packets;
    ppc_bitmap bitmap;
} ppc_rx_info;


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

  u32 pad;
  u32 seq_num; /* Useful only for encap node */
  ppc_rx_info ppc_rx;

  u64 pad2[5];
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

  /* Pot option */
  u8 has_pot_option;

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

  /* PPC Testing */
  u32 *ppc_array;
  u32 ppc_array_num;  /* Number of elements in ppc_array - 1*/

  /* Array of function pointers to ADD and POP HBH option handling routines */
  u8 options_size[256];
  int (*add_options[256])(u8 *rewrite_string, u8 rewrite_size);
  int (*pop_options[256])(vlib_buffer_t *b,ip6_header_t *ip, ip6_hop_by_hop_option_t *opt);
  
  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} ip6_hop_by_hop_ioam_main_t;

extern ip6_hop_by_hop_ioam_main_t ip6_hop_by_hop_ioam_main;

extern u8 * format_path_map(u8 * s, va_list * args);
extern clib_error_t *
ip6_ioam_trace_profile_set(u32 trace_option_elts, u32 trace_type, u32 node_id,
                           u32 app_data, int has_pot_option, u32 trace_tsp,
                           int has_e2e_option);
extern int ip6_ioam_set_destination (ip6_address_t *addr, u32 mask_width,
                  u32 vrf_id, int is_add, int is_pop, int is_none);

extern clib_error_t * clear_ioam_rewrite_fn(void);

void ppc_init_flow (ioam_ipfix_elts_t *ipfix);
extern void ioam6_check_ppc(ppc_rx_info *ppc_rx, u64 ppc);

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

void ioam_flow_add_enc(vnet_classify_table_t * t, vnet_classify_entry_t * v);
void ioam_flow_add_dec(vnet_classify_table_t * t, vnet_classify_entry_t * v);
void ioam_flow_del(vnet_classify_table_t * t, vnet_classify_entry_t * v);

int ip6_hbh_add_register_option (u8 option,
				 u8 size,
				 int rewrite_options(u8 *rewrite_string, u8 size));
int ip6_hbh_add_unregister_option (u8 option);

int ip6_hbh_pop_register_option (u8 option,
				 int options(vlib_buffer_t *b,ip6_header_t *ip, ip6_hop_by_hop_option_t *opt));
int ip6_hbh_pop_unregister_option (u8 option);


#endif /* __included_ip6_hop_by_hop_ioam_h__ */
