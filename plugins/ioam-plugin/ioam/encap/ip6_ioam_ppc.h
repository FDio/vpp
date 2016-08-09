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

#ifndef __included_ip6_ioam_ppc_h__
#define __included_ip6_ioam_ppc_h__

#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_hop_by_hop.h>

#define SEQ_CHECK_VALUE 0x80000000 /* for seq number wraparound detection */

#define PPC_WINDOW_SIZE 2048
#define PPC_WINDOW_ARRAY_SIZE 64

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
  ppc_bitmap bitmap;
} ppc_rx_info;

/* This structure is 64-byte aligned */
typedef struct ioam_ppc_data_ {
  union {
    u32 seq_num; /* Useful only for encap node */
    ppc_rx_info ppc_rx;
  };
} ioam_ppc_data;

typedef struct ioam_ppc_data_main_t_ {
  ioam_ppc_data *ppc_data;
} ioam_ppc_data_main_t;

u32 ioam_ppc_flow_create(u32 ctx);

void ioam_ppc_flow_delete(u32 ppc_opaque);

int ioam_ppc_encap_handler(vlib_buffer_t *b, ip6_header_t *ip,
                           ip6_hop_by_hop_option_t *opt);

int
ioam_ppc_decap_handler(vlib_buffer_t *b, ip6_header_t *ip,
                       ip6_hop_by_hop_option_t *opt);

void ioam_analyze_ppc(ppc_rx_info *ppc_rx, u64 ppc);

u8 *
show_ioam_ppc_cmd_fn(u8 *s, u32 ppc_opaque, u8 enc);

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_ENCAP_IOAM_PPC_H_ */
