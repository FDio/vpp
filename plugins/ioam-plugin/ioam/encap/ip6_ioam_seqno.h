/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef __included_ip6_ioam_seqno_h__
#define __included_ip6_ioam_seqno_h__

#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_hop_by_hop.h>

#define SEQ_CHECK_VALUE 0x80000000 /* for seq number wraparound detection */

#define SEQNO_WINDOW_SIZE 2048
#define SEQNO_WINDOW_ARRAY_SIZE 64

typedef struct seqno_bitmap_ {
  u32 window_size;
  u32 array_size;
  u32 mask;
  u32 pad;
  u64 highest;
  u64 array[SEQNO_WINDOW_ARRAY_SIZE];    /* Will be alloc to array_size */
} seqno_bitmap;

typedef struct seqno_rx_info_ {
  u64 rx_packets;
  u64 lost_packets;
  u64 reordered_packets;
  u64 dup_packets;
  seqno_bitmap bitmap;
} seqno_rx_info;

/* This structure is 64-byte aligned */
typedef struct ioam_seqno_data_ {
  union {
    u32 seq_num; /* Useful only for encap node */
    seqno_rx_info seqno_rx;
  };
} ioam_seqno_data;

typedef struct ioam_seqno_data_main_t_ {
  ioam_seqno_data *seqno_data;
} ioam_seqno_data_main_t;

void ioam_seqno_init_bitmap(ioam_seqno_data *data);

int ioam_seqno_encap_handler(vlib_buffer_t *b, ip6_header_t *ip,
                             ip6_hop_by_hop_option_t *opt);

int
ioam_seqno_decap_handler(vlib_buffer_t *b, ip6_header_t *ip,
                         ip6_hop_by_hop_option_t *opt);

void ioam_analyze_seqno(seqno_rx_info *ppc_rx, u64 seqno);

u8 *
show_ioam_seqno_cmd_fn(u8 *s, ioam_seqno_data *seqno_data, u8 enc);

#endif
