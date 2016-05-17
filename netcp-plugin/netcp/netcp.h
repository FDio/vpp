
/*
 * netcp.h - skeleton vpp engine plug-in header file 
 *
 * Copyright (c) <current-year> <your-organization>
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
#ifndef __included_netcp_h__
#define __included_netcp_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include "netcp_packet.h"

typedef enum {
  NETCP_STATE_START = 0,
  NETCP_STATE_SENT_SEND_FILE,
  NETCP_STATE_DATA,
} netcp_state_t;

typedef struct {
  union {
    ip4_address_t ip4;
    ip4_address_t ip6;
  };
} netcp_addr_t;

typedef struct {
  /* from, to addresses */
  netcp_addr_t from;
  netcp_addr_t to;

  /* src, dst filenames */
  u8 * src_file;
  u8 * dst_file;
  u64 size_in_bytes;

  /* Current place in src file */
  u64 my_current_offset;
  u64 their_current_offset;

  /* Session state variables */
  netcp_state_t state;
  u32 session_id;
  u32 retry_count;
  f64 retry_timer;
  
  /* window size, in pkts */
  u32 window_size;

  /* mmap address */
  u8 * map_addr;

  /* properties */
  u8 is_sender;
  u8 is_ip4;

  u16 segment_size;

  /* encap string */
  u8 * rewrite;
} netcp_session_t;  

typedef struct {
  netcp_session_t * sessions;
  uword * session_by_id;

  f64 process_sleep_timer;

  u32 random_seed;

  /* Vector of per-PDU handler functions */
  void **rx_handlers;

  /* API message ID base */
  u16 msg_id_base;

  /* node indices */
  u32 ip4_lookup_index;
  u32 ip6_lookup_index;
  u16 segment_size;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ethernet_main_t * ethernet_main;
} netcp_main_t;

netcp_main_t netcp_main;

extern vlib_node_registration_t netcp_node;

typedef CLIB_PACKED (struct {
  ip4_header_t ip;
  netcp_header_t netcp;
}) ip4_and_netcp_header_t;

extern vlib_node_registration_t netcp_node;

u8 * map_file (u8 *filename, u64 *sizep, int is_write);
int unmap_file (u8 * filename, u8 * addr, u64 size, int truncate);

#define NETCP_PROCESS_EVENT_SET_TIMER 1

#endif /* __included_netcp_h__ */
