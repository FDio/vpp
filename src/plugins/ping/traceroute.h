/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
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
#ifndef traceroute_h
#define traceroute_h

#include <vnet/ip/ip.h>
#include <vnet/ip/lookup.h>

#include <ping/common.h>

typedef struct
{
  ip_address_t dest; /* destination address */
  f64 interval;	     /* time between packets */
  u32 fib_index;     /* FIB table index */
  u32 sw_if_index;   /* egress interface */
  u32 data_len;	     /* length of data to send */
  u16 port;	     /* destination port */
  u8 max_hops;	     /* maximum hops to trace */
  u8 repeat;	     /* repeat number */
  u8 burst;	     /* number of packets to send per hop per repeat */
  u8 l4_proto;	     /* L4 protocol to use */
  u8 verbose;	     /* verbose output */
} traceroute_args_t;

/*
 * Currently running ping command.
 */
typedef struct
{
  traceroute_args_t *args; /* arguments for the traceroute */
  uword cli_process_id;
  u32 n_packets_sent;	  /* number of packets sent so far */
  u32 n_packets_received; /* number of packets received so far */
  u16 id;		  /* traceroute ID */
  u8 current_hop;	  /* current hop number */
  u8 current_repeat;	  /* current repeat number */
} traceroute_run_t;

typedef struct
{
  traceroute_run_t **active_runs; /* currently running traceroutes */
} traceroute_main_t;

extern traceroute_main_t traceroute_main;

#define foreach_traceroute_result                                             \
  _ (OK, "OK")                                                                \
  _ (ALLOC_FAIL, "packet allocation failed")                                  \
  _ (NO_SRC_ADDRESS, "no source address for egress interface")                \
  _ (NO_BUFFERS, "could not allocate a new buffer")

typedef enum
{
#define _(v, s) TRACEROUTE_##v,
  foreach_traceroute_result
#undef _
} traceroute_result_t;

typedef enum
{
  TRACEROUTE_REPLY_GOOD_CONTINUE,
  TRACEROUTE_REPLY_GOOD_STOP,
  TRACEROUTE_REPLY_BAD_HASH,
} traceroute_reply_result_t;

#define TRACEROUTE_DEFAULT_DATA_LEN 60
#define TRACEROUTE_DEFAULT_INTERVAL 1.0

#define TRACEROUTE_MAXIMUM_DATA_SIZE 32768

typedef enum
{
  TRACEROUTE_REPLY_NEXT_DROP,
  TRACEROUTE_REPLY_NEXT_PUNT,
  TRACEROUTE_REPLY_N_NEXT,
} traceroute_reply_next_t;

#define get_seq_from_hop_and_repeat(_h, _r) (((u16) (_h)) << 8 | (u16) (_r))

#endif /* traceroute_h */
