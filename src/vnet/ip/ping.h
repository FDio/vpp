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
#ifndef included_vnet_ping_h
#define included_vnet_ping_h


#include <vnet/ip/ip.h>

#include <vnet/ip/lookup.h>

typedef enum
{
  PING_RESPONSE_IP6 = 42,
  PING_RESPONSE_IP4,
} ping_response_type_t;

typedef enum
{
  SEND_PING_OK = 0,
  SEND_PING_ALLOC_FAIL,
  SEND_PING_NO_INTERFACE,
  SEND_PING_NO_TABLE,
  SEND_PING_NO_SRC_ADDRESS,
} send_ip46_ping_result_t;

/*
 * Currently running ping command.
 */
typedef struct ping_run_t
{
  u16 icmp_id;
  u16 curr_seq;
  uword cli_process_id;
  uword cli_thread_index;
} ping_run_t;

typedef struct ping_main_t
{
  ip6_main_t *ip6_main;
  ip4_main_t *ip4_main;
  ping_run_t *ping_runs;
  /* hash table to find back the CLI process for a reply */
  // uword *cli_proc_by_icmp_id;
  ping_run_t *ping_run_by_icmp_id;
} ping_main_t;

ping_main_t ping_main;

#define PING_DEFAULT_DATA_LEN 60
#define PING_DEFAULT_INTERVAL 1.0

#define PING_MAXIMUM_DATA_SIZE (VLIB_BUFFER_DATA_SIZE - sizeof(ip6_header_t) - sizeof(icmp46_header_t) - offsetof(icmp46_echo_request_t, data))

/* *INDENT-OFF* */

typedef CLIB_PACKED (struct {
  u16 id;
  u16 seq;
  f64 time_sent;
  u8 data[0];
}) icmp46_echo_request_t;


typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  icmp46_header_t icmp;
  icmp46_echo_request_t icmp_echo;
}) icmp6_echo_request_header_t;

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  icmp46_header_t icmp;
  icmp46_echo_request_t icmp_echo;
}) icmp4_echo_request_header_t;

/* *INDENT-ON* */


typedef struct
{
  u16 id;
  u16 seq;
  u8 bound;
} icmp_echo_trace_t;




typedef enum
{
  ICMP6_ECHO_REPLY_NEXT_DROP,
  ICMP6_ECHO_REPLY_NEXT_PUNT,
  ICMP6_ECHO_REPLY_N_NEXT,
} icmp6_echo_reply_next_t;

typedef enum
{
  ICMP4_ECHO_REPLY_NEXT_DROP,
  ICMP4_ECHO_REPLY_NEXT_PUNT,
  ICMP4_ECHO_REPLY_N_NEXT,
} icmp4_echo_reply_next_t;

#endif /* included_vnet_ping_h */
