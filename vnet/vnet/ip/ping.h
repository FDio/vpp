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

#include <vnet/ip/ip.h>

#include <vnet/ip/lookup.h>

typedef enum {
  PING_RESPONSE_IP6 = 42,
} ping_response_type_t;

typedef struct ping_main_t {
  vlib_packet_template_t icmp6_echo_request_packet_template; 
  ip6_main_t *ip6_main;
  // uword cli_proc;
  /* hash table to find back the CLI process for a reply */
  uword *cli_proc_by_icmp_id;
} ping_main_t;

ping_main_t ping_main;

#define PING_MAXIMUM_DATA_SIZE 2000

typedef CLIB_PACKED (struct {
  u16 id;
  u16 seq;
  u8 data[PING_MAXIMUM_DATA_SIZE];
}) icmp6_echo_request_t;


typedef CLIB_PACKED (struct {
  ip6_header_t ip;
  icmp46_header_t icmp;
  icmp6_echo_request_t icmp_echo;
}) icmp6_echo_request_header_t;



typedef enum {
  ICMP6_ECHO_REPLY_NEXT_NORMAL,
  ICMP6_ECHO_REPLY_N_NEXT,
} icmp6_echo_reply_next_t;

