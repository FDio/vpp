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
#ifndef included_ping_ping_h
#define included_ping_ping_h


#include <vnet/ip/ip.h>

#include <vnet/ip/lookup.h>

typedef enum
{
  PING_RESPONSE_IP6 = 42,
  PING_RESPONSE_IP4,
} ping_response_type_t;

#define foreach_ip46_ping_result                                      \
  _ (OK, "OK")                                                        \
  _ (ALLOC_FAIL, "packet allocation failed")                          \
  _ (NO_INTERFACE, "no egress interface")                             \
  _ (NO_TABLE, "no FIB table for lookup")                            \
  _ (NO_SRC_ADDRESS, "no source address for egress interface")        \
  _ (NO_BUFFERS, "could not allocate a new buffer")                   \

typedef enum
{
#define _(v, s) SEND_PING_##v,
    foreach_ip46_ping_result
#undef _
} send_ip46_ping_result_t;

/*
 * Currently running ping command.
 */
typedef struct ping_run_t
{
  u16 icmp_id;
  uword cli_process_id;
} ping_run_t;

typedef struct ping_main_t
{
  /* API message ID base */
  u16 msg_id_base;

  ip6_main_t *ip6_main;
  ip4_main_t *ip4_main;
  /* a vector of current ping runs. */
  ping_run_t *active_ping_runs;
  /* a lock held while add/remove/search on active_ping_runs */
  clib_spinlock_t ping_run_check_lock;
} ping_main_t;

extern ping_main_t ping_main;

#define PING_DEFAULT_DATA_LEN 60
#define PING_DEFAULT_INTERVAL 1.0

#define PING_MAXIMUM_DATA_SIZE 32768

#define PING_CLI_UNKNOWN_NODE (~0)

/* *INDENT-OFF* */

typedef CLIB_PACKED (struct {
  u16 id;
  u16 seq;
  u64 time_sent;
  u8 data[0];
}) icmp46_echo_request_t;

/* *INDENT-ON* */


typedef enum
{
  ICMP46_ECHO_REPLY_NEXT_DROP,
  ICMP46_ECHO_REPLY_NEXT_PUNT,
  ICMP46_ECHO_REPLY_N_NEXT,
} icmp46_echo_reply_next_t;

extern void set_cli_process_id_by_icmp_id_mt (vlib_main_t * vm, u16 icmp_id, uword cli_process_id);
extern uword get_cli_process_id_by_icmp_id_mt (vlib_main_t * vm, u16 icmp_id);
extern void clear_cli_process_id_by_icmp_id_mt (vlib_main_t * vm, u16 icmp_id);

extern clib_error_t *ping_plugin_api_hookup (vlib_main_t *vm);
extern send_ip46_ping_result_t send_ip4_ping(vlib_main_t * vm,
	       u32 table_id, ip4_address_t * pa4,
	       u32 sw_if_index, u16 seq_host, u16 id_host, u16 data_len,
	       u32 burst, u8 verbose);
extern send_ip46_ping_result_t send_ip6_ping(vlib_main_t * vm,
	       u32 table_id, ip6_address_t * pa6,
	       u32 sw_if_index, u16 seq_host, u16 id_host, u16 data_len,
	       u32 burst, u8 verbose);

#endif /* included_ping_ping_h */
