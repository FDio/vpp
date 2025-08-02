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

#include <ping/common.h>

#define ERROR_OUT(e)                                                          \
  do                                                                          \
    {                                                                         \
      err = e;                                                                \
      goto done;                                                              \
    }                                                                         \
  while (0)

#define foreach_ip46_ping_result                                              \
  _ (OK, "OK")                                                                \
  _ (ALLOC_FAIL, "packet allocation failed")                                  \
  _ (NO_INTERFACE, "no egress interface")                                     \
  _ (NO_TABLE, "no FIB table for lookup")                                     \
  _ (NO_SRC_ADDRESS, "no source address for egress interface")                \
  _ (NO_BUFFERS, "could not allocate a new buffer")

typedef enum
{
#define _(v, s) SEND_PING_##v,
  foreach_ip46_ping_result
#undef _
} send_ip46_ping_result_t;

#define PING_DEFAULT_DATA_LEN 60
#define PING_DEFAULT_INTERVAL 1.0

#define PING_MAXIMUM_DATA_SIZE 32768

clib_error_t *ping_plugin_api_hookup (vlib_main_t *vm);
send_ip46_ping_result_t send_ip4_ping (vlib_main_t *vm, u32 table_id,
				       ip4_address_t *pa4, u32 sw_if_index,
				       u16 seq_host, u16 id_host, u16 data_len,
				       u32 burst, u8 verbose, u64 *time_sent);
send_ip46_ping_result_t send_ip6_ping (vlib_main_t *vm, u32 table_id,
				       ip6_address_t *pa6, u32 sw_if_index,
				       u16 seq_host, u16 id_host, u16 data_len,
				       u32 burst, u8 verbose, u64 *time_sent);

#endif /* included_ping_ping_h */
