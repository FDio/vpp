/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_SESSION_SESSION_LOOKUP_H_
#define SRC_VNET_SESSION_SESSION_LOOKUP_H_

#include <vnet/session/stream_session.h>
#include <vnet/session/transport.h>

typedef struct _session_lookup_table
{
  /**
   * Lookup tables for established sessions and listeners
   */
  clib_bihash_16_8_t v4_session_hash;
  clib_bihash_48_8_t v6_session_hash;

  /**
   * Lookup tables for half-open sessions
   */
  clib_bihash_16_8_t v4_half_open_hash;
  clib_bihash_48_8_t v6_half_open_hash;
} session_lookup_table_t;

#define SESSION_TABLE_INVALID_INDEX ((u32)~0)
#define SESSION_INVALID_INDEX ((u32)~0)

stream_session_t *session_lookup4 (u32 fib_index, ip4_address_t * lcl,
                                   ip4_address_t * rmt, u16 lcl_port,
                                   u16 rmt_port, u8 proto);
stream_session_t *session_lookup6 (ip6_address_t * lcl, ip6_address_t * rmt,
                                   u16 lcl_port, u16 rmt_port, u8 proto);
transport_connection_t *session_lookup_connection_wt4 (u32 fib_index,
                                                       ip4_address_t * lcl,
                                                       ip4_address_t * rmt,
                                                       u16 lcl_port,
                                                       u16 rmt_port,
                                                       u8 proto,
                                                       u32 thread_index);
transport_connection_t *session_lookup_connection4 (u32 fib_index,
                                                    ip4_address_t * lcl,
                                                    ip4_address_t * rmt,
                                                    u16 lcl_port,
                                                    u16 rmt_port,
                                                    u8 proto);
transport_connection_t *session_lookup_connection_wt6 (u32 fib_index,
                                                       ip6_address_t * lcl,
                                                       ip6_address_t * rmt,
                                                       u16 lcl_port,
                                                       u16 rmt_port,
                                                       u8 proto,
                                                       u32 thread_index);
transport_connection_t *session_lookup_connection6 (u32 fib_index,
                                                    ip6_address_t * lcl,
                                                    ip6_address_t * rmt,
                                                    u16 lcl_port,
                                                    u16 rmt_port,
                                                    u8 proto);
stream_session_t *session_lookup_listener4 (u32 fib_index, ip4_address_t * lcl,
                                            u16 lcl_port, u8 proto);
stream_session_t *session_lookup_listener6 (u32 fib_index, ip6_address_t * lcl,
                                            u16 lcl_port, u8 proto);
stream_session_t *session_lookup_listener (ip46_address_t * lcl,
                                           u16 lcl_port, u8 proto);
u32 session_lookup_session_endpoint (u32 table_index, session_endpoint_t *sep);
u64 session_lookup_half_open_handle (transport_connection_t *tc);
int session_table_add_connection (transport_connection_t * tc, u64 value);
int session_table_del_connection (transport_connection_t * tc);
int session_table_del_half_open (transport_connection_t * tc);
int session_table_add_half_open (transport_connection_t * tc, u64 value);
int session_table_del_session (stream_session_t * s);
int session_table_add_session_endpoint (u32 table_index, session_endpoint_t *sep,
                                        u64 value);

u32 session_table_get_index_for_nns (u32 nns_index);
void session_lookup_init (void);

#endif /* SRC_VNET_SESSION_SESSION_LOOKUP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
