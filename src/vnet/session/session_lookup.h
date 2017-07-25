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

typedef struct _session_lookup
{
  /** Lookup tables for established sessions and listeners */
  clib_bihash_16_8_t v4_session_hash;
  clib_bihash_48_8_t v6_session_hash;

  /** Lookup tables for half-open sessions */
  clib_bihash_16_8_t v4_half_open_hash;
  clib_bihash_48_8_t v6_half_open_hash;
} session_lookup_t;

stream_session_t *stream_session_lookup_listener4 (ip4_address_t * lcl,
						   u16 lcl_port, u8 proto);
stream_session_t *stream_session_lookup4 (ip4_address_t * lcl,
					  ip4_address_t * rmt, u16 lcl_port,
					  u16 rmt_port, u8 proto);
stream_session_t *stream_session_lookup_listener6 (ip6_address_t * lcl,
						   u16 lcl_port, u8 proto);
stream_session_t *stream_session_lookup6 (ip6_address_t * lcl,
					  ip6_address_t * rmt, u16 lcl_port,
					  u16 rmt_port, u8 proto);
transport_connection_t *stream_session_lookup_transport_wt4 (ip4_address_t *
							     lcl,
							     ip4_address_t *
							     rmt,
							     u16 lcl_port,
							     u16 rmt_port,
							     u8 proto,
							     u32
							     thread_index);
transport_connection_t *stream_session_lookup_transport4 (ip4_address_t * lcl,
							  ip4_address_t * rmt,
							  u16 lcl_port,
							  u16 rmt_port,
							  u8 proto);
transport_connection_t *stream_session_lookup_transport_wt6 (ip6_address_t *
							     lcl,
							     ip6_address_t *
							     rmt,
							     u16 lcl_port,
							     u16 rmt_port,
							     u8 proto,
							     u32
							     thread_index);
transport_connection_t *stream_session_lookup_transport6 (ip6_address_t * lcl,
							  ip6_address_t * rmt,
							  u16 lcl_port,
							  u16 rmt_port,
							  u8 proto);

stream_session_t *stream_session_lookup_listener (ip46_address_t * lcl,
						  u16 lcl_port, u8 proto);
u64 stream_session_half_open_lookup_handle (ip46_address_t * lcl,
					    ip46_address_t * rmt,
					    u16 lcl_port,
					    u16 rmt_port, u8 proto);
transport_connection_t *stream_session_half_open_lookup (ip46_address_t * lcl,
							 ip46_address_t * rmt,
							 u16 lcl_port,
							 u16 rmt_port,
							 u8 proto);
void stream_session_table_add_for_tc (transport_connection_t * tc, u64 value);
int stream_session_table_del_for_tc (transport_connection_t * tc);
int stream_session_table_del (stream_session_t * s);
void stream_session_half_open_table_del (transport_connection_t * tc);
void stream_session_half_open_table_add (transport_connection_t * tc,
					 u64 value);

void session_lookup_init (void);

#endif /* SRC_VNET_SESSION_SESSION_LOOKUP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
