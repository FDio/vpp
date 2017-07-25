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

#ifndef SRC_VNET_SESSION_TRANSPORT_INTERFACE_H_
#define SRC_VNET_SESSION_TRANSPORT_INTERFACE_H_

#include <vnet/vnet.h>
#include <vnet/session/transport.h>

/*
 * Transport protocol virtual function table
 */
typedef struct _transport_proto_vft
{
  /*
   * Setup
   */
  u32 (*bind) (u32 session_index, transport_endpoint_t * lcl);
  u32 (*unbind) (u32);
  int (*open) (transport_endpoint_t * rmt);
  void (*close) (u32 conn_index, u32 thread_index);
  void (*cleanup) (u32 conn_index, u32 thread_index);

  /*
   * Transmission
   */
    u32 (*push_header) (transport_connection_t * tconn, vlib_buffer_t * b);
    u16 (*send_mss) (transport_connection_t * tc);
    u32 (*send_space) (transport_connection_t * tc);
    u32 (*tx_fifo_offset) (transport_connection_t * tc);

  /*
   * Connection retrieval
   */
  transport_connection_t *(*get_connection) (u32 conn_idx, u32 thread_idx);
  transport_connection_t *(*get_listener) (u32 conn_index);
  transport_connection_t *(*get_half_open) (u32 conn_index);

  /*
   * Format
   */
  u8 *(*format_connection) (u8 * s, va_list * args);
  u8 *(*format_listener) (u8 * s, va_list * args);
  u8 *(*format_half_open) (u8 * s, va_list * args);
} transport_proto_vft_t;

typedef clib_bihash_24_8_t transport_endpoint_table_t;

#define TRANSPORT_ENDPOINT_INVALID_INDEX ((u32)~0)

u32 transport_endpoint_lookup (transport_endpoint_table_t * ht,
			       ip46_address_t * ip, u16 port);
void transport_endpoint_table_add (transport_endpoint_table_t * ht,
				   transport_endpoint_t * te, u32 value);
void transport_endpoint_table_del (transport_endpoint_table_t * ht,
				   transport_endpoint_t * te);

void session_register_transport (transport_proto_t transport_proto, u8 is_ip4,
				 const transport_proto_vft_t * vft);
transport_proto_vft_t *session_get_transport_vft (u8 session_type);

#endif /* SRC_VNET_SESSION_TRANSPORT_INTERFACE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
