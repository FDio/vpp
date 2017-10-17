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

#ifndef VNET_VNET_URI_TRANSPORT_H_
#define VNET_VNET_URI_TRANSPORT_H_

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_debug.h>

/*
 * Protocol independent transport properties associated to a session
 */
typedef struct _transport_connection
{
  ip46_address_t rmt_ip;	/**< Remote IP */
  ip46_address_t lcl_ip;	/**< Local IP */
  u16 lcl_port;			/**< Local port */
  u16 rmt_port;			/**< Remote port */
  u8 proto;			/**< Protocol id */
  u8 is_ip4;			/**< Flag if IP4 connection */
  u32 fib_index;			/**< Network namespace */

  u32 s_index;			/**< Parent session index */
  u32 c_index;			/**< Connection index in transport pool */
  u32 thread_index;		/**< Worker-thread index */

  fib_node_index_t rmt_fei;	/**< FIB entry index for rmt */
  dpo_id_t rmt_dpo;		/**< Forwarding DPO for rmt */

#if TRANSPORT_DEBUG
  elog_track_t elog_track;	/**< Event logging */
  u32 cc_stat_tstamp;		/**< CC stats timestamp */
#endif

  /** Macros for 'derived classes' where base is named "connection" */
#define c_lcl_ip connection.lcl_ip
#define c_rmt_ip connection.rmt_ip
#define c_lcl_ip4 connection.lcl_ip.ip4
#define c_rmt_ip4 connection.rmt_ip.ip4
#define c_lcl_ip6 connection.lcl_ip.ip6
#define c_rmt_ip6 connection.rmt_ip.ip6
#define c_lcl_port connection.lcl_port
#define c_rmt_port connection.rmt_port
#define c_proto connection.proto
#define c_fib_index connection.fib_index
#define c_s_index connection.s_index
#define c_c_index connection.c_index
#define c_is_ip4 connection.is_ip4
#define c_thread_index connection.thread_index
#define c_elog_track connection.elog_track
#define c_cc_stat_tstamp connection.cc_stat_tstamp
#define c_rmt_fei connection.rmt_fei
#define c_rmt_dpo connection.rmt_dpo
} transport_connection_t;

typedef enum _transport_proto
{
  TRANSPORT_PROTO_TCP,
  TRANSPORT_PROTO_UDP,
  TRANSPORT_N_PROTO
} transport_proto_t;

u8 *format_transport_proto (u8 * s, va_list * args);
uword unformat_transport_proto (unformat_input_t * input, va_list * args);

#define foreach_transport_connection_fields				\
  _(u32, sw_if_index) 	/**< interface endpoint is associated with  */	\
  _(ip46_address_t, ip) /**< ip address */				\
  _(u32, fib_index)	/**< fib table endpoint is associated with */	\
  _(u8, is_ip4)	/**< 1 if ip4 */					\
  _(u16, port)		/**< port in net order */			\

typedef struct _transport_endpoint
{
#define _(type, name) type name;
  foreach_transport_connection_fields
#undef _
} transport_endpoint_t;

typedef clib_bihash_24_8_t transport_endpoint_table_t;

#define ENDPOINT_INVALID_INDEX ((u32)~0)

always_inline u8
transport_connection_fib_proto (transport_connection_t * tc)
{
  return tc->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
}

always_inline u8
transport_endpoint_fib_proto (transport_endpoint_t * tep)
{
  return tep->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
}

always_inline u8
transport_is_stream (u8 proto)
{
  return (proto == TRANSPORT_PROTO_TCP);
}

always_inline u8
transport_is_dgram (u8 proto)
{
  return (proto == TRANSPORT_PROTO_UDP);
}

int transport_alloc_local_port (u8 proto, ip46_address_t * ip);
int transport_alloc_local_endpoint (u8 proto, transport_endpoint_t * rmt,
				    ip46_address_t * lcl_addr,
				    u16 * lcl_port);
void transport_endpoint_cleanup (u8 proto, ip46_address_t * lcl_ip, u16 port);
void transport_init (void);

#endif /* VNET_VNET_URI_TRANSPORT_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
