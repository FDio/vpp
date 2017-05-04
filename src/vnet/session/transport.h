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
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_48_8.h>
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
  u8 proto;			/**< Transport protocol id (also session type) */

  u32 s_index;			/**< Parent session index */
  u32 c_index;			/**< Connection index in transport pool */
  u8 is_ip4;			/**< Flag if IP4 connection */
  u32 thread_index;		/**< Worker-thread index */

#if TRANSPORT_DEBUG
  elog_track_t elog_track;	/**< Event logging */
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
#define c_state connection.state
#define c_s_index connection.s_index
#define c_c_index connection.c_index
#define c_is_ip4 connection.is_ip4
#define c_thread_index connection.thread_index
#define c_elog_track connection.elog_track
} transport_connection_t;

/*
 * Transport protocol virtual function table
 */
typedef struct _transport_proto_vft
{
  /*
   * Setup
   */
  u32 (*bind) (u32, ip46_address_t *, u16);
  u32 (*unbind) (u32);
  int (*open) (ip46_address_t * addr, u16 port_host_byte_order);
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

/* *INDENT-OFF* */
/* 16 octets */
typedef CLIB_PACKED (struct {
  union
    {
      struct
	{
	  ip4_address_t src;
	  ip4_address_t dst;
	  u16 src_port;
	  u16 dst_port;
	  /* align by making this 4 octets even though its a 1-bit field
	   * NOTE: avoid key overlap with other transports that use 5 tuples for
	   * session identification.
	   */
	  u32 proto;
	};
      u64 as_u64[2];
    };
}) v4_connection_key_t;

typedef CLIB_PACKED (struct {
  union
    {
      struct
	{
	  /* 48 octets */
	  ip6_address_t src;
	  ip6_address_t dst;
	  u16 src_port;
	  u16 dst_port;
	  u32 proto;
	  u64 unused;
	};
      u64 as_u64[6];
    };
}) v6_connection_key_t;
/* *INDENT-ON* */

typedef clib_bihash_kv_16_8_t session_kv4_t;
typedef clib_bihash_kv_48_8_t session_kv6_t;

always_inline void
make_v4_ss_kv (session_kv4_t * kv, ip4_address_t * lcl, ip4_address_t * rmt,
	       u16 lcl_port, u16 rmt_port, u8 proto)
{
  v4_connection_key_t *key = (v4_connection_key_t *) kv->key;

  key->src.as_u32 = lcl->as_u32;
  key->dst.as_u32 = rmt->as_u32;
  key->src_port = lcl_port;
  key->dst_port = rmt_port;
  key->proto = proto;

  kv->value = ~0ULL;
}

always_inline void
make_v4_listener_kv (session_kv4_t * kv, ip4_address_t * lcl, u16 lcl_port,
		     u8 proto)
{
  v4_connection_key_t *key = (v4_connection_key_t *) kv->key;

  key->src.as_u32 = lcl->as_u32;
  key->dst.as_u32 = 0;
  key->src_port = lcl_port;
  key->dst_port = 0;
  key->proto = proto;

  kv->value = ~0ULL;
}

always_inline void
make_v4_ss_kv_from_tc (session_kv4_t * kv, transport_connection_t * t)
{
  return make_v4_ss_kv (kv, &t->lcl_ip.ip4, &t->rmt_ip.ip4, t->lcl_port,
			t->rmt_port, t->proto);
}

always_inline void
make_v6_ss_kv (session_kv6_t * kv, ip6_address_t * lcl, ip6_address_t * rmt,
	       u16 lcl_port, u16 rmt_port, u8 proto)
{
  v6_connection_key_t *key = (v6_connection_key_t *) kv->key;

  key->src.as_u64[0] = lcl->as_u64[0];
  key->src.as_u64[1] = lcl->as_u64[1];
  key->dst.as_u64[0] = rmt->as_u64[0];
  key->dst.as_u64[1] = rmt->as_u64[1];
  key->src_port = lcl_port;
  key->dst_port = rmt_port;
  key->proto = proto;
  key->unused = 0;

  kv->value = ~0ULL;
}

always_inline void
make_v6_listener_kv (session_kv6_t * kv, ip6_address_t * lcl, u16 lcl_port,
		     u8 proto)
{
  v6_connection_key_t *key = (v6_connection_key_t *) kv->key;

  key->src.as_u64[0] = lcl->as_u64[0];
  key->src.as_u64[1] = lcl->as_u64[1];
  key->dst.as_u64[0] = 0;
  key->dst.as_u64[1] = 0;
  key->src_port = lcl_port;
  key->dst_port = 0;
  key->proto = proto;
  key->unused = 0;

  kv->value = ~0ULL;
}

always_inline void
make_v6_ss_kv_from_tc (session_kv6_t * kv, transport_connection_t * t)
{
  make_v6_ss_kv (kv, &t->lcl_ip.ip6, &t->rmt_ip.ip6, t->lcl_port,
		 t->rmt_port, t->proto);
}

typedef struct _transport_endpoint
{
  ip46_address_t ip;	/** ip address */
  u16 port;		/** port in host order */
  u8 is_ip4;		/** 1 if ip4 */
  u32 vrf;		/** fib table the endpoint is associated with */
} transport_endpoint_t;

typedef clib_bihash_24_8_t transport_endpoint_table_t;

#define TRANSPORT_ENDPOINT_INVALID_INDEX ((u32)~0)

u32
transport_endpoint_lookup (transport_endpoint_table_t * ht,
			   ip46_address_t * ip, u16 port);
void transport_endpoint_table_add (transport_endpoint_table_t * ht,
				   transport_endpoint_t * te, u32 value);
void transport_endpoint_table_del (transport_endpoint_table_t * ht,
				   transport_endpoint_t * te);

#endif /* VNET_VNET_URI_TRANSPORT_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
