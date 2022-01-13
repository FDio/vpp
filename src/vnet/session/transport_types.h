/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
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

#ifndef VNET_VNET_URI_TRANSPORT_TYPES_H_
#define VNET_VNET_URI_TRANSPORT_TYPES_H_

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_debug.h>
#include <vppinfra/bihash_24_8.h>

#define TRANSPORT_MAX_HDRS_LEN    140	/* Max number of bytes for headers */

typedef enum transport_dequeue_type_
{
  TRANSPORT_TX_PEEK,		/**< reliable transport protos */
  TRANSPORT_TX_DEQUEUE,		/**< unreliable transport protos */
  TRANSPORT_TX_INTERNAL,	/**< apps acting as transports */
  TRANSPORT_TX_DGRAM,		/**< datagram mode */
  TRANSPORT_TX_N_FNS
} transport_tx_fn_type_t;

typedef enum transport_service_type_
{
  TRANSPORT_SERVICE_VC,		/**< virtual circuit service */
  TRANSPORT_SERVICE_CL,		/**< connectionless service */
  TRANSPORT_SERVICE_APP,	/**< app transport service */
  TRANSPORT_N_SERVICES
} transport_service_type_t;

typedef enum transport_connection_flags_
{
  TRANSPORT_CONNECTION_F_IS_TX_PACED = 1 << 0,
  /**
   * Don't register connection in lookup. Does not apply to local apps
   * and transports using the network layer (udp/tcp)
   */
  TRANSPORT_CONNECTION_F_NO_LOOKUP = 1 << 1,
  /**
   * Connection descheduled by the session layer.
   */
  TRANSPORT_CONNECTION_F_DESCHED = 1 << 2,
  /**
   * Connection is "connection less". Some important implications of that
   * are that connections are not pinned to workers and listeners will
   * have fifos associated to them
   */
  TRANSPORT_CONNECTION_F_CLESS = 1 << 3,
} transport_connection_flags_t;

typedef struct _spacer
{
  u64 bytes_per_sec;
  i64 bucket;
  clib_us_time_t last_update;
  f32 tokens_per_period;
  u32 max_burst;
} spacer_t;

#define TRANSPORT_CONN_ID_LEN	44

/*
 * Protocol independent transport properties associated to a session
 */
typedef struct _transport_connection
{
  /** Connection ID */
  union
  {
    /*
     * Network connection ID tuple
     */
    struct
    {
      ip46_address_t rmt_ip;	/**< Remote IP */
      ip46_address_t lcl_ip;	/**< Local IP */
      u32 fib_index;		/**< Network namespace */
      u16 rmt_port;		/**< Remote port */
      u16 lcl_port;		/**< Local port */
      u8 is_ip4;		/**< Flag if IP4 connection */
      u8 proto;			/**< Protocol id */
      u8 unused[2];		/**< First field after id wants to be
				     4-byte aligned) */
    };
    /*
     * Opaque connection ID
     */
    u8 opaque_conn_id[TRANSPORT_CONN_ID_LEN];
  };

  u32 s_index;			/**< Parent session index */
  u32 c_index;			/**< Connection index in transport pool */
  u32 thread_index;		/**< Worker-thread index */
  u8 flags;			/**< Transport specific flags */
  u8 dscp;			/**< Differentiated Services Code Point */

  /*fib_node_index_t rmt_fei;
     dpo_id_t rmt_dpo; */

  spacer_t pacer;		/**< Simple transport pacer */

#if TRANSPORT_DEBUG
  elog_track_t elog_track;	/**< Event logging */
  u32 cc_stat_tstamp;		/**< CC stats timestamp */
#endif

  /**
   * Transport specific state starts in next cache line. Meant to avoid
   * alignment surprises in transports when base class changes.
   */
    CLIB_CACHE_LINE_ALIGN_MARK (end);

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
#define c_opaque_id connection.opaque_conn_id
#define c_stats connection.stats
#define c_pacer connection.pacer
#define c_flags connection.flags
#define c_dscp		 connection.dscp
#define s_ho_handle pacer.bytes_per_sec
} transport_connection_t;

STATIC_ASSERT (STRUCT_OFFSET_OF (transport_connection_t, s_index)
	       == TRANSPORT_CONN_ID_LEN, "update conn id len");

/* Warn if size changes. Two cache lines is already generous, hopefully we
 * won't have to outgrow that. */
STATIC_ASSERT (sizeof (transport_connection_t) <= 128,
	       "moved into 3rd cache line");

#define foreach_transport_proto                                               \
  _ (TCP, "tcp", "T")                                                         \
  _ (UDP, "udp", "U")                                                         \
  _ (NONE, "ct", "C")                                                         \
  _ (TLS, "tls", "J")                                                         \
  _ (QUIC, "quic", "Q")                                                       \
  _ (DTLS, "dtls", "D")                                                       \
  _ (SRTP, "srtp", "R")								\
  _ (HTTP, "http", "H")

typedef enum _transport_proto
{
#define _(sym, str, sstr) TRANSPORT_PROTO_ ## sym,
  foreach_transport_proto
#undef _
} transport_proto_t;

u8 *format_transport_proto (u8 * s, va_list * args);
u8 *format_transport_proto_short (u8 * s, va_list * args);
u8 *format_transport_connection (u8 * s, va_list * args);
u8 *format_transport_listen_connection (u8 * s, va_list * args);
u8 *format_transport_half_open_connection (u8 * s, va_list * args);

uword unformat_transport_proto (unformat_input_t * input, va_list * args);
u8 *format_transport_protos (u8 * s, va_list * args);

#define foreach_transport_endpoint_fields				\
  _(ip46_address_t, ip) /**< ip address in net order */			\
  _(u16, port)		/**< port in net order */			\
  _(u8, is_ip4)		/**< set if ip4 */				\
  _(u32, sw_if_index) 	/**< interface endpoint is associated with  */	\
  _(u32, fib_index)	/**< fib table endpoint is associated with */	\

typedef struct transport_endpoint_
{
#define _(type, name) type name;
  foreach_transport_endpoint_fields
#undef _
} transport_endpoint_t;

typedef enum transport_endpt_cfg_flags_
{
  TRANSPORT_CFG_F_CONNECTED = 1 << 0,
  TRANSPORT_CFG_F_UNIDIRECTIONAL = 1 << 1,
} transport_endpt_cfg_flags_t;

/* clang-format off */
#define foreach_transport_endpoint_cfg_fields				\
  foreach_transport_endpoint_fields					\
  _ (transport_endpoint_t, peer)            				\
  _ (u32, next_node_index) 						\
  _ (u32, next_node_opaque)						\
  _ (u16, mss)           						\
  _ (u8, dscp) \
  _ (u8, transport_flags)						\
/* clang-format on */

typedef struct transport_endpoint_pair_
{
#define _(type, name) type name;
  foreach_transport_endpoint_cfg_fields
#undef _
} transport_endpoint_cfg_t;

#define foreach_transport_endpt_cfg_flags                                     \
  _ (CSUM_OFFLOAD)                                                            \
  _ (GSO)                                                                     \
  _ (RATE_SAMPLING)

typedef enum transport_endpt_attr_flag_bit_
{
#define _(name) TRANSPORT_ENDPT_ATTR_F_BIT_##name,
  foreach_transport_endpt_cfg_flags
#undef _
} __clib_packed transport_endpt_attr_flag_bit_t;

typedef enum transport_endpt_attr_flag_
{
#define _(name)                                                               \
  TRANSPORT_ENDPT_ATTR_F_##name = 1 << TRANSPORT_ENDPT_ATTR_F_BIT_##name,
  foreach_transport_endpt_cfg_flags
#undef _
} __clib_packed transport_endpt_attr_flag_t;

#define foreach_transport_attr_fields                                         \
  _ (u64, next_output_node, NEXT_OUTPUT_NODE)                                 \
  _ (u16, mss, MSS)                                                           \
  _ (u8, flags, FLAGS)                                                        \
  _ (u8, cc_algo, CC_ALGO)

typedef enum transport_endpt_attr_type_
{
#define _(type, name, str) TRANSPORT_ENDPT_ATTR_##str,
  foreach_transport_attr_fields
#undef _
} __clib_packed transport_endpt_attr_type_t;

typedef struct transport_endpt_attr_
{
  transport_endpt_attr_type_t type;
  union
  {
#define _(type, name, str) type name;
    foreach_transport_attr_fields
#undef _
  };
} transport_endpt_attr_t;

typedef enum transport_endpt_ext_cfg_type_
{
  TRANSPORT_ENDPT_EXT_CFG_NONE,
  TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
} transport_endpt_ext_cfg_type_t;

typedef struct transport_endpt_crypto_cfg_
{
  u32 ckpair_index;
  u8 crypto_engine;
  u8 hostname[256]; /**< full domain len is 255 as per rfc 3986 */
} transport_endpt_crypto_cfg_t;

typedef struct transport_endpt_ext_cfg_
{
  u16 type;
  u16 len;
  union
  {
    transport_endpt_crypto_cfg_t crypto;
    u8 data[0];
  };
} transport_endpt_ext_cfg_t;

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

u8 transport_protocol_is_cl (transport_proto_t tp);
transport_service_type_t transport_protocol_service_type (transport_proto_t);
transport_tx_fn_type_t transport_protocol_tx_fn_type (transport_proto_t tp);

#endif /* VNET_VNET_URI_TRANSPORT_TYPES_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
