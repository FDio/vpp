/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
 */

#ifndef VNET_VNET_URI_TRANSPORT_TYPES_H_
#define VNET_VNET_URI_TRANSPORT_TYPES_H_

#include <vnet/vnet.h>
#include <vnet/ip/ip_types.h>
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
  TRANSPORT_SERVICE_VC, /**< virtual circuit service */
  TRANSPORT_SERVICE_CL, /**< connectionless service */
  TRANSPORT_N_SERVICES
} transport_service_type_t;

/*
 * IS_TX_PACED : Connection sending is paced
 * NO_LOOKUP: Don't register connection in lookup. Does not apply to local
 * 	      apps and transports using the network layer (udp/tcp)
 * DESCHED: Connection descheduled by the session layer
 * CLESS: Connection is "connection less". Some important implications of that
 *        are that connections are not pinned to workers and listeners will
 *        have fifos associated to them
 */
#define foreach_transport_connection_flag                                                          \
  _ (IS_TX_PACED, "tx_paced")                                                                      \
  _ (NO_LOOKUP, "no_lookup")                                                                       \
  _ (DESCHED, "descheduled")                                                                       \
  _ (CLESS, "connectionless")                                                                      \
  _ (ERROR, "error")

typedef enum transport_connection_flags_bits_
{
#define _(sym, str) TRANSPORT_CONNECTION_F_BIT_##sym,
  foreach_transport_connection_flag
#undef _
    TRANSPORT_CONNECTION_N_FLAGS
} transport_connection_flags_bits_t;

typedef enum transport_connection_flags_
{
#define _(sym, str)                                                           \
  TRANSPORT_CONNECTION_F_##sym = 1 << TRANSPORT_CONNECTION_F_BIT_##sym,
  foreach_transport_connection_flag
#undef _
} __clib_packed transport_connection_flags_t;

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
      u8 dscp;			/**< Differentiated Services Code Point */
      u8 unused[3];		/**< Last unused bytes in conn id */
      u8 is_ip4;		/**< Flag if IP4 connection */
      u8 proto;			/**< Protocol id */
    };
    /*
     * Opaque connection ID, does not include is_ip4 and proto
     */
    u8 opaque_conn_id[TRANSPORT_CONN_ID_LEN];
  };

  u32 s_index;			    /**< Parent session index */
  u32 c_index;			    /**< Connection index in transport pool */
  clib_thread_index_t thread_index; /**< Worker-thread index */
  transport_connection_flags_t flags; /**< Transport specific flags */

  /*fib_node_index_t rmt_fei;
     dpo_id_t rmt_dpo; */

  spacer_t pacer;		/**< Simple transport pacer */

#if TRANSPORT_DEBUG
  elog_track_t elog_track;	/**< Event logging */
  f64 cc_stat_tstamp;		/**< CC stats timestamp */
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

STATIC_ASSERT (STRUCT_OFFSET_OF (transport_connection_t, is_ip4) == TRANSPORT_CONN_ID_LEN,
	       "update conn id len");

/* Warn if size changes. Two cache lines is already generous, hopefully we
 * won't have to outgrow that. */
STATIC_ASSERT (sizeof (transport_connection_t) <= 128,
	       "moved into 3rd cache line");

#define foreach_transport_proto                                               \
  _ (TCP, "tcp", "T")                                                         \
  _ (UDP, "udp", "U")                                                         \
  _ (CT, "ct", "C")                                                           \
  _ (TLS, "tls", "J")                                                         \
  _ (QUIC, "quic", "Q")                                                       \
  _ (DTLS, "dtls", "D")                                                       \
  _ (SRTP, "srtp", "R")                                                       \
  _ (HTTP, "http", "H")

typedef enum _transport_proto
{
#define _(sym, str, sstr) TRANSPORT_PROTO_ ## sym,
  foreach_transport_proto
#undef _
} transport_proto_t;

#define TRANSPORT_PROTO_NONE TRANSPORT_PROTO_CT

u8 *format_transport_proto (u8 * s, va_list * args);
u8 *format_transport_proto_short (u8 * s, va_list * args);
u8 *format_transport_flags (u8 *s, va_list *args);
u8 *format_transport_connection (u8 * s, va_list * args);
u8 *format_transport_listen_connection (u8 * s, va_list * args);
u8 *format_transport_half_open_connection (u8 * s, va_list * args);

uword unformat_transport_proto (unformat_input_t * input, va_list * args);
u8 *format_transport_protos (u8 * s, va_list * args);
u8 *format_transport_state (u8 *s, va_list *args);

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
  _ (u32, al_index)						        \
  _ (u32, app_wrk_connect_index)					\
  _ (u16, mss)           						\
  _ (u8, dscp)                                                          \
  _ (u8, transport_flags)
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

typedef enum transport_endpt_ext_cfg_type_
{
  TRANSPORT_ENDPT_EXT_CFG_NONE,
  TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
  TRANSPORT_ENDPT_EXT_CFG_HTTP,
} transport_endpt_ext_cfg_type_t;

#define foreach_tls_verify_cfg                                                \
  _ (NONE, "none")                                                            \
  _ (PEER, "peer")                                                            \
  _ (PEER_CERT, "peer-cert")                                                  \
  _ (HOSTNAME, "hostname")                                                    \
  _ (HOSTNAME_STRICT, "hostname-strict")

enum tls_verify_cfg_bit_
{
#define _(sym, name) TLS_VERIFY_CFG_BIT_##sym,
  foreach_tls_verify_cfg
#undef _
};

typedef enum tls_verify_cfg_
{
#define _(sym, name) TLS_VERIFY_F_##sym = 1 << TLS_VERIFY_CFG_BIT_##sym,
  foreach_tls_verify_cfg
#undef _
} tls_verify_cfg_t;

#define foreach_tls_alpn_protos                                               \
  _ (NONE, "none")                                                            \
  _ (HTTP_1_1, "http/1.1")                                                    \
  _ (HTTP_2, "h2")                                                            \
  _ (HTTP_3, "h3")                                                            \
  _ (IMAP, "imap")                                                            \
  _ (POP3, "pop3")                                                            \
  _ (SMB2, "smb")                                                             \
  _ (TURN, "stun.turn")                                                       \
  _ (STUN, "stun.nat-discovery")                                              \
  _ (WEBRTC, "webrtc")                                                        \
  _ (CWEBRTC, "c-webrtc")                                                     \
  _ (FTP, "ftp")                                                              \
  _ (MANAGE_SIEVE, "managesieve")                                             \
  _ (COAP_TLS, "coap")                                                        \
  _ (COAP_DSTL, "co")                                                         \
  _ (XMPP_CLIENT, "xmpp-client")                                              \
  _ (XMPP_SERVER, "xmpp-server")                                              \
  _ (ACME_TLS_1, "acme-tls/1")                                                \
  _ (MQTT, "mqtt")                                                            \
  _ (DNS_OVER_TLS, "dot")                                                     \
  _ (NTSKE_1, "ntske/1")                                                      \
  _ (SUN_RPC, "sunrpc")                                                       \
  _ (IRC, "irc")                                                              \
  _ (NNTP, "nntp")                                                            \
  _ (NNSP, "nnsp")                                                            \
  _ (DOQ, "doq")                                                              \
  _ (SIP_2, "sip/2")                                                          \
  _ (TDS_8_0, "tds/8.0")                                                      \
  _ (DICOM, "dicom")                                                          \
  _ (POSTGRESQL, "postgresql")                                                \
  _ (RADIUS_1_0, "radius/1.0")                                                \
  _ (RADIUS_1_1, "radius/1.1")

typedef enum tls_alpn_proto_
{
#define _(sym, str) TLS_ALPN_PROTO_##sym,
  foreach_tls_alpn_protos
#undef _
} __clib_packed tls_alpn_proto_t;

typedef struct tls_alpn_proto_id_
{
  u8 len;
  u8 *base;
} tls_alpn_proto_id_t;

static const tls_alpn_proto_id_t tls_alpn_proto_ids[] = {
#define _(sym, str) { (u8) (sizeof (str) - 1), (u8 *) str },
  foreach_tls_alpn_protos
#undef _
};

static_always_inline u8
tls_alpn_proto_id_eq (tls_alpn_proto_id_t *actual,
		      tls_alpn_proto_id_t *expected)
{
  if (actual->len != expected->len)
    return 0;
  return memcmp (actual->base, expected->base, expected->len) == 0 ? 1 : 0;
}

tls_alpn_proto_t tls_alpn_proto_by_str (tls_alpn_proto_id_t *alpn_id);
format_function_t format_tls_alpn_proto;

typedef struct transport_endpt_crypto_cfg_
{
  u32 ckpair_index;   /**< index of ck pair in application crypto layer */
  u32 ca_trust_index; /**< index of ca trust in application crypto layer */
  u8 alpn_protos[4];  /**< ordered by preference for server */
  u8 crypto_engine;   /**< crypto engine requested */
  tls_verify_cfg_t verify_cfg; /**< cert verification mode */
  u8 hostname[256];	       /**< full domain len is 255 as per rfc 3986 */
} transport_endpt_crypto_cfg_t;

typedef struct tls_cert_
{
  void *cert;
} tls_cert_t;

typedef struct transport_endpt_ext_cfg_
{
  u16 type;
  u16 len;
  union
  {
    transport_endpt_crypto_cfg_t crypto;
    u32 opaque; /**< For general use */
    u8 data[0];
  };
} transport_endpt_ext_cfg_t;

#define TRANSPORT_ENDPT_EXT_CFG_HEADER_SIZE 4

typedef struct transport_endpt_ext_cfgs_
{
  u32 len;	   /**< length of config data chunk */
  u32 tail_offset; /**< current tail in config data chunk */
  u8 *data;	   /**< start of config data chunk */
} transport_endpt_ext_cfgs_t;

#define TRANSPORT_ENDPT_EXT_CFGS_CHUNK_SIZE 512

#define TRANSPORT_ENDPT_EXT_CFGS_NULL                                         \
  {                                                                           \
    .len = 0, .tail_offset = 0, .data = 0,                                    \
  }

#define foreach_transport_attr_fields                                         \
  _ (u64, next_output_node, NEXT_OUTPUT_NODE)                                 \
  _ (u16, mss, MSS)                                                           \
  _ (u8, flags, FLAGS)                                                        \
  _ (u8, cc_algo, CC_ALGO)                                                    \
  _ (transport_endpoint_t, ext_endpt, EXT_ENDPT)                              \
  _ (tls_cert_t, tls_peer_cert, TLS_PEER_CERT)                                \
  _ (tls_alpn_proto_t, tls_alpn, TLS_ALPN)                                    \
  _ (u64, next_transport, NEXT_TRANSPORT)                                     \
  _ (u64, app_proto_err_code, APP_PROTO_ERR_CODE)

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

typedef void *transport_cleanup_cb_fn;

/* Reuse tc connection pacer bytes_per_sec field to store cleanup callback function pointer */
#define transport_set_cleanup_cb_fn(tc, fn) ((tc)->pacer.bytes_per_sec = pointer_to_uword (cb_fn))
#define transport_get_cleanup_cb_fn(tc)                                                            \
  ((transport_cleanup_cb_fn) uword_to_pointer ((tc)->pacer.bytes_per_sec, void *))

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
