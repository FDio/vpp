/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_VPERF_BUILTIN_H_
#define SRC_PLUGINS_VPERF_BUILTIN_H_

#include <vperf/vperf_test.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/transport_types.h>
#include <http/http.h>

#define VP_TEST_DELAY_DISCONNECT 1

typedef enum
{
#define _(sym, str, sstr) VP_PROTO_##sym,
  foreach_transport_proto
#undef _
    VP_PROTO_HTTP_CONNECT_TCP,
  VP_PROTO_HTTP_CONNECT_UDP,
  VP_N_PROTOS,
} vp_test_proto_t;

typedef enum
{
  VP_HTTP_CONNECT_PROTO_NONE,
  VP_HTTP_CONNECT_PROTO_TCP,
  VP_HTTP_CONNECT_PROTO_UDP,
} vp_http_connect_proto_t;

typedef struct
{
  vperf_cfg_t test_cfg;	      /**< Test parameters */
  char *uri;		      /**< URI for connect/listen */
  session_endpoint_cfg_t sep; /**< Session endpoint */
  u32 tls_engine;	      /**< TLS engine */
  u32 ckpair_index;	      /**< Cert and key */
  u32 ca_trust_index;	      /**< CA trust chain to be used */
  u32 fifo_size;	      /**< Fifo size */
  u32 prealloc_fifos;	      /**< Preallocate fifos */
  u32 n_clients;	      /**< Number of clients */
  u32 n_streams;	      /**< QUIC/HTTP streams per connection */
  u64 private_segment_size;   /**< Size of private segments  */
  u64 bytes_to_send;	      /**< Bytes to send */
  vp_test_proto_t proto;      /**< Tested protocol */
  http_version_t http_version; /**< HTTP version used for connects */
  vp_http_connect_proto_t http_connect_proto;
  u8 echo_bytes;	      /**< Don't use zero-copy mode */
  u8 report_interval_total;   /**< Shown data are totals since the start of the test */
  u8 report_interval_jitter;  /**< Report jitter in periodic reports */
  u8 is_server;		      /**< Server side app */
  u64 report_interval;	      /**< Time between periodic reports (s) */
  f64 run_time;		      /**< Length of a test (s) */
} vp_test_cfg_t;

typedef enum vp_proto_rtt_stat_ : u8
{
  VP_UDP_RTT_TX_FLAG = 1,
  VP_UDP_RTT_RX_FLAG = 2
} vp_udp_rtt_flag_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define _(type, name) type name;
  foreach_app_session_field
#undef _
    u64 vpp_session_handle;

  u64 opaque;
  u64 dgrams_received;
  u64 bytes_received;
  u64 bytes_sent;
  u64 dgrams_sent;
  f64 rtt;
  vp_udp_rtt_flag_t rtt_stat;

  union
  {
    /* client */
    struct
    {
      u64 bytes_to_send;
      u64 bytes_to_receive;
      u64 bytes_paced_target;
      u64 bytes_paced_current;
      f64 time_to_send;
      f64 send_rtt;
      f64 jitter;
      u32 rtt_udp_buffer_offset;
    };
    /* server */
    struct
    {
      u32 rx_retries;
      u8 byte_index;
    };
  };
} vp_test_session_t;

typedef struct vp_test_worker_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vp_test_session_t *sessions;	 /**< session pool */
  u8 *rx_buf;			 /**< prealloced rx buffer */
  u32 *conn_indices;		 /**< sessions handled by worker */
  u32 *conns_this_batch;	 /**< sessions handled in batch */
  u64 dgrams_received;
  u64 bytes_received;
  u64 dgrams_sent;
  u64 bytes_sent;
} vp_test_worker_t;

always_inline vp_test_session_t *
vp_test_session_alloc (vp_test_worker_t *wrk)
{
  vp_test_session_t *es;

  pool_get_zero (wrk->sessions, es);
  es->session_index = es - wrk->sessions;
  return es;
}

typedef struct
{
  void (*test_init) (vlib_main_t *vm, u32 cli_node_index, vp_test_cfg_t *cfg);
  int (*listen) (vnet_listen_args_t *a, vp_test_cfg_t *cfg);
  int (*server_rx) (vp_test_session_t *es, session_t *s, u8 *rx_buf);
  int (*server_rx_test_bytes) (vp_test_session_t *es, session_t *s, u8 *rx_buf);
  void (*server_rx_no_echo) (vp_test_session_t *es, session_t *s);
  int (*connect) (vnet_connect_args_t *a, vp_test_cfg_t *cfg);
  u32 (*connected) (session_t *s, vp_test_cfg_t *cfg, vp_test_worker_t *wrk, u32 app_index);
  u8 (*client_rx) (vp_test_session_t *es, session_t *s, u8 *rx_buf);
  u8 (*client_rx_test_bytes) (vp_test_session_t *es, session_t *s, u8 *rx_buf);
  u32 (*client_tx) (vp_test_session_t *es, u32 max_send);
  u32 (*client_tx_test_bytes) (vp_test_session_t *es, u8 *test_data, u32 max_send);
} vp_test_proto_vft_t;

typedef struct
{
  vp_test_proto_vft_t protos[VP_N_PROTOS];
} vp_test_main_t;

extern vp_test_main_t vp_test_main;

#define VP_TEST_REGISTER_PROTO(proto, vft)                                                         \
  static void __attribute__ ((constructor)) vp_test_init_##proto (void)                            \
  {                                                                                                \
    vp_test_main.protos[proto] = (vft);                                                            \
  }

always_inline int
vp_test_transport_needs_crypto (session_endpoint_cfg_t *sep)
{
  return sep->flags & SESSION_ENDPT_CFG_F_SECURE || sep->transport_proto == TRANSPORT_PROTO_TLS ||
	 sep->transport_proto == TRANSPORT_PROTO_DTLS ||
	 sep->transport_proto == TRANSPORT_PROTO_QUIC;
}

#define vp_proto_err(_fmt, _args...) clib_warning (_fmt, ##_args);

#define vp_cli(_fmt, _args...) vlib_cli_output (vm, _fmt, ##_args)

always_inline void
vp_test_set_proto (vp_test_cfg_t *cfg)
{
  switch (cfg->sep.transport_proto)
    {
    case TRANSPORT_PROTO_TCP:
      cfg->proto = VP_PROTO_TCP;
      break;
    case TRANSPORT_PROTO_UDP:
      cfg->proto = VP_PROTO_UDP;
      break;
    case TRANSPORT_PROTO_TLS:
      cfg->proto = VP_PROTO_TLS;
      break;
    case TRANSPORT_PROTO_QUIC:
      cfg->proto = VP_PROTO_QUIC;
      break;
    case TRANSPORT_PROTO_HTTP:
      switch (cfg->http_connect_proto)
	{
	case VP_HTTP_CONNECT_PROTO_NONE:
	  cfg->proto = VP_PROTO_HTTP;
	  break;
	case VP_HTTP_CONNECT_PROTO_TCP:
	  cfg->proto = VP_PROTO_HTTP_CONNECT_TCP;
	  break;
	case VP_HTTP_CONNECT_PROTO_UDP:
	  cfg->proto = VP_PROTO_HTTP_CONNECT_UDP;
	  break;
	}
      break;
    default:
      vp_proto_err ("unsupported protocol %U", format_transport_proto, cfg->sep.transport_proto);
      break;
    }
}

#endif /* SRC_PLUGINS_VPERF_BUILTIN_H_ */
