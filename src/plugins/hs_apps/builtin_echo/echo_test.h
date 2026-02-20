/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HSA_ECHO_TEST_H_
#define SRC_PLUGINS_HSA_ECHO_TEST_H_

#include <hs_apps/hs_test.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/transport_types.h>

typedef struct
{
  hs_test_cfg_t test_cfg;     /**< Test parameters */
  char *uri;		      /**< URI for connect/listen */
  session_endpoint_cfg_t sep; /**< Session endpoint */
  u32 tls_engine;	      /**< TLS engine */
  u32 ckpair_index;	      /**< Cert and key */
  u32 ca_trust_index;	      /**< CA trust chain to be used */
  u32 fifo_size;	      /**< Fifo size */
  u32 prealloc_fifos;	      /**< Preallocate fifos */
  u32 private_segment_count;  /**< Number of private segments  */
  u64 private_segment_size;   /**< Size of private segments  */
  transport_proto_t proto;    /**< Tested protocolo */
} echo_test_cfg_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define _(type, name) type name;
  foreach_app_session_field
#undef _
    u64 vpp_session_handle;
  u32 vpp_session_index;
  clib_thread_index_t thread_index;

  union
  {
    /* client */
    struct
    {
      u64 bytes_to_send;
      u64 bytes_sent;
      u64 bytes_to_receive;
      u64 bytes_received;
      u64 bytes_paced_target;
      u64 bytes_paced_current;
      u64 dgrams_sent;
      u64 dgrams_received;
      f64 time_to_send;
      f64 send_rtt;
      f64 jitter;
      u32 rtt_udp_buffer_offset;
      u8 rtt_stat;
    };
    /* server */
    struct
    {
      u32 rx_retries;
      u8 byte_index;
    };
  };
} echo_test_session_t;

typedef struct
{
  int (*listen) (vnet_listen_args_t *a, echo_test_cfg_t *cfg);
} echo_test_proto_vft_t;

typedef struct
{
  echo_test_proto_vft_t protos[TRANSPORT_PROTO_HTTP + 1];
} echo_test_main_t;

extern echo_test_main_t echo_test_main;

#define ECHO_TEST_REGISTER_PROTO(proto, vft)                                                       \
  static void __attribute__ ((constructor)) echo_test_init_##proto (void)                          \
  {                                                                                                \
    echo_test_main.protos[proto] = (vft);                                                          \
  }

always_inline int
echo_test_transport_needs_crypto (session_endpoint_cfg_t *sep)
{
  return sep->flags & SESSION_ENDPT_CFG_F_SECURE || sep->transport_proto == TRANSPORT_PROTO_TLS ||
	 sep->transport_proto == TRANSPORT_PROTO_DTLS ||
	 sep->transport_proto == TRANSPORT_PROTO_QUIC;
}

#endif /* SRC_PLUGINS_HSA_ECHO_TEST_H_ */
