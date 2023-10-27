
/*
 * echo_client.h - built-in application layer echo client
 *
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
#ifndef __included_echo_client_h__
#define __included_echo_client_h__

#include <hs_apps/hs_test.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

typedef struct ec_session_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define _(type, name) type name;
  foreach_app_session_field
#undef _
    u32 vpp_session_index;
  u32 thread_index;
  u64 bytes_to_send;
  u64 bytes_sent;
  u64 bytes_to_receive;
  u64 bytes_received;
  u64 vpp_session_handle;
} ec_session_t;

typedef struct ec_worker_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  ec_session_t *sessions;	/**< session pool */
  u8 *rx_buf;			/**< prealloced rx buffer */
  u32 *conn_indices;		/**< sessions handled by worker */
  u32 *conns_this_batch;	/**< sessions handled in batch */
  svm_msg_q_t *vpp_event_queue; /**< session layer worker mq */
  u32 thread_index;		/**< thread index for worker */
} ec_worker_t;

typedef struct
{
  ec_worker_t *wrk;		 /**< Per-thread state */
  u8 *connect_test_data;	 /**< Pre-computed test data */

  volatile u32 ready_connections;
  volatile u64 rx_total;
  volatile u64 tx_total;
  volatile int run_test; /**< Signal start of test */

  f64 syn_start_time;
  f64 test_start_time;
  f64 test_end_time;
  u32 prev_conns;
  u32 repeats;

  u32 connect_conn_index; /**< Connects attempted progress */

  /*
   * Application setup parameters
   */

  u32 cli_node_index;			/**< cli process node index */
  u32 app_index;			/**< app index after attach */
  session_handle_t ctrl_session_handle; /**< control session handle */

  /*
   * Configuration params
   */
  hs_test_cfg_t cfg;
  u32 n_clients;			/**< Number of clients */
  u8 *connect_uri;			/**< URI for slave's connect */
  session_endpoint_cfg_t connect_sep;	/**< Sever session endpoint */
  u64 bytes_to_send;			/**< Bytes to send */
  u32 configured_segment_size;
  u32 fifo_size;
  u32 expected_connections;		/**< Number of clients/connections */
  u32 connections_per_batch;		/**< Connections to rx/tx at once */
  u32 private_segment_count;		/**< Number of private fifo segs */
  u64 private_segment_size;		/**< size of private fifo segs */
  u32 tls_engine;			/**< TLS engine mbedtls/openssl */
  u32 no_copy;				/**< Don't memcpy data to tx fifo */
  u32 quic_streams;			/**< QUIC streams per connection */
  u32 ckpair_index;			/**< Cert key pair for tls/quic */
  u64 attach_flags;			/**< App attach flags */
  u8 *appns_id;				/**< App namespaces id */
  u64 appns_secret;			/**< App namespace secret */
  f64 syn_timeout;			/**< Test syn timeout (s) */
  f64 test_timeout;			/**< Test timeout (s) */

  /*
   * Flags
   */
  u8 app_is_init;
  u8 test_client_attached;
  u8 echo_bytes;
  u8 test_return_packets;
  int drop_packets;		/**< drop all packets */
  u8 prealloc_fifos;		/**< Request fifo preallocation */
  u8 prealloc_sessions;
  u8 test_failed;
  u8 transport_proto;
  u8 barrier_acq_needed;

  vlib_main_t *vlib_main;
} ec_main_t;

typedef enum ec_state_
{
  EC_STARTING,
  EC_RUNNING,
  EC_EXITING
} ec_state_t;

typedef enum ec_cli_signal_
{
  EC_CLI_CONNECTS_DONE = 1,
  EC_CLI_CONNECTS_FAILED,
  EC_CLI_CFG_SYNC,
  EC_CLI_START,
  EC_CLI_STOP,
  EC_CLI_TEST_DONE
} ec_cli_signal_t;

void ec_program_connects (void);

#endif /* __included_echo_client_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
