
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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  app_session_t data;
  u64 bytes_to_send;
  u64 bytes_sent;
  u64 bytes_to_receive;
  u64 bytes_received;
  u64 vpp_session_handle;
  u8 thread_index;
} eclient_session_t;

typedef struct
{
  /*
   * Test state variables
   */
  eclient_session_t *sessions;	 /**< Session pool, shared */
  clib_spinlock_t sessions_lock; /**< Session pool lock */
  u8 **rx_buf;			 /**< intermediate rx buffers */
  u8 *connect_test_data;	 /**< Pre-computed test data */
  u32 **quic_session_index_by_thread;
  u32 **connection_index_by_thread;
  u32 **connections_this_batch_by_thread; /**< active connection batch */

  volatile u32 ready_connections;
  volatile u32 finished_connections;
  volatile u64 rx_total;
  volatile u64 tx_total;
  volatile int run_test; /**< Signal start of test */

  f64 syn_start_time;
  f64 test_start_time;
  f64 test_end_time;
  u32 prev_conns;
  u32 repeats;

  /*
   * Application setup parameters
   */
  svm_msg_q_t **vpp_event_queue;

  u32 cli_node_index;			/**< cli process node index */
  u32 app_index;			/**< app index after attach */
  pthread_t client_thread_handle;

  /*
   * Configuration params
   */
  u32 n_clients;			/**< Number of clients */
  u8 *connect_uri;			/**< URI for slave's connect */
  session_endpoint_cfg_t connect_sep;	/**< Sever session endpoint */
  u64 bytes_to_send;			/**< Bytes to send */
  u32 configured_segment_size;
  u32 fifo_size;
  u32 expected_connections;		/**< Number of clients/connections */
  u32 connections_per_batch;		/**< Connections to rx/tx at once */
  u32 private_segment_count;		/**< Number of private fifo segs */
  u32 private_segment_size;		/**< size of private fifo segs */
  u32 tls_engine;			/**< TLS engine mbedtls/openssl */
  u8 is_dgram;
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
  u8 no_return;
  u8 test_return_packets;
  int drop_packets;		/**< drop all packets */
  u8 prealloc_fifos;		/**< Request fifo preallocation */
  u8 prealloc_sessions;
  u8 no_output;
  u8 test_bytes;
  u8 test_failed;
  u8 transport_proto;
  u8 barrier_acq_needed;

  vlib_main_t *vlib_main;
} echo_client_main_t;

enum
{
  ECHO_CLIENTS_STARTING,
  ECHO_CLIENTS_RUNNING,
  ECHO_CLIENTS_EXITING
} echo_clients_test_state_e;
extern echo_client_main_t echo_client_main;

vlib_node_registration_t echo_clients_node;

#endif /* __included_echo_client_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
