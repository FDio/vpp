
/*
 * tclient.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <current-year> <your-organization>
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
#ifndef __included_tclient_h__
#define __included_tclient_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vlibmemory/unix_shared_memory_queue.h>
#include <svm/svm_fifo_segment.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

typedef struct
{
  u64 bytes_to_send;
  u64 bytes_sent;
  u64 bytes_to_receive;
  u64 bytes_received;

  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;

  u64 vpp_session_handle;
} session_t;

typedef struct
{
  /*
   * Application setup parameters
   */
  unix_shared_memory_queue_t *vl_input_queue;	/**< vpe input queue */
  unix_shared_memory_queue_t **vpp_event_queue;

  u32 cli_node_index;			/**< cli process node index */
  u32 my_client_index;			/**< loopback API client handle */
  u32 app_index;			/**< app index after attach */

  /*
   * Configuration params
   */
  u8 *connect_uri;			/**< URI for slave's connect */
  u64 bytes_to_send;			/**< Bytes to send */
  u32 configured_segment_size;
  u32 fifo_size;
  u32 expected_connections;		/**< Number of clients/connections */
  u32 connections_per_batch;		/**< Connections to rx/tx at once */
  u32 private_segment_count;		/**< Number of private fifo segs */
  u32 private_segment_size;		/**< size of private fifo segs */

  /*
   * Test state variables
   */
  session_t *sessions;			/**< Session pool, shared */
  clib_spinlock_t sessions_lock;
  u8 **rx_buf;				/**< intermediate rx buffers */
  u8 *connect_test_data;		/**< Pre-computed test data */
  u32 **connection_index_by_thread;
  u32 **connections_this_batch_by_thread; /**< active connection batch */
  pthread_t client_thread_handle;

  volatile u32 ready_connections;
  volatile u32 finished_connections;
  volatile u64 rx_total;
  volatile u64 tx_total;
  volatile int run_test;		/**< Signal start of test */

  f64 test_start_time;
  f64 test_end_time;
  u32 prev_conns;
  u32 repeats;
  /*
   * Flags
   */
  u8 is_init;
  u8 test_client_attached;
  u8 no_return;
  u8 test_return_packets;
  int i_am_master;
  int drop_packets;		/**< drop all packets */
  u8 prealloc_fifos;		/**< Request fifo preallocation */

  /*
   * Convenience
   */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} tclient_main_t;

tclient_main_t tclient_main;

vlib_node_registration_t tclient_node;

#endif /* __included_tclient_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
