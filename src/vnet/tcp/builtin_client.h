
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
  /* API message ID base */
  u16 msg_id_base;

  /* vpe input queue */
  unix_shared_memory_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  /* The URI we're playing with */
  u8 *uri;

  /* Session pool */
  session_t *sessions;

  /* Hash table for disconnect processing */
  uword *session_index_by_vpp_handles;

  /* intermediate rx buffer */
  u8 *rx_buf;

  /* URI for slave's connect */
  u8 *connect_uri;

  u32 connected_session_index;

  int i_am_master;

  /* drop all packets */
  int drop_packets;

  /* Our event queue */
  unix_shared_memory_queue_t *our_event_queue;

  /* $$$ single thread only for the moment */
  unix_shared_memory_queue_t *vpp_event_queue;

  pid_t my_pid;

  f64 test_start_time;
  f64 test_end_time;

  u32 expected_connections;
  u32 **connection_index_by_thread;
  volatile u32 ready_connections;
  volatile u32 finished_connections;

  volatile u64 rx_total;
  u32 cli_node_index;

  /* Signal variable */
  volatile int run_test;

  /* Bytes to send */
  u64 bytes_to_send;

  u32 configured_segment_size;

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;

  u8 *connect_test_data;
  pthread_t client_thread_handle;
  u64 client_bytes_received;
  u8 test_return_packets;

  u8 is_init;
  u8 test_client_attached;

  u32 node_index;

  /* convenience */
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
