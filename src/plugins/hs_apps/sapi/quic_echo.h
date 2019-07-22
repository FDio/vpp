/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <stdio.h>
#include <signal.h>

#include <vnet/session/application_interface.h>

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

#define NITER 4000000
#define TIMEOUT 10.0

#define CHECK(expected, result, _fmt, _args...)		\
    if (expected != result)				\
      ECHO_FAIL ("expected %d, got %d : " _fmt, expected, result, ##_args);

#define ECHO_FAIL(_fmt,_args...)	\
  {					\
    echo_main_t *em = &echo_main;	\
    em->has_failed = 1;		\
    em->time_to_stop = 1;		\
    if (em->log_lvl > 0)		\
      clib_warning ("ECHO-ERROR: "_fmt, ##_args); 	\
  }

#define ECHO_LOG(lvl, _fmt,_args...)	\
  {					\
    echo_main_t *em = &echo_main;	\
    if (em->log_lvl > lvl)		\
      clib_warning (_fmt, ##_args); 	\
  }

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define _(type, name) type name;
  foreach_app_session_field
#undef _
  u64 vpp_session_handle;
  u64 bytes_sent;
  u64 bytes_to_send;
  volatile u64 bytes_received;
  volatile u64 bytes_to_receive;
  f64 start;
  u32 listener_index;		/* listener index in echo session pool */
  u32 idle_cycles;		/* consecutive enq/deq with no data */
  volatile u64 accepted_session_count;	/* sessions we accepted */
} echo_session_t;

typedef enum
{
  ECHO_NO_DATA_SOURCE,
  ECHO_TEST_DATA_SOURCE,
  ECHO_RX_DATA_SOURCE,
  ECHO_INVALID_DATA_SOURCE
} data_source_t;

enum echo_close_f_t
{
  ECHO_CLOSE_F_INVALID = 0,
  ECHO_CLOSE_F_PASSIVE,		/* wait for close msg */
  ECHO_CLOSE_F_ACTIVE,		/* send close msg */
  ECHO_CLOSE_F_NONE,		/* don't bother sending close msg */
};

enum quic_session_type_t
{
  QUIC_SESSION_TYPE_QUIC,
  QUIC_SESSION_TYPE_STREAM,
  QUIC_SESSION_TYPE_LISTEN,
};

enum quic_session_state_t
{
  QUIC_SESSION_STATE_INITIAL,
  QUIC_SESSION_STATE_READY,
  QUIC_SESSION_STATE_AWAIT_CLOSING,	/* Data transfer is done, wait for close evt */
  QUIC_SESSION_STATE_AWAIT_DATA,	/* Peer closed, wait for outstanding data */
  QUIC_SESSION_STATE_CLOSING,	/* told vpp to close */
  QUIC_SESSION_STATE_CLOSED,	/* closed in vpp */
};

typedef enum
{
  STATE_START,
  STATE_ATTACHED,
  STATE_LISTEN,
  STATE_READY,
  STATE_DATA_DONE,
  STATE_DISCONNECTED,
  STATE_DETACHED
} connection_state_t;

typedef enum echo_test_evt_
{
  ECHO_EVT_START = 1,		/* app starts */
  ECHO_EVT_FIRST_QCONNECT = (1 << 1),	/* First connect Quic session sent */
  ECHO_EVT_LAST_QCONNECTED = (1 << 2),	/* All Quic session are connected */
  ECHO_EVT_FIRST_SCONNECT = (1 << 3),	/* First connect Stream session sent */
  ECHO_EVT_LAST_SCONNECTED = (1 << 4),	/* All Stream session are connected */
  ECHO_EVT_LAST_BYTE = (1 << 5),	/* Last byte received */
  ECHO_EVT_EXIT = (1 << 6),	/* app exits */
} echo_test_evt_t;

typedef struct _quic_echo_cb_vft
{
  void (*quic_connected_cb) (session_connected_msg_t * mp, u32 session_index);
  void (*client_stream_connected_cb) (session_connected_msg_t * mp,
				      u32 session_index);
  void (*server_stream_connected_cb) (session_connected_msg_t * mp,
				      u32 session_index);
  void (*quic_accepted_cb) (session_accepted_msg_t * mp, u32 session_index);
  void (*client_stream_accepted_cb) (session_accepted_msg_t * mp,
				     u32 session_index);
  void (*server_stream_accepted_cb) (session_accepted_msg_t * mp,
				     u32 session_index);
} quic_echo_cb_vft_t;


typedef enum
{
  RETURN_PACKETS_NOTEST,
  RETURN_PACKETS_LOG_WRONG,
  RETURN_PACKETS_ASSERT,
} test_return_packets_t;

typedef struct teardown_stat_
{
  u32 q; /* quic sessions */
  u32 s; /* stream sessions */
} teardown_stat_t;

typedef struct
{
  svm_queue_t *vl_input_queue;	/* vpe input queue */
  u32 my_client_index;		/* API client handle */
  u8 *uri;			/* The URI we're playing with */
  echo_session_t *sessions;	/* Session pool */
  svm_msg_q_t *our_event_queue;	/* Our event queue */
  clib_time_t clib_time;	/* For deadman timers */
  u8 *socket_name;
  int i_am_master;
  u32 listen_session_index;	/* Index of vpp listener session */

  uword *session_index_by_vpp_handles;	/* Hash table : quic_echo s_id -> vpp s_handle */
  clib_spinlock_t sid_vpp_handles_lock;	/* Hash table lock */

  uword *shared_segment_handles;	/* Hash table : segment_names -> 1*/
  clib_spinlock_t segment_handles_lock;	/* Hash table lock */
  quic_echo_cb_vft_t cb_vft;	/* cb vft for QUIC scenarios */
  svm_msg_q_t *rpc_msq_queue;	/* MQ between quic_echo threads */
  fifo_segment_main_t segment_main;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile connection_state_t state;
  volatile u8 time_to_stop;	/* Signal variables */
  u8 has_failed;		/* stores the exit code */

  /** Flag that decides if socket, instead of svm, api is used to connect to
   * vpp. If sock api is used, shm binary api is subsequently bootstrapped
   * and all other messages are exchanged using shm IPC. */
  u8 use_sock_api;

  u8 *connect_test_data;
  u8 test_return_packets;
  u64 bytes_to_send;		/* target per stream */
  u64 bytes_to_receive;		/* target per stream */
  u32 fifo_size;
  u32 rx_buf_size;
  u32 tx_buf_size;
  data_source_t data_source;	/* Use no/dummy/mirrored data */
  u8 send_quic_disconnects;	/* actively send disconnect */
  u8 send_stream_disconnects;	/* actively send disconnect */
  u8 output_json;		/* Output stats as JSON */
  u8 log_lvl;			/* Verbosity of the logging */
  int max_test_msg;		/* Limit the number of incorrect data messages */

  u8 *appns_id;
  u64 appns_flags;
  u64 appns_secret;

  pthread_t *data_thread_handles;	/* vec of data thread handles */
  pthread_t mq_thread_handle;	/* Message queue thread handle */
  u32 *data_thread_args;

  u32 n_clients;		/* Target number of QUIC sessions */
  u32 n_stream_clients;		/* Target Number of STREAM sessions per QUIC session */
  volatile u32 n_quic_clients_connected;	/* Number of connected QUIC sessions */
  volatile u32 n_clients_connected;	/* Number of STREAM sessions connected */
  u32 n_rx_threads;		/* Number of data threads */
  volatile u32 nxt_available_sidx; /* next unused prealloced session_index */

  struct {
    u64 tx_total;
    u64 rx_total;
    teardown_stat_t reset_count; /* received reset from vpp */
    teardown_stat_t close_count; /* received close from vpp */
    teardown_stat_t active_count; /* sent close to vpp */
    teardown_stat_t clean_count; /* cleaned up stale session */
  } stats;

  struct /* Event based timing : start & end depend on CLI specified events */
  {
    f64 start_time;
    f64 end_time;
    u8 events_sent;
    u8 start_event;
    u8 end_event;
  } timing;
} echo_main_t;

typedef void (*echo_rpc_t) (void *arg, u32 opaque);

typedef struct
{
  void *fp;
  void *arg;
  u32 opaque;
} echo_rpc_msg_t;
