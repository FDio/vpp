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

#ifndef __included_vpp_echo_common_h__
#define __included_vpp_echo_common_h__

#include <vnet/session/application_interface.h>
#include <vnet/format_fns.h>
#include <vnet/session/session.api_enum.h>
#include <vnet/session/session.api_types.h>

#define TIMEOUT 10.0
#define LOGGING_BATCH (100)
#define LOG_EVERY_N_IDLE_CYCLES (1e8)
#define ECHO_MQ_SEG_HANDLE	((u64) ~0 - 1)

#define ECHO_INVALID_SEGMENT_INDEX  ((u32) ~0)
#define ECHO_INVALID_SEGMENT_HANDLE ((u64) ~0)

#define foreach_echo_fail_code                                          \
  _(ECHO_FAIL_NONE, "ECHO_FAIL_NONE")                                   \
  _(ECHO_FAIL_USAGE, "ECHO_FAIL_USAGE")                                 \
  _(ECHO_FAIL_SEND_IO_EVT, "ECHO_FAIL_SEND_IO_EVT")                     \
  _(ECHO_FAIL_SOCKET_CONNECT, "ECHO_FAIL_SOCKET_CONNECT")               \
  _(ECHO_FAIL_INIT_SHM_API, "ECHO_FAIL_INIT_SHM_API")                   \
  _(ECHO_FAIL_SHMEM_CONNECT, "ECHO_FAIL_SHMEM_CONNECT")                 \
  _(ECHO_FAIL_TEST_BYTES_ERR, "ECHO_FAIL_TEST_BYTES_ERR")               \
  _(ECHO_FAIL_BIND, "ECHO_FAIL_BIND")                                   \
  _(ECHO_FAIL_SESSION_ACCEPTED_BAD_LISTENER,                            \
    "ECHO_FAIL_SESSION_ACCEPTED_BAD_LISTENER")                          \
  _(ECHO_FAIL_ACCEPTED_WAIT_FOR_SEG_ALLOC,                              \
    "ECHO_FAIL_ACCEPTED_WAIT_FOR_SEG_ALLOC")                            \
  _(ECHO_FAIL_SESSION_CONNECT, "ECHO_FAIL_SESSION_CONNECT")             \
  _(ECHO_FAIL_CONNECTED_WAIT_FOR_SEG_ALLOC,                             \
    "ECHO_FAIL_CONNECTED_WAIT_FOR_SEG_ALLOC")                           \
  _(ECHO_FAIL_APP_ATTACH, "ECHO_FAIL_APP_ATTACH")                       \
  _(ECHO_FAIL_SERVER_DISCONNECT_TIMEOUT,                                \
    "ECHO_FAIL_SERVER_DISCONNECT_TIMEOUT")                              \
  _(ECHO_FAIL_INVALID_URI, "ECHO_FAIL_INVALID_URI")                     \
  _(ECHO_FAIL_PROTOCOL_NOT_SUPPORTED,                                   \
    "ECHO_FAIL_PROTOCOL_NOT_SUPPORTED")                                 \
  _(ECHO_FAIL_CONNECT_TO_VPP, "ECHO_FAIL_CONNECT_TO_VPP")               \
  _(ECHO_FAIL_ATTACH_TO_VPP, "ECHO_FAIL_ATTACH_TO_VPP")                 \
  _(ECHO_FAIL_1ST_PTHREAD_CREATE, "ECHO_FAIL_1ST_PTHREAD_CREATE")       \
  _(ECHO_FAIL_PTHREAD_CREATE, "ECHO_FAIL_PTHREAD_CREATE")               \
  _(ECHO_FAIL_DETACH, "ECHO_FAIL_DETACH")                               \
  _(ECHO_FAIL_DEL_CERT_KEY, "ECHO_FAIL_DEL_CERT_KEY")                               \
  _(ECHO_FAIL_MQ_PTHREAD, "ECHO_FAIL_MQ_PTHREAD")                       \
  _(ECHO_FAIL_VL_API_APP_ATTACH, "ECHO_FAIL_VL_API_APP_ATTACH")         \
  _(ECHO_FAIL_VL_API_MISSING_SEGMENT_NAME,                              \
    "ECHO_FAIL_VL_API_MISSING_SEGMENT_NAME")                            \
  _(ECHO_FAIL_VL_API_NULL_APP_MQ, "ECHO_FAIL_VL_API_NULL_APP_MQ")       \
  _(ECHO_FAIL_VL_API_RECV_FD_MSG, "ECHO_FAIL_VL_API_RECV_FD_MSG")       \
  _(ECHO_FAIL_VL_API_SVM_FIFO_SEG_ATTACH,                               \
    "ECHO_FAIL_VL_API_SVM_FIFO_SEG_ATTACH")                             \
  _(ECHO_FAIL_VL_API_FIFO_SEG_ATTACH,                                   \
    "ECHO_FAIL_VL_API_FIFO_SEG_ATTACH")                                 \
  _(ECHO_FAIL_VL_API_DETACH_REPLY, "ECHO_FAIL_VL_API_DETACH_REPLY")     \
  _(ECHO_FAIL_VL_API_BIND_URI_REPLY, "ECHO_FAIL_VL_API_BIND_URI_REPLY") \
  _(ECHO_FAIL_VL_API_UNBIND_REPLY, "ECHO_FAIL_VL_API_UNBIND_REPLY")     \
  _(ECHO_FAIL_SESSION_DISCONNECT, "ECHO_FAIL_SESSION_DISCONNECT")       \
  _(ECHO_FAIL_SESSION_RESET, "ECHO_FAIL_SESSION_RESET")                 \
  _(ECHO_FAIL_VL_API_CERT_KEY_ADD_REPLY,                                \
    "ECHO_FAIL_VL_API_CERT_KEY_ADD_REPLY")                              \
  _(ECHO_FAIL_VL_API_CERT_KEY_DEL_REPLY,                                \
    "ECHO_FAIL_VL_API_CERT_KEY_DEL_REPLY")                              \
  _(ECHO_FAIL_GET_SESSION_FROM_HANDLE,                                  \
    "ECHO_FAIL_GET_SESSION_FROM_HANDLE")                                \
  _(ECHO_FAIL_QUIC_WRONG_CONNECT, "ECHO_FAIL_QUIC_WRONG_CONNECT")       \
  _(ECHO_FAIL_QUIC_WRONG_ACCEPT, "ECHO_FAIL_QUIC_WRONG_ACCEPT")         \
  _(ECHO_FAIL_TCP_BAPI_CONNECT, "ECHO_FAIL_TCP_BAPI_CONNECT")           \
  _(ECHO_FAIL_UDP_BAPI_CONNECT, "ECHO_FAIL_UDP_BAPI_CONNECT")           \
  _(ECHO_FAIL_MISSING_START_EVENT, "ECHO_FAIL_MISSING_START_EVENT")     \
  _(ECHO_FAIL_MISSING_END_EVENT, "ECHO_FAIL_MISSING_END_EVENT")         \
  _(ECHO_FAIL_TEST_ASSERT_RX_TOTAL, "ECHO_FAIL_TEST_ASSERT_RX_TOTAL")   \
  _(ECHO_FAIL_UNIDIRECTIONAL, "ECHO_FAIL_UNIDIRECTIONAL")               \
  _(ECHO_FAIL_TEST_ASSERT_TX_TOTAL, "ECHO_FAIL_TEST_ASSERT_TX_TOTAL")   \
  _(ECHO_FAIL_TEST_ASSERT_ALL_SESSIONS_CLOSED,                          \
    "ECHO_FAIL_TEST_ASSERT_ALL_SESSIONS_CLOSED")                        \
  _(ECHO_FAIL_RPC_SIZE, "ECHO_FAIL_RPC_SIZE")

typedef enum
{
#define _(sym, str) sym,
  foreach_echo_fail_code
#undef _
} echo_fail_t;

extern char *echo_fail_code_str[];

#define CHECK_SAME(fail, expected, result, _fmt, _args...)      \
do {                                                            \
  if ((expected) != (result))                                   \
    ECHO_FAIL ((fail), "expected same (%lld, got %lld) : "_fmt, \
               (u64)(expected), (u64)(result), ##_args);        \
} while (0)

#define CHECK_DIFF(fail, expected, result, _fmt, _args...)      \
do {                                                            \
  if ((expected) == (result))                                   \
    ECHO_FAIL ((fail), "expected different (both %lld) : "_fmt, \
               (u64)(expected), ##_args);                       \
} while (0)

#define ECHO_FAIL(fail, _fmt, _args...)                                 \
do {                                                                    \
    echo_main_t *em = &echo_main;                                       \
    em->has_failed = (fail);                                            \
    if (vec_len(em->fail_descr))                                        \
      em->fail_descr = format(em->fail_descr, " | %s (%u): "_fmt,       \
                              echo_fail_code_str[fail], fail, ##_args); \
    else                                                                \
      em->fail_descr = format(0, "%s (%u): "_fmt,                       \
                              echo_fail_code_str[fail], fail, ##_args); \
    em->time_to_stop = 1;                                               \
    if (em->log_lvl > 0)                                                \
      clib_warning ("%v", em->fail_descr);                              \
} while (0)

#define ECHO_LOG(lvl, _fmt,_args...)    \
  {                                     \
    echo_main_t *em = &echo_main;       \
    if (em->log_lvl > lvl)              \
         clib_warning (_fmt, ##_args);  \
  }

#define ECHO_REGISTER_PROTO(proto, vft)         	\
  static void __clib_constructor                	\
  vpp_echo_init_##proto ()                      	\
  {                                             	\
    echo_main_t *em = &echo_main;               	\
    vec_validate (em->available_proto_cb_vft, proto);	\
    em->available_proto_cb_vft[proto] = &vft;   	\
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
  volatile u64 accepted_session_count;	/* sessions we accepted (as a listener) */
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
  ECHO_SESSION_TYPE_QUIC,
  ECHO_SESSION_TYPE_STREAM,
  ECHO_SESSION_TYPE_LISTEN,
};

enum quic_session_state_t
{
  ECHO_SESSION_STATE_INITIAL,
  ECHO_SESSION_STATE_READY,
  ECHO_SESSION_STATE_AWAIT_CLOSING,	/* Data transfer is done, wait for close evt */
  ECHO_SESSION_STATE_AWAIT_DATA,	/* Peer closed, wait for outstanding data */
  ECHO_SESSION_STATE_CLOSING,	/* told vpp to close */
  ECHO_SESSION_STATE_CLOSED,	/* closed in vpp */
};

typedef enum
{
  STATE_START,
  STATE_ATTACHED_NO_CERT,
  STATE_ATTACHED,
  STATE_LISTEN,
  STATE_READY,
  STATE_DATA_DONE,
  STATE_DISCONNECTED,
  STATE_CLEANED_CERT_KEY,
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

typedef union session_connected_bundled_msg_
{
  session_connected_msg_t *mp;
} session_connected_bundled_msg_t;

typedef struct echo_proto_cb_vft_
{
  void (*connected_cb) (session_connected_bundled_msg_t * mp, u32 session_index, u8 is_failed);	/* Session is connected */
  void (*accepted_cb) (session_accepted_msg_t * mp, echo_session_t * session);	/* Session got accepted */
  void (*bound_uri_cb) (session_bound_msg_t * mp, echo_session_t * session);	/* Session got bound */
  void (*reset_cb) (session_reset_msg_t * mp, echo_session_t * s);	/* Received RESET on session */
  void (*disconnected_cb) (session_disconnected_msg_t * mp, echo_session_t * s);	/* Received DISCONNECT on session */
  void (*sent_disconnect_cb) (echo_session_t * s);	/* ACK disconnect we sent to vpp */
  void (*cleanup_cb) (echo_session_t * s, u8 parent_died);	/* Session should be cleaned up (parent listener may be dead) */
  /* Add CLI options */
  int (*process_opts_cb) (unformat_input_t * a);
  void (*set_defaults_before_opts_cb) (void);
  void (*set_defaults_after_opts_cb) (void);
  void (*print_usage_cb) (void);
} echo_proto_cb_vft_t;

typedef enum
{
  RETURN_PACKETS_NOTEST,
  RETURN_PACKETS_LOG_WRONG,
  RETURN_PACKETS_ASSERT,
} test_return_packets_t;

typedef struct teardown_stat_
{
  u32 q;			/* quic sessions */
  u32 s;			/* stream sessions */
} teardown_stat_t;

typedef struct echo_stats_
{
  u64 tx_total;
  u64 rx_total;
  u64 tx_expected;
  u64 rx_expected;
  teardown_stat_t reset_count;	/* received reset from vpp */
  teardown_stat_t close_count;	/* received close from vpp */
  teardown_stat_t active_count;	/* sent close to vpp */
  teardown_stat_t clean_count;	/* cleaned up stale session */
  teardown_stat_t connected_count;	/* connected sessions count */
  teardown_stat_t accepted_count;	/* connected sessions count */
} echo_stats_t;

typedef struct
{
  svm_queue_t *vl_input_queue;	/* vpe input queue */
  u32 my_client_index;		/* API client handle */
  u8 *uri;			/* The URI we're playing with */
  u8 *app_name;
  u32 n_uris;			/* Cycle through adjacent ips */
  ip46_address_t lcl_ip;	/* Local ip for client */
  u8 lcl_ip_set;
  echo_session_t *sessions;	/* Session pool */
  svm_msg_q_t *app_mq;		/* Our receiveing event queue */
  svm_msg_q_t *ctrl_mq;		/* Our control queue (towards vpp) */
  clib_time_t clib_time;	/* For deadman timers */
  u8 *socket_name;
  u8 use_app_socket_api;
  clib_socket_t app_api_sock;
  int i_am_master;
  u32 *listen_session_indexes;	/* vec of vpp listener sessions */
  volatile u32 listen_session_cnt;

  uword *session_index_by_vpp_handles;	/* Hash table : quic_echo s_id -> vpp s_handle */
  clib_spinlock_t sid_vpp_handles_lock;	/* Hash table lock */

  uword *shared_segment_handles;	/* Hash table : segment_names -> 1 */
  clib_spinlock_t segment_handles_lock;	/* Hash table lock */
  echo_proto_cb_vft_t *proto_cb_vft;
  svm_msg_q_t rpc_msq_queue; /* MQ between quic_echo threads */
  fifo_segment_main_t segment_main;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile connection_state_t state;
  volatile u8 time_to_stop;	/* Signal variables */
  u8 rx_results_diff;		/* Rx results will be different than cfg */
  u8 tx_results_diff;		/* Tx results will be different than cfg */
  u8 has_failed;		/* stores the exit code */
  u8 *fail_descr;		/* vector containing fail description */

  u8 *connect_test_data;
  u8 test_return_packets;
  u64 bytes_to_send;		/* target per stream */
  u64 bytes_to_receive;		/* target per stream */
  u32 fifo_size;
  u32 prealloc_fifo_pairs;
  u64 rx_buf_size;
  u64 tx_buf_size;
  data_source_t data_source;	/* Use no/placeholder/mirrored data */
  u8 send_stream_disconnects;	/* actively send disconnect */
  u8 output_json;		/* Output stats as JSON */
  volatile u8 wait_for_gdb;	/* Wait for gdb to attach */
  u8 log_lvl;			/* Verbosity of the logging */
  int max_test_msg;		/* Limit the number of incorrect data messages */
  u32 evt_q_size;		/* Size of the vpp MQ (app<->vpp events) */
  u32 ckpair_index;		/* Cert key pair used */
  u8 crypto_engine;		/* crypto engine used */
  u8 connect_flag;		/* flags to pass to mq connect */
  u32 periodic_stats_delta;	/* seconds between periodic stats */

  u8 *appns_id;
  u64 appns_flags;
  u64 appns_secret;

  pthread_t *data_thread_handles;	/* vec of data thread handles */
  pthread_t mq_thread_handle;	/* Message queue thread handle */
  u32 *volatile data_thread_args;

  u32 n_connects;		/* Target number of connects to send */
  u32 n_sessions;		/* Number of sessions to prealloc */
  u32 n_clients;		/* Target number of clients doing RX/TX */
  u32 n_rx_threads;		/* Number of data threads */

  volatile u32 n_clients_connected;	/* Number of STREAM sessions connected */
  volatile u32 nxt_available_sidx;	/* next unused prealloced session_index */

  volatile int max_sim_connects;

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;
  echo_proto_cb_vft_t **available_proto_cb_vft;

  echo_stats_t stats;
  echo_stats_t last_stat_sampling;	/* copy of stats at last sampling */
  f64 last_stat_sampling_ts;

  struct			/* Event based timing : start & end depend on CLI specified events */
  {
    f64 start_time;
    f64 end_time;
    u8 events_sent;
    u8 start_event;
    u8 end_event;
  } timing;

  struct
  {
    u32 transport_proto;
    ip46_address_t ip;
    u32 port;
    u8 is_ip4;
  } uri_elts;
} echo_main_t;

extern echo_main_t echo_main;


typedef struct echo_connect_args_
{
  u32 context;
  u64 parent_session_handle;
  ip46_address_t ip;
  ip46_address_t lcl_ip;
} echo_connect_args_t;

typedef struct echo_disconnect_args_
{
  u64 session_handle;
} echo_disconnect_args_t;

typedef union
{
  echo_connect_args_t connect;
  echo_disconnect_args_t disconnect;
} echo_rpc_args_t;

typedef void (*echo_rpc_t) (echo_main_t * em, echo_rpc_args_t * arg);

typedef struct
{
  void *fp;
  echo_rpc_args_t args;
} echo_rpc_msg_t;


u8 *format_ip4_address (u8 * s, va_list * args);
u8 *format_ip6_address (u8 * s, va_list * args);
u8 *format_ip46_address (u8 * s, va_list * args);
u8 *format_api_error (u8 * s, va_list * args);
void init_error_string_table ();
u8 *echo_format_session (u8 * s, va_list * args);
u8 *echo_format_session_type (u8 * s, va_list * args);
u8 *echo_format_session_state (u8 * s, va_list * args);
u8 *echo_format_app_state (u8 * s, va_list * args);
uword echo_unformat_close (unformat_input_t * input, va_list * args);
uword echo_unformat_timing_event (unformat_input_t * input, va_list * args);
u8 *echo_format_timing_event (u8 * s, va_list * args);
uword unformat_transport_proto (unformat_input_t * input, va_list * args);
u8 *format_transport_proto (u8 * s, va_list * args);
uword unformat_ip4_address (unformat_input_t * input, va_list * args);
uword unformat_ip6_address (unformat_input_t * input, va_list * args);

void echo_session_handle_add_del (echo_main_t * em, u64 handle, u32 sid);
echo_session_t *echo_session_new (echo_main_t * em);
int echo_send_rpc (echo_main_t * em, void *fp, echo_rpc_args_t * args);
echo_session_t *echo_get_session_from_handle (echo_main_t * em, u64 handle);
int wait_for_state_change (echo_main_t * em, connection_state_t state,
			   f64 timeout);
void echo_notify_event (echo_main_t * em, echo_test_evt_t e);
void echo_session_print_stats (echo_main_t * em, echo_session_t * session);
u8 *echo_format_crypto_engine (u8 * s, va_list * args);
uword echo_unformat_crypto_engine (unformat_input_t * input, va_list * args);
u8 *echo_format_bytes_per_sec (u8 * s, va_list * args);
int echo_segment_attach (u64 segment_handle, char *name,
			 ssvm_segment_type_t type, int fd);
u32 echo_segment_lookup (u64 segment_handle);
void echo_segment_detach (u64 segment_handle);
int echo_attach_session (uword segment_handle, uword rxf_offset,
			 uword mq_offset, uword txf_offset, echo_session_t *s);
int echo_segment_attach_mq (uword segment_handle, uword mq_offset,
			    u32 mq_index, svm_msg_q_t **mq);
svm_fifo_chunk_t *echo_segment_alloc_chunk (uword segment_handle,
					    u32 slice_index, u32 size,
					    uword *offset);

/* Binary API */

void echo_send_attach (echo_main_t * em);
void echo_send_detach (echo_main_t * em);
void echo_send_listen (echo_main_t * em, ip46_address_t * ip);
void echo_send_unbind (echo_main_t * em, echo_session_t * s);
void echo_send_connect (echo_main_t * em, void *args);
void echo_send_connect_stream (echo_main_t *em, void *args);
void echo_send_disconnect_session (echo_main_t * em, void *args);
void echo_api_hookup (echo_main_t * em);
void echo_send_add_cert_key (echo_main_t * em);
void echo_send_del_cert_key (echo_main_t * em);
int echo_bapi_recv_fd (echo_main_t *em, int *fds, int n_fds);

/* Session socket API */
int echo_sapi_attach (echo_main_t *em);
int echo_sapi_add_cert_key (echo_main_t *em);
int echo_sapi_del_cert_key (echo_main_t *em);
int echo_api_connect_app_socket (echo_main_t *em);
int echo_sapi_detach (echo_main_t *em);
int echo_sapi_recv_fd (echo_main_t *em, int *fds, int n_fds);

#endif /* __included_vpp_echo_common_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
