/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef __included_uri_h__
#define __included_uri_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <svm/svm_fifo_segment.h>
#include <vnet/uri/uri_db.h>

#define foreach_uri_input_error                                         \
_(NO_SESSION, "No session drops")                                       \
_(NO_LISTENER, "No listener for dst port drops")                        \
_(ENQUEUED, "Packets pushed into rx fifo")                              \
_(NOT_READY, "Session not ready packets")                               \
_(FIFO_FULL, "Packets dropped for lack of rx fifo space")               \
_(EVENT_FIFO_FULL, "Events not sent for lack of event fifo space")      \
_(API_QUEUE_FULL, "Sessions not created for lack of API queue space")   \
_(NEW_SEG_NO_SPACE, "Created segment, couldn't allocate a fifo pair")	\
_(NO_SPACE, "Couldn't allocate a fifo pair")

typedef enum {
#define _(sym,str) URI_INPUT_ERROR_##sym,
  foreach_uri_input_error
#undef _
  URI_INPUT_N_ERROR,
} uri_input_error_t;

typedef struct
{
  u8 * bind_name;
  u8 * server_name;
  u8 * segment_name;
  u32 segment_size;
  u32 bind_client_index;
  u32 accept_cookie;
  u32 connect_client_index;
} uri_bind_table_entry_t;

typedef struct
{
  /* Bind tables */
  /* Named rx/tx fifo pairs */
  uri_bind_table_entry_t * fifo_bind_table;
  uword * uri_bind_table_entry_by_name;
  
  /* Convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} uri_main_t;

extern uri_main_t uri_main;

typedef struct
{
  char *uri;
  u32 api_client_index;
  u32 accept_cookie;
  u32 segment_size;
  u64 * options;
  void * send_session_create_callback;
  void * send_session_delete_callback;
  void * send_session_clear_callback;
  void * add_segment_callback;
  void * builtin_server_rx_callback;

  /** segment name (result) */
  char *segment_name;

  /** segment name length (result) */
  u32 segment_name_length;

  /** Event queue addresses (result)*/
  u64 server_event_queue_address;
} vnet_bind_uri_args_t;

/* Bind / connect options */
typedef enum
{
  URI_OPTIONS_FLAGS,
  URI_OPTIONS_ADD_SEGMENT_SIZE,
  URI_OPTIONS_RX_FIFO_SIZE,
  URI_OPTIONS_TX_FIFO_SIZE,
  URI_OPTIONS_N_OPTIONS
} uri_options_index_t;

/* TODO decide how much since we have pre-data as well */
#define MAX_HDRS_LEN    100             /* Max number of bytes for headers */

/** Server can handle delegated connect requests from local clients */
#define URI_OPTIONS_FLAGS_USE_FIFO	(1<<0)

/** Server wants vpp to add segments when out of memory for fifos */
#define URI_OPTIONS_FLAGS_ADD_SEGMENT   (1<<1)

#define VNET_CONNECT_URI_REDIRECTED	123

int
vnet_bind_uri (vnet_bind_uri_args_t *);

int
vnet_unbind_uri (char * uri, u32 api_client_index);

int
vnet_connect_uri (char * uri, u32 api_client_index, u64 *options,
                  char *segment_name, u32 *name_length, void *mp);

int
vnet_disconnect_uri (u32 client_index, u32 session_index, u32 thread_index);

int
vnet_connect_ip4_udp (ip4_address_t *ip46_address, u16 port,
                      u32 api_client_index, u64 *options, u8 * segment_name,
                      u32 * name_length, void * mp);

#endif /* __included_uri_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
