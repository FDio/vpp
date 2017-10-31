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
#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/session/transport.h>

typedef struct _vnet_app_attach_args_t
{
  /** Binary API client index */
  u32 api_client_index;

  /** Application and segment manager options */
  u64 *options;

  /* Namespace id */
  u8 *namespace_id;

  /** Session to application callback functions */
  session_cb_vft_t *session_cb_vft;

  /*
   * Results
   */
  u8 *segment_name;
  u32 segment_name_length;
  u32 segment_size;
  u64 app_event_queue_address;
  u32 app_index;
} vnet_app_attach_args_t;

typedef struct _vnet_app_detach_args_t
{
  u32 app_index;
} vnet_app_detach_args_t;

typedef struct _vnet_bind_args_t
{
  union
  {
    char *uri;
    session_endpoint_t sep;
  };

  u32 app_index;

  /*
   * Results
   */
  char *segment_name;
  u32 segment_name_length;
  u64 server_event_queue_address;
  u64 handle;
} vnet_bind_args_t;

typedef struct _vnet_unbind_args_t
{
  union
  {
    char *uri;
    u64 handle;
  };
  u32 app_index;
} vnet_unbind_args_t;

typedef struct _vnet_connect_args
{
  char *uri;
  session_endpoint_t sep;
  u32 app_index;
  u32 api_context;

  /* Used for redirects */
  void *mp;
  u64 session_handle;
} vnet_connect_args_t;

typedef struct _vnet_disconnect_args_t
{
  u64 handle;
  u32 app_index;
} vnet_disconnect_args_t;

/* Application attach options */
typedef enum
{
  APP_EVT_QUEUE_SIZE,
  APP_OPTIONS_FLAGS,
  APP_OPTIONS_PREALLOC_FIFO_PAIRS,
  APP_OPTIONS_PRIVATE_SEGMENT_COUNT,
  APP_OPTIONS_PRIVATE_SEGMENT_SIZE,
  APP_OPTIONS_NAMESPACE,
  APP_OPTIONS_NAMESPACE_SECRET,
  APP_OPTIONS_PROXY_TRANSPORT,
  SESSION_OPTIONS_SEGMENT_SIZE,
  SESSION_OPTIONS_ADD_SEGMENT_SIZE,
  SESSION_OPTIONS_RX_FIFO_SIZE,
  SESSION_OPTIONS_TX_FIFO_SIZE,
  SESSION_OPTIONS_PREALLOCATED_FIFO_PAIRS,
  SESSION_OPTIONS_ACCEPT_COOKIE,
  SESSION_OPTIONS_N_OPTIONS
} app_attach_options_index_t;

#define foreach_app_options_flags				\
  _(ACCEPT_REDIRECT, "Use FIFO with redirects")			\
  _(ADD_SEGMENT, "Add segment and signal app if needed")	\
  _(IS_BUILTIN, "Application is builtin")			\
  _(IS_PROXY, "Application is proxying")				\
  _(USE_GLOBAL_SCOPE, "App can use global session scope")	\
  _(USE_LOCAL_SCOPE, "App can use local session scope")

typedef enum _app_options
{
#define _(sym, str) APP_OPTIONS_##sym,
  foreach_app_options_flags
#undef _
} app_options_t;

typedef enum _app_options_flags
{
#define _(sym, str) APP_OPTIONS_FLAGS_##sym = 1 << APP_OPTIONS_##sym,
  foreach_app_options_flags
#undef _
} app_options_flags_t;

clib_error_t *vnet_application_attach (vnet_app_attach_args_t * a);
int vnet_application_detach (vnet_app_detach_args_t * a);

int vnet_bind_uri (vnet_bind_args_t *);
int vnet_unbind_uri (vnet_unbind_args_t * a);
clib_error_t *vnet_connect_uri (vnet_connect_args_t * a);
int vnet_disconnect_session (vnet_disconnect_args_t * a);

clib_error_t *vnet_bind (vnet_bind_args_t * a);
clib_error_t *vnet_connect (vnet_connect_args_t * a);
clib_error_t *vnet_unbind (vnet_unbind_args_t * a);

int
api_parse_session_handle (u64 handle, u32 * session_index,
			  u32 * thread_index);

#endif /* __included_uri_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
