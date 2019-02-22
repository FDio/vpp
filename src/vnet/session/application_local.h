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


#ifndef SRC_VNET_SESSION_APPLICATION_LOCAL_H_
#define SRC_VNET_SESSION_APPLICATION_LOCAL_H_

#include <vnet/session/application.h>

local_session_t *application_local_listen_session_alloc (application_t * app);
void application_local_listen_session_free (application_t * app,
					    local_session_t * ll);
void application_local_listener_session_endpoint (local_session_t * ll,
						  session_endpoint_t * sep);

local_session_t *app_worker_local_session_alloc (app_worker_t * app_wrk);
void app_worker_local_session_free (app_worker_t * app_wrk,
				    local_session_t * s);
local_session_t *app_worker_get_local_session (app_worker_t * app_wrk,
					       u32 session_index);
local_session_t *app_worker_get_local_session_from_handle (session_handle_t
							   handle);

void app_worker_local_sessions_free (app_worker_t * app_wrk);
int app_worker_local_session_cleanup (app_worker_t * client_wrk,
				      app_worker_t * server_wrk,
				      local_session_t * ls);

int app_worker_local_session_connect_notify (local_session_t * ls);
int app_worker_local_session_connect (app_worker_t * client,
				      app_worker_t * server,
				      local_session_t * ls, u32 opaque);
int app_worker_local_session_disconnect (u32 app_or_wrk,
					 local_session_t * ls);
int app_worker_local_session_disconnect_w_index (u32 app_or_wrk,
						 u32 ls_index);

void app_worker_format_local_sessions (app_worker_t * app_wrk, int verbose);
void app_worker_format_local_connects (app_worker_t * app, int verbose);

void mq_send_local_session_disconnected_cb (u32 app_or_wrk,
					    local_session_t * ls);

always_inline local_session_t *
application_get_local_listen_session (application_t * app, u32 session_index)
{
  return pool_elt_at_index (app->local_listen_sessions, session_index);
}

always_inline local_session_t *
application_get_local_listener_w_handle (session_handle_t handle)
{
  u32 server_index, session_index;
  application_t *app;
  local_session_parse_handle (handle, &server_index, &session_index);
  app = application_get (server_index);
  return application_get_local_listen_session (app, session_index);
}

always_inline u8
application_local_session_listener_has_transport (local_session_t * ls)
{
  transport_proto_t tp;
  tp = session_type_transport_proto (ls->listener_session_type);
  return (tp != TRANSPORT_PROTO_NONE);
}

#endif /* SRC_VNET_SESSION_APPLICATION_LOCAL_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
