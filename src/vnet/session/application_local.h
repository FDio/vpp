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
#include <vnet/session/transport.h>

typedef struct ct_connection_
{
  transport_connection_t connection;
  u32 client_wrk;
  u32 server_wrk;
  u32 transport_listener_index;
  transport_proto_t actual_tp;
  u32 client_opaque;
  u32 peer_index;
  u64 segment_handle;
  svm_fifo_t *client_rx_fifo;
  svm_fifo_t *client_tx_fifo;
  u8 is_client;
} ct_connection_t;

session_t *ct_session_get_peer (session_t * s);
void ct_session_endpoint (session_t * ll, session_endpoint_t * sep);
int ct_session_connect_notify (session_t * ls);
int ct_session_tx (session_t * s);

#endif /* SRC_VNET_SESSION_APPLICATION_LOCAL_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
