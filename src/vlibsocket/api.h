/*
 *------------------------------------------------------------------
 * api.h
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef included_vlibsocket_api_h
#define included_vlibsocket_api_h

#include <vlibapi/api.h>

typedef struct
{
  /* Server port number */
  int portno;

  /* By default, localhost... */
  u32 bind_address;

  /*
   * (listen, server, client) registrations. Shared memory
   * registrations are in shared memory
   */
  vl_api_registration_t *registration_pool;
  /*
   * Chain-drag variables, so message API handlers
   * (generally) don't know whether they're talking to a socket
   * or to a shared-memory connection.
   */
  vl_api_registration_t *current_rp;
  clib_file_t *current_uf;
  /* One input buffer, shared across all sockets */
  i8 *input_buffer;
} socket_main_t;

extern socket_main_t socket_main;

void socksvr_add_pending_output (clib_file_t * uf,
				 struct vl_api_registration_ *cf,
				 u8 * buffer, uword buffer_bytes);

#define SOCKSVR_DEFAULT_PORT 32741	/* whatever */

void vl_free_socket_registration_index (u32 pool_index);
void vl_socket_process_msg (clib_file_t * uf,
			    struct vl_api_registration_ *rp, i8 * input_v);
clib_error_t *vl_socket_read_ready (clib_file_t * uf);
void vl_socket_add_pending_output (clib_file_t * uf,
				   struct vl_api_registration_ *rp,
				   u8 * buffer, uword buffer_bytes);
clib_error_t *vl_socket_write_ready (clib_file_t * uf);
void vl_socket_api_send (vl_api_registration_t * rp, u8 * elem);
void vl_socket_api_send_with_data (vl_api_registration_t * rp,
				   u8 * elem, u8 * data_vector);
void vl_socket_api_send_with_length (vl_api_registration_t * rp,
				     u8 * elem, u32 msg_length);
void vl_socket_api_send_with_length_no_free (vl_api_registration_t * rp,
					     u8 * elem, u32 msg_length);
u32 sockclnt_open_index (char *client_name, char *hostname, int port);
void sockclnt_close_index (u32 index);
void vl_client_msg_api_send (vl_api_registration_t * cm, u8 * elem);
vl_api_registration_t *sockclnt_get_registration (u32 index);
void socksvr_set_port (u16 port);
void socksvr_set_bind_address (u32 bind_address);

#endif /* included_vlibsocket_api_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
