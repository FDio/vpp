/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef SRC_VLIBMEMORY_SOCKET_API_H_
#define SRC_VLIBMEMORY_SOCKET_API_H_

#include <vlibapi/api_common.h>
#include <vppinfra/file.h>

#define API_SOCKET_FILE "/run/vpp-api.sock"

typedef struct
{
  clib_file_t *clib_file;
  vl_api_registration_t *regp;
  u8 *data;
} vl_socket_args_for_process_t;

typedef struct
{
  /* Server port number */
  u8 *socket_name;

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

  /* pool of process args for socket clients */
  vl_socket_args_for_process_t *process_args;

  /* Listen for API connections here */
  clib_socket_t socksvr_listen_socket;
} socket_main_t;

extern socket_main_t socket_main;

typedef struct
{
  int socket_fd;
  /* Temporarily disable the connection, so we can keep it around... */
  int socket_enable;

  clib_socket_t client_socket;

  u32 socket_buffer_size;
  u8 *socket_tx_buffer;
  u8 *socket_rx_buffer;
  u32 socket_tx_nbytes;
  int control_pings_outstanding;

  u8 *name;
  clib_time_t clib_time;
} socket_client_main_t;

extern socket_client_main_t socket_client_main;

#define SOCKET_CLIENT_DEFAULT_BUFFER_SIZE 4096

void vl_socket_free_registration_index (u32 pool_index);
clib_error_t *vl_socket_read_ready (struct clib_file *uf);
void vl_socket_add_pending_output (struct clib_file *uf,
				   struct vl_api_registration_ *rp,
				   u8 * buffer, uword buffer_bytes);
void vl_socket_add_pending_output_no_flush (struct clib_file *uf,
					    struct vl_api_registration_ *rp,
					    u8 * buffer, uword buffer_bytes);
clib_error_t *vl_socket_write_ready (struct clib_file *uf);
void vl_socket_api_send (vl_api_registration_t * rp, u8 * elem);
void vl_socket_process_api_msg (clib_file_t * uf, vl_api_registration_t * rp,
				i8 * input_v);
int vl_socket_client_connect (char *socket_path, char *client_name,
			      u32 socket_buffer_size);
void vl_socket_client_disconnect (void);
int vl_socket_client_read (int wait);
int vl_socket_client_write (void);
void vl_socket_client_enable_disable (int enable);
void *vl_socket_client_msg_alloc (int nbytes);
int vl_socket_client_init_shm (vl_api_shm_elem_config_t * config);
void vl_sock_api_dump_clients (vlib_main_t * vm, api_main_t * am);
#endif /* SRC_VLIBMEMORY_SOCKET_API_H_ */
