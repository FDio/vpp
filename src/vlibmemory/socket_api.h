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
#include <svm/ssvm.h>
#include <vppinfra/file.h>

/* Deprecated */
#define API_SOCKET_FILE "/run/vpp/api.sock"

#define API_SOCKET_FILENAME "api.sock"

typedef struct
{
  u32 reg_index;
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
  /* One input buffer, shared across all sockets */
  i8 *input_buffer;

  /* pool of process args for socket clients */
  vl_socket_args_for_process_t *process_args;

  /* Listen for API connections here */
  clib_socket_t socksvr_listen_socket;

  /* vector of indices into the pool of files to clean up*/
  u32 *zombie_socket_files;
  u32 *zombie_socket_files_inferno;
} socket_main_t;

extern socket_main_t socket_main;

always_inline vl_api_registration_t *
vl_socket_get_registration (u32 reg_index)
{
  if (pool_is_free_index (socket_main.registration_pool, reg_index))
    return 0;
  return pool_elt_at_index (socket_main.registration_pool, reg_index);
}

void vl_socket_free_registration_index (u32 pool_index);
clib_error_t *vl_socket_read_ready (struct clib_file *uf);
clib_error_t *vl_socket_write_ready (struct clib_file *uf);
void vl_socket_api_send (vl_api_registration_t * rp, u8 * elem);
void vl_socket_process_api_msg (vl_api_registration_t * rp, i8 * input_v);
void vl_sock_api_dump_clients (vlib_main_t * vm, api_main_t * am);
clib_error_t *vl_sock_api_init (vlib_main_t * vm);
clib_error_t *vl_sock_api_send_fd_msg (int socket_fd, int fds[], int n_fds);
clib_error_t *vl_sock_api_recv_fd_msg (int socket_fd, int fds[], int n_fds,
				       u32 wait);

vl_api_registration_t *vl_socket_api_client_handle_to_registration (u32 idx);
u8 vl_socket_api_registration_handle_is_valid (u32 reg_index);

#endif /* SRC_VLIBMEMORY_SOCKET_API_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
