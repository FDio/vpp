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

#ifndef SRC_VLIBMEMORY_SOCKET_CLIENT_H_
#define SRC_VLIBMEMORY_SOCKET_CLIENT_H_

#include <vppinfra/file.h>
#include <vppinfra/time.h>
#include <vlibapi/memory_shared.h>

typedef struct
{
  int socket_fd;
  int socket_enable;		/**< Can temporarily disable the connection
				     but still can keep it around... */
  u32 client_index;		/**< Client index allocated by VPP */

  clib_socket_t client_socket;

  u32 socket_buffer_size;
  u8 *socket_tx_buffer;
  u8 *socket_rx_buffer;
  int control_pings_outstanding;

  u8 *name;
  clib_time_t clib_time;
  ssvm_private_t memfd_segment;

  int want_shm_pthread;
} socket_client_main_t;

extern socket_client_main_t socket_client_main;

#define SOCKET_CLIENT_DEFAULT_BUFFER_SIZE 4096

int vl_socket_client_connect (char *socket_path, char *client_name,
			      u32 socket_buffer_size);
void vl_socket_client_disconnect (void);
void vl_socket_client_enable_disable (int enable);
int vl_socket_client_read (int wait);
int vl_socket_client_write (void);
void *vl_socket_client_msg_alloc (int nbytes);
int vl_socket_client_init_shm (vl_api_shm_elem_config_t * config,
			       int want_pthread);
clib_error_t *vl_socket_client_recv_fd_msg (int fds[], int n_fds, u32 wait);

/*
 * Socket client apis that explicitly pass socket main as an argument
 */

int vl_socket_client_connect2 (socket_client_main_t * scm, char *socket_path,
			       char *client_name, u32 socket_buffer_size);
void vl_socket_client_disconnect2 (socket_client_main_t * scm);
void vl_socket_client_enable_disable2 (socket_client_main_t * scm,
				       int enable);
int vl_socket_client_read2 (socket_client_main_t * scm, int wait);
int vl_socket_client_write2 (socket_client_main_t * scm);
void *vl_socket_client_msg_alloc2 (socket_client_main_t * scm, int nbytes);
int vl_socket_client_init_shm2 (socket_client_main_t * scm,
				vl_api_shm_elem_config_t * config,
				int want_pthread);
clib_error_t *vl_socket_client_recv_fd_msg2 (socket_client_main_t * scm,
					     int fds[], int n_fds, u32 wait);

#endif /* SRC_VLIBMEMORY_SOCKET_CLIENT_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
