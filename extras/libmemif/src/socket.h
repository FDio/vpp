/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef _SOCKET_H_
#define _SOCKET_H

#include <memif_private.h>

/* interface identification errors (disconnect messages)*/
#define MEMIF_VER_ERR       "incompatible version"
#define MEMIF_ID_ERR        "unmatched interface id"
#define MEMIF_SLAVE_ERR     "cannot connect to salve"
#define MEMIF_CONN_ERR      "already connected"
#define MEMIF_MODE_ERR      "mode mismatch"
#define MEMIF_SECRET_ERR    "incorrect secret"
#define MEMIF_NOSECRET_ERR  "secret required"

/* socket.c */

int memif_conn_fd_read_ready (memif_connection_t * c);

int memif_conn_fd_write_ready (memif_connection_t * c);

int memif_conn_fd_error (memif_connection_t * c);

int memif_conn_fd_accept_ready (memif_socket_t * ms);

int memif_read_ready (int fd);

int memif_msg_send_disconnect (int fd, uint8_t * err_string,
			       uint32_t err_code);

/* when compiling unit tests, compile functions without static keyword
   and declare functions in header file */
#ifdef MEMIF_UNIT_TEST
#define static_fn

int memif_msg_send (int fd, memif_msg_t * msg, int afd);

int memif_msg_enq_ack (memif_connection_t * c);

int memif_msg_send_hello (int fd);

int memif_msg_enq_init (memif_connection_t * c);

int memif_msg_enq_add_region (memif_connection_t * c, uint8_t region);

int memif_msg_enq_add_ring (memif_connection_t * c, uint8_t index,
			    uint8_t dir);

int memif_msg_receive_hello (memif_connection_t * c, memif_msg_t * msg);

int memif_msg_receive_init (memif_socket_t * ms, int fd, memif_msg_t * msg);

int memif_msg_receive_add_region (memif_connection_t * c, memif_msg_t * msg,
				  int fd);

int memif_msg_receive_add_ring (memif_connection_t * c, memif_msg_t * msg,
				int fd);

int memif_msg_enq_connect (memif_connection_t * c);

int memif_msg_enq_connected (memif_connection_t * c);

int memif_msg_receive_connect (memif_connection_t * c, memif_msg_t * msg);

int memif_msg_receive_connected (memif_connection_t * c, memif_msg_t * msg);

int memif_msg_receive_disconnect (memif_connection_t * c, memif_msg_t * msg);

#else
#define static_fn static
#endif /* MEMIF_UNIT_TEST */

#endif /* _SOCKET_H_ */
