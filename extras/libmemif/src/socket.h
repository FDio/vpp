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
#define _SOCKET_H_

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

int memif_listener_handler (memif_fd_event_type_t type, void *private_ctx);

int memif_control_channel_handler (memif_fd_event_type_t type,
				   void *private_ctx);

void memif_delete_control_channel (memif_control_channel_t *cc);

#endif /* _SOCKET_H_ */
