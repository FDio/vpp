/*
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
 */

#ifndef SRC_VNET_SESSION_STREAM_SESSION_H_
#define SRC_VNET_SESSION_STREAM_SESSION_H_

#include <vnet/vnet.h>
#include <svm/svm_fifo.h>

#define foreach_session_type                    \
  _(IP4_TCP, ip4_tcp)                           \
  _(IP4_UDP, ip4_udp)                           \
  _(IP6_TCP, ip6_tcp)                           \
  _(IP6_UDP, ip6_udp)

typedef enum
{
#define _(A, a) SESSION_TYPE_##A,
  foreach_session_type
#undef _
    SESSION_N_TYPES,
} session_type_t;

/*
 * Application session state
 */
typedef enum
{
  SESSION_STATE_LISTENING,
  SESSION_STATE_CONNECTING,
  SESSION_STATE_ACCEPTING,
  SESSION_STATE_READY,
  SESSION_STATE_CLOSED,
  SESSION_STATE_N_STATES,
} stream_session_state_t;

typedef struct _stream_session_t
{
  /** fifo pointers. Once allocated, these do not move */
  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;

  /** Type */
  u8 session_type;

  /** State */
  volatile u8 session_state;

  u8 thread_index;

  /** To avoid n**2 "one event per frame" check */
  u8 enqueue_epoch;

  /** svm segment index where fifos were allocated */
  u32 svm_segment_index;

  /** Session index in per_thread pool */
  u32 session_index;

  /** Transport specific */
  u32 connection_index;

  /** stream server pool index */
  u32 app_index;

  /** Parent listener session if the result of an accept */
  u32 listener_index;

    CLIB_CACHE_LINE_ALIGN_MARK (pad);
} stream_session_t;

#endif /* SRC_VNET_SESSION_STREAM_SESSION_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
