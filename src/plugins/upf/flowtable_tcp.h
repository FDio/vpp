/*---------------------------------------------------------------------------
 * Copyright (c) 2016 Qosmos and/or its affiliates.
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
 *---------------------------------------------------------------------------
 */

#ifndef __flowtable_tcp_h__
#define __flowtable_tcp_h__

#include <vnet/tcp/tcp_packet.h>

typedef enum tcp_state {
  TCP_STATE_START,
  TCP_STATE_SYN,
  TCP_STATE_SYNACK,
  TCP_STATE_ESTABLISHED,
  TCP_STATE_FIN,
  TCP_STATE_FINACK,
  TCP_STATE_RST,
  TCP_STATE_MAX
} tcp_state_t;

typedef enum tcp_event {
  TCP_EV_NONE,
  TCP_EV_SYN,
  TCP_EV_SYNACK,
  TCP_EV_FIN,
  TCP_EV_FINACK,
  TCP_EV_RST,
  TCP_EV_PSHACK,
  TCP_EV_MAX
} tcp_event_t;

/* flow lifetime in seconds */
static const int tcp_lifetime[TCP_STATE_MAX] =
  {
    [TCP_STATE_SYN]         = 15,
    [TCP_STATE_SYNACK]      = 60,
    [TCP_STATE_ESTABLISHED] = 299,
    [TCP_STATE_FIN]         = 15,
    [TCP_STATE_FINACK]      = 3,
    [TCP_STATE_RST]         = 6
  };

static const tcp_state_t tcp_trans[TCP_STATE_MAX][TCP_EV_MAX] =
  {
    [TCP_STATE_START] = {
      [TCP_EV_SYN]    = TCP_STATE_SYN,
      [TCP_EV_SYNACK] = TCP_STATE_SYNACK,
      [TCP_EV_FIN]    = TCP_STATE_FIN,
      [TCP_EV_FINACK] = TCP_STATE_FINACK,
      [TCP_EV_RST]    = TCP_STATE_RST,
      [TCP_EV_NONE]   = TCP_STATE_ESTABLISHED,
    },
    [TCP_STATE_SYN] = {
      [TCP_EV_SYNACK] = TCP_STATE_SYNACK,
      [TCP_EV_PSHACK] = TCP_STATE_ESTABLISHED,
      [TCP_EV_FIN]    = TCP_STATE_FIN,
      [TCP_EV_FINACK] = TCP_STATE_FINACK,
      [TCP_EV_RST]    = TCP_STATE_RST,
    },
    [TCP_STATE_SYNACK] = {
      [TCP_EV_PSHACK] = TCP_STATE_ESTABLISHED,
      [TCP_EV_FIN]    = TCP_STATE_FIN,
      [TCP_EV_FINACK] = TCP_STATE_FINACK,
      [TCP_EV_RST]    = TCP_STATE_RST,
    },
    [TCP_STATE_ESTABLISHED] = {
      [TCP_EV_FIN]    = TCP_STATE_FIN,
      [TCP_EV_FINACK] = TCP_STATE_FINACK,
      [TCP_EV_RST]    = TCP_STATE_RST,
    },
    [TCP_STATE_FIN] = {
      [TCP_EV_FINACK] = TCP_STATE_FINACK,
      [TCP_EV_RST]    = TCP_STATE_RST,
    },
    [TCP_STATE_FINACK] = {
      [TCP_EV_RST]    = TCP_STATE_RST,
    },
  };

always_inline tcp_event_t
tcp_event(tcp_header_t * hdr)
{
  tcp_event_t event = TCP_EV_NONE;
  if(hdr->flags & TCP_FLAG_SYN && hdr->flags & TCP_FLAG_ACK) {
    event = TCP_EV_SYNACK;
  } else if(hdr->flags & TCP_FLAG_SYN) {
    event = TCP_EV_SYN;
  } else if(hdr->flags & TCP_FLAG_FIN && hdr->flags & TCP_FLAG_ACK) {
    event = TCP_EV_FINACK;
  } else if(hdr->flags & TCP_FLAG_FIN) {
    event = TCP_EV_FIN;
  } else if(hdr->flags & TCP_FLAG_RST) {
    event = TCP_EV_RST;
  } else {
    event = TCP_EV_PSHACK;
  }

  return event;
}

#endif /* __flowtable_tcp_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
