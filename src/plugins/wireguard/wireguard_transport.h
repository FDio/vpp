/*
 * Copyright (c) 2025 Internet Mastering & Company, Inc.
 * Copyright (c) 2025 AmneziaWG 1.5 i-header support for VPP
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

#ifndef __included_wg_transport_h__
#define __included_wg_transport_h__

#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>

/**
 * Transport protocol types supported by WireGuard
 */
typedef enum wg_transport_type_t_
{
  WG_TRANSPORT_UDP = 0,
  WG_TRANSPORT_TCP = 1,
} wg_transport_type_t;

/**
 * TCP Framing for WireGuard
 *
 * Since TCP is stream-based, we need to delimit WireGuard messages.
 * We use a simple 2-byte length prefix in network byte order.
 *
 * Format: [2-byte length][WireGuard message]
 *
 * This is similar to the approach used by:
 * - udp2raw
 * - OpenVPN --proto tcp
 * - Other VPN-over-TCP implementations
 */
typedef struct wg_tcp_frame_header_t_
{
  u16 length; /* Length of WireGuard message in network byte order */
} __clib_packed wg_tcp_frame_header_t;

#define WG_TCP_FRAME_HEADER_SIZE sizeof(wg_tcp_frame_header_t)

/**
 * Maximum WireGuard message size
 * Based on wireguard_messages.h:
 * - message_data_t: 16 + 8 + 8 + MAX_CONTENT_SIZE + 16
 * - MAX_CONTENT_SIZE is typically the MTU-sized payload
 * We use a conservative 2048 bytes for the max message
 */
#define WG_MAX_MESSAGE_SIZE 2048

/**
 * IPv4 + TCP header structures for WireGuard
 */
typedef struct ip4_tcp_header_t_
{
  ip4_header_t ip4;
  tcp_header_t tcp;
} __clib_packed ip4_tcp_header_t;

typedef struct ip4_tcp_wg_header_t_
{
  ip4_header_t ip4;
  tcp_header_t tcp;
  wg_tcp_frame_header_t frame;
  /* WireGuard message follows */
} __clib_packed ip4_tcp_wg_header_t;

/**
 * IPv6 + TCP header structures for WireGuard
 */
typedef struct ip6_tcp_header_t_
{
  ip6_header_t ip6;
  tcp_header_t tcp;
} __clib_packed ip6_tcp_header_t;

typedef struct ip6_tcp_wg_header_t_
{
  ip6_header_t ip6;
  tcp_header_t tcp;
  wg_tcp_frame_header_t frame;
  /* WireGuard message follows */
} __clib_packed ip6_tcp_wg_header_t;

/**
 * TCP connection state for WireGuard peers
 *
 * Unlike standard TCP which uses the session layer for full
 * connection management, WireGuard's TCP support uses a simplified
 * stateless model suitable for encrypted tunnels:
 *
 * - No formal handshake required (TCP is only for transport)
 * - Sequence numbers are maintained per-peer
 * - No retransmission (WireGuard handles reliability)
 * - No congestion control (tunnel handles backpressure)
 */
typedef struct wg_tcp_state_t_
{
  u32 snd_nxt;  /* Next sequence number to send */
  u32 rcv_nxt;  /* Next sequence number to receive */
  u32 snd_wnd;  /* Send window */
  u32 rcv_wnd;  /* Receive window */
  u8 established; /* Connection established flag */
} wg_tcp_state_t;

/**
 * Format functions
 */
u8 *format_wg_transport_type (u8 *s, va_list *va);
u8 *format_ip4_tcp_header (u8 *s, va_list *va);
u8 *format_ip6_tcp_header (u8 *s, va_list *va);

/**
 * Helper functions
 */

/* Get transport protocol as IP protocol number */
static_always_inline u8
wg_transport_get_ip_protocol (wg_transport_type_t transport)
{
  return transport == WG_TRANSPORT_TCP ? IP_PROTOCOL_TCP : IP_PROTOCOL_UDP;
}

/* Get transport header size (TCP or UDP) */
static_always_inline u16
wg_transport_get_header_size (wg_transport_type_t transport)
{
  if (transport == WG_TRANSPORT_TCP)
    return sizeof (tcp_header_t) + WG_TCP_FRAME_HEADER_SIZE;
  else
    return sizeof (udp_header_t);
}

/* Get transport name as string */
static_always_inline const char *
wg_transport_get_name (wg_transport_type_t transport)
{
  return transport == WG_TRANSPORT_TCP ? "TCP" : "UDP";
}

/**
 * TCP sequence number management
 */
static_always_inline u32
wg_tcp_snd_space (wg_tcp_state_t *state)
{
  return state->snd_wnd;
}

static_always_inline void
wg_tcp_update_snd_nxt (wg_tcp_state_t *state, u32 bytes)
{
  state->snd_nxt += bytes;
}

static_always_inline void
wg_tcp_update_rcv_nxt (wg_tcp_state_t *state, u32 bytes)
{
  state->rcv_nxt += bytes;
}

#endif /* __included_wg_transport_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
