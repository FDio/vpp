/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * ip/tcp.h: tcp protocol
 *
 * Copyright (c) 2011 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_tcp_protocol_h
#define included_tcp_protocol_h

#include <vppinfra/vector.h>

/* No support for e.g. Altivec. */
#if defined (__SSE2__)
#define TCP_HAVE_VEC128
#endif

typedef union {
  struct {
    u16 src, dst;
  };
  u32 as_u32;
} tcp_udp_ports_t;

typedef union {
#ifdef TCP_HAVE_VEC128
  u32x4 as_u32x4;
#endif
  tcp_udp_ports_t as_ports[4];
} tcp_udp_ports_x4_t;

typedef struct {
  union {
#ifdef TCP_HAVE_VEC128
    u32x4 as_u32x4;
#endif
    ip4_address_t as_ip4_address[4];
  } src, dst;
  tcp_udp_ports_x4_t ports;
} ip4_tcp_udp_address_x4_t;

typedef struct {
  union {
#ifdef TCP_HAVE_VEC128
    u32x4 as_u32x4[4];
#endif
    u32   as_u32[4][4];
  } src, dst;
  tcp_udp_ports_x4_t ports;
} ip6_tcp_udp_address_x4_t;

typedef struct {
  u32 his, ours;
} tcp_sequence_pair_t;

/* Time stamps saved from options. */
typedef struct {
  u32 ours_host_byte_order, his_net_byte_order;
} tcp_time_stamp_pair_t;

typedef struct {
  ip4_tcp_udp_address_x4_t address_x4;
  u32 time_stamps[4];
} ip4_tcp_udp_address_x4_and_timestamps_t;

typedef struct {
  ip6_tcp_udp_address_x4_t address_x4;
  u32 time_stamps[4];
} ip6_tcp_udp_address_x4_and_timestamps_t;

#define foreach_tcp_connection_state					\
  /* unused */								\
  _ (unused)								\
  /* Sent SYN-ACK waiting for ACK if he ever feels like sending one. */	\
  _ (listen_ack_wait)							\
  /* Sent SYN waiting for ACK or RST. */				\
  _ (connecting)							\
  /* Pseudo-type for established connections. */			\
  _ (established)

typedef enum {
#define _(f) TCP_CONNECTION_STATE_##f,
  foreach_tcp_connection_state
#undef _
  TCP_N_CONNECTION_STATE,
} tcp_connection_state_t;

/* Kept small to fight off syn flood attacks. */
typedef struct {
  tcp_sequence_pair_t sequence_numbers;

  tcp_time_stamp_pair_t time_stamps;

  /* segment size and window scale (saved from options
     or set to defaults). */
  u16 max_segment_size;

  u8 window_scale;

  tcp_connection_state_t state : 8;
} tcp_mini_connection_t;

typedef struct {
  /* Sum and sum^2 of measurements.
     Used to compute average and RMS. */
  f64 sum, sum2;

  /* Number of measurements. */
  f64 count;
} tcp_round_trip_time_stats_t;

typedef struct {
  u32 first_buffer_index_this_packet;

  u16 data_ip_checksum;

  u16 n_data_bytes;
} tcp_tx_packet_t;

typedef struct {
  tcp_sequence_pair_t sequence_numbers;

  tcp_time_stamp_pair_t time_stamps;

  tcp_tx_packet_t head_packet, tx_tail_packet, write_tail_packet;

  u32 write_tail_buffer_index;

  tcp_round_trip_time_stats_t round_trip_time_stats;

  /* Number of un-acknowledged bytes we've sent. */
  u32 n_tx_unacked_bytes;

  /* segment size and window scale (saved from options
     or set to defaults). */
  u16 max_segment_size;

  /* Window from latest received packet. */
  u16 his_window;

  u16 my_window;

  u8 his_window_scale;

  u8 my_window_scale;

  /* ip4/ip6 tos/ttl to use for packets we send. */
  u8 tos, ttl;

  u16 flags;
#define foreach_tcp_connection_flag		\
  _ (ack_pending)				\
  _ (fin_received)				\
  _ (fin_sent)					\
  _ (application_requested_close)

  u8 listener_opaque[128
		     - 1 * sizeof (tcp_sequence_pair_t)
		     - 1 * sizeof (tcp_time_stamp_pair_t)
		     - 3 * sizeof (tcp_tx_packet_t)
		     - 1 * sizeof (tcp_round_trip_time_stats_t)
		     - 2 * sizeof (u32)
		     - 4 * sizeof (u16)
		     - 4 * sizeof (u8)];
} tcp_connection_t;

typedef enum {
  TCP_IP4,
  TCP_IP6,
  TCP_N_IP46,
} tcp_ip_4_or_6_t;

typedef enum {
#define _(f) LOG2_TCP_CONNECTION_FLAG_##f,
  foreach_tcp_connection_flag
#undef _
  N_TCP_CONNECTION_FLAG,
#define _(f) TCP_CONNECTION_FLAG_##f = 1 << LOG2_TCP_CONNECTION_FLAG_##f,
  foreach_tcp_connection_flag
#undef _
} tcp_connection_flag_t;

typedef enum {
  TCP_PACKET_TEMPLATE_SYN,
  TCP_PACKET_TEMPLATE_SYN_ACK,
  TCP_PACKET_TEMPLATE_ACK,
  TCP_PACKET_TEMPLATE_FIN_ACK,
  TCP_PACKET_TEMPLATE_RST_ACK,
  TCP_N_PACKET_TEMPLATE,
} tcp_packet_template_type_t;

typedef struct {
  vlib_packet_template_t vlib;

  /* TCP checksum of template with zeros for all
     variable fields.  Network byte order. */
  u16 tcp_checksum_net_byte_order;

  /* IP4 checksum. */
  u16 ip4_checksum_net_byte_order;
} tcp_packet_template_t;

typedef struct {
  u8 log2_n_mini_connection_hash_elts;
  u8 log2_n_established_connection_hash_elts;
  u8 is_ip6;

  u32 mini_connection_hash_mask;
  u32 established_connection_hash_mask;

  uword * established_connection_overflow_hash;

  tcp_mini_connection_t * mini_connections;

  tcp_connection_t * established_connections;

  /* Vector of established connection indices which need ACKs sent. */
  u32 * connections_pending_acks;

  /* Default valid_local_adjacency_bitmap for listeners who want to listen
     for a given port in on all interfaces. */
  uword * default_valid_local_adjacency_bitmap;

  u32 output_node_index;

  tcp_packet_template_t packet_templates[TCP_N_PACKET_TEMPLATE];
} ip46_tcp_main_t;

#define foreach_tcp_event					\
  /* Received a SYN-ACK after sending a SYN to connect. */	\
  _ (connection_established)					\
  /* Received a reset (RST) after sending a SYN to connect. */	\
  _ (connect_failed)						\
  /* Received a FIN from an established connection. */		\
  _ (fin_received)						\
  _ (connection_closed)						\
  /* Received a reset RST from an established connection. */	\
  _ (reset_received)

typedef enum {
#define _(f) TCP_EVENT_##f,
  foreach_tcp_event
#undef _
} tcp_event_type_t;

typedef void (tcp_event_function_t)
  (u32 * connections,
   tcp_event_type_t event_type);

typedef struct {
  /* Bitmap indicating which of local (interface) addresses
     we should listen on for this destination port. */
  uword * valid_local_adjacency_bitmap;

  /* Destination tcp/udp port to listen for connections. */
  u16 dst_port;

  u16 next_index;

  u32 flags;

  /* Connection indices for which event in event_function applies to. */
  u32 * event_connections[TCP_N_IP46];
  u32 * eof_connections[TCP_N_IP46];
  u32 * close_connections[TCP_N_IP46];

  tcp_event_function_t * event_function;
} tcp_listener_t;

typedef struct {
  u8 next, error;
} tcp_lookup_disposition_t;

#define foreach_tcp_timer			\
  /* Used to rank mini connections. */		\
  _ (mini_connection, 10e-3)			\
  /* Used for timestamps. */			\
  _ (timestamp, 1e-6)

typedef enum {
#define _(f,s) TCP_TIMER_##f,
  foreach_tcp_timer
#undef _
  TCP_N_TIMER,
} tcp_timer_type_t;

typedef struct {
  ip46_tcp_main_t ip4, ip6;

  /* Array of non-established connections, but soon-to be established connections. */
  ip4_tcp_udp_address_x4_and_timestamps_t * ip4_mini_connection_address_hash;
  ip6_tcp_udp_address_x4_and_timestamps_t * ip6_mini_connection_address_hash;

  /* Vector of size log2_n_established_connection_hash_elts plus overflow. */
  ip4_tcp_udp_address_x4_t * ip4_established_connection_address_hash;
  ip6_tcp_udp_address_x4_t * ip6_established_connection_address_hash;

  /* Jenkins hash seeds for established and mini hash tables. */
  u32x4_union_t connection_hash_seeds[2][3];
  u32x4_union_t connection_hash_masks[2];

  /* Pool of listeners. */
  tcp_listener_t * listener_pool;

  /* Table mapping destination port to listener index. */
  u16 * listener_index_by_dst_port;

  tcp_lookup_disposition_t disposition_by_state_and_flags[TCP_N_CONNECTION_STATE][64];

  u8 log2_clocks_per_tick[TCP_N_TIMER];

  f64 secs_per_tick[TCP_N_TIMER];

  /* Holds pointers to default and per-packet TCP options while
     parsing a TCP packet's options. */
  tcp_mini_connection_t option_decode_mini_connection_template;

  /* Count of currently established connections. */
  u32 n_established_connections[TCP_N_IP46];

  u32 tx_buffer_free_list;
  u32 tx_buffer_free_list_n_buffer_bytes;
} tcp_main_t;

/* Global TCP main structure. */
tcp_main_t tcp_main;

typedef struct {
  /* Listen on this port. */
  u16 port;

#define TCP_LISTENER_IP4 (1 << 0)
#define TCP_LISTENER_IP6 (1 << 1)
  u16 flags;

  /* Next node index for data packets. */
  u32 data_node_index;

  /* Event function: called on new connections, etc. */
  tcp_event_function_t * event_function;
} tcp_listener_registration_t;

uword
tcp_register_listener (vlib_main_t * vm, tcp_listener_registration_t * r);

always_inline tcp_ip_4_or_6_t
tcp_connection_is_ip6 (u32 h)
{ return h & 1; }

always_inline tcp_ip_4_or_6_t
tcp_connection_handle_set (u32 iest, tcp_ip_4_or_6_t is_ip6)
{ return is_ip6 + 2*iest; }

always_inline tcp_connection_t *
tcp_get_connection (u32 connection_handle)
{
  u32 iest = connection_handle / 2;
  tcp_ip_4_or_6_t is_ip6 = tcp_connection_is_ip6 (connection_handle);
  tcp_main_t * tm = &tcp_main;
  ip46_tcp_main_t * tm46 = is_ip6 ? &tm->ip6 : &tm->ip4;
  return vec_elt_at_index (tm46->established_connections, iest);
}

#endif /* included_tcp_protocol_h */
