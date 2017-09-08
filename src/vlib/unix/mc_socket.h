/*
 * mc_socket.h: socket based multicast for vlib mc
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#ifndef __included_mc_socket_h__
#define __included_mc_socket_h__

#include <vlib/unix/unix.h>
#include <netinet/in.h>

typedef struct
{
  int socket;
  struct sockaddr_in tx_addr;
} mc_multicast_socket_t;

/* TCP catchup socket */
typedef struct
{
  int socket;
  u32 clib_file_index;

  u8 *input_vector;
  u8 *output_vector;
  u32 output_vector_n_written;

  u32 connect_in_progress;
} mc_socket_catchup_t;

typedef struct mc_socket_main_t
{
  mc_main_t mc_main;

  /* Multicast mastership/to-relay/from-relay sockets. */
  mc_multicast_socket_t multicast_sockets[MC_N_TRANSPORT_TYPE];

  /* Unicast UDP ack sockets */
  int ack_socket;

  /* TCP catchup server socket */
  int catchup_server_socket;

  /* Pool of stream-private catchup sockets */
  mc_socket_catchup_t *catchups;

  uword *catchup_index_by_file_descriptor;

  u32 rx_mtu_n_bytes;

  /* Receive MTU in bytes and VLIB buffers. */
  u32 rx_mtu_n_buffers;

  /* Vector of RX VLIB buffers. */
  u32 *rx_buffers;
  /* Vector of scatter/gather descriptors for sending/receiving VLIB buffers
     via kernel. */
  struct iovec *iovecs;

  /* IP address of interface to use for multicast. */
  u32 if_ip4_address_net_byte_order;

  u32 ack_udp_port;
  u32 catchup_tcp_port;

  /* Interface on which to listen for multicasts. */
  char *multicast_interface_name;

  /* Multicast address to use (e.g. 0xefff0000).
     Host byte order. */
  u32 multicast_tx_ip4_address_host_byte_order;

  /* TTL to use for multicasts. */
  u32 multicast_ttl;

  /* Multicast ports for mastership, joins, etc. will be chosen
     starting at the given port in host byte order.
     A total of MC_N_TRANSPORT_TYPE ports will be used. */
  u32 base_multicast_udp_port_host_byte_order;
} mc_socket_main_t;

always_inline u32
mc_socket_peer_id_get_address (mc_peer_id_t i)
{
  u32 a = ((i.as_u8[0] << 24)
	   | (i.as_u8[1] << 16) | (i.as_u8[2] << 8) | (i.as_u8[3] << 0));
  return clib_host_to_net_u32 (a);
}

always_inline u32
mc_socket_peer_id_get_port (mc_peer_id_t i)
{
  return clib_host_to_net_u16 ((i.as_u8[4] << 8) | i.as_u8[5]);
}

static_always_inline mc_peer_id_t
mc_socket_set_peer_id (u32 address_net_byte_order, u32 port_host_byte_order)
{
  mc_peer_id_t i;
  u32 a = ntohl (address_net_byte_order);
  u32 p = port_host_byte_order;
  i.as_u8[0] = (a >> 24) & 0xff;
  i.as_u8[1] = (a >> 16) & 0xff;
  i.as_u8[2] = (a >> 8) & 0xff;
  i.as_u8[3] = (a >> 0) & 0xff;
  i.as_u8[4] = (p >> 8) & 0xff;
  i.as_u8[5] = (p >> 0) & 0xff;
  i.as_u8[6] = 0;
  i.as_u8[7] = 0;
  return i;
}

clib_error_t *mc_socket_main_init (mc_socket_main_t * msm,
				   char **intfc_probe_list,
				   int n_intfcs_to_probe);
#endif /* __included_mc_socket_h__ */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
