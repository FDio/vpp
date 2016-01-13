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
 * ip/ip.h: ip generic (4 or 6) main
 *
 * Copyright (c) 2008 Eliot Dresselhaus
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

#ifndef included_ip_main_h
#define included_ip_main_h

#include <vppinfra/hash.h>
#include <vppinfra/heap.h>		/* adjacency heap */

#include <vnet/vnet.h>

#include <vnet/ip/format.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/lookup.h>

#include <vnet/ip/tcp_packet.h>
#include <vnet/ip/udp_packet.h>
#include <vnet/ip/icmp46_packet.h>

#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/icmp4.h>

#include <vnet/ip/ip6.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_error.h>
#include <vnet/ip/icmp6.h>

#include <vnet/ip/tcp.h>

#if DPDK > 0
#include <vnet/devices/dpdk/dpdk.h>
#endif

#include <vnet/classify/vnet_classify.h>

typedef union {
  ip4_address_t ip4;
  ip6_address_t ip6;
} ip46_address_t;

/* Per protocol info. */
typedef struct {
  /* Protocol name (also used as hash key). */
  u8 * name;

  /* Protocol number. */
  ip_protocol_t protocol;

  /* Format function for this IP protocol. */
  format_function_t * format_header;

  /* Parser for header. */
  unformat_function_t * unformat_header;

  /* Parser for per-protocol matches. */
  unformat_function_t * unformat_match;

  /* Parser for packet generator edits for this protocol. */
  unformat_function_t * unformat_pg_edit;
} ip_protocol_info_t;

/* Per TCP/UDP port info. */
typedef struct {
  /* Port name (used as hash key). */
  u8 * name;

  /* UDP/TCP port number in network byte order. */
  u16 port;

  /* Port specific format function. */
  format_function_t * format_header;

  /* Parser for packet generator edits for this protocol. */
  unformat_function_t * unformat_pg_edit;
} tcp_udp_port_info_t;

typedef struct {
  /* Per IP protocol info. */
  ip_protocol_info_t * protocol_infos;

  /* Protocol info index hashed by 8 bit IP protocol. */
  uword * protocol_info_by_protocol;

  /* Hash table mapping IP protocol name (see protocols.def)
     to protocol number. */
  uword * protocol_info_by_name;

  /* Per TCP/UDP port info. */
  tcp_udp_port_info_t * port_infos;

  /* Hash table from network-byte-order port to port info index. */
  uword * port_info_by_port;

  /* Hash table mapping TCP/UDP name to port info index. */
  uword * port_info_by_name;
} ip_main_t;

extern ip_main_t ip_main;

clib_error_t *
ip_main_init (vlib_main_t * vm);

static inline ip_protocol_info_t *
ip_get_protocol_info (ip_main_t * im, u32 protocol)
{
  uword * p;

  p = hash_get (im->protocol_info_by_protocol, protocol);
  return p ? vec_elt_at_index (im->protocol_infos, p[0]) : 0;
}

static inline tcp_udp_port_info_t *
ip_get_tcp_udp_port_info (ip_main_t * im, u32 port)
{
  uword * p;

  p = hash_get (im->port_info_by_port, port);
  return p ? vec_elt_at_index (im->port_infos, p[0]) : 0;
}
      
always_inline ip_csum_t
ip_incremental_checksum_buffer (vlib_main_t * vm, vlib_buffer_t * first_buffer,
				u32 first_buffer_offset,
				u32 n_bytes_to_checksum,
				ip_csum_t sum)
#if DPDK > 0
{
  u32 n_bytes_left = n_bytes_to_checksum;
  struct rte_mbuf * mb = ((struct rte_mbuf *)first_buffer)-1;
  u8 nb_segs = mb->nb_segs;
  ASSERT(mb->data_len >= first_buffer_offset);
  void * h;
  u32 n;
  
  n = clib_min (n_bytes_left, mb->data_len);
  h = vlib_buffer_get_current (first_buffer) + first_buffer_offset;
  while (n_bytes_left)
    {
      sum = ip_incremental_checksum (sum, h, n);
      n_bytes_left -= n;
      nb_segs--;
      mb = mb->next;
      if ((nb_segs == 0) || (mb == 0))
	break;

      n = clib_min (n_bytes_left, mb->data_len);
      h = rte_ctrlmbuf_data(mb);
    }
 
  ASSERT(n_bytes_left == 0);
  ASSERT(nb_segs == 0);
  return sum;
}
#else
{
  vlib_buffer_t * b = first_buffer;
  u32 n_bytes_left = n_bytes_to_checksum;
  ASSERT (b->current_length >= first_buffer_offset);
  void * h;
  u32 n;

  n = clib_min (n_bytes_left, b->current_length);
  h = vlib_buffer_get_current (b) + first_buffer_offset;
  sum = ip_incremental_checksum (sum, h, n);
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      while (1)
	{
	  n_bytes_left -= n;
	  if (n_bytes_left == 0)
	    break;
	  b = vlib_get_buffer (vm, b->next_buffer);
	  n = clib_min (n_bytes_left, b->current_length);
	  h = vlib_buffer_get_current (b);
	  sum = ip_incremental_checksum (sum, h, n);
	}
    }

  return sum;
}
#endif /* DPDK */

void ip_del_all_interface_addresses (vlib_main_t *vm, u32 sw_if_index);

#endif /* included_ip_main_h */
