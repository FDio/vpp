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
#include <vppinfra/heap.h>	/* adjacency heap */
#include <vppinfra/ptclosure.h>

#include <vnet/vnet.h>

#include <vnet/ip/ip_types.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/ip_interface.h>

#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/icmp46_packet.h>

#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/icmp4.h>

#include <vnet/ip/ip6.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_error.h>
#include <vnet/ip/icmp6.h>

/* Per protocol info. */
typedef struct
{
  /* Protocol name (also used as hash key). */
  u8 *name;

  /* Protocol number. */
  ip_protocol_t protocol;

  /* Format function for this IP protocol. */
  format_function_t *format_header;

  /* Parser for header. */
  unformat_function_t *unformat_header;

  /* Parser for per-protocol matches. */
  unformat_function_t *unformat_match;

  /* Parser for packet generator edits for this protocol. */
  unformat_function_t *unformat_pg_edit;
} ip_protocol_info_t;

/* Per TCP/UDP port info. */
typedef struct
{
  /* Port name (used as hash key). */
  u8 *name;

  /* UDP/TCP port number in network byte order. */
  u16 port;

  /* Port specific format function. */
  format_function_t *format_header;

  /* Parser for packet generator edits for this protocol. */
  unformat_function_t *unformat_pg_edit;
} tcp_udp_port_info_t;

typedef struct
{
  /* Per IP protocol info. */
  ip_protocol_info_t *protocol_infos;

  /* Protocol info index hashed by 8 bit IP protocol. */
  uword *protocol_info_by_protocol;

  /* Hash table mapping IP protocol name (see protocols.def)
     to protocol number. */
  uword *protocol_info_by_name;

  /* Per TCP/UDP port info. */
  tcp_udp_port_info_t *port_infos;

  /* Hash table from network-byte-order port to port info index. */
  uword *port_info_by_port;

  /* Hash table mapping TCP/UDP name to port info index. */
  uword *port_info_by_name;
} ip_main_t;

extern ip_main_t ip_main;

clib_error_t *ip_main_init (vlib_main_t * vm);

static inline ip_protocol_info_t *
ip_get_protocol_info (ip_main_t * im, u32 protocol)
{
  uword *p;

  p = hash_get (im->protocol_info_by_protocol, protocol);
  return p ? vec_elt_at_index (im->protocol_infos, p[0]) : 0;
}

static inline tcp_udp_port_info_t *
ip_get_tcp_udp_port_info (ip_main_t * im, u32 port)
{
  uword *p;

  p = hash_get (im->port_info_by_port, port);
  return p ? vec_elt_at_index (im->port_infos, p[0]) : 0;
}

always_inline ip_csum_t
ip_incremental_checksum_buffer (vlib_main_t * vm,
				vlib_buffer_t * first_buffer,
				u32 first_buffer_offset,
				u32 n_bytes_to_checksum, ip_csum_t sum)
{
  vlib_buffer_t *b = first_buffer;
  u32 n_bytes_left = n_bytes_to_checksum;
  ASSERT (b->current_length >= first_buffer_offset);
  void *h;
  u32 n;

  n = clib_min (n_bytes_left, b->current_length - first_buffer_offset);
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

always_inline u16
ip_calculate_l4_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
			  ip_csum_t sum0, u32 payload_length,
			  u8 * iph, u32 ip_header_size, u8 * l4h)
{
  u16 sum16;
  u8 *data_this_buffer, length_odd;
  u32 n_bytes_left, n_this_buffer, n_ip_bytes_this_buffer;

  n_bytes_left = payload_length;

  if (l4h)			/* packet l4 header and no buffer chain involved */
    {
      ASSERT (p0 == NULL);
      n_this_buffer = payload_length;
      data_this_buffer = l4h;
    }
  else
    {
      ASSERT (p0);
      if (iph)			/* ip header pointer set to packet in buffer */
	{
	  ASSERT (ip_header_size);
	  n_this_buffer = payload_length;
	  data_this_buffer = iph + ip_header_size;	/* at l4 header */
	  n_ip_bytes_this_buffer =
	    p0->current_length - (((u8 *) iph - p0->data) - p0->current_data);
	  if (PREDICT_FALSE (payload_length + ip_header_size >
			     n_ip_bytes_this_buffer))
	    {
	      n_this_buffer = n_ip_bytes_this_buffer - ip_header_size;
	      if (PREDICT_FALSE (n_this_buffer >> 31))
		{		/*  error - ip header don't fit this buffer */
		  return 0xfefe;
		}
	    }
	}
      else			/* packet in buffer with no ip header  */
	{			/* buffer current pointer at l4 header */
	  n_this_buffer = p0->current_length;
	  data_this_buffer = vlib_buffer_get_current (p0);
	}
      n_this_buffer = clib_min (n_this_buffer, n_bytes_left);
    }

  while (1)
    {
      sum0 = ip_incremental_checksum (sum0, data_this_buffer, n_this_buffer);
      n_bytes_left -= n_this_buffer;
      if (n_bytes_left == 0)
	break;

      if (!(p0->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  return 0xfefe;
	}

      length_odd = (n_this_buffer & 1);

      p0 = vlib_get_buffer (vm, p0->next_buffer);
      data_this_buffer = vlib_buffer_get_current (p0);
      n_this_buffer = clib_min (p0->current_length, n_bytes_left);

      if (PREDICT_FALSE (length_odd))
	{
	  /* Prepend a 0 byte to maintain 2-byte checksum alignment */
	  data_this_buffer--;
	  n_this_buffer++;
	  n_bytes_left++;
	  data_this_buffer[0] = 0;
	}
    }

  sum16 = ~ip_csum_fold (sum0);
  return sum16;
}

void ip_del_all_interface_addresses (vlib_main_t * vm, u32 sw_if_index);

extern vlib_node_registration_t ip4_inacl_node;
extern vlib_node_registration_t ip6_inacl_node;

void ip_table_create (fib_protocol_t fproto, u32 table_id, u8 is_api,
		      const u8 * name);

void ip_table_delete (fib_protocol_t fproto, u32 table_id, u8 is_api);

int ip_table_bind (fib_protocol_t fproto, u32 sw_if_index,
		   u32 table_id, u8 is_api);

u8 ip_is_zero (ip46_address_t * ip46_address, u8 is_ip4);
u8 ip_is_local_host (ip46_address_t * ip46_address, u8 is_ip4);
u8 ip4_is_local_host (ip4_address_t * ip4_address);
u8 ip6_is_local_host (ip6_address_t * ip6_address);
u8 ip_is_local (u32 fib_index, ip46_address_t * ip46_address, u8 is_ip4);
void ip_copy (ip46_address_t * dst, ip46_address_t * src, u8 is_ip4);
void ip_set (ip46_address_t * dst, void *src, u8 is_ip4);

void ip_feature_enable_disable (ip_address_family_t af,
				ip_sub_address_family_t safi,
				vlib_dir_t dir,
				const char *feature,
				u32 sw_if_index, int enable_disable,
				void *feature_config,
				u32 n_feature_config_bytes);

always_inline u32 vlib_buffer_get_ip4_fib_index (vlib_buffer_t * b);
always_inline u32 vlib_buffer_get_ip6_fib_index (vlib_buffer_t * b);
always_inline u32
vlib_buffer_get_ip_fib_index (vlib_buffer_t * b, u8 is_ip4)
{
  return (is_ip4 ? vlib_buffer_get_ip4_fib_index
	  : vlib_buffer_get_ip6_fib_index) (b);
}

#endif /* included_ip_main_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
