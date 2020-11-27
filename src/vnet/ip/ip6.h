/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 * ip/ip6.h: ip6 main include file
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

#ifndef included_ip_ip6_h
#define included_ip_ip6_h

#include <stdbool.h>

#include <vlib/buffer.h>

#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/ip_interface.h>
#include <vnet/ip/ip_flow_hash.h>

typedef struct
{
  ip6_address_t addr;
  u32 dst_address_length;
  u32 vrf_index;
} ip6_fib_key_t;

typedef struct
{
  /* required for pool_get_aligned. */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Table ID (hash key) for this FIB. */
  u32 table_id;

  /* Index into FIB vector. */
  u32 index;
} ip6_fib_t;

typedef struct ip6_mfib_t
{
  /* required for pool_get_aligned. */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Table ID (hash key) for this FIB. */
  u32 table_id;

  /* Index into FIB vector. */
  u32 index;
} ip6_mfib_t;

struct ip6_main_t;

typedef void (ip6_add_del_interface_address_function_t)
  (struct ip6_main_t * im,
   uword opaque,
   u32 sw_if_index,
   ip6_address_t * address,
   u32 address_length, u32 if_address_index, u32 is_del);

typedef struct
{
  ip6_add_del_interface_address_function_t *function;
  uword function_opaque;
} ip6_add_del_interface_address_callback_t;

typedef void (ip6_table_bind_function_t)
  (struct ip6_main_t * im,
   uword opaque, u32 sw_if_index, u32 new_fib_index, u32 old_fib_index);

typedef struct
{
  ip6_table_bind_function_t *function;
  uword function_opaque;
} ip6_table_bind_callback_t;

typedef struct ip6_main_t
{
  ip_lookup_main_t lookup_main;

  /* Pool of FIBs. */
  struct fib_table_t_ *fibs;

  /* Pool of V6 FIBs. */
  ip6_fib_t *v6_fibs;

  /** Vector of MFIBs. */
  struct mfib_table_t_ *mfibs;

  /* Network byte orders subnet mask for each prefix length */
  ip6_address_t fib_masks[129];

  /* Table index indexed by software interface. */
  u32 *fib_index_by_sw_if_index;

  /** Table index indexed by software interface. */
  u32 *mfib_index_by_sw_if_index;

  /* IP6 enabled count by software interface */
  u8 *ip_enabled_by_sw_if_index;

  /* Hash table mapping table id to fib index.
     ID space is not necessarily dense; index space is dense. */
  uword *fib_index_by_table_id;

  /** Hash table mapping table id to multicast fib index.
     ID space is not necessarily dense; index space is dense. */
  uword *mfib_index_by_table_id;

  /* Hash table mapping interface rewrite adjacency index by sw if index. */
  uword *interface_route_adj_index_by_sw_if_index;

  /* Functions to call when interface address changes. */
    ip6_add_del_interface_address_callback_t
    * add_del_interface_address_callbacks;

  /** Functions to call when interface to table biding changes. */
  ip6_table_bind_callback_t *table_bind_callbacks;

  /* Seed for Jenkins hash used to compute ip6 flow hash. */
  u32 flow_hash_seed;

  struct
  {
    /* TTL to use for host generated packets. */
    u8 ttl;

    u8 pad[3];
  } host_config;

  /* HBH processing enabled? */
  u8 hbh_enabled;
} ip6_main_t;

#define ND_THROTTLE_BITS 512

/* Global ip6 main structure. */
extern ip6_main_t ip6_main;

/* Global ip6 input node.  Errors get attached to ip6 input node. */
extern vlib_node_registration_t ip6_input_node;
extern vlib_node_registration_t ip6_rewrite_node;
extern vlib_node_registration_t ip6_rewrite_mcast_node;
extern vlib_node_registration_t ip6_rewrite_local_node;
extern vlib_node_registration_t ip6_discover_neighbor_node;
extern vlib_node_registration_t ip6_glean_node;
extern vlib_node_registration_t ip6_midchain_node;
extern vlib_node_registration_t ip6_punt_node;

extern void ip6_forward_next_trace (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame);

always_inline uword
ip6_destination_matches_route (const ip6_main_t * im,
			       const ip6_address_t * key,
			       const ip6_address_t * dest, uword dest_length)
{
  int i;
  for (i = 0; i < ARRAY_LEN (key->as_uword); i++)
    {
      if ((key->as_uword[i] ^ dest->as_uword[i]) & im->
	  fib_masks[dest_length].as_uword[i])
	return 0;
    }
  return 1;
}

always_inline uword
ip6_destination_matches_interface (ip6_main_t * im,
				   ip6_address_t * key,
				   ip_interface_address_t * ia)
{
  ip6_address_t *a = ip_interface_address_get_address (&im->lookup_main, ia);
  return ip6_destination_matches_route (im, key, a, ia->address_length);
}

/* As above but allows for unaligned destinations (e.g. works right from IP header of packet). */
always_inline uword
ip6_unaligned_destination_matches_route (ip6_main_t * im,
					 ip6_address_t * key,
					 ip6_address_t * dest,
					 uword dest_length)
{
  int i;
  for (i = 0; i < ARRAY_LEN (key->as_uword); i++)
    {
      if ((clib_mem_unaligned (&key->as_uword[i], uword) ^ dest->as_uword[i])
	  & im->fib_masks[dest_length].as_uword[i])
	return 0;
    }
  return 1;
}

/* Find interface address which matches destination. */
always_inline ip6_address_t *
ip6_interface_address_matching_destination (ip6_main_t * im,
					    const ip6_address_t * dst,
					    u32 sw_if_index,
					    ip_interface_address_t **
					    result_ia)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_address_t *ia;
  ip6_address_t *result = 0;

  /* *INDENT-OFF* */
  foreach_ip_interface_address (lm, ia, sw_if_index,
                                1 /* honor unnumbered */,
  ({
    ip6_address_t * a = ip_interface_address_get_address (lm, ia);
    if (ip6_destination_matches_route (im, dst, a, ia->address_length))
      {
	result = a;
	break;
      }
  }));
  /* *INDENT-ON* */
  if (result_ia)
    *result_ia = result ? ia : 0;
  return result;
}

clib_error_t *ip6_add_del_interface_address (vlib_main_t * vm,
					     u32 sw_if_index,
					     ip6_address_t * address,
					     u32 address_length, u32 is_del);
void ip6_sw_interface_enable_disable (u32 sw_if_index, u32 is_enable);

/**
 * @brief get first IPv6 interface address
 */
ip6_address_t *ip6_interface_first_address (ip6_main_t * im, u32 sw_if_index);

int ip6_address_compare (ip6_address_t * a1, ip6_address_t * a2);

uword
ip6_udp_register_listener (vlib_main_t * vm,
			   u16 dst_port, u32 next_node_index);

u16 ip6_tcp_udp_icmp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
				       ip6_header_t * ip0,
				       int *bogus_lengthp);

void ip6_register_protocol (u32 protocol, u32 node_index);
void ip6_unregister_protocol (u32 protocol);
void ip6_local_hop_by_hop_register_protocol (u32 protocol, u32 node_index);

serialize_function_t serialize_vnet_ip6_main, unserialize_vnet_ip6_main;

int vnet_set_ip6_flow_hash (u32 table_id,
			    flow_hash_config_t flow_hash_config);

u8 *format_ip6_forward_next_trace (u8 * s, va_list * args);

u32 ip6_tcp_udp_icmp_validate_checksum (vlib_main_t * vm, vlib_buffer_t * p0);

void ip6_punt_policer_add_del (u8 is_add, u32 policer_index);
void ip6_punt_redirect_add (u32 rx_sw_if_index,
			    u32 tx_sw_if_index, ip46_address_t * nh);
void ip6_punt_redirect_add_paths (u32 rx_sw_if_index,
				  fib_route_path_t * paths);
void ip6_punt_redirect_del (u32 rx_sw_if_index);

int vnet_set_ip6_classify_intfc (vlib_main_t * vm, u32 sw_if_index,
				 u32 table_index);
extern vlib_node_registration_t ip6_lookup_node;

u8 *format_ip6_hop_by_hop_ext_hdr (u8 * s, va_list * args);
/*
 * Hop-by-Hop handling
 */
typedef struct
{
  /* Array of function pointers to HBH option handling routines */
  int (*options[256]) (vlib_buffer_t * b, ip6_header_t * ip,
		       ip6_hop_by_hop_option_t * opt);
  u8 *(*trace[256]) (u8 * s, ip6_hop_by_hop_option_t * opt);
  uword next_override;
} ip6_hop_by_hop_main_t;

extern ip6_hop_by_hop_main_t ip6_hop_by_hop_main;

int ip6_hbh_register_option (u8 option,
			     int options (vlib_buffer_t * b,
					  ip6_header_t * ip,
					  ip6_hop_by_hop_option_t * opt),
			     u8 * trace (u8 * s,
					 ip6_hop_by_hop_option_t * opt));
int ip6_hbh_unregister_option (u8 option);
void ip6_hbh_set_next_override (uword next);

always_inline u32
vlib_buffer_get_ip6_fib_index (vlib_buffer_t * b)
{
  u32 fib_index, sw_if_index;
  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  fib_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
  return (fib_index == (u32) ~ 0) ?
    vec_elt (ip6_main.fib_index_by_sw_if_index, sw_if_index) : fib_index;
}
#endif /* included_ip_ip6_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
