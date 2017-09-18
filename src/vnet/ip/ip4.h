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
 * ip/ip4.h: ip4 main include file
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

#ifndef included_ip_ip4_h
#define included_ip_ip4_h

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/lookup.h>
#include <vnet/buffer.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/icmp46_packet.h>

typedef struct ip4_mfib_t
{
  /* Hash table for each prefix length mapping. */
  uword *fib_entry_by_dst_address[65];

  /* Table ID (hash key) for this FIB. */
  u32 table_id;

  /* Index into FIB vector. */
  u32 index;
} ip4_mfib_t;

struct ip4_main_t;

typedef void (ip4_add_del_interface_address_function_t)
  (struct ip4_main_t * im,
   uword opaque,
   u32 sw_if_index,
   ip4_address_t * address,
   u32 address_length, u32 if_address_index, u32 is_del);

typedef struct
{
  ip4_add_del_interface_address_function_t *function;
  uword function_opaque;
} ip4_add_del_interface_address_callback_t;

typedef void (ip4_table_bind_function_t)
  (struct ip4_main_t * im,
   uword opaque, u32 sw_if_index, u32 new_fib_index, u32 old_fib_index);

typedef struct
{
  ip4_table_bind_function_t *function;
  uword function_opaque;
} ip4_table_bind_callback_t;

/**
 * @brief IPv4 main type.
 *
 * State of IPv4 VPP processing including:
 * - FIBs
 * - Feature indices used in feature topological sort
 * - Feature node run time references
 */

typedef struct ip4_main_t
{
  ip_lookup_main_t lookup_main;

  /** Vector of FIBs. */
  struct fib_table_t_ *fibs;

  /** Vector of MTries. */
  struct ip4_fib_t_ *v4_fibs;

  /** Vector of MFIBs. */
  struct mfib_table_t_ *mfibs;

  u32 fib_masks[33];

  /** Table index indexed by software interface. */
  u32 *fib_index_by_sw_if_index;

  /** Table index indexed by software interface. */
  u32 *mfib_index_by_sw_if_index;

  /* IP4 enabled count by software interface */
  u8 *ip_enabled_by_sw_if_index;

  /** Hash table mapping table id to fib index.
     ID space is not necessarily dense; index space is dense. */
  uword *fib_index_by_table_id;

  /** Hash table mapping table id to multicast fib index.
     ID space is not necessarily dense; index space is dense. */
  uword *mfib_index_by_table_id;

  /** Functions to call when interface address changes. */
    ip4_add_del_interface_address_callback_t
    * add_del_interface_address_callbacks;

  /** Functions to call when interface to table biding changes. */
  ip4_table_bind_callback_t *table_bind_callbacks;

  /** Template used to generate IP4 ARP packets. */
  vlib_packet_template_t ip4_arp_request_packet_template;

  /** Seed for Jenkins hash used to compute ip4 flow hash. */
  u32 flow_hash_seed;

  /** @brief Template information for VPP generated packets */
  struct
  {
    /** TTL to use for host generated packets. */
    u8 ttl;

    /** TOS byte to use for host generated packets. */
    u8 tos;

    u8 pad[2];
  } host_config;
} ip4_main_t;

/** Global ip4 main structure. */
extern ip4_main_t ip4_main;

/** Global ip4 input node.  Errors get attached to ip4 input node. */
extern vlib_node_registration_t ip4_input_node;
extern vlib_node_registration_t ip4_lookup_node;
extern vlib_node_registration_t ip4_local_node;
extern vlib_node_registration_t ip4_rewrite_node;
extern vlib_node_registration_t ip4_rewrite_mcast_node;
extern vlib_node_registration_t ip4_rewrite_local_node;
extern vlib_node_registration_t ip4_arp_node;
extern vlib_node_registration_t ip4_glean_node;
extern vlib_node_registration_t ip4_midchain_node;

always_inline uword
ip4_destination_matches_route (const ip4_main_t * im,
			       const ip4_address_t * key,
			       const ip4_address_t * dest, uword dest_length)
{
  return 0 == ((key->data_u32 ^ dest->data_u32) & im->fib_masks[dest_length]);
}

always_inline uword
ip4_destination_matches_interface (ip4_main_t * im,
				   ip4_address_t * key,
				   ip_interface_address_t * ia)
{
  ip4_address_t *a = ip_interface_address_get_address (&im->lookup_main, ia);
  return ip4_destination_matches_route (im, key, a, ia->address_length);
}

/* As above but allows for unaligned destinations (e.g. works right from IP header of packet). */
always_inline uword
ip4_unaligned_destination_matches_route (ip4_main_t * im,
					 ip4_address_t * key,
					 ip4_address_t * dest,
					 uword dest_length)
{
  return 0 ==
    ((clib_mem_unaligned (&key->data_u32, u32) ^ dest->
      data_u32) & im->fib_masks[dest_length]);
}

always_inline int
ip4_src_address_for_packet (ip_lookup_main_t * lm,
			    u32 sw_if_index, ip4_address_t * src)
{
  u32 if_add_index = lm->if_address_pool_index_by_sw_if_index[sw_if_index];
  if (PREDICT_TRUE (if_add_index != ~0))
    {
      ip_interface_address_t *if_add =
	pool_elt_at_index (lm->if_address_pool, if_add_index);
      ip4_address_t *if_ip = ip_interface_address_get_address (lm, if_add);
      *src = *if_ip;
      return 0;
    }
  else
    {
      src->as_u32 = 0;
    }
  return (!0);
}

/* Find interface address which matches destination. */
always_inline ip4_address_t *
ip4_interface_address_matching_destination (ip4_main_t * im,
					    ip4_address_t * dst,
					    u32 sw_if_index,
					    ip_interface_address_t **
					    result_ia)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_address_t *ia;
  ip4_address_t *result = 0;

  /* *INDENT-OFF* */
  foreach_ip_interface_address (lm, ia, sw_if_index,
                                1 /* honor unnumbered */,
  ({
    ip4_address_t * a = ip_interface_address_get_address (lm, ia);
    if (ip4_destination_matches_route (im, dst, a, ia->address_length))
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

ip4_address_t *ip4_interface_first_address (ip4_main_t * im, u32 sw_if_index,
					    ip_interface_address_t **
					    result_ia);

clib_error_t *ip4_add_del_interface_address (vlib_main_t * vm,
					     u32 sw_if_index,
					     ip4_address_t * address,
					     u32 address_length, u32 is_del);

void ip4_sw_interface_enable_disable (u32 sw_if_index, u32 is_enable);

int ip4_address_compare (ip4_address_t * a1, ip4_address_t * a2);

/* Send an ARP request to see if given destination is reachable on given interface. */
clib_error_t *ip4_probe_neighbor (vlib_main_t * vm, ip4_address_t * dst,
				  u32 sw_if_index);

clib_error_t *ip4_set_arp_limit (u32 arp_limit);

uword
ip4_udp_register_listener (vlib_main_t * vm,
			   u16 dst_port, u32 next_node_index);

void
ip4_icmp_register_type (vlib_main_t * vm, icmp4_type_t type, u32 node_index);

u16 ip4_tcp_udp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
				  ip4_header_t * ip0);

void ip4_register_protocol (u32 protocol, u32 node_index);

serialize_function_t serialize_vnet_ip4_main, unserialize_vnet_ip4_main;

int vnet_set_ip4_flow_hash (u32 table_id,
			    flow_hash_config_t flow_hash_config);

int vnet_set_ip4_classify_intfc (vlib_main_t * vm, u32 sw_if_index,
				 u32 table_index);

/* Compute flow hash.  We'll use it to select which adjacency to use for this
   flow.  And other things. */
always_inline u32
ip4_compute_flow_hash (const ip4_header_t * ip,
		       flow_hash_config_t flow_hash_config)
{
  tcp_header_t *tcp = (void *) (ip + 1);
  u32 a, b, c, t1, t2;
  uword is_tcp_udp = (ip->protocol == IP_PROTOCOL_TCP
		      || ip->protocol == IP_PROTOCOL_UDP);

  t1 = (flow_hash_config & IP_FLOW_HASH_SRC_ADDR)
    ? ip->src_address.data_u32 : 0;
  t2 = (flow_hash_config & IP_FLOW_HASH_DST_ADDR)
    ? ip->dst_address.data_u32 : 0;

  a = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t2 : t1;
  b = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t1 : t2;
  b ^= (flow_hash_config & IP_FLOW_HASH_PROTO) ? ip->protocol : 0;

  t1 = is_tcp_udp ? tcp->src : 0;
  t2 = is_tcp_udp ? tcp->dst : 0;

  t1 = (flow_hash_config & IP_FLOW_HASH_SRC_PORT) ? t1 : 0;
  t2 = (flow_hash_config & IP_FLOW_HASH_DST_PORT) ? t2 : 0;

  c = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ?
    (t1 << 16) | t2 : (t2 << 16) | t1;

  hash_v3_mix32 (a, b, c);
  hash_v3_finalize32 (a, b, c);

  return c;
}

void
ip4_forward_next_trace (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame,
			vlib_rx_or_tx_t which_adj_index);

u8 *format_ip4_forward_next_trace (u8 * s, va_list * args);

u32 ip4_tcp_udp_validate_checksum (vlib_main_t * vm, vlib_buffer_t * p0);

#define IP_DF 0x4000		/* don't fragment */

/**
 * Push IPv4 header to buffer
 *
 * This does not support fragmentation.
 *
 * @param vm - vlib_main
 * @param b - buffer to write the header to
 * @param src - source IP
 * @param dst - destination IP
 * @param prot - payload proto
 *
 * @return - pointer to start of IP header
 */
always_inline void *
vlib_buffer_push_ip4 (vlib_main_t * vm, vlib_buffer_t * b,
		      ip4_address_t * src, ip4_address_t * dst, int proto,
		      u8 csum_offload)
{
  ip4_header_t *ih;

  /* make some room */
  ih = vlib_buffer_push_uninit (b, sizeof (ip4_header_t));

  ih->ip_version_and_header_length = 0x45;
  ih->tos = 0;
  ih->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b));

  /* No fragments */
  ih->flags_and_fragment_offset = clib_host_to_net_u16 (IP_DF);
  ih->ttl = 255;
  ih->protocol = proto;
  ih->src_address.as_u32 = src->as_u32;
  ih->dst_address.as_u32 = dst->as_u32;

  /* Offload ip4 header checksum generation */
  if (csum_offload)
    {
      ih->checksum = 0;
      b->flags |= VNET_BUFFER_F_OFFLOAD_IP_CKSUM | VNET_BUFFER_F_IS_IP4;
      vnet_buffer (b)->l3_hdr_offset = (u8 *) ih - b->data;
      vnet_buffer (b)->l4_hdr_offset = vnet_buffer (b)->l3_hdr_offset +
	sizeof (*ih);
    }
  else
    ih->checksum = ip4_header_checksum (ih);

  return ih;
}
#endif /* included_ip_ip4_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
