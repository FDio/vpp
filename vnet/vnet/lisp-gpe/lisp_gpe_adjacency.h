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
/**
 * @file
 * @brief Common utility functions for IPv4, IPv6 and L2 LISP-GPE adjacencys.
 *
 */

#ifndef LISP_GPE_ADJACENCY_H__
#define LISP_GPE_ADJACENCY_H__

#include <vnet/fib/fib_node.h>
#include <vnet/lisp-gpe/lisp_gpe.h>

/**
 * @brief A LISP GPE Adjacency.
 *
 * A adjacency represents peer on an L3 sub-interface to which to send traffic.
 * adjacencies are thus present in the EID space.
 * The peer is identified by the key:{remote-rloc, sub-interface}, which is
 * equivalent to the usal adjacency key {next-hop, interface}. So curiously
 * the rloc address from the underlay is used as a next hop address in the overlay
 * This is OK because:
 *  1 - the RLOC is unique in the underlay AND there is only one underlay VRF per
 *      overlay
 *  2 - the RLOC may overlap with an address in the overlay, but we do not create
 *      an adj-fib (i.e. a route in the overlay FIB for the rloc)
 *
 *
 */
typedef struct lisp_gpe_adjacency_t_
{
  /**
   * The LISP adj is a part of the FIB control plane graph.
   */
  fib_node_t fib_node;

  /**
   * remote RLOC. The adjacency's next-hop
   */
  ip_address_t remote_rloc;

  /**
   * The VNI. Used in combination with the local-rloc to get the sub-interface
   */
  u32 vni;

  /**
   * The number of locks/reference counts on the adjacency.
   */
  u32 locks;

  /**
   * The index of the LISP L3 subinterface
   */
  u32 lisp_l3_sub_index;

  /**
   * The SW IF index of the sub-interface this adjacency uses.
   * Cached for convenience from the LISP L3 sub-interface
   */
  u32 sw_if_index;

  /**
   * The index of the LISP GPE tunnel that provides the transport
   * in the underlay.
   */
  u32 tunnel_index;

  /**
   * This adjacency is a child of the FIB entry to reach the RLOC.
   * This is so when the reachability of that RLOC changes, we can restack
   * the FIB adjacnecies.
   */
  u32 fib_entry_child_index;

  /**
   * LISP header fields in HOST byte order
   */
  u8 flags;
  u8 ver_res;
  u8 res;
  u8 next_protocol;

} lisp_gpe_adjacency_t;

extern index_t lisp_gpe_adjacency_find_or_create_and_lock (const
							   locator_pair_t *
							   pair,
							   u32 rloc_fib_index,
							   u32 vni);

extern void lisp_gpe_adjacency_unlock (index_t l3si);

extern const lisp_gpe_adjacency_t *lisp_gpe_adjacency_get (index_t l3si);

extern void lisp_gpe_update_adjacency (vnet_main_t * vnm,
				       u32 sw_if_index, adj_index_t ai);
extern u8 *lisp_gpe_build_rewrite (vnet_main_t * vnm,
				   u32 sw_if_index,
				   vnet_link_t link_type,
				   const void *dst_address);


/**
 * @brief Flags for displaying the adjacency
 */
typedef enum lisp_gpe_adjacency_format_flags_t_
{
  LISP_GPE_ADJ_FORMAT_FLAG_NONE,
  LISP_GPE_ADJ_FORMAT_FLAG_DETAIL,
} lisp_gpe_adjacency_format_flags_t;

extern u8 *format_lisp_gpe_adjacency (u8 * s, va_list * args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
