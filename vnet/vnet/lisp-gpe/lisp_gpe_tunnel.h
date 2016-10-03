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
 * @brief Common utility functions for IPv4, IPv6 and L2 LISP-GPE tunnels.
 *
 */

#ifndef LISP_GPE_TUNNEL_H__
#define LISP_GPE_TUNNEL_H__

#include <vnet/lisp-gpe/lisp_gpe.h>
#include <vnet/lisp-gpe/lisp_gpe_packet.h>

/**
 * Forward declaration
 */
struct lisp_gpe_adjacency_t_;

/**
 * A Key for a tunnel
 */
typedef struct lisp_gpe_tunnel_key_t_
{
  ip_address_t rmt;
  ip_address_t lcl;
  u32 fib_index;
} lisp_gpe_tunnel_key_t;

/**
 * @brief A LISP GPE Tunnel.
 *
 * A tunnel represents an associatation between a local and remote RLOC.
 * As such it represents a unique LISP rewrite.
 */
typedef struct lisp_gpe_tunnel_t_
{
  /**
   * RLOC pair and rloc fib_index. This is the tunnel's key.
   */
  lisp_gpe_tunnel_key_t *key;

  /**
   * number of reference counting locks
   */
  u32 locks;

  /**
   * the FIB entry through which the remote rloc is reachable
   s */
  fib_node_index_t fib_entry_index;
} lisp_gpe_tunnel_t;

extern index_t lisp_gpe_tunnel_find_or_create_and_lock (const locator_pair_t *
							pair,
							u32 rloc_fib_index);

extern void lisp_gpe_tunnel_unlock (index_t lgti);

extern const lisp_gpe_tunnel_t *lisp_gpe_tunnel_get (index_t lgti);

extern u8 *lisp_gpe_tunnel_build_rewrite (const lisp_gpe_tunnel_t * lgt,
					  const struct lisp_gpe_adjacency_t_
					  *ladj,
					  lisp_gpe_next_protocol_e
					  payload_proto);
extern u8 *format_lisp_gpe_tunnel (u8 * s, va_list * args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
