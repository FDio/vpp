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
 * ip/ip_lookup.h: ip (4 or 6) lookup structures, adjacencies, ...
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

/**
 * @file
 * Definitions for all things IP (v4|v6) unicast and multicast lookup related.
 *
 * - Adjacency definitions and registration.
 * - Callbacks on route add.
 * - Callbacks on interface address change.
 */
#ifndef included_ip_lookup_h
#define included_ip_lookup_h

#include <vnet/vnet.h>
#include <vlib/buffer.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/fib/fib_node.h>
#include <vnet/adj/adj.h>
#include <vnet/dpo/dpo.h>
#include <vnet/feature/feature.h>

/** Flow hash configuration */
#define IP_FLOW_HASH_SRC_ADDR (1<<0)
#define IP_FLOW_HASH_DST_ADDR (1<<1)
#define IP_FLOW_HASH_PROTO (1<<2)
#define IP_FLOW_HASH_SRC_PORT (1<<3)
#define IP_FLOW_HASH_DST_PORT (1<<4)
#define IP_FLOW_HASH_REVERSE_SRC_DST (1<<5)

/** Default: 5-tuple without the "reverse" bit */
#define IP_FLOW_HASH_DEFAULT (0x1F)

#define foreach_flow_hash_bit                   \
_(src, IP_FLOW_HASH_SRC_ADDR)                   \
_(dst, IP_FLOW_HASH_DST_ADDR)                   \
_(sport, IP_FLOW_HASH_SRC_PORT)                 \
_(dport, IP_FLOW_HASH_DST_PORT)                 \
_(proto, IP_FLOW_HASH_PROTO)	                \
_(reverse, IP_FLOW_HASH_REVERSE_SRC_DST)

/**
 * A flow hash configuration is a mask of the flow hash options
 */
typedef u32 flow_hash_config_t;

/* An all zeros address */
extern const ip46_address_t zero_addr;


typedef struct
{
  /* Key for mhash; in fact, just a byte offset into mhash key vector. */
  u32 address_key;

  /* Interface which has this address. */
  u32 sw_if_index;

  /* Address (prefix) length for this interface. */
  u16 address_length;

  /* Will be used for something eventually.  Primary vs. secondary? */
  u16 flags;

  /* Next and previous pointers for doubly linked list of
     addresses per software interface. */
  u32 next_this_sw_interface;
  u32 prev_this_sw_interface;
} ip_interface_address_t;

typedef enum
{
  IP_LOCAL_NEXT_DROP,
  IP_LOCAL_NEXT_PUNT,
  IP_LOCAL_NEXT_UDP_LOOKUP,
  IP_LOCAL_NEXT_ICMP,
  IP_LOCAL_N_NEXT,
} ip_local_next_t;

struct ip_lookup_main_t;

typedef struct ip_lookup_main_t
{
  /** Pool of addresses that are assigned to interfaces. */
  ip_interface_address_t *if_address_pool;

  /** Hash table mapping address to index in interface address pool. */
  mhash_t address_to_if_address_index;

  /** Head of doubly linked list of interface addresses for each software interface.
     ~0 means this interface has no address. */
  u32 *if_address_pool_index_by_sw_if_index;

  /** First table index to use for this interface, ~0 => none */
  u32 *classify_table_index_by_sw_if_index;

  /** Feature arc indices */
  u8 mcast_feature_arc_index;
  u8 ucast_feature_arc_index;
  u8 output_feature_arc_index;

  /** Number of bytes in a fib result.  Must be at least
     sizeof (uword).  First word is always adjacency index. */
  u32 fib_result_n_bytes, fib_result_n_words;

  /** 1 for ip6; 0 for ip4. */
  u32 is_ip6;

  /** Either format_ip4_address_and_length or format_ip6_address_and_length. */
  format_function_t *format_address_and_length;

  /** Table mapping ip protocol to ip[46]-local node next index. */
  u8 local_next_by_ip_protocol[256];

  /** IP_BUILTIN_PROTOCOL_{TCP,UDP,ICMP,OTHER} by protocol in IP header. */
  u8 builtin_protocol_by_ip_protocol[256];
} ip_lookup_main_t;

clib_error_t *ip_interface_address_add_del (ip_lookup_main_t * lm,
					    u32 sw_if_index,
					    void *address,
					    u32 address_length,
					    u32 is_del, u32 * result_index);

u8 *format_ip_flow_hash_config (u8 * s, va_list * args);

always_inline ip_interface_address_t *
ip_get_interface_address (ip_lookup_main_t * lm, void *addr_fib)
{
  uword *p = mhash_get (&lm->address_to_if_address_index, addr_fib);
  return p ? pool_elt_at_index (lm->if_address_pool, p[0]) : 0;
}

always_inline void *
ip_interface_address_get_address (ip_lookup_main_t * lm,
				  ip_interface_address_t * a)
{
  return mhash_key_to_mem (&lm->address_to_if_address_index, a->address_key);
}

/* *INDENT-OFF* */
#define foreach_ip_interface_address(lm,a,sw_if_index,loop,body)        \
do {                                                                    \
    vnet_main_t *_vnm = vnet_get_main();                                \
    u32 _sw_if_index = sw_if_index;                                     \
    vnet_sw_interface_t *_swif;                                         \
    _swif = vnet_get_sw_interface (_vnm, _sw_if_index);                 \
                                                                        \
    /*                                                                  \
     * Loop => honor unnumbered interface addressing.                   \
     */                                                                 \
    if (_swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)               \
      {                                                                 \
        if (loop)                                                       \
          _sw_if_index = _swif->unnumbered_sw_if_index;                 \
        else                                                            \
          /* the interface is unnumbered, by the caller does not want   \
           * unnumbered interfaces considered/honoured */               \
          break;                                                        \
      }                                                                 \
    u32 _ia = ((vec_len((lm)->if_address_pool_index_by_sw_if_index)     \
                > (_sw_if_index)) ?                                     \
               vec_elt ((lm)->if_address_pool_index_by_sw_if_index,     \
                        (_sw_if_index)) :                               \
               (u32)~0);                                                \
    ip_interface_address_t * _a;                                        \
    while (_ia != ~0)                                                   \
    {                                                                   \
        _a = pool_elt_at_index ((lm)->if_address_pool, _ia);            \
        _ia = _a->next_this_sw_interface;                               \
        (a) = _a;                                                       \
        body;                                                           \
    }                                                                   \
} while (0)
/* *INDENT-ON* */

typedef struct _vnet_ip_container_proxy_args
{
  fib_prefix_t prefix;
  u32 sw_if_index;
  u8 is_add;
} vnet_ip_container_proxy_args_t;

clib_error_t *vnet_ip_container_proxy_add_del (vnet_ip_container_proxy_args_t
					       * args);

void ip_lookup_init (ip_lookup_main_t * lm, u32 ip_lookup_node_index);

#endif /* included_ip_lookup_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
