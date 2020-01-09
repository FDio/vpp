/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 * @brief NAT port/address allocation lib
 */

#ifndef __included_nat_lib_alloc_h__
#define __included_nat_lib_alloc_h__

#include <vnet/ip/ip.h>

typedef struct ip4_pool_s ip4_pool_t;
typedef struct ip4_addr_port_s ip4_addr_port_t;


typedef void (add_del_ip4_pool_addr_clb_t) (ip4_address_t * addr,
                                            u8 is_add, void * opaque);

typedef int (alloc_addr_and_port_clb_t) (ip4_pool_t * pool,
                                         u32 fib_index,
                                         u32 thread_index,
                                         u32 nat_thread_index,
                                         u16 port_per_thread,
                                         u16 protocol,
                                         ip4_addr_port_t * out);

/* Supported L4 protocols */
#define foreach_nat_protocol \
  _(UDP, 0, udp, "udp")       \
  _(TCP, 1, tcp, "tcp")       \
  _(ICMP, 2, icmp, "icmp")

typedef enum
{
#define _(N, i, n, s) NAT_PROTOCOL_##N = i,
  foreach_nat_protocol
#undef _
} nat_protocol_t;

typedef struct
{
  ip4_address_t addr;
  // not used in dslite
  u32 fib_index; 
/* *INDENT-OFF* */
#define _(N, i, n, s) \
  u16 busy_##n##_ports; \
  u16 * busy_##n##_ports_per_thread; \
  uword * busy_##n##_port_bitmap;
  foreach_nat_protocol
#undef _
/* *INDENT-ON* */
} ip4_pool_addr_t;

struct ip4_pool_s
{
  add_del_ip4_pool_addr_clb_t *add_del_pool_addr_clb;
  alloc_addr_and_port_clb_t *alloc_addr_and_port_clb;
  ip4_pool_addr_t *pool_addr;
  u32 random_seed;
};

struct ip4_addr_port_s
{
  ip4_address_t addr;
  u16 port;
};

int
add_del_ip4_pool_addr (ip4_pool_t * pool, ip4_address_t * addr, u8 is_add);

int
add_del_ip4_pool_addrs (ip4_pool_t * pool,
                        ip4_address_t addr, u32 count, u8 is_add, void * opaque);


int
alloc_addr_and_port_clb_default (ip4_pool_t * pool,
                                 u32 fib_index,
                                 u32 thread_index,
                                 u32 nat_thread_index,
                                 u16 port_per_thread,
                                 u16 protocol,
                                 ip4_addr_port_t * out);

int
alloc_addr_and_port (ip4_pool_t * pool,
                     u32 fib_index,
                     u32 thread_index,
                     u32 nat_thread_index,
                     u16 port_per_thread,
                     u16 protocol,
                     ip4_addr_port_t * out);

int
free_addr_and_port (ip4_pool_t * pool,
                    u32 thread_index,
                    u16 protocol,
                    ip4_addr_port_t * addr_port);

// TODO:
// free multiple addresses and ports
// snat_free_outside_address_and_port

/* TODO:
 * 1) port allocation function should take protocol type,
 *  should returnaddress so we can setup session indirectly,
 *  should take snat thread index (how to solve it differently) ?
 *  we should be able to return port number also !!, or another callback
 *    - not really good to have a callback in this situation because we
 *    are using those calls inside node functions
 *
 *  - nevidim, ze by sa nejakym sposobom menilo ohranicenie port rangu
 *    - co ak dana adresa je uz pouzita s danym portom tiez ?
 *    - start port sa neinkrementuje, taktiez mame presne definovane ohranicenie
 *    start_port, end_port a pouzivame taktiez psid, psid_offset
 */

#endif /* __included_nat_lib_alloc_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
