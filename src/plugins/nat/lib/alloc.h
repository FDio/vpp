/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief NAT port/address allocation lib
 */

#ifndef included_nat_lib_alloc_h__
#define included_nat_lib_alloc_h__

#include <vnet/ip/ip.h>
#include <nat/lib/nat_proto.h>

typedef struct nat_ip4_pool_addr_s nat_ip4_pool_addr_t;
typedef struct nat_ip4_addr_port_s nat_ip4_addr_port_t;
typedef struct nat_ip4_pool_s nat_ip4_pool_t;

typedef void (nat_add_del_ip4_pool_addr_cb_t) (ip4_address_t addr,
					       u8 is_add, void *opaque);

typedef int (nat_alloc_ip4_addr_and_port_cb_t) (nat_ip4_pool_t * pool,
						u32 fib_index,
						u32 thread_index,
						u32 nat_thread_index,
						u16 port_per_thread,
						u16 protocol,
						nat_ip4_addr_port_t * out);

struct nat_ip4_pool_addr_s
{
  ip4_address_t addr;
  u32 fib_index;
#define _(N, i, n, s) \
  u16 busy_##n##_ports; \
  u16 * busy_##n##_ports_per_thread; \
  uword * busy_##n##_port_bitmap;
  foreach_nat_protocol
#undef _
};

struct nat_ip4_addr_port_s
{
  ip4_address_t addr;
  u16 port;
};

struct nat_ip4_pool_s
{
  nat_add_del_ip4_pool_addr_cb_t *add_del_pool_addr_cb;
  nat_alloc_ip4_addr_and_port_cb_t *alloc_addr_and_port_cb;
  nat_ip4_pool_addr_t *pool_addr;
  u32 random_seed;
};

int
nat_add_del_ip4_pool_addr (nat_ip4_pool_t * pool,
			   ip4_address_t addr, u8 is_add);

int
nat_add_del_ip4_pool_addrs (nat_ip4_pool_t * pool,
			    ip4_address_t addr,
			    u32 count, u8 is_add, void *opaque);

int
nat_alloc_ip4_addr_and_port_cb_default (nat_ip4_pool_t * pool,
					u32 fib_index,
					u32 thread_index,
					u32 nat_thread_index,
					u16 port_per_thread,
					u16 protocol,
					nat_ip4_addr_port_t * out);

int
nat_alloc_ip4_addr_and_port (nat_ip4_pool_t * pool,
			     u32 fib_index,
			     u32 thread_index,
			     u32 nat_thread_index,
			     u16 port_per_thread,
			     u16 protocol, nat_ip4_addr_port_t * out);

int
nat_free_ip4_addr_and_port (nat_ip4_pool_t * pool,
			    u32 thread_index,
			    u16 protocol, nat_ip4_addr_port_t * in);

#endif /* included_nat_lib_alloc_h__ */
