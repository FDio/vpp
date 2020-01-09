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

#include <nat/lib/alloc.h>

static_always_inline void
increment_ip4_addr (ip4_address_t * addr)
{
  u32 v;
  v = clib_net_to_host_u32 (addr->as_u32) + 1;
  addr->as_u32 = clib_host_to_net_u32 (v);
}

int
add_del_ip4_pool_addr (ip4_pool_t * pool, ip4_address_t * addr, u8 is_add)
{
  int i;
  ip4_pool_addr_t *a = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  // lookup for the address
  for (i = 0; i < vec_len (pool); i++)
    {
      if (pool->pool_addr[i].addr.as_u32 == addr->as_u32)
        {
          a = pool->pool_addr + 1;
          break;
        }
    }
  if (is_add)
    {
      if (a)
        return VNET_API_ERROR_VALUE_EXIST;
      vec_add2 (pool->pool_addr, a, 1);
      a->addr = *addr;
#define _(N, i, n, s) \
      clib_bitmap_alloc (a->busy_##n##_port_bitmap, 65535); \
      a->busy_##n##_ports = 0; \
      vec_validate_init_empty (a->busy_##n##_ports_per_thread, tm->n_vlib_mains - 1, 0);
      foreach_nat_protocol
#undef _
    }
  else
    {
      if (!a)
        return VNET_API_ERROR_NO_SUCH_ENTRY;
#define _(N, id, n, s) \
      clib_bitmap_free (a->busy_##n##_port_bitmap); \
      vec_free (a->busy_##n##_ports_per_thread);
      foreach_nat_protocol
#undef _
      vec_del1 (pool->pool_addr, i);
    }
  return 0;
}

int
add_del_ip4_pool_addrs (ip4_pool_t * pool,
                        ip4_address_t addr, u32 count, u8 is_add, void * opaque)
{
  int i, rv;

  for (i = 0; i < count; i++)
    {
      rv = add_del_ip4_pool_addr (pool, &addr, is_add);

      // pre call ?
      // pool->add_del_pool_addr_pre_clb (&addr, is_add, opaque);

      switch (rv)
        {
          case VNET_API_ERROR_NO_SUCH_ENTRY:
          case VNET_API_ERROR_VALUE_EXIST:
            return rv;

        }

      // post call ?
      // pool->add_del_pool_addr_post_clb (&addr, is_add, opaque);

      pool->add_del_pool_addr_clb (&addr, is_add, opaque);
      increment_ip4_addr (&addr);
    }

  return 0;
}

static_always_inline u16
nat_random_port (u32 random_seed, u16 min, u16 max)
{
  return min + random_u32 (&random_seed) /
    (random_u32_max () / (max - min + 1) + 1);
}

int
alloc_addr_and_port_clb_default (ip4_pool_t * pool,
                                 u32 fib_index,
                                 u32 thread_index,
                                 u32 nat_thread_index,
                                 u16 port_per_thread,
                                 u16 protocol,
                                 ip4_addr_port_t * out)
{
  ip4_pool_addr_t *a, *ga = 0;
  u32 i;
  u32 portnum;

  for (i = 0; i < vec_len (pool->pool_addr); i++)
    {
      a = pool->pool_addr + i;
      switch (protocol)
	{
#define _(N, j, n, s) \
        case NAT_PROTOCOL_##N: \
          if (a->busy_##n##_ports_per_thread[thread_index] < port_per_thread) \
            { \
              if (a->fib_index == fib_index) \
                { \
                  while (1) \
                    { \
                      portnum = (port_per_thread * \
                        nat_thread_index) + \
                        nat_random_port(pool->random_seed, 1, port_per_thread) + 1024; \
                      if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, portnum)) \
                        continue; \
                      clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, portnum, 1); \
                      a->busy_##n##_ports_per_thread[thread_index]++; \
                      a->busy_##n##_ports++; \
                      out->addr = a->addr; \
                      out->port = clib_host_to_net_u16(portnum); \
                      return 0; \
                    } \
                } \
              else if (a->fib_index == ~0) \
                { \
                  ga = a; \
                } \
            } \
          break;
	  foreach_nat_protocol
#undef _
	default:
          // unknown protocol
	  return -2;
	}

    }

  if (ga)
    {
      a = ga;
      switch (protocol)
	{
#define _(N, j, n, s) \
        case NAT_PROTOCOL_##N: \
          while (1) \
            { \
              portnum = (port_per_thread * \
                nat_thread_index) + \
                nat_random_port(pool->random_seed, 1, port_per_thread) + 1024; \
              if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, portnum)) \
                continue; \
              clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, portnum, 1); \
              a->busy_##n##_ports_per_thread[thread_index]++; \
              a->busy_##n##_ports++; \
              out->addr = a->addr; \
              out->port = clib_host_to_net_u16(portnum); \
              return 0; \
            }
	  break;
	  foreach_nat_protocol
#undef _
	default:
	  // unknown protocol
	  return -2;
	}
    }

  // out of translations
  return -1;
}

int
alloc_addr_and_port (ip4_pool_t * pool,
                     u32 fib_index,
                     u32 thread_index,
                     u32 nat_thread_index,
                     u16 port_per_thread,
                     u16 protocol,
                     ip4_addr_port_t * out)
{
  return pool->alloc_addr_and_port_clb (pool,
                                        fib_index,
                                        thread_index,
                                        nat_thread_index,
                                        port_per_thread,
                                        protocol,
                                        out);
}

int
free_addr_and_port (ip4_pool_t * pool,
                    u32 thread_index,
                    u16 protocol,
                    ip4_addr_port_t * addr_port)
{
  ip4_pool_addr_t *a = 0;
  u32 i;
  u16 port = clib_net_to_host_u16 (addr_port->port);

  for (i = 0; i < vec_len (pool->pool_addr); i++)
    {
      if (pool->pool_addr[i].addr.as_u32 == addr_port->addr.as_u32)
        {
          a = pool->pool_addr + i;
          break;
        }
    }

  if (!a)
    {
      return 1;
    }

  switch (protocol)
    {
#define _(N, i, n, s) \
    case NAT_PROTOCOL_##N: \
      ASSERT (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, \
        port) == 1); \
      clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, \
        port, 0); \
      a->busy_##n##_ports--; \
      a->busy_##n##_ports_per_thread[thread_index]--; \
      break;
      foreach_nat_protocol
#undef _
    default:
      // unknown protocol
      return 1;
    }
  return 0;
}

// vrf_id, twice_nat what else do we need to move inside ??
//snat_add_address (snat_main_t * sm, ip4_address_t * addr, u32 vrf_id,
//                  u8 twice_nat)
//snat_del_address (snat_main_t * sm, ip4_address_t addr, u8 delete_sm,
//                  u8 twice_nat)
//dslite_add_del_pool_addr (dslite_main_t * dm, ip4_address_t * addr, u8 is_add)

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
