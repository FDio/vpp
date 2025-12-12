/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/ip/vtep.h>

uword
vtep_addr_ref (vtep_table_t * t, u32 fib_index, ip46_address_t * ip)
{
  vtep4_key_t key4 = {.addr = ip->ip4,.fib_index = fib_index };
  vtep6_key_t key6 = {.addr = ip->ip6,.fib_index = fib_index };
  uword *vtep = ip46_address_is_ip4 (ip) ?
    hash_get (t->vtep4, key4.as_u64) : hash_get_mem (t->vtep6, &key6);
  if (vtep)
    return ++(*vtep);
  ip46_address_is_ip4 (ip) ?
    hash_set (t->vtep4, key4.as_u64, 1) :
    hash_set_mem_alloc (&t->vtep6, &key6, 1);
  return 1;
}

uword
vtep_addr_unref (vtep_table_t * t, u32 fib_index, ip46_address_t * ip)
{
  vtep4_key_t key4 = {.addr = ip->ip4,.fib_index = fib_index };
  vtep6_key_t key6 = {.addr = ip->ip6,.fib_index = fib_index };
  uword *vtep = ip46_address_is_ip4 (ip) ?
    hash_get (t->vtep4, key4.as_u64) : hash_get_mem (t->vtep6, &key6);
  ALWAYS_ASSERT (vtep);
  if (--(*vtep) != 0)
    return *vtep;
  ip46_address_is_ip4 (ip) ?
    hash_unset (t->vtep4, key4.as_u64) :
    hash_unset_mem_free (&t->vtep6, &key6);
  return 0;
}
