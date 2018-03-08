/*---------------------------------------------------------------------------
 * Copyright (c) 2009-2014 Cisco and/or its affiliates.
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
 *---------------------------------------------------------------------------
 */
#include <stdbool.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip.h>
#include <vnet/ipip/ipip.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>

#define SIXRD_DEFAULT_MTU 1480	/* 1500 - IPv4 header */

#define foreach_sixrd_error                                                    \
  /* Must be first. */                                                         \
  _(NONE, "valid SIXRD packets")                                               \
  _(BAD_PROTOCOL, "bad protocol")                                              \
  _(SEC_CHECK, "security check failed")                                        \
  _(NO_TUNNEL, "no tunnel")


typedef enum
{
#define _(sym, str) SIXRD_ERROR_##sym,
  foreach_sixrd_error
#undef _
    SIXRD_N_ERROR,
} sixrd_error_t;

extern sixrd_main_t sixrd_main;

static_always_inline sixrd_tunnel_t *
find_tunnel_by_ip4_address (ip4_address_t * ip)
{
  sixrd_main_t *sm = &sixrd_main;
  uword *p;
  p = hash_get (sm->tunnel_by_ip, ip->as_u32);
  if (!p)
    return NULL;
  return pool_elt_at_index (sm->tunnels, p[0]);
}

static_always_inline sixrd_tunnel_t *
ip4_sixrd_get_tunnel (u32 sdi, ip4_address_t * addr, u8 * error)
{
  sixrd_tunnel_t *t = find_tunnel_by_ip4_address (addr);
  if (!t)
    {
      *error = SIXRD_ERROR_NO_TUNNEL;
      return NULL;
    }
  return t;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
