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
#include <vnet/vnet.h>
#include <vppinfra/error.h>

typedef struct {
  u32 fib_index;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 tunnel_index;
  ip6_address_t ip6_prefix;
  ip4_address_t ip4_prefix;
  ip4_address_t ip4_src;
  u8 ip6_prefix_len;
  u8 ip4_prefix_len;

  /* helpers */
  u8 shift;

  u16 mtu;
} sixrd_tunnel_t;

typedef struct {
  u16 msg_id_base;

  /* pool of SIXRD domains */
  sixrd_tunnel_t *tunnels;
  u32 *tunnel_index_by_sw_if_index;
  uword *tunnel_by_ip;

} sixrd_main_t;

#define foreach_sixrd_error                                                    \
  /* Must be first. */                                                         \
  _(NONE, "valid SIXRD packets")                                               \
  _(BAD_PROTOCOL, "bad protocol")                                              \
  _(SEC_CHECK, "security check failed")                                        \
  _(NO_TUNNEL, "no tunnel")


typedef enum {
#define _(sym, str) SIXRD_ERROR_##sym,
  foreach_sixrd_error
#undef _
      SIXRD_N_ERROR,
} sixrd_error_t;

extern sixrd_main_t sixrd_main;

/*
 * sixrd_get_addr
 */
static_always_inline u32 sixrd_get_addr(const sixrd_tunnel_t *t, u64 dal) {

  /* 1:1 mode */
  if (t->ip4_prefix_len == 32)
    return (t->ip4_prefix.as_u32);

  /* Grab 32 - ip4_prefix_len bits out of IPv6 address from offset
   * ip6_prefix_len */
  return (t->ip4_prefix.as_u32 | (u32)(dal >> t->shift));
}

static_always_inline sixrd_tunnel_t *
find_tunnel_by_ip4_address (ip4_address_t *ip)
{
  sixrd_main_t *sm = &sixrd_main;
  uword *p;
  p = hash_get (sm->tunnel_by_ip, ip->as_u32);
  if (!p) return NULL;
  return pool_elt_at_index (sm->tunnels, p[0]);
}

static_always_inline sixrd_tunnel_t *
ip4_sixrd_get_tunnel (u32 sdi,  ip4_address_t *addr, u8 *error)
{
  sixrd_tunnel_t *t = find_tunnel_by_ip4_address(addr);
  if (!t) {
    *error = SIXRD_ERROR_NO_TUNNEL;
    return NULL;
  }
  return t;
}
