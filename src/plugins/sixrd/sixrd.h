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
  u32 hw_if_index;
  u32 fib_index;
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

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} sixrd_main_t;

#define foreach_sixrd_error                                                    \
  /* Must be first. */                                                         \
  _(NONE, "valid SIXRD packets")                                               \
  _(BAD_PROTOCOL, "bad protocol")                                              \
  _(WRONG_ICMP_TYPE, "wrong icmp type")                                        \
  _(SEC_CHECK, "security check failed")                                        \
  _(ICMP, "unable to translate ICMP")                                          \
  _(UNKNOWN, "unknown")                                                        \
  _(NO_DOMAIN, "no domain")                                                    \
  _(ENCAPSULATED, "encapsulated")                                              \
  _(DECAPSULATED, "decapsulated")                                              \
  _(TRANSLATED_4TO6, "translated 4 to 6")                                      \
  _(TRANSLATED_6TO4, "translated 6 to 4")                                      \
  _(FRAGMENT, "fragment handling error")                                       \
  _(FRAGMENT_QUEUED, "dropped, missing first fragment")                        \
  _(FRAGMENTED, "packets requiring fragmentation")                             \
  _(FRAGMENT_PARTS, "fragment parts")                                          \
  _(MALFORMED, "malformed packet")

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
