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
#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/ip6_fib.h>

#include "sixrd_dpo.h"

int sixrd_create_domain(ip6_address_t *ip6_prefix, u8 ip6_prefix_len,
			ip4_address_t *ip4_prefix, u8 ip4_prefix_len,
			ip4_address_t *ip4_src, u32 *sixrd_domain_index, u16 mtu);
int sixrd_delete_domain(u32 sixrd_domain_index);
u8 *format_sixrd_trace(u8 *s, va_list *args);

typedef struct {
  ip6_address_t ip6_prefix;
  ip4_address_t ip4_prefix;
  ip4_address_t ip4_src;
  u8 ip6_prefix_len;
  u8 ip4_prefix_len;

  /* helpers */
  u8 shift;

  u16 mtu;
} sixrd_domain_t;

typedef struct {
  /* pool of SIXRD domains */
  sixrd_domain_t *domains;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} sixrd_main_t;

#define foreach_sixrd_error				\
  /* Must be first. */					\
 _(NONE, "valid SIXRD packets")				\
 _(BAD_PROTOCOL, "bad protocol")			\
 _(WRONG_ICMP_TYPE, "wrong icmp type")			\
 _(SEC_CHECK, "security check failed")			\
 _(ICMP, "unable to translate ICMP")			\
 _(UNKNOWN, "unknown")					\
 _(NO_DOMAIN, "no domain")				\
 _(ENCAPSULATED, "encapsulated")			\
 _(DECAPSULATED, "decapsulated")			\
 _(TRANSLATED_4TO6, "translated 4 to 6")		\
 _(TRANSLATED_6TO4, "translated 6 to 4")		\
 _(FRAGMENT, "fragment handling error")			\
 _(FRAGMENT_QUEUED, "dropped, missing first fragment")	\
 _(FRAGMENTED, "packets requiring fragmentation")	\
 _(FRAGMENT_PARTS, "fragment parts")                    \
 _(MALFORMED, "malformed packet")

typedef enum {
#define _(sym,str) SIXRD_ERROR_##sym,
   foreach_sixrd_error
#undef _
   SIXRD_N_ERROR,
 } sixrd_error_t;

typedef struct {
  u32 sixrd_domain_index;
} sixrd_trace_t;

sixrd_main_t sixrd_main;

/*
 * sixrd_get_addr
 */
static_always_inline u32
sixrd_get_addr (sixrd_domain_t *d, u64 dal)
{

  /* 1:1 mode */
  if (d->ip4_prefix_len == 32) return (d->ip4_prefix.as_u32);

  /* Grab 32 - ip4_prefix_len bits out of IPv6 address from offset ip6_prefix_len */
  return (d->ip4_prefix.as_u32 | (u32)(dal >> d->shift));
}

/*
 * Get the SIXRD domain from an IPv6 lookup adjacency.
 */
static_always_inline sixrd_domain_t *
ip6_sixrd_get_domain (u32 sdi, u32 *sixrd_domain_index)
{
  sixrd_main_t *mm = &sixrd_main;
  sixrd_dpo_t *sd;

  sd = sixrd_dpo_get(sdi);

  ASSERT(sd);
  *sixrd_domain_index = sd->sd_domain;
  return pool_elt_at_index(mm->domains, *sixrd_domain_index);
}

/*
 * Get the SIXRD domain from an IPv4 lookup adjacency.
 * If the IPv4 address is not shared, no lookup is required.
 * The IPv6 address is used otherwise.
 */
static_always_inline sixrd_domain_t *
ip4_sixrd_get_domain (u32 sdi, ip6_address_t *addr,
		      u32 *sixrd_domain_index, u8 *error)
{
  sixrd_main_t *mm = &sixrd_main;
  sixrd_dpo_t *sd;

  sd = sixrd_dpo_get(sdi);
  *sixrd_domain_index = sd->sd_domain;
  if (*sixrd_domain_index != ~0)
    return pool_elt_at_index(mm->domains, *sixrd_domain_index);

  u32 lbi = ip6_fib_table_fwding_lookup(&ip6_main, 0, addr);
  const dpo_id_t *dpo = load_balance_get_bucket(lbi, 0);
  if (PREDICT_TRUE(dpo->dpoi_type == sixrd_dpo_type))
    {
      sd = sixrd_dpo_get(dpo->dpoi_index);
      *sixrd_domain_index = sd->sd_domain;
      return pool_elt_at_index(mm->domains, *sixrd_domain_index);
    }
  *error = SIXRD_ERROR_NO_DOMAIN;
  return NULL;
}
