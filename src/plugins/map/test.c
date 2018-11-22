/*
 * test.c : MAP unit tests
 *
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

#include <assert.h>
#include "map.h"

static map_domain_t *
get_domain(ip4_address_t * ip4_prefix, u8 ip4_prefix_len,
	   ip6_address_t * ip6_prefix, u8 ip6_prefix_len,
	   ip6_address_t * ip6_src, u8 ip6_src_len,
	   u8 ea_bits_len, u8 psid_offset,
	   u8 psid_length, u16 mtu, u8 flags)
{
  map_domain_t * d = malloc(sizeof(*d));
  u8 suffix_len;

  /* EA bits must be within the first 64 bits */
  if (ea_bits_len > 0 && (ip6_prefix_len + ea_bits_len) > 64)
    return NULL;

  /* Init domain struct */
  d->ip4_prefix.as_u32 = ip4_prefix->as_u32;
  d->ip4_prefix_len = ip4_prefix_len;
  d->ip6_prefix = *ip6_prefix;
  d->ip6_prefix_len = ip6_prefix_len;
  d->ip6_src = *ip6_src;
  d->ip6_src_len = ip6_src_len;
  d->ea_bits_len = ea_bits_len;
  d->psid_offset = psid_offset;
  d->psid_length = psid_length;
  d->mtu = mtu;
  d->flags = flags;

  /* How many, and which bits to grab from the IPv4 DA */
  if (ip4_prefix_len + ea_bits_len < 32)
    {
      d->flags |= MAP_DOMAIN_PREFIX;
      d->suffix_shift = 32 - ip4_prefix_len - ea_bits_len;
      suffix_len = ea_bits_len;
    }
  else
    {
      d->suffix_shift = 0;
      suffix_len = 32 - ip4_prefix_len;
    }
  d->suffix_mask = (1 << suffix_len) - 1;

  d->psid_shift = 16 - psid_length - psid_offset;
  d->psid_mask = (1 << d->psid_length) - 1;

  if (ip6_prefix_len + suffix_len + d->psid_length > 64)
    return NULL;

  d->ea_shift = 64 - ip6_prefix_len - suffix_len - d->psid_length;

  return d;
}


/*
 * VPP-340:
 * map_add_domain ip4-pfx 20.0.0.0/8 ip6-pfx 2001:db8::/40 ip6-src 2001:db8:ffff::/96 ea-bits-len 24 psid-offset 0 psid-len 0 map-t
 * IPv4 src = 100.0.0.1
 * IPv4 dst = 20.169.201.219
 * UDP dest port = 1232
 * IPv6 src = 2001:db8:ffff::6400:1
 * IPv6 dst = a9c9:dfb8::14a9:c9db:0
 * a9c9:dfb8::14a9:c9db:0 != 2001:db8:a9:c9db:0:14a9:c9db:0
 */
static void
test_map_t_destaddr (void)
{
  ip4_address_t ip4_prefix;
  ip6_address_t ip6_prefix;
  ip6_address_t ip6_src;

  ip4_prefix.as_u32 = clib_host_to_net_u32(0x14000000);
  ip6_prefix.as_u64[0] = clib_host_to_net_u64(0x20010db800000000);
  ip6_prefix.as_u64[1] = 0;
  ip6_src.as_u64[0] = clib_host_to_net_u64(0x20010db8ffff0000);
  map_domain_t * d = get_domain (&ip4_prefix, 8, &ip6_prefix, 40, &ip6_src, 96, 24, 0, 0, 0, MAP_DOMAIN_TRANSLATION);

  ip6_address_t dst6;

  dst6.as_u64[0] = map_get_pfx(d, 0x14a9c9db, 1232);
  dst6.as_u64[1] = map_get_sfx(d, 0x14a9c9db, 1232);
  assert(dst6.as_u64[0] == 0x20010db800a9c9db);
  assert(dst6.as_u64[1] == 0x000014a9c9db0000);
}

/*
 * VPP-228
 * ip4-pfx 20.0.0.0/8
 * ip6-pfx 2001:db8::/<n>
 * ip6-src 2001:db8:ffff::1
 * ea-bits-len 16 psid-offset 6 psid-len 8
 * 20.169.201.219 port 1232
 */
static void
test_map_eabits (void)
{
  ip4_address_t ip4_prefix;
  ip6_address_t ip6_prefix;
  ip6_address_t ip6_src;
  ip6_address_t dst6;

  ip4_prefix.as_u32 = clib_host_to_net_u32(0x14000000);
  ip6_prefix.as_u64[0] = clib_host_to_net_u64(0x20010db800000000);
  ip6_prefix.as_u64[1] = 0;
  ip6_src.as_u64[0] = clib_host_to_net_u64(0x20010db8ffff0000);
  ip6_src.as_u64[1] = clib_host_to_net_u64(0x0000000000000001);
  map_domain_t * d = get_domain (&ip4_prefix, 16, &ip6_prefix, 48, &ip6_src,
				 128, 16, 6, 8, 0, 0);
  assert(!d);

  //20.0.0.0/8	2001:db8::/32	4	2001:db8:a000::14a0:0:0
  d = get_domain (&ip4_prefix, 8, &ip6_prefix, 32, &ip6_src,
		  128, 4, 0, 0, 0, 0);
  dst6.as_u64[0] = map_get_pfx(d, 0x14a9c9db, 1232);
  dst6.as_u64[1] = map_get_sfx(d, 0x14a9c9db, 1232);
  assert(dst6.as_u64[0] == 0x20010db8a0000000);
  assert(dst6.as_u64[1] == 0x000014a000000000);

  //20.0.0.0/8	2001:db8::/32	8	2001:db8:a900::14a9:0:0
  d = get_domain (&ip4_prefix, 8, &ip6_prefix, 32, &ip6_src,
		  128, 8, 0, 0, 0, 0);
  dst6.as_u64[0] = map_get_pfx(d, 0x14a9c9db, 1232);
  dst6.as_u64[1] = map_get_sfx(d, 0x14a9c9db, 1232);
  assert(dst6.as_u64[0] == 0x20010db8a9000000);
  assert(dst6.as_u64[1] == 0x000014a900000000);

  //20.0.0.0/8	2001:db8::/32	10	2001:db8:a9c0::14a9:c000:0
  d = get_domain (&ip4_prefix, 8, &ip6_prefix, 32, &ip6_src,
		  128, 10, 0, 0, 0, 0);
  dst6.as_u64[0] = map_get_pfx(d, 0x14a9c9db, 1232);
  dst6.as_u64[1] = map_get_sfx(d, 0x14a9c9db, 1232);
  assert(dst6.as_u64[0] == 0x20010db8a9c00000);
  assert(dst6.as_u64[1] == 0x000014a9c0000000);

  //20.0.0.0/8	2001:db8::/32	16	2001:db8:a9c9::14a9:c900:0
  d = get_domain (&ip4_prefix, 8, &ip6_prefix, 32, &ip6_src,
		  128, 16, 0, 0, 0, 0);
  dst6.as_u64[0] = map_get_pfx(d, 0x14a9c9db, 1232);
  dst6.as_u64[1] = map_get_sfx(d, 0x14a9c9db, 1232);
  assert(dst6.as_u64[0] == 0x20010db8a9c90000);
  assert(dst6.as_u64[1] == 0x000014a9c9000000);

  //20.0.0.0/8	2001:db8::/32	20	2001:db8:a9c9:d000:0:14a9:c9d0:0
  d = get_domain (&ip4_prefix, 8, &ip6_prefix, 32, &ip6_src,
		  128, 20, 0, 0, 0, 0);
  dst6.as_u64[0] = map_get_pfx(d, 0x14a9c9db, 1232);
  dst6.as_u64[1] = map_get_sfx(d, 0x14a9c9db, 1232);
  assert(dst6.as_u64[0] == 0x20010db8a9c9d000);
  assert(dst6.as_u64[1] == 0x000014a9c9d00000);

  //20.0.0.0/8	2001:db8::/32	23	2001:db8:a9c9:da00:0:14a9:c9da:0
  d = get_domain (&ip4_prefix, 8, &ip6_prefix, 32, &ip6_src,
		  128, 23, 0, 0, 0, 0);
  dst6.as_u64[0] = map_get_pfx(d, 0x14a9c9db, 1232);
  dst6.as_u64[1] = map_get_sfx(d, 0x14a9c9db, 1232);
  assert(dst6.as_u64[0] == 0x20010db8a9c9da00);
  assert(dst6.as_u64[1] == 0x000014a9c9da0000);

  //20.169.201.0/24	2001:db8::/32	7	2001:db8:da00::14a9:c9da:0
  d = get_domain (&ip4_prefix, 8, &ip6_prefix, 32, &ip6_src,
		  128, 7, 0, 0, 0, 0);
  dst6.as_u64[0] = map_get_pfx(d, 0x14a9c9db, 1232);
  dst6.as_u64[1] = map_get_sfx(d, 0x14a9c9db, 1232);
  assert(dst6.as_u64[0] == 0x20010db8a8000000);
  assert(dst6.as_u64[1] == 0x000014a800000000);
}

#define foreach_test_case			\
  _(map_t_destaddr)				\
  _(map_eabits)

static void
run_tests (void)
{
#define _(_test_name)				\
  test_ ## _test_name ();

  foreach_test_case
#undef _
}

int main()
{
  run_tests ();
  return 0;
}
