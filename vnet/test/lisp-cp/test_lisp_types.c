/*
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

#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/lisp-cp/lisp_types.h>
#include <vnet/lisp-cp/lisp_cp_messages.h>

#define _assert(e)                    \
  error = CLIB_ERROR_ASSERT (e);      \
  if (error)                          \
    goto done;

static clib_error_t * test_locator_type (void)
{
  clib_error_t * error = 0;
  gid_address_t _gid_addr, * gid_addr = &_gid_addr;
  gid_address_type(gid_addr) = IP_PREFIX;
  gid_address_ippref_len(gid_addr) = 24;
  ip_prefix_version(&gid_addr->ippref) = IP4;
  gid_addr->ippref.addr.ip.v4.as_u32 = 0x20304050;

  /* local locator */
  locator_t loc1, loc2 = {
    .local = 1,
    .state = 2,
    .sw_if_index = 8,
    .priority = 3,
    .weight = 100,
    .mpriority = 4,
    .mweight = 101
  };
  locator_copy (&loc1, &loc2);
  _assert (0 == locator_cmp (&loc1, &loc2));

  /* remote locator */
  loc2.local = 0;
  loc2.address = gid_addr[0];
  locator_copy(&loc1, &loc2);

  _assert (0 == locator_cmp (&loc1, &loc2));

done:
  return error;
}

static clib_error_t * test_gid_parse ()
{
  clib_error_t * error = 0;
  return error;
}

static clib_error_t * test_format_unformat_gid_address (void)
{
  u8 * s = 0;
  clib_error_t * error = 0;
  unformat_input_t _input;
  unformat_input_t * input = &_input;
  gid_address_t _gid_addr, * gid_addr = &_gid_addr;
  gid_address_t unformated_gid;

  /* format/unformat IPv4 global ID address */
  gid_address_type(gid_addr) = IP_PREFIX;
  gid_address_ippref_len(gid_addr) = 24;
  ip_prefix_version(&gid_addr->ippref) = IP4;
  gid_addr->ippref.addr.ip.v4.as_u32 = 0x20304050;

  s = format(0, "%U", format_gid_address, gid_addr);
  vec_add1(s, 0);
  unformat_init_string(input, (char *)s, vec_len(s));

  _assert (unformat(input, "%U",
        unformat_gid_address, &unformated_gid));
  _assert (0 == gid_address_cmp (&unformated_gid, gid_addr));

  unformat_free(input);
  vec_free(s);
  s = 0;

  /* format/unformat IPv6 global ID address */
  gid_address_type(gid_addr) = IP_PREFIX;
  gid_address_ippref_len(gid_addr) = 64;
  ip_prefix_version(&gid_addr->ippref) = IP6;
  u8 ipv6[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
  memcpy(gid_addr->ippref.addr.ip.v6.as_u8, ipv6, sizeof(ipv6));

  s = format(0, "%U", format_gid_address, gid_addr);
  vec_add1(s, 0);
  unformat_init_string(input, (char *)s, vec_len(s));

  _assert (unformat (input, "%U", unformat_gid_address,
        &unformated_gid));
  _assert (0 == gid_address_cmp(&unformated_gid, gid_addr));

  /* test address copy */
  gid_address_t gid_addr_copy;
  gid_address_copy(&gid_addr_copy, gid_addr);
  _assert (0 == gid_address_cmp (&gid_addr_copy, gid_addr));

done:
  unformat_free(input);
  vec_free(s);
  return error;
}

#define foreach_test_case                 \
  _(format_unformat_gid_address)          \
  _(locator_type)                         \
  _(gid_parse)

int run_tests (void)
{
  clib_error_t * error;

#define _(_test_name)                   \
  error = test_ ## _test_name ();       \
  if (error)                            \
    {                                   \
      clib_error_report (error);        \
      return 0;                         \
    }

  foreach_test_case
#undef _

  return 0;
}

int main()
{
  return run_tests ();
}

