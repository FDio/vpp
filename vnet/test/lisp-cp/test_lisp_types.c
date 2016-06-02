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
  gid_address_t _gid_addr, * gid = &_gid_addr;
  ip_prefix_t * ippref;
  gid_address_type (gid) = GID_ADDR_IP_PREFIX;
  gid_address_ippref_len (gid) = 24;
  ippref = &gid_address_ippref (gid);
  ip_prefix_version (ippref) = IP4;
  ip_prefix_len (ippref) = 0;
  ip4_address_t * ip4 = &ip_prefix_v4 (ippref);
  ip4->as_u32 = 0x20304050;

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

  ip_prefix_t nested_ippref;
  ip_prefix_version (&nested_ippref) = IP4;
  ip_prefix_len (&nested_ippref) = 0;
  ip4 = &ip_prefix_v4 (&nested_ippref);
  ip4->as_u32 = 0x33882299;
  gid_address_t nested_gid =
    {
      .type = GID_ADDR_IP_PREFIX,
      .ippref = nested_ippref
    };

  lcaf_t lcaf =
    {
      .type = LCAF_INSTANCE_ID,
      .uni =
        {
          .vni_mask_len = 5,
          .vni = 0xa1b2c3d4,
          .gid_addr = &nested_gid
        }
    };
  gid_address_type (gid) = GID_ADDR_LCAF;
  gid_address_lcaf (gid) = lcaf;

  loc2.address = gid[0];
  locator_copy(&loc1, &loc2);

  _assert (0 == locator_cmp (&loc1, &loc2));

done:
  locator_free (&loc1);
  return error;
}

static clib_error_t * test_gid_parse_ip_pref ()
{
  clib_error_t * error = 0;
  gid_address_t _gid_addr, * gid_addr = &_gid_addr;
  gid_address_t _gid_addr_copy, * gid_addr_copy = &_gid_addr_copy;
  u8 data[] =
    {
      0x00, 0x01,             /* AFI = IPv4 */
      0x10, 0xbb, 0xcc, 0xdd, /* ipv4 address */
    };

  u32 len = gid_address_parse (data, gid_addr);
  _assert (6 == len);
  gid_address_copy (gid_addr_copy, gid_addr);
  _assert (0 == gid_address_cmp (gid_addr_copy, gid_addr));
done:
  return error;
}

static clib_error_t * test_gid_parse_lcaf ()
{
  clib_error_t * error = 0;
  gid_address_t _gid_addr, * gid_addr = &_gid_addr;
  gid_address_t _gid_addr_copy, * gid_addr_copy = &_gid_addr_copy;

  memset (gid_addr, 0, sizeof (gid_addr[0]));
  memset (gid_addr_copy, 0, sizeof (gid_addr_copy[0]));

  u8 data[] =
    {
      0x40, 0x03,             /* AFI = LCAF*/

      /* LCAF header*/
      0x00, 0x00,             /* reserved1, flags */
      0x02,                   /* type = Instance ID */
      0x18,                   /* IID mask-len */
      0x00, 0x0a,             /* iid length + next AFI lenght */
      /* LCAF Instance ID */
      0x00, 0x00, 0x00, 0x09, /* iid */
      0x00, 0x01,             /* AFI = ipv4 */
      0x10, 0xbb, 0xcc, 0xdd, /* ipv4 address */
    };
  u32 len = gid_address_parse (data, gid_addr);
  _assert (18 == len);
  gid_address_copy (gid_addr_copy, gid_addr);
  _assert (0 == gid_address_cmp (gid_addr_copy, gid_addr));

  lcaf_t * lcaf = &gid_address_lcaf (gid_addr_copy);
  vni_t * vni = (vni_t *) lcaf;
  _assert (lcaf->type == LCAF_INSTANCE_ID);
  _assert (vni->vni == 9);
  _assert (vni->vni_mask_len == 0x18);

  gid_address_t * g = vni_gid (vni);
  _assert (gid_address_type (g) == GID_ADDR_IP_PREFIX);
done:
  gid_address_free (gid_addr);
  gid_address_free (gid_addr_copy);
  return error;
}

static clib_error_t * test_gid_parse_lcaf_complex ()
{
  clib_error_t * error = 0;
  gid_address_t _gid_addr, * gid_addr = &_gid_addr;
  gid_address_t _gid_addr_copy, * gid_addr_copy = &_gid_addr_copy;

  memset (gid_addr, 0, sizeof (gid_addr[0]));
  memset (gid_addr_copy, 0, sizeof (gid_addr_copy[0]));

  u8 data[] =
    {
      0x40, 0x03,             /* AFI = LCAF*/

      /* LCAF header*/
      0x00, 0x00,             /* reserved1, flags */
      0x02,                   /* type = Instance ID */
      0x18,                   /* IID mask-len */
      0x00, 0x0a,             /* iid length + next AFI lenght */
      /* LCAF Instance ID */
      0x00, 0x00, 0x00, 0x0b, /* iid */

      0x40, 0x03,             /* AFI = LCAF*/
      /* LCAF header*/
      0x00, 0x00,             /* reserved1, flags */
      0x02,                   /* type = Instance ID */
      0x17,                   /* IID mask-len */
      0x00, 0x0a,             /* iid length + next AFI lenght */
      /* LCAF Instance ID */
      0x00, 0x00, 0x00, 0x0c, /* iid */

      0x40, 0x03,             /* AFI = LCAF*/
      /* LCAF header*/
      0x00, 0x00,             /* reserved1, flags */
      0x02,                   /* type = Instance ID */
      0x16,                   /* IID mask-len */
      0x00, 0x16,             /* iid length + next AFI lenght */
      /* LCAF Instance ID */
      0x00, 0x00, 0x00, 0x0d, /* iid */

      0x00, 0x02,             /* AFI = IPv6 */

      0x10, 0xbb, 0xcc, 0xdd,
      0x10, 0xbb, 0xcc, 0xdd,
      0x10, 0xbb, 0xcc, 0xdd,
      0x10, 0xbb, 0xcc, 0xdd, /* ipv6 address */
    };
  u32 len = gid_address_parse (data, gid_addr);
  _assert (54 == len);
  _assert (gid_addr->type == GID_ADDR_LCAF);
  gid_address_copy (gid_addr_copy, gid_addr);
  _assert (0 == gid_address_cmp (gid_addr_copy, gid_addr));
  _assert (gid_addr_copy->type == GID_ADDR_LCAF);

  lcaf_t * lcaf = &gid_address_lcaf (gid_addr_copy);
  _assert (lcaf->type == LCAF_INSTANCE_ID);
  vni_t * v = (vni_t *) lcaf;
  _assert (v->vni == 0x0b);
  _assert (v->vni_mask_len == 0x18);

  gid_address_t * tmp = vni_gid (v);
  _assert (gid_address_type (tmp) == GID_ADDR_LCAF);
  lcaf = &gid_address_lcaf (tmp);
  _assert (lcaf->type == LCAF_INSTANCE_ID);

  v = (vni_t *) lcaf;
  _assert (v->vni == 0x0c);
  _assert (v->vni_mask_len == 0x17);

  tmp = vni_gid (v);
  _assert (gid_address_type (tmp) == GID_ADDR_LCAF);
  lcaf = &gid_address_lcaf (tmp);

  _assert (lcaf->type == LCAF_INSTANCE_ID);
  v = (vni_t *) lcaf;
  _assert (v->vni == 0x0d);
  _assert (v->vni_mask_len == 0x16);

  tmp = vni_gid (v);
  _assert (gid_address_type (tmp) == GID_ADDR_IP_PREFIX);

  ip_prefix_t * ip_pref = &gid_address_ippref (tmp);
  ip6_address_t * ip6 = &ip_prefix_v6 (ip_pref);
  _assert (ip6->as_u32[0] == 0xddccbb10);
  _assert (ip6->as_u32[1] == 0xddccbb10);
  _assert (ip6->as_u32[2] == 0xddccbb10);
  _assert (ip6->as_u32[3] == 0xddccbb10);
  _assert (ip_prefix_version (ip_pref) == IP6);

done:
  gid_address_free (gid_addr);
  gid_address_free (gid_addr_copy);
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
  gid_address_type(gid_addr) = GID_ADDR_IP_PREFIX;
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
  gid_address_type(gid_addr) = GID_ADDR_IP_PREFIX;
  gid_address_ippref_len(gid_addr) = 64;
  ip_prefix_version(&gid_addr->ippref) = IP6;
  u8 ipv6[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
  clib_memcpy(gid_addr->ippref.addr.ip.v6.as_u8, ipv6, sizeof(ipv6));

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

static clib_error_t * test_gid_address_write (void)
{
  clib_error_t * error = 0;
  ip_prefix_t ippref_data, * ippref = &ippref_data;

  u8 * b = clib_mem_alloc(500);
  memset(b, 0, 500);

  ip_prefix_version (ippref) = IP4;
  ip_prefix_len (ippref) = 9;
  ip4_address_t * ip4 = &ip_prefix_v4 (ippref);
  ip4->as_u32 = 0xaabbccdd;

  gid_address_t nested_gid =
    {
      .ippref = ippref[0],
      .type = GID_ADDR_IP_PREFIX,
    };

  lcaf_t lcaf =
    {
      .type = LCAF_INSTANCE_ID,
      .uni =
        {
          .vni_mask_len = 0x18,
          .vni = 0x01020304,
          .gid_addr = &nested_gid
        }
    };

  gid_address_t gid =
    {
      .type = GID_ADDR_LCAF,
      .lcaf = lcaf
    };
  _assert (18 == gid_address_size_to_put (&gid));
  _assert (gid_address_len (&gid) == 9);

  u16 write_len = gid_address_put (b, &gid);
  _assert (18 == write_len);

  u8 expected_gid_data[] =
    {
      0x40, 0x03,             /* AFI = LCAF */
      0x00,                   /* reserved1 */
      0x00,                   /* flags */
      0x02,                   /* LCAF type = Instance ID */
      0x18,                   /* IID/VNI mask len */
      0x00, 0x0a,             /* length */
      0x01, 0x02, 0x03, 0x04, /* Instance ID / VNI */

      0x00, 0x01,             /* AFI = IPv4 */
      0xdd, 0xcc, 0xbb, 0xaa, /* ipv4 addr */
    };
  _assert (0 == memcmp (expected_gid_data, b, sizeof (expected_gid_data)));
done:
  clib_mem_free (b);
  return error;
}

#define foreach_test_case                 \
  _(format_unformat_gid_address)          \
  _(locator_type)                         \
  _(gid_parse_ip_pref)                    \
  _(gid_parse_lcaf)                       \
  _(gid_parse_lcaf_complex)               \
  _(gid_address_write)

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

