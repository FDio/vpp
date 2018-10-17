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
  gid_address_t _gid_addr_copy, * copy = &_gid_addr_copy;
  u8 data[] =
    {
      0x00, 0x01,             /* AFI = IPv4 */
      0x10, 0xbb, 0xcc, 0xdd, /* ipv4 address */
    };

  u32 len = gid_address_parse (data, gid_addr);
  _assert (6 == len);
  gid_address_copy (copy, gid_addr);
  _assert (0 == gid_address_cmp (copy, gid_addr));
done:
  return error;
}

static clib_error_t * test_gid_parse_mac ()
{
  clib_error_t * error = 0;
  gid_address_t _gid, * gid = &_gid;
  gid_address_t _gid_copy, * gid_copy = &_gid_copy;

  u8 data[] =
    {
      0x40, 0x05,             /* AFI = MAC address */
      0x10, 0xbb, 0xcc, 0xdd, /* MAC */
      0x77, 0x99,
    };

  u32 len = gid_address_parse (data, gid);
  _assert (8 == len);
  _assert (GID_ADDR_MAC == gid_address_type (gid));
  gid_address_copy (gid_copy, gid);
  _assert (0 == gid_address_cmp (gid_copy, gid));
done:
  return error;
}

static clib_error_t *
test_gid_write_nsh (void)
{
  clib_error_t * error = 0;

  u8 * b = clib_mem_alloc(500);
  clib_memset(b, 0, 500);

  gid_address_t g =
    {
      .vni = 0,
      .nsh.spi = 0x112233,
      .nsh.si = 0x42,
      .type = GID_ADDR_NSH,
    };

  u16 len = gid_address_put (b, &g);

  u8 expected[] =
    {
      0x40, 0x03, 0x00, 0x00, /* AFI = LCAF*/
      0x11, 0x00, 0x00, 0x04, /* type = SPI LCAF, length = 4 */

      /* Service Path ID, Service index */
      0x11, 0x22, 0x33, 0x42, /* SPI, SI */
    };

  _assert (sizeof (expected) == len);
  _assert (0 == memcmp (expected, b, len));
done:
  clib_mem_free (b);
  return error;
}

static clib_error_t *
test_gid_parse_nsh ()
{
  clib_error_t * error = 0;
  gid_address_t _gid_addr, * gid_addr = &_gid_addr;
  gid_address_t _gid_addr_copy, * copy = &_gid_addr_copy;

  clib_memset (gid_addr, 0, sizeof (gid_addr[0]));
  clib_memset (copy, 0, sizeof (copy[0]));

  u8 data[] =
    {
      0x40, 0x03, 0x00, 0x00, /* AFI = LCAF*/
      0x11, 0x00, 0x00, 0x04, /* type = SPI LCAF, length = 4 */

      /* Service Path ID, Service index */
      0x55, 0x99, 0x42, 0x09, /* SPI, SI */
    };

  u32 len = gid_address_parse (data, gid_addr);
  _assert (sizeof (data) == len);
  gid_address_copy (copy, gid_addr);
  _assert (0 == gid_address_cmp (gid_addr, copy));
  _assert (GID_ADDR_NSH == gid_address_type (copy));
  _assert (0 == gid_address_vni (copy));
  _assert (gid_address_nsh_spi (copy) == 0x559942);
  _assert (gid_address_nsh_si (copy) == 0x09);

done:
  gid_address_free (copy);
  gid_address_free (gid_addr);
  return error;
}

static clib_error_t * test_gid_parse_lcaf ()
{
  clib_error_t * error = 0;
  gid_address_t _gid_addr, * gid_addr = &_gid_addr;
  gid_address_t _gid_addr_copy, * gid_addr_copy = &_gid_addr_copy;

  clib_memset (gid_addr, 0, sizeof (gid_addr[0]));
  clib_memset (gid_addr_copy, 0, sizeof (gid_addr_copy[0]));

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
  _assert (GID_ADDR_IP_PREFIX == gid_address_type (gid_addr));
  _assert (9 == gid_address_vni (gid_addr));
  _assert (0x18 == gid_address_vni_mask (gid_addr));
  _assert (0xddccbb10 == gid_addr->ippref.addr.ip.v4.as_u32);

done:
  gid_address_free (gid_addr);
  gid_address_free (gid_addr_copy);
  return error;
}

/* recursive LCAFs are not supported */
#if 0
static clib_error_t * test_gid_parse_lcaf_complex ()
{
  clib_error_t * error = 0;
  gid_address_t _gid_addr, * gid_addr = &_gid_addr;
  gid_address_t _gid_addr_copy, * gid_addr_copy = &_gid_addr_copy;

  clib_memset (gid_addr, 0, sizeof (gid_addr[0]));
  clib_memset (gid_addr_copy, 0, sizeof (gid_addr_copy[0]));

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
#endif

static clib_error_t * test_write_mac_in_lcaf (void)
{
  clib_error_t * error = 0;

  u8 * b = clib_mem_alloc(500);
  clib_memset(b, 0, 500);

  gid_address_t g =
    {
      .mac = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
      .vni = 0x01020304,
      .vni_mask = 0x10,
      .type = GID_ADDR_MAC,
    };

  u16 len = gid_address_put (b, &g);

  u8 expected[] =
    {
      0x40, 0x03,             /* AFI = LCAF */
      0x00,                   /* reserved1 */
      0x00,                   /* flags */
      0x02,                   /* LCAF type = Instance ID */
      0x10,                   /* IID/IID mask len */
      0x00, 0x0c,             /* length */
      0x01, 0x02, 0x03, 0x04, /* Instance ID / VNI */

      0x40, 0x05,             /* AFI = MAC */
      0x01, 0x02, 0x03, 0x04,
      0x05, 0x06              /* MAC */
    };
  _assert (sizeof (expected) == len);
  _assert (0 == memcmp (expected, b, len));
done:
  clib_mem_free (b);
  return error;
}

static clib_error_t * test_mac_address_write (void)
{
  clib_error_t * error = 0;

  u8 * b = clib_mem_alloc(500);
  clib_memset(b, 0, 500);

  gid_address_t g =
    {
      .mac = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
      .type = GID_ADDR_MAC,
    };

  u16 len = gid_address_put (b, &g);
  _assert (8 == len);

  u8 expected[] =
    {
      0x40, 0x05,             /* AFI = MAC */
      0x01, 0x02, 0x03, 0x04,
      0x05, 0x06              /* MAC */
    };
  _assert (0 == memcmp (expected, b, len));
done:
  clib_mem_free (b);
  return error;
}

static clib_error_t *
test_src_dst_with_vni_serdes (void)
{
  clib_error_t * error = 0;
  u8 * b = clib_mem_alloc (500);
  clib_memset (b, 0, 500);

  fid_address_t src =
    {
      .type = FID_ADDR_IP_PREF,
      .ippref =
        {
          .len = 24,
          .addr =
            {
              .version = IP4,
              .ip.v4.data = { 0x1, 0x2, 0x3, 0x0 }
            }
        }
    };

  fid_address_t dst =
    {
      .type = FID_ADDR_IP_PREF,
      .ippref =
        {
          .len = 16,
          .addr =
            {
              .version = IP4,
              .ip.v4.data = { 0x9, 0x8, 0x0, 0x0 }
            }
        }
    };

  source_dest_t sd =
    {
      .src = src,
      .dst = dst
    };

  gid_address_t g =
    {
      .sd = sd,
      .type = GID_ADDR_SRC_DST,
      .vni = 0x12345678,
      .vni_mask = 0x9
    };

  u16 size_to_put = gid_address_size_to_put(&g);
  _assert (36 == size_to_put);
  _assert (0 == gid_address_len(&g));

  u16 write_len = gid_address_put (b, &g);
  printf("sizetoput %d; writelen %d\n", size_to_put, write_len);
  _assert (size_to_put == write_len);

  u8 expected_data[] =
    {
      0x40, 0x03, 0x00, 0x00,  /* AFI = LCAF, reserved1, flags */
      0x02, 0x09, 0x00, 0x1c,  /* LCAF type = IID, IID mask-len, length */
      0x12, 0x34, 0x56, 0x78,  /* reserved; source-ML, Dest-ML */

      0x40, 0x03, 0x00, 0x00,  /* AFI = LCAF, reserved1, flags */
      0x0c, 0x00, 0x00, 0x10,  /* LCAF type = source/dest key, rsvd, length */
      0x00, 0x00, 0x18, 0x10,  /* reserved; source-ML, Dest-ML */

      0x00, 0x01,              /* AFI = ip4 */
      0x01, 0x02, 0x03, 0x00,  /* source */

      0x00, 0x01,              /* AFI = ip4 */
      0x09, 0x08, 0x00, 0x00,  /* destination */
    };
  _assert (0 == memcmp (expected_data, b, sizeof (expected_data)));

  gid_address_t p;
  clib_memset (&p, 0, sizeof (p));
  _assert (write_len == gid_address_parse (b, &p));
  _assert (0 == gid_address_cmp (&g, &p));
done:
  clib_mem_free (b);
  return error;
}

static clib_error_t *
test_src_dst_deser_bad_afi (void)
{
  clib_error_t * error = 0;

  u8 expected_data[] =
    {
      0x40, 0x03, 0x00, 0x00,  /* AFI = LCAF, reserved1, flags */
      0x0c, 0x00, 0x00, 0x14,  /* LCAF type = source/dest key, rsvd, length */
      0x00, 0x00, 0x00, 0x00,  /* reserved; source-ML, Dest-ML */

      0xde, 0xad,              /* AFI = bad value */
      0x11, 0x22, 0x33, 0x44,
      0x55, 0x66,              /* source */

      0x40, 0x05,              /* AFI = MAC */
      0x10, 0x21, 0x32, 0x43,
      0x54, 0x65,              /* destination */
    };

  gid_address_t p;
  _assert (~0 == gid_address_parse (expected_data, &p));
done:
  return error;
}

static clib_error_t *
test_src_dst_serdes (void)
{
  clib_error_t * error = 0;

  u8 * b = clib_mem_alloc (500);
  clib_memset (b, 0, 500);

  fid_address_t src =
    {
      .type = FID_ADDR_MAC,
      .mac = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }
    };

  fid_address_t dst =
    {
      .type = FID_ADDR_MAC,
      .mac = { 0x10, 0x21, 0x32, 0x43, 0x54, 0x65 }
    };

  source_dest_t sd =
    {
      .src = src,
      .dst = dst
    };

  gid_address_t g =
    {
      .sd = sd,
      .type = GID_ADDR_SRC_DST,
      .vni = 0x0,
      .vni_mask = 0x0
    };

  u16 size_to_put = gid_address_size_to_put(&g);
  _assert (28 == size_to_put);
  _assert (0 == gid_address_len(&g));

  u16 write_len = gid_address_put (b, &g);
  _assert (size_to_put == write_len);

  u8 expected_data[] =
    {
      0x40, 0x03, 0x00, 0x00,  /* AFI = LCAF, reserved1, flags */
      0x0c, 0x00, 0x00, 0x14,  /* LCAF type = source/dest key, rsvd, length */
      0x00, 0x00, 0x00, 0x00,  /* reserved; source-ML, Dest-ML */

      0x40, 0x05,              /* AFI = MAC */
      0x11, 0x22, 0x33, 0x44,
      0x55, 0x66,              /* source */

      0x40, 0x05,              /* AFI = MAC */
      0x10, 0x21, 0x32, 0x43,
      0x54, 0x65,              /* destination */
    };
  _assert (0 == memcmp (expected_data, b, sizeof (expected_data)));

  gid_address_t p;
  clib_memset (&p, 0, sizeof (p));
  _assert (write_len == gid_address_parse (b, &p));
  _assert (0 == gid_address_cmp (&g, &p));
done:
  clib_mem_free (b);
  return error;
}

static clib_error_t * test_gid_address_write (void)
{
  clib_error_t * error = 0;
  ip_prefix_t ippref_data, * ippref = &ippref_data;

  u8 * b = clib_mem_alloc(500);
  clib_memset(b, 0, 500);

  ip_prefix_version (ippref) = IP4;
  ip_prefix_len (ippref) = 9;
  ip4_address_t * ip4 = &ip_prefix_v4 (ippref);
  ip4->as_u32 = 0xaabbccdd;

  gid_address_t g =
    {
      .ippref = ippref[0],
      .type = GID_ADDR_IP_PREFIX,
      .vni = 0x01020304,
      .vni_mask = 0x18
    };

  _assert (18 == gid_address_size_to_put (&g));
  _assert (gid_address_len (&g) == 9);

  u16 write_len = gid_address_put (b, &g);
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
  _(locator_type)                         \
  _(gid_parse_ip_pref)                    \
  _(gid_parse_mac)                        \
  _(gid_parse_lcaf)                       \
  _(gid_parse_nsh)                        \
  _(gid_write_nsh)                        \
  _(mac_address_write)                    \
  _(gid_address_write)                    \
  _(src_dst_serdes)                       \
  _(write_mac_in_lcaf)                    \
  _(src_dst_deser_bad_afi)                \
  _(src_dst_with_vni_serdes)

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

