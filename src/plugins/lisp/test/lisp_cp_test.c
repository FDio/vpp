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

#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <lisp/lisp-cp/lisp_cp_messages.h>
#include <lisp/lisp-cp/control.h>
#include <lisp/lisp-cp/lisp_msg_serdes.h>
#include <vlibapi/api.h>
#include <lisp/lisp-cp/packets.h>

#define _assert(e)                    			\
  error = CLIB_ERROR_ASSERT (e);      			\
  if (error)                 		         	\
    {							\
      fformat(stderr, "FAIL: line %d \n\n", __LINE__);	\
      goto done;					\
    }

static void
print_chunk (u8 * b, int *offset, int c, char *des)
{
  int i, n = offset[0] + c;;
  for (i = offset[0]; i < n; i++)
    {
      printf ("0x%02x, ", b[i]);
    }
  printf (" // %s\n", des);
  *offset += c;
}

void
print_map_request (map_request_hdr_t * h)
{
#define pchunk(_count, _desc) \
  print_chunk((u8 *)h, &offset, _count, _desc)

  int offset = 0;

  pchunk (4, "data");
  pchunk (8, "Nonce");
  pchunk (2, "Source-EID-AFI");
  pchunk (4, "Source EID Address");
  pchunk (2, "ITR-RLOC-AFI 1");
  pchunk (4, "ITR-RLOC Address 1");
  pchunk (2, "ITR-RLOC-AFI 2");
  pchunk (16, "ITR-RLOC Address 2");
  pchunk (1, "REC: reserved");
  pchunk (1, "REC: EID mask-len");
  pchunk (2, "REC: EID-prefix-AFI");
  pchunk (4, "REC: EID-prefix");
  printf ("\n");
}

static clib_error_t *
test_lisp_msg_push_ecm ()
{
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error = 0;
  gid_address_t la, ra;
  vlib_buffer_t *b = 0;
  u32 buff_len = 900;
  int lp = 0x15, rp = 0x14;

  b = clib_mem_alloc (buff_len);
  clib_memset ((u8 *) b, 0, buff_len);
  b->current_length = buff_len;
  b->current_data = sizeof (udp_header_t) + sizeof (ip4_header_t) +
    sizeof (ecm_hdr_t) + 1;

  la.type = GID_ADDR_IP_PREFIX;
  la.ippref.addr.ip.ip4.as_u32 = 0xa1b2c3d4;
  la.ippref.addr.version = AF_IP4;

  ra.type = GID_ADDR_IP_PREFIX;
  ra.ippref.addr.ip.ip4.as_u32 = 0x90817263;
  ra.ippref.addr.version = AF_IP4;

  ecm_hdr_t *lh = lisp_msg_push_ecm (vm, b, lp, rp, &la, &ra);

  u8 expected_ecm_hdr[] = {
    0x80, 0x00, 0x00, 0x00
  };
  _assert (0 == memcmp (expected_ecm_hdr, lh, sizeof (expected_ecm_hdr)));

  ip4_header_t *ih = (ip4_header_t *) (lh + 1);
  /* clear ip checksum */
  clib_memset ((u8 *) ih + 10, 0, 2);

  /* *INDENT-OFF* */
  u8 expected_ip4_hdr[] = {
    0x45,                   /* version; IHL */
    0x00,                   /* services */
    0x03, 0xa0,             /* total length */
    0x00, 0x00,             /* identification */
    0x40, 0x00,             /* flags; fragment offset*/
    0xff,                   /* TTL */
    0x11,                   /* protocol */
    0x00, 0x00,             /* header checksum */
    0xd4, 0xc3, 0xb2, 0xa1, /* src IP */
    0x63, 0x72, 0x81, 0x90, /* dst IP */
  };
  /* *INDENT-ON* */

  _assert (0 == memcmp (ih, expected_ip4_hdr, sizeof (expected_ip4_hdr)));

  udp_header_t *uh = (udp_header_t *) (ih + 1);
  /* clear udp checksum */
  clib_memset ((u8 *) uh + 6, 0, 2);

  /* *INDENT-OFF* */
  u8 expected_udp_hdr[] = {
    0x00, 0x15, /* src port */
    0x00, 0x14, /* dst port */
    0x03, 0x8c, /* length */
    0x00, 0x00, /* checksum */
  };
  /* *INDENT-ON* */

  _assert (0 == memcmp (uh, expected_udp_hdr, sizeof (expected_udp_hdr)));

done:
  clib_mem_free (b);
  return error;
}

static clib_error_t *
test_lisp_msg_parse_mapping_record ()
{
  clib_error_t *error = 0;
  locator_t probed;
  locator_t *locs = 0;
  vlib_buffer_t *b = 0;
  gid_address_t eid;
  u32 buff_len = 500;

  b = clib_mem_alloc (buff_len);
  clib_memset ((u8 *) b, 0, buff_len);

  /* *INDENT-OFF* */
  u8 map_reply_records[] = {
    /* 1. record */
    0x01, 0x02, 0x03, 0x04, /* record TTL */
    0x01,                   /* locator count */
    0x00, 0x00, 0x00,       /* eid-mask-len; ... */
    0x00, 0x00,             /* reserved; map-version num */
    0x00, 0x01,             /* EID-Prefix-AFI */
    0x33, 0x44, 0x55, 0x66, /* eid-prefix */
    /* loc */
    0x0a,                   /* prority */
    0x0b,                   /* weight */
    0x0c,                   /* m-prority */
    0x0d,                   /* m-weight */
    0x00, 0x00,             /* unused flags */
    0x00, 0x01,             /* Loc-AFI */
    0xaa, 0xbb, 0xcc, 0xdd, /* Loator */
  };
  /* *INDENT-ON* */

  b->current_length = buff_len;
  clib_memcpy (b->data, map_reply_records, sizeof (map_reply_records));

  lisp_msg_parse_mapping_record (b, &eid, &locs, &probed);
  _assert (vec_len (locs) == 1);
  _assert (eid.ippref.addr.ip.ip4.as_u32 == 0x66554433);
  _assert (locs[0].local == 0);
  _assert (locs[0].address.ippref.addr.ip.ip4.as_u32 == 0xddccbbaa);
  _assert (locs[0].address.type == GID_ADDR_IP_PREFIX);
  _assert (locs[0].priority == 0xa);
  _assert (locs[0].weight == 0xb);
  _assert (locs[0].mpriority == 0xc);
  _assert (locs[0].mweight == 0xd);

done:
  clib_mem_free (b);
  if (locs)
    vec_free (locs);
  return error;
}

static map_request_hdr_t *
build_map_request (lisp_cp_main_t * lcm, vlib_buffer_t * b,
		   gid_address_t * rlocs)
{
  gid_address_t _seid, *seid = &_seid;
  gid_address_t _deid, *deid = &_deid;
  u8 is_smr_invoked = 1;
  u8 rloc_probe_set = 0;
  u64 nonce = 0;
  map_request_hdr_t *h = 0;
  clib_memset (deid, 0, sizeof (deid[0]));
  clib_memset (seid, 0, sizeof (seid[0]));

  gid_address_type (seid) = GID_ADDR_IP_PREFIX;
  ip_address_t *ip_addr = &gid_address_ip (seid);
  ip_addr_v4 (ip_addr).as_u32 = 0x12345678;
  seid->ippref.addr.version = AF_IP4;

  gid_address_type (deid) = GID_ADDR_IP_PREFIX;
  ip_address_t *ip_addr2 = &gid_address_ip (deid);
  ip_addr_v4 (ip_addr2).as_u32 = 0x9abcdef0;
  deid->ippref.addr.version = AF_IP4;
  gid_address_ippref_len (deid) = 24;

  h = lisp_msg_put_mreq (lcm, b, seid, deid, rlocs,
			 is_smr_invoked, rloc_probe_set, &nonce);
  vec_free (rlocs);
  return h;
}

static void
generate_rlocs (gid_address_t ** rlocs, u32 * count)
{
  gid_address_t gid_addr_data, *gid_addr = &gid_addr_data;
  clib_memset (gid_addr, 0, sizeof (gid_addr[0]));
  ip_address_t *addr = &gid_address_ip (gid_addr);

  gid_address_type (gid_addr) = GID_ADDR_IP_PREFIX;

  ip_addr_version (addr) = AF_IP4;
  ip_addr_v4 (addr).data_u32 = 0x10203040;
  vec_add1 (rlocs[0], gid_addr[0]);

  ip_addr_v6 (addr).as_u32[0] = 0xffeeddcc;
  ip_addr_v6 (addr).as_u32[1] = 0xbbaa9988;
  ip_addr_v6 (addr).as_u32[2] = 0x77665544;
  ip_addr_v6 (addr).as_u32[3] = 0x33221100;
  ip_addr_version (addr) = AF_IP6;
  vec_add1 (rlocs[0], gid_addr[0]);
}

static clib_error_t *
test_lisp_msg_parse ()
{
  gid_address_t eid;
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  map_request_hdr_t *h;
  gid_address_t gid;
  clib_error_t *error = 0;
  vlib_buffer_t *b;
  gid_address_t *rlocs_decode = 0, *rlocs = 0;
  u32 rloc_count_parse = 0;

  u8 *data = clib_mem_alloc (500);
  clib_memset (data, 0, 500);
  b = (vlib_buffer_t *) data;

  generate_rlocs (&rlocs_decode, &rloc_count_parse);
  h = build_map_request (lcm, b, rlocs_decode);

  vlib_buffer_pull (b, sizeof (*h));
  u32 len = lisp_msg_parse_addr (b, &gid);
  _assert (len == 2 + 4
	   /* Source-EID-AFI field lenght + IPv4 address length */ );
  _assert (gid.ippref.addr.ip.ip4.as_u32 == 0x12345678);
  _assert (gid.ippref.addr.version == AF_IP4);

  u8 rloc_count = MREQ_ITR_RLOC_COUNT (h) + 1;
  lisp_msg_parse_itr_rlocs (b, &rlocs, rloc_count);

  _assert (vec_len (rlocs) == 2);
  _assert (rlocs[0].ippref.addr.ip.ip4.as_u32 == 0x10203040);
  _assert (rlocs[0].ippref.addr.version == AF_IP4);

  _assert (rlocs[1].ippref.addr.ip.ip6.as_u32[0] == 0xffeeddcc);
  _assert (rlocs[1].ippref.addr.ip.ip6.as_u32[1] == 0xbbaa9988);
  _assert (rlocs[1].ippref.addr.ip.ip6.as_u32[2] == 0x77665544);
  _assert (rlocs[1].ippref.addr.ip.ip6.as_u32[3] == 0x33221100);
  _assert (rlocs[1].ippref.addr.version == AF_IP6);

  lisp_msg_parse_eid_rec (b, &eid);
  _assert (eid.ippref.addr.ip.ip4.as_u32 == 0x9abcdef0);
  _assert (eid.ippref.addr.version == AF_IP4);
  _assert (eid.ippref.len == 24);

done:
  clib_mem_free (data);
  if (rlocs)
    vec_free (rlocs);
  return error;
}

static clib_error_t *
test_lisp_msg_put_mreq_with_lcaf ()
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  clib_error_t *error = 0;
  map_request_hdr_t *h = 0;
  gid_address_t *rlocs = 0;

  ip_prefix_t ippref;
  ip_prefix_version (&ippref) = AF_IP4;
  ip4_address_t *ip = &ip_prefix_v4 (&ippref);
  ip->as_u32 = 0x11223344;
  ippref.len = 32;

  gid_address_t g = {
    .type = GID_ADDR_IP_PREFIX,
    .ippref = ippref,
    .vni = 0x90919293,
    .vni_mask = 0x17
  };
  vec_add1 (rlocs, g);

  u8 *data = clib_mem_alloc (500);
  clib_memset (data, 0, 500);

  h = build_map_request (lcm, (vlib_buffer_t *) data, rlocs);

  /* clear Nonce to simplify comparison */
  clib_memset ((u8 *) h + 4, 0, 8);

  /* *INDENT-OFF* */
  u8 expected_data[] =
    {
      0x10, 0x40, 0x00, 0x01, /* type; flags; IRC; REC count */
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, /* nonce */
      0x00, 0x01,             /* Source-EID-AFI */
      0x78, 0x56, 0x34, 0x12, /* Source EID Address */

      /* RLOCs */
      0x40, 0x03,             /* AFI = LCAF*/
      /* LCAF header*/
      0x00, 0x00,             /* reserved1, flags */
      0x02,                   /* type = Instance ID */
      0x17,                   /* IID mask-len */
      0x00, 0x0a,             /* lenght */
      0x90, 0x91, 0x92, 0x93, /* IID / VNI */

      0x00, 0x01,             /* AFI = ipv4 */
      0x44, 0x33, 0x22, 0x11, /* ITR-RLOC Address 1 */

      /* record */
      0x00,                   /* reserved */
      0x18,                   /* EID mask-len */
      0x00, 0x01,             /* EID-prefix-AFI */
      0xf0, 0xde, 0xbc, 0x9a, /* EID-prefix */
    };
  /* *INDENT-ON* */

  _assert (0 == memcmp (expected_data, (u8 *) h, sizeof (expected_data)));
done:
  clib_mem_free (data);
  return error;
}

static clib_error_t *
test_lisp_msg_put_mreq ()
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();
  clib_error_t *error = 0;
  map_request_hdr_t *h;
  gid_address_t *rlocs = 0;
  u32 rloc_count = 0;

  u8 *data = clib_mem_alloc (500);
  clib_memset (data, 0, 500);

  generate_rlocs (&rlocs, &rloc_count);
  h = build_map_request (lcm, (vlib_buffer_t *) data, rlocs);

  /* clear Nonce to simplify comparison */
  clib_memset ((u8 *) h + 4, 0, 8);

  print_map_request (h);

  /* *INDENT-OFF* */
  u8 expected_data[50] = {
    0x10, 0x40, 0x01, 0x01, /* type; flags; IRC; REC count */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, /* nonce */
    0x00, 0x01,             /* Source-EID-AFI */
    0x78, 0x56, 0x34, 0x12, /* Source EID Address */

    /* RLOCs */
    0x00, 0x01,             /* ITR-RLOC-AFI 1 */
    0x40, 0x30, 0x20, 0x10, /* ITR-RLOC Address 1 */
    0x00, 0x02,             /* ITR-RLOC-AFI 2 */
    0xcc, 0xdd, 0xee, 0xff,
    0x88, 0x99, 0xaa, 0xbb,
    0x44, 0x55, 0x66, 0x77,
    0x00, 0x11, 0x22, 0x33, /* ITR-RLOC Address 2 */

    /* record */
    0x00,                   /* reserved */
    0x18,                   /* EID mask-len */
    0x00, 0x01,             /* EID-prefix-AFI */
    0xf0, 0xde, 0xbc, 0x9a, /* EID-prefix */
  };
  /* *INDENT-ON* */

  _assert (0 == memcmp (expected_data, (u8 *) h, sizeof (expected_data)));

done:
  clib_mem_free (data);
  return error;
}

/* generate a vector of eid records */
static mapping_t *
build_test_map_records ()
{
  mapping_t *records = 0;

  /* *INDENT-OFF* */
  mapping_t r = {
    .ttl = MAP_REGISTER_DEFAULT_TTL,
    .eid = {
      .type = GID_ADDR_MAC,
      .mac = {1, 2, 3, 4, 5, 6},
      .vni = 0x0
    }
  };

  locator_t loc = {
    .weight = 1,
    .priority = 2,
    .local = 1,
    .address = {
      .type = GID_ADDR_IP_PREFIX,
      .ippref = {
        .addr = {
          .ip.ip4.as_u32 = 0x99887766,
          .version = AF_IP4
        }
      }
    }
  };
  /* *INDENT-ON* */

  vec_add1 (r.locators, loc);
  vec_add1 (records, r);

  return records;
}

static void
free_test_map_records (mapping_t * maps)
{
  mapping_t *map;
  vec_foreach (map, maps)
  {
    vec_free (map->locators);
  }
  vec_free (maps);
}

static clib_error_t *
test_lisp_map_register ()
{
  vlib_buffer_t *b;
  clib_error_t *error = 0;
  u64 nonce;
  u32 msg_len = 0;
  mapping_t *records = build_test_map_records ();

  u8 *data = clib_mem_alloc (500);
  clib_memset (data, 0, 500);
  b = (vlib_buffer_t *) data;

  lisp_msg_put_map_register (b, records, 1 /* want map notify */ ,
			     20 /* length of HMAC_SHA_1_96 */ ,
			     &nonce, &msg_len);
  free_test_map_records (records);

  /* clear Nonce to simplify comparison */
  clib_memset ((u8 *) b->data + 4, 0, 8);

  /* clear authentication data */
  clib_memset ((u8 *) b->data + 16, 0, 20);

  /* *INDENT-OFF* */
  u8 expected_data[] = {
    0x30, 0x00, 0x01, 0x01, /* type; rsvd; want notify; REC count */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, /* nonce */
    0x00, 0x00, 0x00, 0x00, /* key id, auth data length:
                              both are zeroes because those are set in another
                              function (see auth_data_len_by_key_id())*/
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, /* auth data */

    /* first record */
    /* 0x00, 0x00, 0x03, 0x84, */ /* default ttl (15 minues) */
    0x00, 0x01, 0x51, 0x80, /* default ttl (24h = 86400s) */
    0x01, 0x00, 0x00, 0x00, /* loc count, eid len, ACT, A */
    0x00, 0x00, 0x40, 0x05, /* rsvd, map ver num, AFI = MAC */
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06,             /* MAC EID */

    /* locator 1 */
    0x02, 0x01, 0x00, 0x00, /* prio, weight, mprio, mweight */
    0x00, 0x04, 0x00, 0x01, /* flags, AFI = ipv4 */
    0x66, 0x77, 0x88, 0x99, /* ipv4 locator address */
  };
  /* *INDENT-ON* */

  _assert (0 == memcmp (expected_data, b->data, sizeof (expected_data)));
done:
  clib_mem_free (data);
  return error;
}

static vlib_buffer_t *
create_buffer (u8 * data, u32 data_len)
{
  vlib_buffer_t *b;

  u8 *buf_data = clib_mem_alloc (500);
  clib_memset (buf_data, 0, 500);
  b = (vlib_buffer_t *) buf_data;

  u8 *p = vlib_buffer_put_uninit (b, data_len);
  clib_memcpy (p, data, data_len);

  return b;
}

static clib_error_t *
test_lisp_parse_map_reply ()
{
  clib_error_t *error = 0;

  /* *INDENT-OFF* */
  u8 map_reply_data[] =
    {
      0x00, 0x00, 0x00, 0x01, /* type; rsvd; mapping count */
      0x00, 0x00, 0x00, 0x00,
    };
  /* *INDENT-ON* */

  vlib_buffer_t *b = create_buffer (map_reply_data, sizeof (map_reply_data));
  map_records_arg_t *mrecs = parse_map_reply (b);
  _assert (0 == mrecs);
  clib_mem_free (b);

  /* *INDENT-OFF* */
  u8 map_reply_data2[] =
    {
      0x00, 0x00, 0x00, 0x01, /* type; rsvd */
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, /* nonce */

      /* 1. record  - incomplete */
      0x01, 0x02, 0x03, 0x04, /* record TTL */
      0x01,                   /* locator count */
    };
  /* *INDENT-ON* */

  b = create_buffer (map_reply_data2, sizeof (map_reply_data2));
  mrecs = parse_map_reply (b);
  _assert (0 == mrecs);
done:
  clib_mem_free (b);
  return error;
}

static clib_error_t *
test_lisp_parse_lcaf ()
{
  int i;
  clib_error_t *error = 0;
  gid_address_t eid;
  locator_t *locs = 0;
  locator_t probed;
  vlib_buffer_t *b = 0;
  u32 buff_len = 500;

  b = clib_mem_alloc (buff_len);
  clib_memset ((u8 *) b, 0, buff_len);

  /* *INDENT-OFF* */
  u8 map_reply_records[] =
    {
      /* 1. record */
      0x01, 0x02, 0x03, 0x04, /* record TTL */
      0x03,                   /* locator count */
      0x00, 0x00, 0x00,       /* eid-mask-len; ... */
      0x00, 0x00,             /* reserved; map-version num */
      0x00, 0x01,             /* EID-Prefix-AFI */
      0x33, 0x44, 0x55, 0x66, /* eid-prefix */

      /* 1st locator */
      0x0a,                   /* prority */
      0x0b,                   /* weight */
      0x0c,                   /* m-prority */
      0x0d,                   /* m-weight */
      0x00, 0x00,             /* unused flags */
      0x40, 0x03,             /* Loc-AFI = LCAF*/

      /* LCAF header*/
      0x00, 0x00,             /* reserved1, flags */
      0x02,                   /* type = Instance ID */
      0x18,                   /* IID mask-len */
      0x00, 0x0a,             /* lenght */
      /* LCAF Instance ID */
      0x00, 0x00, 0x00, 0x09, /* iid */
      0x00, 0x01,             /* AFI = ipv4 */
      0x10, 0xbb, 0xcc, 0xdd, /* ipv4 loator address */

      /* 2nd locator */
      0x07,                   /* prority */
      0x06,                   /* weight */
      0x05,                   /* m-prority */
      0x04,                   /* m-weight */
      0x00, 0x00,             /* unused flags */
      0x40, 0x03,             /* Loc-AFI = LCAF*/

      /* LCAF header*/
      0x00, 0x00,             /* reserved1, flags */
      0x02,                   /* type = Instance ID */
      0x18,                   /* IID mask-len */
      0x00, 0x16,             /* iid length + next AFI lenght */
      /* LCAF Instance ID */
      0x22, 0x44, 0x66, 0x88, /* iid */
      0x00, 0x02,             /* AFI = ipv6 */
      0xcc, 0xdd, 0xee, 0xff,
      0x88, 0x99, 0xaa, 0xbb,
      0x44, 0x55, 0x66, 0x77,
      0x00, 0x11, 0x22, 0x33, /* ipv6 locator address */

      /* 3rd locator */
      0x0a,                   /* prority */
      0x0b,                   /* weight */
      0x0c,                   /* m-prority */
      0x0d,                   /* m-weight */
      0x00, 0x00,             /* unused flags */
      0x00, 0x01,             /* Loc-AFI */
      0xaa, 0xbb, 0xcc, 0xdd, /* Loator */
    };
  /* *INDENT-ON* */

  b->current_length = buff_len;
  memcpy (b->data, map_reply_records, sizeof (map_reply_records));

  lisp_msg_parse_mapping_record (b, &eid, &locs, &probed);
  _assert (vec_len (locs) == 3);
  _assert (eid.ippref.addr.ip.ip4.as_u32 == 0x66554433);

  /* check 1st locator - an LCAF with ipv4 */
  _assert (locs[0].local == 0);
  _assert (locs[0].priority == 0xa);
  _assert (locs[0].weight == 0xb);
  _assert (locs[0].mpriority == 0xc);
  _assert (locs[0].mweight == 0xd);

  _assert (gid_address_type (&locs[0].address) == GID_ADDR_IP_PREFIX);
  _assert (gid_address_vni (&locs[0].address) == 0x09);
  ip_prefix_t *ip_pref = &gid_address_ippref (&locs[0].address);
  _assert (AF_IP4 == ip_prefix_version (ip_pref));

  /* 2nd locator - LCAF entry with ipv6 address */
  _assert (locs[1].local == 0);
  _assert (locs[1].priority == 0x7);
  _assert (locs[1].weight == 0x6);
  _assert (locs[1].mpriority == 0x5);
  _assert (locs[1].mweight == 0x4);

  _assert (gid_address_type (&locs[1].address) == GID_ADDR_IP_PREFIX);
  _assert (0x22446688 == gid_address_vni (&locs[1].address));
  ip_pref = &gid_address_ippref (&locs[1].address);
  _assert (AF_IP6 == ip_prefix_version (ip_pref));

  /* 3rd locator - simple ipv4 address */
  _assert (gid_address_type (&locs[2].address) == GID_ADDR_IP_PREFIX);
done:
  clib_mem_free (b);

  for (i = 0; i < 3; i++)
    locator_free (&locs[i]);
  vec_free (locs);
  return error;
}

#define foreach_test_case                 \
  _(lisp_msg_put_mreq)                    \
  _(lisp_msg_put_mreq_with_lcaf)          \
  _(lisp_msg_push_ecm)                    \
  _(lisp_msg_parse)                       \
  _(lisp_msg_parse_mapping_record)        \
  _(lisp_parse_map_reply)                 \
  _(lisp_parse_lcaf)                      \
  _(lisp_map_register)

static int
lisp_cp_serdes_tests (vlib_main_t * vm, unformat_input_t * input)
{
  clib_error_t *error;

#define _(_test_name)                   		\
  error = test_ ## _test_name ();       		\
  if (error)                            		\
    {                                   		\
      fformat (stderr, "FAIL: test_" #_test_name "\n");	\
      return -1;                        		\
    }							\
  else							\
      fformat (stderr, "PASS: test_" #_test_name "\n");	\

  foreach_test_case
#undef _
    return 0;
}

static clib_error_t *
test_locator_type (void)
{
  clib_error_t *error = 0;
  gid_address_t _gid_addr, *gid = &_gid_addr;
  ip_prefix_t *ippref;
  gid_address_type (gid) = GID_ADDR_IP_PREFIX;
  gid_address_ippref_len (gid) = 24;
  ippref = &gid_address_ippref (gid);
  ip_prefix_version (ippref) = AF_IP4;
  ip_prefix_len (ippref) = 0;
  ip4_address_t *ip4 = &ip_prefix_v4 (ippref);
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
  ip_prefix_version (&nested_ippref) = AF_IP4;
  ip_prefix_len (&nested_ippref) = 0;
  ip4 = &ip_prefix_v4 (&nested_ippref);
  ip4->as_u32 = 0x33882299;
  gid_address_t nested_gid = {
    .type = GID_ADDR_IP_PREFIX,
    .ippref = nested_ippref
  };

  lcaf_t lcaf = {
    .type = LCAF_INSTANCE_ID,
    .uni = {
	    .vni_mask_len = 5,
	    .vni = 0xa1b2c3d4,
	    .gid_addr = &nested_gid}
  };
  gid_address_type (gid) = GID_ADDR_LCAF;
  gid_address_lcaf (gid) = lcaf;

  loc2.address = gid[0];
  locator_copy (&loc1, &loc2);

  _assert (0 == locator_cmp (&loc1, &loc2));

done:
  locator_free (&loc1);
  return error;
}

static clib_error_t *
test_gid_parse_ip_pref ()
{
  clib_error_t *error = 0;
  gid_address_t _gid_addr, *gid_addr = &_gid_addr;
  gid_address_t _gid_addr_copy, *copy = &_gid_addr_copy;

  /* *INDENT-OFF* */
  u8 data[] =
    {
      0x00, 0x01,             /* AFI = IPv4 */
      0x10, 0xbb, 0xcc, 0xdd, /* ipv4 address */
    };
  /* *INDENT-ON* */

  u32 len = gid_address_parse (data, gid_addr);
  _assert (6 == len);
  gid_address_copy (copy, gid_addr);
  _assert (0 == gid_address_cmp (copy, gid_addr));
done:
  return error;
}

static clib_error_t *
test_gid_parse_mac ()
{
  clib_error_t *error = 0;
  gid_address_t _gid, *gid = &_gid;
  gid_address_t _gid_copy, *gid_copy = &_gid_copy;

  /* *INDENT-OFF* */
  u8 data[] =
    {
      0x40, 0x05,             /* AFI = MAC address */
      0x10, 0xbb, 0xcc, 0xdd, /* MAC */
      0x77, 0x99,
    };
  /* *INDENT-ON* */

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
  clib_error_t *error = 0;

  u8 *b = clib_mem_alloc (500);
  clib_memset (b, 0, 500);

  gid_address_t g = {
    .vni = 0,
    .nsh.spi = 0x112233,
    .nsh.si = 0x42,
    .type = GID_ADDR_NSH,
  };

  u16 len = gid_address_put (b, &g);

  /* *INDENT-OFF* */
  u8 expected[] =
    {
      0x40, 0x03, 0x00, 0x00, /* AFI = LCAF*/
      0x11, 0x00, 0x00, 0x04, /* type = SPI LCAF, length = 4 */

      /* Service Path ID, Service index */
      0x11, 0x22, 0x33, 0x42, /* SPI, SI */
    };
  /* *INDENT-ON* */

  _assert (sizeof (expected) == len);
  _assert (0 == memcmp (expected, b, len));
done:
  clib_mem_free (b);
  return error;
}

static clib_error_t *
test_gid_parse_nsh ()
{
  clib_error_t *error = 0;
  gid_address_t _gid_addr, *gid_addr = &_gid_addr;
  gid_address_t _gid_addr_copy, *copy = &_gid_addr_copy;

  clib_memset (gid_addr, 0, sizeof (gid_addr[0]));
  clib_memset (copy, 0, sizeof (copy[0]));

  /* *INDENT-OFF* */
  u8 data[] =
    {
      0x40, 0x03, 0x00, 0x00, /* AFI = LCAF*/
      0x11, 0x00, 0x00, 0x04, /* type = SPI LCAF, length = 4 */

      /* Service Path ID, Service index */
      0x55, 0x99, 0x42, 0x09, /* SPI, SI */
    };
  /* *INDENT-ON* */

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

static clib_error_t *
test_gid_parse_lcaf ()
{
  clib_error_t *error = 0;
  gid_address_t _gid_addr, *gid_addr = &_gid_addr;
  gid_address_t _gid_addr_copy, *gid_addr_copy = &_gid_addr_copy;

  clib_memset (gid_addr, 0, sizeof (gid_addr[0]));
  clib_memset (gid_addr_copy, 0, sizeof (gid_addr_copy[0]));

  /* *INDENT-OFF* */
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
  /* *INDENT-ON* */

  u32 len = gid_address_parse (data, gid_addr);
  _assert (18 == len);
  gid_address_copy (gid_addr_copy, gid_addr);
  _assert (0 == gid_address_cmp (gid_addr_copy, gid_addr));
  _assert (GID_ADDR_IP_PREFIX == gid_address_type (gid_addr));
  _assert (9 == gid_address_vni (gid_addr));
  _assert (0x18 == gid_address_vni_mask (gid_addr));
  _assert (0xddccbb10 == gid_addr->ippref.addr.ip.ip4.as_u32);

done:
  gid_address_free (gid_addr);
  gid_address_free (gid_addr_copy);
  return error;
}

/* recursive LCAFs are not supported */
#if 0
static clib_error_t *
test_gid_parse_lcaf_complex ()
{
  clib_error_t *error = 0;
  gid_address_t _gid_addr, *gid_addr = &_gid_addr;
  gid_address_t _gid_addr_copy, *gid_addr_copy = &_gid_addr_copy;

  clib_memset (gid_addr, 0, sizeof (gid_addr[0]));
  clib_memset (gid_addr_copy, 0, sizeof (gid_addr_copy[0]));

  /* *INDENT-OFF* */
  u8 data[] = {
    0x40, 0x03,			/* AFI = LCAF */

    /* LCAF header */
    0x00, 0x00,			/* reserved1, flags */
    0x02,			/* type = Instance ID */
    0x18,			/* IID mask-len */
    0x00, 0x0a,			/* iid length + next AFI lenght */
    /* LCAF Instance ID */
    0x00, 0x00, 0x00, 0x0b,	/* iid */

    0x40, 0x03,			/* AFI = LCAF */
    /* LCAF header */
    0x00, 0x00,			/* reserved1, flags */
    0x02,			/* type = Instance ID */
    0x17,			/* IID mask-len */
    0x00, 0x0a,			/* iid length + next AFI lenght */
    /* LCAF Instance ID */
    0x00, 0x00, 0x00, 0x0c,	/* iid */

    0x40, 0x03,			/* AFI = LCAF */
    /* LCAF header */
    0x00, 0x00,			/* reserved1, flags */
    0x02,			/* type = Instance ID */
    0x16,			/* IID mask-len */
    0x00, 0x16,			/* iid length + next AFI lenght */
    /* LCAF Instance ID */
    0x00, 0x00, 0x00, 0x0d,	/* iid */

    0x00, 0x02,			/* AFI = IPv6 */

    0x10, 0xbb, 0xcc, 0xdd,
    0x10, 0xbb, 0xcc, 0xdd,
    0x10, 0xbb, 0xcc, 0xdd,
    0x10, 0xbb, 0xcc, 0xdd,	/* ipv6 address */
  };
  /* *INDENT-ON* */

  u32 len = gid_address_parse (data, gid_addr);
  _assert (54 == len);
  _assert (gid_addr->type == GID_ADDR_LCAF);
  gid_address_copy (gid_addr_copy, gid_addr);
  _assert (0 == gid_address_cmp (gid_addr_copy, gid_addr));
  _assert (gid_addr_copy->type == GID_ADDR_LCAF);

  lcaf_t *lcaf = &gid_address_lcaf (gid_addr_copy);
  _assert (lcaf->type == LCAF_INSTANCE_ID);
  vni_t *v = (vni_t *) lcaf;
  _assert (v->vni == 0x0b);
  _assert (v->vni_mask_len == 0x18);

  gid_address_t *tmp = vni_gid (v);
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

  ip_prefix_t *ip_pref = &gid_address_ippref (tmp);
  ip6_address_t *ip6 = &ip_prefix_v6 (ip_pref);
  _assert (ip6->as_u32[0] == 0xddccbb10);
  _assert (ip6->as_u32[1] == 0xddccbb10);
  _assert (ip6->as_u32[2] == 0xddccbb10);
  _assert (ip6->as_u32[3] == 0xddccbb10);
  _assert (ip_prefix_version (ip_pref) == AF_IP6);

done:
  gid_address_free (gid_addr);
  gid_address_free (gid_addr_copy);
  return error;
}
#endif

static clib_error_t *
test_write_mac_in_lcaf (void)
{
  clib_error_t *error = 0;

  u8 *b = clib_mem_alloc (500);
  clib_memset (b, 0, 500);

  gid_address_t g = {
    .mac = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
    .vni = 0x01020304,
    .vni_mask = 0x10,
    .type = GID_ADDR_MAC,
  };

  u16 len = gid_address_put (b, &g);

  /* *INDENT-OFF* */
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
  /* *INDENT-ON* */

  _assert (sizeof (expected) == len);
  _assert (0 == memcmp (expected, b, len));
done:
  clib_mem_free (b);
  return error;
}

static clib_error_t *
test_mac_address_write (void)
{
  clib_error_t *error = 0;

  u8 *b = clib_mem_alloc (500);
  clib_memset (b, 0, 500);

  gid_address_t g = {
    .mac = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
    .type = GID_ADDR_MAC,
  };

  u16 len = gid_address_put (b, &g);
  _assert (8 == len);

  /* *INDENT-OFF* */
  u8 expected[] =
    {
      0x40, 0x05,             /* AFI = MAC */
      0x01, 0x02, 0x03, 0x04,
      0x05, 0x06              /* MAC */
    };
  /* *INDENT-ON* */

  _assert (0 == memcmp (expected, b, len));
done:
  clib_mem_free (b);
  return error;
}

static clib_error_t *
test_src_dst_with_vni_serdes (void)
{
  clib_error_t *error = 0;
  u8 *b = clib_mem_alloc (500);
  clib_memset (b, 0, 500);

  /* *INDENT-OFF* */
  fid_address_t src =
    {
      .type = FID_ADDR_IP_PREF,
      .ippref =
        {
          .len = 24,
          .addr =
            {
              .version = AF_IP4,
              .ip.ip4.data = { 0x1, 0x2, 0x3, 0x0 }
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
              .version = AF_IP4,
              .ip.ip4.data = { 0x9, 0x8, 0x0, 0x0 }
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

  /* *INDENT-ON* */

  u16 size_to_put = gid_address_size_to_put (&g);
  _assert (36 == size_to_put);
  _assert (0 == gid_address_len (&g));

  u16 write_len = gid_address_put (b, &g);
  _assert (size_to_put == write_len);

  /* *INDENT-OFF* */
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
  /* *INDENT-ON* */

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
  clib_error_t *error = 0;

  /* *INDENT-OFF* */
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
  /* *INDENT-ON* */

  gid_address_t p;
  _assert (~0 == gid_address_parse (expected_data, &p));
done:
  return error;
}

static clib_error_t *
test_src_dst_serdes (void)
{
  clib_error_t *error = 0;

  u8 *b = clib_mem_alloc (500);
  clib_memset (b, 0, 500);

  fid_address_t src = {
    .type = FID_ADDR_MAC,
    .mac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
  };

  fid_address_t dst = {
    .type = FID_ADDR_MAC,
    .mac = {0x10, 0x21, 0x32, 0x43, 0x54, 0x65}
  };

  source_dest_t sd = {
    .src = src,
    .dst = dst
  };

  gid_address_t g = {
    .sd = sd,
    .type = GID_ADDR_SRC_DST,
    .vni = 0x0,
    .vni_mask = 0x0
  };

  u16 size_to_put = gid_address_size_to_put (&g);
  _assert (28 == size_to_put);
  _assert (0 == gid_address_len (&g));

  u16 write_len = gid_address_put (b, &g);
  _assert (size_to_put == write_len);

  /* *INDENT-OFF* */
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
  /* *INDENT-ON* */

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
test_gid_address_write (void)
{
  clib_error_t *error = 0;
  ip_prefix_t ippref_data, *ippref = &ippref_data;

  u8 *b = clib_mem_alloc (500);
  clib_memset (b, 0, 500);

  ip_prefix_version (ippref) = AF_IP4;
  ip_prefix_len (ippref) = 9;
  ip4_address_t *ip4 = &ip_prefix_v4 (ippref);
  ip4->as_u32 = 0xaabbccdd;

  gid_address_t g = {
    .ippref = ippref[0],
    .type = GID_ADDR_IP_PREFIX,
    .vni = 0x01020304,
    .vni_mask = 0x18
  };

  _assert (18 == gid_address_size_to_put (&g));
  _assert (gid_address_len (&g) == 9);

  u16 write_len = gid_address_put (b, &g);
  _assert (18 == write_len);

  /* *INDENT-OFF* */
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
  /* *INDENT-ON* */

  _assert (0 == memcmp (expected_gid_data, b, sizeof (expected_gid_data)));
done:
  clib_mem_free (b);
  return error;
}

#undef foreach_test_case

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

static int
lisp_cp_types_tests (vlib_main_t * vm, unformat_input_t * input)
{
  clib_error_t *error;

#define _(_test_name)                   		\
  error = test_ ## _test_name ();       		\
  if (error)                            		\
    {                                   		\
      fformat (stderr, "FAIL: test_" #_test_name "\n");	\
      return -1;                        		\
    }							\
  else							\
      fformat (stderr, "PASS: test_" #_test_name "\n");	\

  foreach_test_case
#undef _
    return 0;
}

#undef _assert

static clib_error_t *
lisp_cp_test (vlib_main_t * vm, unformat_input_t * input,
	      vlib_cli_command_t * cmd_arg)
{
  int res = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "serdes"))
	{
	  res = lisp_cp_serdes_tests (vm, input);
	}
      if (unformat (input, "types"))
	{
	  res = lisp_cp_types_tests (vm, input);
	}
      else if (unformat (input, "all"))
	{
	  if ((res = lisp_cp_serdes_tests (vm, input)))
	    goto done;
	  if ((res = lisp_cp_types_tests (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "rbtree unit test failed");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_cp_command, static) =
{
  .path = "test lisp cp",
  .short_help = "lisp cp internal unit tests",
  .function = lisp_cp_test,
};
/* *INDENT-ON* */

#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Test Locator ID Separation Protocol (LISP)",
    .default_disabled = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
