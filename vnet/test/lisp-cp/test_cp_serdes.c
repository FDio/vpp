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
#include <vnet/lisp-cp/lisp_cp_messages.h>
#include <vnet/lisp-cp/control.h>
#include <vnet/lisp-cp/lisp_msg_serdes.h>
#include <vlibapi/api.h>
#include <vnet/lisp-cp/packets.h>

#define _assert(e)                    \
  error = CLIB_ERROR_ASSERT (e);      \
  if (error)                          \
    goto done;

static void print_chunk(u8 * b, int * offset, int c, char * des)
{
  int i, n = offset[0] + c;;
  for (i = offset[0]; i < n; i++)
  {
    printf("0x%02x, ", b[i]);
  }
  printf(" // %s\n", des);
  *offset += c;
}

void print_map_request(map_request_hdr_t * h)
{
#define pchunk(_count, _desc) \
  print_chunk((u8 *)h, &offset, _count, _desc)

  int offset = 0;

  pchunk(4, "data");
  pchunk(8, "Nonce");
  pchunk(2, "Source-EID-AFI");
  pchunk(4, "Source EID Address");
  pchunk(2, "ITR-RLOC-AFI 1");
  pchunk(4, "ITR-RLOC Address 1");
  pchunk(2, "ITR-RLOC-AFI 2");
  pchunk(16, "ITR-RLOC Address 2");
  pchunk(1, "REC: reserved");
  pchunk(1, "REC: EID mask-len");
  pchunk(2, "REC: EID-prefix-AFI");
  pchunk(4, "REC: EID-prefix");
  printf("\n");
}

static clib_error_t * test_lisp_msg_push_ecm ()
{
  vlib_main_t * vm = vlib_get_main ();
  clib_error_t * error = 0;
  gid_address_t la, ra;
  vlib_buffer_t * b = 0;
  u32 buff_len = 500;
  int lp = 0x15, rp = 0x14;

  b = clib_mem_alloc (buff_len);
  memset((u8 *)b, 0, buff_len);
  b->current_length = buff_len;
  b->current_data = sizeof(udp_header_t) + sizeof(ip4_header_t) +
    sizeof(ecm_hdr_t) + 1;

  la.type = IP_PREFIX;
  la.ippref.addr.ip.v4.as_u32 = 0xa1b2c3d4;
  la.ippref.addr.version = IP4;

  ra.type = IP_PREFIX;
  ra.ippref.addr.ip.v4.as_u32 = 0x90817263;
  ra.ippref.addr.version = IP4;

  ecm_hdr_t * lh = lisp_msg_push_ecm (vm, b, lp, rp, &la, &ra);

  u8 expected_ecm_hdr[] = {
    0x80, 0x00, 0x00, 0x00
  };
  _assert(0 == memcmp(expected_ecm_hdr, lh, sizeof(expected_ecm_hdr)));

  ip4_header_t * ih = (ip4_header_t *) (lh + 1);
  /* clear ip checksum */
  memset((u8 *)ih + 10, 0, 2);

  u8 expected_ip4_hdr[] = {
    0x45,                   /* version; IHL */
    0x00,                   /* services */
    0x02, 0x10,             /* total length */
    0x00, 0x00,             /* identification */
    0x40, 0x00,             /* flags; fragment offset*/
    0xff,                   /* TTL */
    0x11,                   /* protocol */
    0x00, 0x00,             /* header checksum */
    0xd4, 0xc3, 0xb2, 0xa1, /* src IP */
    0x63, 0x72, 0x81, 0x90, /* dst IP */
  };
  _assert(0 == memcmp(ih, expected_ip4_hdr, sizeof(expected_ip4_hdr)));

  udp_header_t * uh = (udp_header_t *) (ih + 1);
  /* clear udp checksum */
  memset((u8 *)uh + 6, 0, 2);

  u8 expected_udp_hdr[] = {
    0x00, 0x15, /* src port */
    0x00, 0x14, /* dst port */
    0x01, 0xfc, /* length */
    0x00, 0x00, /* checksum */
  };
  _assert(0 == memcmp(uh, expected_udp_hdr, sizeof(expected_udp_hdr)));

done:
  clib_mem_free (b);
  return error;
}

static clib_error_t * test_lisp_msg_parse_mapping_record ()
{
  clib_error_t * error = 0;
  locator_t probed;
  locator_t * locs = 0;
  vlib_buffer_t * b = 0;
  gid_address_t eid;
  u32 buff_len = 500;

  b = clib_mem_alloc (buff_len);
  memset((u8 *)b, 0, buff_len);

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
  b->current_length = buff_len;
  clib_memcpy(b->data, map_reply_records, sizeof(map_reply_records));

  lisp_msg_parse_mapping_record (b, &eid, &locs, &probed);
  _assert(vec_len (locs) == 1);
  _assert(eid.ippref.addr.ip.v4.as_u32 == 0x66554433);
  _assert(locs[0].local == 0);
  _assert(locs[0].address.ippref.addr.ip.v4.as_u32 == 0xddccbbaa);
  _assert(locs[0].address.type == IP_PREFIX);
  _assert(locs[0].priority == 0xa);
  _assert(locs[0].weight == 0xb);
  _assert(locs[0].mpriority == 0xc);
  _assert(locs[0].mweight == 0xd);

done:
  clib_mem_free (b);
  if (locs)
    vec_free (locs);
  return error;
}

static map_request_hdr_t *
build_map_request (lisp_cp_main_t * lcm, vlib_buffer_t * b)
{
  gid_address_t _seid, * seid = &_seid;
  gid_address_t _deid, * deid = &_deid;
  u8 is_smr_invoked = 1;
  u64 nonce = 0;
  map_request_hdr_t *h;
  ip_address_t * rlocs = 0;
  ip_address_t _addr, * addr = &_addr;

  gid_address_type(seid) = IP_PREFIX;
  gid_address_ip(seid).ip.v4.as_u32 = 0x12345678;
  seid->ippref.addr.version = IP4;

  gid_address_type(deid) = IP_PREFIX;
  gid_address_ip(deid).ip.v4.as_u32 = 0x9abcdef0;
  deid->ippref.addr.version = IP4;
  gid_address_ippref_len(deid) = 24;

  ip_addr_version(addr) = IP4;
  ip_addr_v4(addr).data_u32 = 0x10203040;
  vec_add1(rlocs, addr[0]);

  ip_addr_v6(addr).as_u32[0] = 0xffeeddcc;
  ip_addr_v6(addr).as_u32[1] = 0xbbaa9988;
  ip_addr_v6(addr).as_u32[2] = 0x77665544;
  ip_addr_v6(addr).as_u32[3] = 0x33221100;
  ip_addr_version(addr) = IP6;
  vec_add1(rlocs, addr[0]);

  h = lisp_msg_put_mreq (lcm, b, seid, deid, rlocs,
                     is_smr_invoked, &nonce);
  vec_free(rlocs);
  return h;
}

static clib_error_t * test_lisp_msg_parse ()
{
  gid_address_t eid;
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  map_request_hdr_t *h;
  gid_address_t gid;
  clib_error_t * error = 0;
  vlib_buffer_t * b;
  gid_address_t * rlocs = 0;

  u8 * data = clib_mem_alloc(500);
  memset(data, 0, 500);
  b = (vlib_buffer_t *) data;

  h = build_map_request (lcm, b);

  vlib_buffer_pull(b, sizeof(*h));
  u32 len = lisp_msg_parse_addr(b, &gid);
  _assert (len == 2 + 4
      /* Source-EID-AFI field lenght + IPv4 address length */);
  _assert (gid.ippref.addr.ip.v4.as_u32 == 0x12345678);
  _assert (gid.ippref.addr.version == IP4);

  u8 rloc_count = MREQ_ITR_RLOC_COUNT(h) + 1;
  lisp_msg_parse_itr_rlocs (b, &rlocs, rloc_count);

  _assert (vec_len (rlocs) == 2);
  _assert (rlocs[0].ippref.addr.ip.v4.as_u32 == 0x10203040);
  _assert (rlocs[0].ippref.addr.version == IP4);

  _assert (rlocs[1].ippref.addr.ip.v6.as_u32[0] == 0xffeeddcc);
  _assert (rlocs[1].ippref.addr.ip.v6.as_u32[1] == 0xbbaa9988);
  _assert (rlocs[1].ippref.addr.ip.v6.as_u32[2] == 0x77665544);
  _assert (rlocs[1].ippref.addr.ip.v6.as_u32[3] == 0x33221100);
  _assert (rlocs[1].ippref.addr.version == IP6);

  lisp_msg_parse_eid_rec (b, &eid);
  _assert (eid.ippref.addr.ip.v4.as_u32 == 0x9abcdef0);
  _assert (eid.ippref.addr.version == IP4);
  _assert (eid.ippref.len == 24);

done:
  clib_mem_free (data);
  if (rlocs)
    vec_free (rlocs);
  return error;
}

static clib_error_t * test_lisp_msg_put_mreq ()
{
  lisp_cp_main_t * lcm = vnet_lisp_cp_get_main();
  clib_error_t * error = 0;
  map_request_hdr_t *h;

  u8 * data = clib_mem_alloc(500);
  memset(data, 0, 500);

  h = build_map_request (lcm, (vlib_buffer_t *)data);

  /* clear Nonce to simplify comparison */
  memset((u8 *)h + 4, 0, 8);

  print_map_request(h);

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

  int r = memcmp(expected_data, (u8 *)h, sizeof(expected_data));
  error = CLIB_ERROR_ASSERT (r == 0);

  clib_mem_free(data);
  return error;
}

#define foreach_test_case                 \
  _(lisp_msg_put_mreq)                    \
  _(lisp_msg_push_ecm)                    \
  _(lisp_msg_parse)                       \
  _(lisp_msg_parse_mapping_record)

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
#undef _assert
