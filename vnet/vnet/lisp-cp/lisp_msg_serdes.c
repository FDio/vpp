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

#include <vnet/lisp-cp/lisp_msg_serdes.h>
#include <vnet/lisp-cp/packets.h>
#include <vppinfra/time.h>

void *
lisp_msg_put_gid (vlib_buffer_t * b, gid_address_t * gid)
{
  u8 * p = vlib_buffer_put_uninit (b, gid_address_size_to_put (gid));
  gid_address_put (p, gid);
  return p;
}

void *
lisp_msg_put_itr_rlocs (lisp_cp_main_t * lcm, vlib_buffer_t * b,
			ip_address_t * rlocs, u8 * locs_put)
{
  u8 * p, * bp, count = 0;
  u32 i;
  ip_address_t * addr;

  bp = vlib_buffer_get_current(b);
  for (i = 0; i < vec_len(rlocs); i++)
  {
    addr = &rlocs[i];
    switch (ip_addr_version(addr))
    {
    case IP4:
      p = vlib_buffer_put_uninit (b, ip4_address_size_to_put());
      ip4_address_put (p, &ip_addr_v4(addr));
      count++;
      break;
    case IP6:
      p = vlib_buffer_put_uninit (b, ip6_address_size_to_put());
      ip6_address_put (p, &ip_addr_v6(addr));
      count++;
      break;
    }
  }

  *locs_put = count-1;
  return bp;
}

void *
lisp_msg_put_eid_rec (vlib_buffer_t * b, gid_address_t * eid)
{
  eid_record_hdr_t * h = vlib_buffer_put_uninit (b, sizeof (*h));

  memset(h, 0, sizeof (*h));
  EID_REC_MLEN (h) = gid_address_len (eid);
  lisp_msg_put_gid (b, eid);
  return h;
}

u64
nonce_build (u32 seed)
{
  u64 nonce;
  u32 nonce_lower;
  u32 nonce_upper;
  struct timespec ts;

  /* Put nanosecond clock in lower 32-bits and put an XOR of the nanosecond
   * clock with the seond clock in the upper 32-bits. */
  syscall (SYS_clock_gettime, CLOCK_REALTIME, &ts);
  nonce_lower = ts.tv_nsec;
  nonce_upper = ts.tv_sec ^ clib_host_to_net_u32(nonce_lower);

  /* OR in a caller provided seed to the low-order 32-bits. */
  nonce_lower |= seed;

  /* Return 64-bit nonce. */
  nonce = nonce_upper;
  nonce = (nonce << 32) | nonce_lower;
  return nonce;
}

void *
lisp_msg_put_mreq (lisp_cp_main_t * lcm, vlib_buffer_t * b,
		   gid_address_t * seid, gid_address_t * deid,
		   ip_address_t * rlocs, u8 is_smr_invoked, u64 * nonce)
{
  u8 loc_count = 0;

  /* Basic header init */
  map_request_hdr_t * h = vlib_buffer_put_uninit (b, sizeof(h[0]));

  memset(h, 0, sizeof(h[0]));
  MREQ_TYPE(h) = LISP_MAP_REQUEST;
  MREQ_NONCE(h) = nonce_build(0);
  MREQ_SMR_INVOKED(h) = is_smr_invoked ? 1 : 0;

  /* We're adding one eid record */
  increment_record_count (h);

  /* Fill source eid */
  lisp_msg_put_gid (b, seid);

  /* Put itr rlocs */
  lisp_msg_put_itr_rlocs(lcm, b, rlocs, &loc_count);
  MREQ_ITR_RLOC_COUNT(h) = loc_count;

  /* Put eid record */
  lisp_msg_put_eid_rec(b, deid);

  nonce[0] = MREQ_NONCE(h);
  return h;
}

void *
lisp_msg_push_ecm (vlib_main_t * vm, vlib_buffer_t *b, int lp, int rp,
                   gid_address_t *la, gid_address_t *ra)
{
  ecm_hdr_t *h;
  ASSERT(gid_address_type(la) == IP_PREFIX);

  /* Push inner ip and udp */
  pkt_push_udp_and_ip (vm, b, lp, rp, &gid_address_ip(la),
                              &gid_address_ip(ra));

  /* Push lisp ecm hdr */
  h = pkt_push_ecm_hdr (b);

  return h;
}

static u32
msg_type_to_hdr_len (lisp_msg_type_e type)
{
  switch (type)
    {
    case LISP_MAP_REQUEST:
      return (sizeof(map_request_hdr_t));
    case LISP_MAP_REPLY:
      return (sizeof(map_reply_hdr_t));
    default:
      return (0);
    }
}

void *
lisp_msg_pull_hdr (vlib_buffer_t * b, lisp_msg_type_e type)
{
  return vlib_buffer_pull (b, msg_type_to_hdr_len (type));
}

u32
lisp_msg_parse_addr (vlib_buffer_t * b, gid_address_t * eid)
{
  u32 len = gid_address_parse (vlib_buffer_get_current (b), eid);
  if (len != ~0)
    vlib_buffer_pull (b, len);
  return len;
}

u32
lisp_msg_parse_eid_rec (vlib_buffer_t * b, gid_address_t * eid)
{
  eid_record_hdr_t * h = vlib_buffer_get_current (b);
  u32 len = gid_address_parse (EID_REC_ADDR(h), eid);
  if (len == ~0)
    return len;

  gid_address_ippref_len(eid) = EID_REC_MLEN(h);
  vlib_buffer_pull (b, len + sizeof(eid_record_hdr_t));

  return len + sizeof(eid_record_hdr_t);
}

u32
lisp_msg_parse_itr_rlocs (vlib_buffer_t * b, gid_address_t ** rlocs,
                          u8 rloc_count)
{
  gid_address_t tloc;
  u32 i, len = 0, tlen = 0;

  //MREQ_ITR_RLOC_COUNT(mreq_hdr) + 1
  for (i = 0; i < rloc_count; i++)
    {
      len = lisp_msg_parse_addr (b, &tloc);
      if (len == ~0)
        return len;
      vec_add1(*rlocs, tloc);
      tlen += len;
    }
  return tlen;
}

u32
lisp_msg_parse_loc (vlib_buffer_t * b, locator_t * loc)
{
  int len;

  len = locator_parse (vlib_buffer_get_current (b), loc);
  if (len == ~0)
      return ~0;

  vlib_buffer_pull (b, len);

  return len;
}

u32
lisp_msg_parse_mapping_record (vlib_buffer_t * b, gid_address_t * eid,
                               locator_t ** locs, locator_t * probed_)
{
  void * h = 0, * loc_hdr = 0;
  locator_t loc, * probed = 0;
  int i = 0, len = 0, llen = 0;

  h = vlib_buffer_get_current (b);
  vlib_buffer_pull (b, sizeof(mapping_record_hdr_t));

  len = gid_address_parse (vlib_buffer_get_current (b), eid);
  if (len == ~0)
    return len;

  vlib_buffer_pull (b, len);
  gid_address_ippref_len(eid) = MAP_REC_EID_PLEN(h);

  for (i = 0; i < MAP_REC_LOC_COUNT(h); i++)
    {
      loc_hdr = vlib_buffer_get_current (b);

      llen = lisp_msg_parse_loc (b, &loc);
      if (llen == ~0)
        return llen;
      vec_add1(*locs, loc);
      len += llen;

      if (LOC_PROBED(loc_hdr))
        {
          if (probed != 0)
            clib_warning("Multiple locators probed! Probing only the first!");
          else
            probed = &loc;
        }
    }
  /* XXX */
  if (probed_ != 0 && probed)
    *probed_ = *probed;

  return len + sizeof(map_reply_hdr_t);
}
