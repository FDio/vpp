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

void *lisp_msg_put_gid (vlib_buffer_t * b, gid_address_t * gid);

static void
lisp_msg_put_locators (vlib_buffer_t * b, locator_t * locators)
{
  locator_t *loc;

  vec_foreach (loc, locators)
  {
    u8 *p = vlib_buffer_put_uninit (b, sizeof (locator_hdr_t));
    memset (p, 0, sizeof (locator_hdr_t));
    LOC_PRIORITY (p) = loc->priority;
    LOC_MPRIORITY (p) = loc->mpriority;
    LOC_WEIGHT (p) = loc->weight;
    LOC_MWEIGHT (p) = loc->mweight;
    LOC_LOCAL (p) = loc->local;
    LOC_PROBED (p) = loc->probed ? 1 : 0;
    lisp_msg_put_gid (b, &loc->address);
  }
}

static void
lisp_msg_put_mapping_record (vlib_buffer_t * b, mapping_t * record)
{
  mapping_record_hdr_t *p =
    vlib_buffer_put_uninit (b, sizeof (mapping_record_hdr_t));
  gid_address_t *eid = &record->eid;

  memset (p, 0, sizeof (*p));
  MAP_REC_EID_PLEN (p) = gid_address_len (eid);
  MAP_REC_TTL (p) = clib_host_to_net_u32 (MAP_REGISTER_DEFAULT_TTL);
  MAP_REC_AUTH (p) = record->authoritative ? 1 : 0;
  MAP_REC_LOC_COUNT (p) = vec_len (record->locators);

  lisp_msg_put_gid (b, eid);
  lisp_msg_put_locators (b, record->locators);
}

static void
lisp_msg_put_mreg_records (vlib_buffer_t * b, mapping_t * records)
{
  u32 i;
  for (i = 0; i < vec_len (records); i++)
    lisp_msg_put_mapping_record (b, &records[i]);
}

void *
lisp_msg_put_gid (vlib_buffer_t * b, gid_address_t * gid)
{
  u8 *p = 0;
  if (!gid)
    {
      /* insert only src-eid-afi field set to 0 */
      p = vlib_buffer_put_uninit (b, sizeof (u16));
      *(u16 *) p = 0;
    }
  else
    {
      p = vlib_buffer_put_uninit (b, gid_address_size_to_put (gid));
      gid_address_put (p, gid);
    }
  return p;
}

static void *
lisp_msg_put_itr_rlocs (lisp_cp_main_t * lcm, vlib_buffer_t * b,
			gid_address_t * rlocs, u8 * locs_put)
{
  u8 *bp, count = 0;
  u32 i;

  bp = vlib_buffer_get_current (b);
  for (i = 0; i < vec_len (rlocs); i++)
    {
      lisp_msg_put_gid (b, &rlocs[i]);
      count++;
    }

  *locs_put = count - 1;
  return bp;
}

void *
lisp_msg_put_eid_rec (vlib_buffer_t * b, gid_address_t * eid)
{
  eid_record_hdr_t *h = vlib_buffer_put_uninit (b, sizeof (*h));

  memset (h, 0, sizeof (*h));
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
   * clock with the second clock in the upper 32-bits. */
  syscall (SYS_clock_gettime, CLOCK_REALTIME, &ts);
  nonce_lower = ts.tv_nsec;
  nonce_upper = ts.tv_sec ^ clib_host_to_net_u32 (nonce_lower);

  /* OR in a caller provided seed to the low-order 32-bits. */
  nonce_lower |= seed;

  /* Return 64-bit nonce. */
  nonce = nonce_upper;
  nonce = (nonce << 32) | nonce_lower;
  return nonce;
}

void *
lisp_msg_put_map_reply (vlib_buffer_t * b, mapping_t * records, u64 nonce,
			u8 probe_bit)
{
  map_reply_hdr_t *h = vlib_buffer_put_uninit (b, sizeof (h[0]));

  memset (h, 0, sizeof (h[0]));
  MREP_TYPE (h) = LISP_MAP_REPLY;
  MREP_NONCE (h) = nonce;
  MREP_REC_COUNT (h) = 1;
  MREP_RLOC_PROBE (h) = probe_bit;

  lisp_msg_put_mreg_records (b, records);
  return h;
}

void *
lisp_msg_put_map_register (vlib_buffer_t * b, mapping_t * records,
			   u8 want_map_notify, u16 auth_data_len, u64 * nonce,
			   u32 * msg_len)
{
  u8 *auth_data = 0;

  /* Basic header init */
  map_register_hdr_t *h = vlib_buffer_put_uninit (b, sizeof (h[0]));

  memset (h, 0, sizeof (h[0]));
  MREG_TYPE (h) = LISP_MAP_REGISTER;
  MREG_NONCE (h) = nonce_build (0);
  MREG_WANT_MAP_NOTIFY (h) = want_map_notify ? 1 : 0;
  MREG_REC_COUNT (h) = vec_len (records);

  auth_data = vlib_buffer_put_uninit (b, auth_data_len);
  memset (auth_data, 0, auth_data_len);

  /* Put map register records */
  lisp_msg_put_mreg_records (b, records);

  nonce[0] = MREG_NONCE (h);
  msg_len[0] = vlib_buffer_get_tail (b) - (u8 *) h;
  return h;
}

void *
lisp_msg_put_mreq (lisp_cp_main_t * lcm, vlib_buffer_t * b,
		   gid_address_t * seid, gid_address_t * deid,
		   gid_address_t * rlocs, u8 is_smr_invoked,
		   u8 rloc_probe_set, u64 * nonce)
{
  u8 loc_count = 0;

  /* Basic header init */
  map_request_hdr_t *h = vlib_buffer_put_uninit (b, sizeof (h[0]));

  memset (h, 0, sizeof (h[0]));
  MREQ_TYPE (h) = LISP_MAP_REQUEST;
  MREQ_NONCE (h) = nonce_build (0);
  MREQ_SMR_INVOKED (h) = is_smr_invoked ? 1 : 0;
  MREQ_RLOC_PROBE (h) = rloc_probe_set ? 1 : 0;

  /* We're adding one eid record */
  increment_record_count (h);

  /* Fill source eid */
  lisp_msg_put_gid (b, seid);

  /* Put itr rlocs */
  lisp_msg_put_itr_rlocs (lcm, b, rlocs, &loc_count);
  MREQ_ITR_RLOC_COUNT (h) = loc_count;

  /* Put eid record */
  lisp_msg_put_eid_rec (b, deid);

  nonce[0] = MREQ_NONCE (h);
  return h;
}

void *
lisp_msg_push_ecm (vlib_main_t * vm, vlib_buffer_t * b, int lp, int rp,
		   gid_address_t * la, gid_address_t * ra)
{
  ecm_hdr_t *h;
  ip_address_t _src_ip, *src_ip = &_src_ip, _dst_ip, *dst_ip = &_dst_ip;
  if (gid_address_type (la) != GID_ADDR_IP_PREFIX)
    {
      /* empty ip4 */
      memset (src_ip, 0, sizeof (src_ip[0]));
      memset (dst_ip, 0, sizeof (dst_ip[0]));
    }
  else
    {
      src_ip = &gid_address_ip (la);
      dst_ip = &gid_address_ip (ra);
    }

  /* Push inner ip and udp */
  pkt_push_udp_and_ip (vm, b, lp, rp, src_ip, dst_ip, 0);

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
      return (sizeof (map_request_hdr_t));
    case LISP_MAP_REPLY:
      return (sizeof (map_reply_hdr_t));
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
  u32 len;
  memset (eid, 0, sizeof (*eid));
  len = gid_address_parse (vlib_buffer_get_current (b), eid);
  if (len != ~0)
    vlib_buffer_pull (b, len);
  return len;
}

u32
lisp_msg_parse_eid_rec (vlib_buffer_t * b, gid_address_t * eid)
{
  eid_record_hdr_t *h = vlib_buffer_get_current (b);
  u32 len;
  memset (eid, 0, sizeof (*eid));
  len = gid_address_parse (EID_REC_ADDR (h), eid);
  if (len == ~0)
    return len;

  gid_address_ippref_len (eid) = EID_REC_MLEN (h);
  vlib_buffer_pull (b, len + sizeof (eid_record_hdr_t));

  return len + sizeof (eid_record_hdr_t);
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
      vec_add1 (*rlocs, tloc);
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

  if (!vlib_buffer_has_space (b, sizeof (len)))
    return ~0;
  vlib_buffer_pull (b, len);

  return len;
}

u32
lisp_msg_parse_mapping_record (vlib_buffer_t * b, gid_address_t * eid,
			       locator_t ** locs, locator_t * probed_)
{
  void *h = 0, *loc_hdr = 0;
  locator_t loc, *probed = 0;
  int i = 0, len = 0, llen = 0;

  h = vlib_buffer_get_current (b);
  if (!vlib_buffer_has_space (b, sizeof (mapping_record_hdr_t)))
    return ~0;

  vlib_buffer_pull (b, sizeof (mapping_record_hdr_t));

  memset (eid, 0, sizeof (*eid));
  len = gid_address_parse (vlib_buffer_get_current (b), eid);
  if (len == ~0)
    return len;

  if (!vlib_buffer_has_space (b, sizeof (len)))
    return ~0;

  vlib_buffer_pull (b, len);
  if (GID_ADDR_IP_PREFIX == gid_address_type (eid))
    gid_address_ippref_len (eid) = MAP_REC_EID_PLEN (h);

  for (i = 0; i < MAP_REC_LOC_COUNT (h); i++)
    {
      loc_hdr = vlib_buffer_get_current (b);

      llen = lisp_msg_parse_loc (b, &loc);
      if (llen == ~0)
	return llen;
      vec_add1 (*locs, loc);
      len += llen;

      if (LOC_PROBED (loc_hdr))
	{
	  if (probed != 0)
	    clib_warning
	      ("Multiple locators probed! Probing only the first!");
	  else
	    probed = &loc;
	}
    }
  /* XXX */
  if (probed_ != 0 && probed)
    *probed_ = *probed;

  return len + sizeof (map_reply_hdr_t);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
