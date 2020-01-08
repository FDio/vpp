/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __MATCH_ENGINE_HASH_DP_H__
#define __MATCH_ENGINE_HASH_DP_H__

#include <vnet/match/match_set.h>
#include <vnet/match/match_types_dp.h>
#include <vnet/match/engines/hash/match_hash.h>

typedef struct match_exact_l4_key_t_
{
  union
  {
    struct
    {
      u8 meki_type;
      u8 meki_code;
    } mek_icmp;
    u16 mek_port;
  };
  u8 mek_proto;
  u8 __mek_pad;
} match_exact_l4_key_t;

typedef struct match_exact_ip6_l4_key_t_
{
  ip6_address_t me6k_ip;
  match_exact_l4_key_t me6k_l4;
} __clib_packed match_exact_ip6_l4_key_t;

typedef struct match_exact_ip4_l4_key_t_
{
  union
  {
    struct
    {
      ip4_address_t me4k_ip;
      match_exact_l4_key_t me4k_l4;
    };
    u64 me4k_u64;
  };
} __clib_packed match_exact_ip4_l4_key_t;

STATIC_ASSERT_SIZEOF (match_exact_ip4_l4_key_t, sizeof (u64));

static_always_inline void
match_exact_l4_mk_key (match_orientation_t mo,
		       u8 proto, u8 * l, match_exact_l4_key_t * key)
{
  key->mek_proto = proto;
  key->__mek_pad = 0;

  if (PREDICT_TRUE ((IP_PROTOCOL_TCP == proto) || (IP_PROTOCOL_UDP == proto)))
    key->mek_port = udp_header_port (mo, (udp_header_t *) l);
  else if (IP_PROTOCOL_ICMP == proto || IP_PROTOCOL_ICMP6 == proto)
    {
      icmp46_header_t *i = (icmp46_header_t *) (l);
      key->mek_icmp.meki_type = i->type;
      key->mek_icmp.meki_code = i->code;
    }
}

static_always_inline void
match_exact_ip4_l4_mk_key (match_orientation_t mo,
			   const ip4_header_t * ip,
			   match_exact_ip4_l4_key_t * key)
{
  key->me4k_ip = *ip4_header_address (mo, ip);
  match_exact_l4_mk_key (mo, ip->protocol, (u8 *) (ip + 1), &key->me4k_l4);
}

static_always_inline void
match_exact_ip6_l4_mk_key (match_orientation_t mo,
			   const ip6_header_t * ip,
			   match_exact_ip6_l4_key_t * key)
{
  key->me6k_ip = *ip6_header_address (mo, ip);
  match_exact_l4_mk_key (mo, ip->protocol, (u8 *) (ip + 1), &key->me6k_l4);
}

static_always_inline bool
match_engine_hash_exact_ip6 (match_orientation_t mo,
			     const match_engine_hash_t * meh,
			     const ip6_header_t * ip, match_result_t * res)
{
  uword *p;

  p = hash_get_mem (meh->meh_hash, ip6_header_address (mo, ip));

  if (p)
    {
      *res = p[0];
      return (true);
    }
  return (false);
}

static_always_inline bool
match_engine_hash_exact_ip4 (match_orientation_t mo,
			     const match_engine_hash_t * meh,
			     const ip4_header_t * ip, match_result_t * res)
{
  uword *p;

  p = hash_get (meh->meh_hash, ip4_header_address (mo, ip));

  if (p)
    {
      *res = p[0];
      return (true);
    }
  return (false);
}

static_always_inline bool
match_engine_hash_exact_ip4_l4 (match_orientation_t mo,
				const match_engine_hash_t * meh,
				const ip4_header_t * ip, match_result_t * res)
{
  match_exact_ip4_l4_key_t key;
  uword *p;

  match_exact_ip4_l4_mk_key (mo, ip, &key);
  p = hash_get (meh->meh_hash, key.me4k_u64);

  if (p)
    {
      *res = p[0];
      return (true);
    }
  return (false);
}

static_always_inline bool
match_engine_hash_exact_ip6_l4 (match_orientation_t mo,
				const match_engine_hash_t * meh,
				const ip6_header_t * ip, match_result_t * res)
{
  match_exact_ip6_l4_key_t key;
  uword *p;

  match_exact_ip6_l4_mk_key (mo, ip, &key);
  p = hash_get_mem (meh->meh_hash, &key);

  if (p)
    {
      *res = p[0];
      return (true);
    }
  return (false);
}

static_always_inline bool
match_engine_hash_match (vlib_main_t * vm,
			 vlib_buffer_t * b,
			 i16 l2_offset,
			 i16 l3_offset,
			 const match_set_app_t * app,
			 f64 now,
			 match_result_t * res,
			 match_type_t mtype,
			 match_orientation_t mo, ethernet_type_t etype)
{
  const match_engine_hash_t *meh0;
  const ip4_header_t *ip40;
  const ip6_header_t *ip60;
  bool match0;

  /* get the table to search in */
  meh0 = pool_elt_at_index (match_engine_hash_pool, app->msa_index);

  ip40 = vlib_buffer_get_current (b) + l3_offset;
  ip60 = (ip6_header_t *) (ip40);
  match0 = false;

  /* match against each rule in turn */
  if (MATCH_TYPE_EXACT_IP == mtype)
    {
      if (ETHERNET_TYPE_IP4 == etype)
	match0 = match_engine_hash_exact_ip4 (mo, meh0, ip40, res);
      else if (ETHERNET_TYPE_IP6 == etype)
	match0 = match_engine_hash_exact_ip6 (mo, meh0, ip60, res);
      else
	match0 = false;
    }
  else if (MATCH_TYPE_EXACT_IP_L4 == mtype)
    {
      if (ETHERNET_TYPE_IP4 == etype)
	match0 = match_engine_hash_exact_ip4_l4 (mo, meh0, ip40, res);
      else if (ETHERNET_TYPE_IP6 == etype)
	match0 = match_engine_hash_exact_ip6_l4 (mo, meh0, ip60, res);
      else
	match0 = false;
    }

  return (match0);
}

/**
 * Data-plane function to go match
 */

static_always_inline bool
match_engine_hash_match_exact_ip_src_ip6 (vlib_main_t * vm,
					  vlib_buffer_t * buf,
					  i16 l2_offset,
					  i16 l3_offset,
					  const match_set_app_t * app,
					  f64 now, match_result_t * res)
{
  return (match_engine_hash_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP, MATCH_SRC, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_hash_match_exact_ip_src_ip4 (vlib_main_t * vm,
					  vlib_buffer_t * buf,
					  i16 l2_offset,
					  i16 l3_offset,
					  const match_set_app_t * app,
					  f64 now, match_result_t * res)
{
  return (match_engine_hash_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP, MATCH_SRC, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_hash_match_exact_ip_dst_ip6 (vlib_main_t * vm,
					  vlib_buffer_t * buf,
					  i16 l2_offset,
					  i16 l3_offset,
					  const match_set_app_t * app,
					  f64 now, match_result_t * res)
{
  return (match_engine_hash_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP, MATCH_DST, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_hash_match_exact_ip_dst_ip4 (vlib_main_t * vm,
					  vlib_buffer_t * buf,
					  i16 l2_offset,
					  i16 l3_offset,
					  const match_set_app_t * app,
					  f64 now, match_result_t * res)
{
  return (match_engine_hash_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP, MATCH_DST, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_hash_match_exact_ip_l4_src_ip6 (vlib_main_t * vm,
					     vlib_buffer_t * buf,
					     i16 l2_offset,
					     i16 l3_offset,
					     const match_set_app_t * app,
					     f64 now, match_result_t * res)
{
  return (match_engine_hash_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP_L4, MATCH_SRC, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_hash_match_exact_ip_l4_src_ip4 (vlib_main_t * vm,
					     vlib_buffer_t * buf,
					     i16 l2_offset,
					     i16 l3_offset,
					     const match_set_app_t * app,
					     f64 now, match_result_t * res)
{
  return (match_engine_hash_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP_L4, MATCH_SRC, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_hash_match_exact_ip_l4_dst_ip6 (vlib_main_t * vm,
					     vlib_buffer_t * buf,
					     i16 l2_offset,
					     i16 l3_offset,
					     const match_set_app_t * app,
					     f64 now, match_result_t * res)
{
  return (match_engine_hash_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP_L4, MATCH_DST, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_hash_match_exact_ip_l4_dst_ip4 (vlib_main_t * vm,
					     vlib_buffer_t * buf,
					     i16 l2_offset,
					     i16 l3_offset,
					     const match_set_app_t * app,
					     f64 now, match_result_t * res)
{
  return (match_engine_hash_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP_L4, MATCH_DST, ETHERNET_TYPE_IP4));
}


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
