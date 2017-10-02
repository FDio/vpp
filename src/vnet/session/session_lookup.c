/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

/** Generate typed init functions for multiple hash table styles... */
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.h>

#include <vppinfra/bihash_template.c>

#undef __included_bihash_template_h__

#include <vppinfra/bihash_48_8.h>
#include <vppinfra/bihash_template.h>

#include <vppinfra/bihash_template.c>
#include <vnet/session/session_lookup.h>
#include <vnet/session/session.h>

/**
 * External vector of per transport virtual functions table
 */
extern transport_proto_vft_t *tp_vfts;

/**
 * Pool of lookup tables
 */
static session_lookup_table_t *lookup_tables;

/**
 * Network namespace (e.g., fib index) to session lookup table. We should
 * have one per network protocol type but for now we only support IP
 */
static u32 *nns_index_to_table_index;

/* *INDENT-OFF* */
/* 16 octets */
typedef CLIB_PACKED (struct {
  union
    {
      struct
	{
	  ip4_address_t src;
	  ip4_address_t dst;
	  u16 src_port;
	  u16 dst_port;
	  /* align by making this 4 octets even though its a 1-bit field
	   * NOTE: avoid key overlap with other transports that use 5 tuples for
	   * session identification.
	   */
	  u32 proto;
	};
      u64 as_u64[2];
    };
}) v4_connection_key_t;

typedef CLIB_PACKED (struct {
  union
    {
      struct
	{
	  /* 48 octets */
	  ip6_address_t src;
	  ip6_address_t dst;
	  u16 src_port;
	  u16 dst_port;
	  u32 proto;
	  u64 unused;
	};
      u64 as_u64[6];
    };
}) v6_connection_key_t;
/* *INDENT-ON* */

typedef clib_bihash_kv_16_8_t session_kv4_t;
typedef clib_bihash_kv_48_8_t session_kv6_t;

always_inline void
make_v4_ss_kv (session_kv4_t * kv, ip4_address_t * lcl, ip4_address_t * rmt,
	       u16 lcl_port, u16 rmt_port, u8 proto)
{
  v4_connection_key_t *key = (v4_connection_key_t *) kv->key;

  key->src.as_u32 = lcl->as_u32;
  key->dst.as_u32 = rmt->as_u32;
  key->src_port = lcl_port;
  key->dst_port = rmt_port;
  key->proto = proto;

  kv->value = ~0ULL;
}

always_inline void
make_v4_listener_kv (session_kv4_t * kv, ip4_address_t * lcl, u16 lcl_port,
		     u8 proto)
{
  v4_connection_key_t *key = (v4_connection_key_t *) kv->key;

  key->src.as_u32 = lcl->as_u32;
  key->dst.as_u32 = 0;
  key->src_port = lcl_port;
  key->dst_port = 0;
  key->proto = proto;

  kv->value = ~0ULL;
}

always_inline void
make_v4_ss_kv_from_tc (session_kv4_t * kv, transport_connection_t * t)
{
  make_v4_ss_kv (kv, &t->lcl_ip.ip4, &t->rmt_ip.ip4, t->lcl_port, t->rmt_port,
		 session_type_from_proto_and_ip (t->transport_proto, 1));
}

always_inline void
make_v6_ss_kv (session_kv6_t * kv, ip6_address_t * lcl, ip6_address_t * rmt,
	       u16 lcl_port, u16 rmt_port, u8 proto)
{
  v6_connection_key_t *key = (v6_connection_key_t *) kv->key;

  key->src.as_u64[0] = lcl->as_u64[0];
  key->src.as_u64[1] = lcl->as_u64[1];
  key->dst.as_u64[0] = rmt->as_u64[0];
  key->dst.as_u64[1] = rmt->as_u64[1];
  key->src_port = lcl_port;
  key->dst_port = rmt_port;
  key->proto = proto;
  key->unused = 0;

  kv->value = ~0ULL;
}

always_inline void
make_v6_listener_kv (session_kv6_t * kv, ip6_address_t * lcl, u16 lcl_port,
		     u8 proto)
{
  v6_connection_key_t *key = (v6_connection_key_t *) kv->key;

  key->src.as_u64[0] = lcl->as_u64[0];
  key->src.as_u64[1] = lcl->as_u64[1];
  key->dst.as_u64[0] = 0;
  key->dst.as_u64[1] = 0;
  key->src_port = lcl_port;
  key->dst_port = 0;
  key->proto = proto;
  key->unused = 0;

  kv->value = ~0ULL;
}

always_inline void
make_v6_ss_kv_from_tc (session_kv6_t * kv, transport_connection_t * t)
{
  make_v6_ss_kv (kv, &t->lcl_ip.ip6, &t->rmt_ip.ip6, t->lcl_port, t->rmt_port,
		 session_type_from_proto_and_ip (t->transport_proto, 0));
}

static session_lookup_table_t *
session_table_get_or_alloc_for_connection (transport_connection_t *tc)
{
  session_lookup_table_t *slt;
  u32 table_index;
  if (vec_len (nns_index_to_table_index) <= tc->fib_index)
    {
      slt = session_table_alloc ();
      table_index = session_table_index (slt);
      vec_validate (nns_index_to_table_index, tc->fib_index);
      nns_index_to_table_index[tc->fib_index] = table_index;
      return slt;
    }
  else
    {
      table_index = nns_index_to_table_index[tc->fib_index];
      return &lookup_tables[table_index];
    }
}

static session_lookup_table_t *
session_table_get_for_connection (transport_connection_t *tc)
{
  if (vec_len (nns_index_to_table_index) <= tc->fib_index)
    return 0;
  return session_table_get (nns_index_to_table_index[tc->fib_index]);
}

static session_lookup_table_t *
session_table_get_for_fib_index (u32 fib_index)
{
  if (vec_len (nns_index_to_table_index) <= fib_index)
    return 0;
  return session_table_get (nns_index_to_table_index[fib_index]);
}

u32
session_table_get_index_for_nns (u32 nns_index)
{
  if (vec_len (nns_index_to_table_index) <= nns_index)
    return SESSION_TABLE_INVALID_INDEX;
  return nns_index_to_table_index[nns_index];
}

/**
 * Add transport connection to a session table
 *
 * Session lookup 5-tuple (src-ip, dst-ip, src-port, dst-port, session-type)
 * is added to requested session table.
 *
 * @param tc 		transport connection to be added
 * @param value	 	value to be stored
 *
 * @return non-zero if failure
 */
int
session_table_add_connection (transport_connection_t * tc,
                              u64 value)
{
  session_lookup_table_t *slt;
  session_kv4_t kv4;
  session_kv6_t kv6;

  slt = session_table_get_or_alloc_for_connection (tc);
  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      kv4.value = value;
      return clib_bihash_add_del_16_8 (slt->v4_session_hash, &kv4, 1 /* is_add */);
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      kv6.value = value;
      return clib_bihash_add_del_48_8 (slt->v6_session_hash, &kv6, 1 /* is_add */);
    }
}

int
session_table_add_session_endpoint (u32 table_index, session_endpoint_t *sep,
                                    u64 value)
{
  session_lookup_table_t *slt;
  session_kv4_t kv4;
  session_kv6_t kv6;

  slt = session_table_get (table_index);
  if (sep->is_ip4)
    {
      make_v4_listener_kv (&kv4, &sep->ip.ip4, sep->port, sep->transport_proto);
      kv4.value = value;
      return clib_bihash_add_del_16_8 (&slt->v4_session_hash, &kv4);
    }
  else
    {
      make_v6_listener_kv (&kv6, &sep->ip.ip6, sep->port, sep->transport_proto);
      kv6.value = value;
      return clib_bihash_add_del_48_8 (&slt->v6_session_hash, &kv6);
    }
}

/**
 * Delete transport connection from session table
 *
 * @param table_index	session table index
 * @param tc		transport connection to be removed
 *
 * @return non-zero if failure
 */
int
session_table_del_connection (transport_connection_t * tc)
{
  session_lookup_table_t *slt;
  session_kv4_t kv4;
  session_kv6_t kv6;

  slt = session_table_get_for_connection (tc);
  if (!slt)
    return -1;
  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      return clib_bihash_add_del_16_8 (&slt->v4_session_hash, &kv4, 0 /* is_add */);
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      return clib_bihash_add_del_48_8 (&slt->v6_session_hash, &kv6, 0 /* is_add */);
    }
}

int
session_table_del_session (stream_session_t * s)
{
  transport_connection_t *ts;
  ts = tp_vfts[s->session_type].get_connection (s->connection_index,
						s->thread_index);
  return session_table_del_connection (ts);
}

int
session_table_add_half_open (transport_connection_t * tc, u64 value)
{
  session_lookup_table_t *slt;
  session_kv4_t kv4;
  session_kv6_t kv6;

  slt = session_table_get_or_alloc_for_connection (tc);
  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      kv4.value = value;
      return clib_bihash_add_del_16_8 (&slt->v4_half_open_hash, &kv4,
				       1 /* is_add */ );
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      kv6.value = value;
      return clib_bihash_add_del_48_8 (&slt->v6_half_open_hash, &kv6,
				       1 /* is_add */ );
    }
}

int
session_table_del_half_open (transport_connection_t * tc)
{
  session_lookup_table_t *slt;
  session_kv4_t kv4;
  session_kv6_t kv6;

  slt = session_table_get_for_connection (tc);
  if (!slt)
    return -1;
  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      return clib_bihash_add_del_16_8 (&slt->v4_half_open_hash, &kv4,
				0 /* is_add */ );
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      return clib_bihash_add_del_48_8 (&slt->v6_half_open_hash, &kv6,
				0 /* is_add */ );
    }
}

u32
session_lookup_session_endpoint (u32 table_index, session_endpoint_t *sep)
{
  session_lookup_table_t *slt;
  session_kv4_t kv4;
  session_kv6_t kv6;
  int rv;

  slt = session_table_get (table_index);
  if (sep->is_ip4)
    {
      make_v4_listener_kv (&kv4, &sep->ip.ip4, sep->port, sep->transport_proto);
      rv = clib_bihash_search_inline_16_8 (&slt->v4_session_hash, &kv4);
      if (rv == 0)
	return (u32) kv4.value;
    }
  else
    {
      make_v6_listener_kv (&kv6, &sep->ip.ip6, sep->port, sep->transport_proto);
      rv = clib_bihash_search_inline_48_8 (&slt->v6_session_hash, &kv6);
      if (rv == 0)
	return (u32) kv6.value;
    }
  return SESSION_INVALID_INDEX;
}

static stream_session_t *
session_lookup_listener4_i (session_lookup_table_t *slt, ip4_address_t * lcl,
                            u16 lcl_port, u8 proto)
{
  session_kv4_t kv4;
  int rv;

  make_v4_listener_kv (&kv4, lcl, lcl_port, proto);
  rv = clib_bihash_search_inline_16_8 (&slt->v4_session_hash, &kv4);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv4.value);

  /* Zero out the lcl ip */
  kv4.key[0] = 0;
  rv = clib_bihash_search_inline_16_8 (&slt->v4_session_hash, &kv4);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv4.value);

  return 0;
}

stream_session_t *
session_lookup_listener4 (u32 fib_index, ip4_address_t * lcl, u16 lcl_port,
                          u8 proto)
{
  session_lookup_table_t *slt;
  slt = session_table_get_for_fib_index (fib_index);
  if (!slt)
    return 0;
  return session_lookup_listener4_i (slt, lcl, lcl_port, proto);
}

static stream_session_t *
session_lookup_listener6_i (session_lookup_table_t *slt, ip6_address_t * lcl,
                            u16 lcl_port, u8 proto)
{
  session_kv6_t kv6;
  int rv;

  make_v6_listener_kv (&kv6, lcl, lcl_port, proto);
  rv = clib_bihash_search_inline_48_8 (&slt->v6_session_hash, &kv6);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv6.value);

  /* Zero out the lcl ip */
  kv6.key[0] = kv6.key[1] = 0;
  rv = clib_bihash_search_inline_48_8 (&slt->v6_session_hash, &kv6);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv6.value);

  return 0;
}

stream_session_t *
session_lookup_listener6 (u32 fib_index, ip6_address_t * lcl, u16 lcl_port,
                          u8 proto)
{
  session_lookup_table_t *slt;
  slt = session_table_get_for_fib_index (fib_index);
  if (!slt)
    return 0;
  return session_lookup_listener6_i (slt, lcl, lcl_port, proto);
}

stream_session_t *
session_lookup_listener (u32 table_index, session_endpoint_t *sep)
{
  session_lookup_table_t *slt;
  slt = session_table_get (table_index);
  if (sep->is_ip4)
      return session_lookup_listener4_i (slt, &sep->ip->ip4, sep->port,
                                         sep->transport_proto);
  else
      return session_lookup_listener6_i (slt, &sep->ip->ip6, sep->port,
                                         sep->transport_proto);
  return 0;
}

u64
session_lookup_half_open_handle (transport_connection_t *tc)
{
  session_lookup_table_t *slt;
  session_kv4_t kv4;
  session_kv6_t kv6;
  int rv;

  slt = session_table_get_for_fib_index (tc->fib_index);
  if (tc->is_ip4)
    {
      make_v4_ss_kv (&kv4, &tc->lcl_ip->ip4, &tc->rmt_ip->ip4, tc->lcl_port,
                     tc->rmt_port, tc->transport_proto);
      rv = clib_bihash_search_inline_16_8 (&slt->v4_half_open_hash, &kv4);
      if (rv == 0)
	return kv4.value;
    }
  else
    {
      make_v6_ss_kv (&kv6, &tc->lcl_ip->ip6, &tc->rmt_ip->ip6, tc->lcl_port,
                     tc->rmt_port, tc->transport_proto);
      rv = clib_bihash_search_inline_48_8 (&slt->v6_half_open_hash, &kv6);
      if (rv == 0)
	return kv6.value;
    }
  return HALF_OPEN_LOOKUP_INVALID_VALUE;
}

transport_connection_t *
session_half_open_lookup_connection (transport_connection_t *tc)
{
  u64 handle;
  u32 sst;

  handle = session_half_open_lookup_handle_i (tc);
  if (handle != HALF_OPEN_LOOKUP_INVALID_VALUE)
    {
      sst = session_type_from_proto_and_ip(tc->transport_proto, tc->is_ip4);
      return tp_vfts[sst].get_half_open (handle & 0xFFFFFFFF);
    }
  return 0;
}

/**
 * Lookup connection with ip4 and transport layer information
 *
 * This is used on the fast path so it needs to be fast. Thereby,
 * duplication of code and 'hacks' allowed.
 *
 * The lookup is incremental and returns whenever something is matched. The
 * steps are:
 * - Try to find an established session
 * - Try to find a fully-formed or local source wildcarded (listener bound to
 *   all interfaces) listener session
 * - Try to find a half-open connection
 * - return 0
 *
 * @param fib_index	index of fib wherein the connection was received
 * @param lcl		local ip4 address
 * @param rmt		remote ip4 address
 * @param lcl_port	local port
 * @param rmt_port	remote port
 * @param proto		transport protocol (e.g., tcp, udp)
 * @param thread_index	thread index for request
 *
 * @return pointer to transport connection, if one is found, 0 otherwise
 */
transport_connection_t *
session_lookup_connection_wt4 (u32 fib_index, ip4_address_t * lcl,
                               ip4_address_t * rmt, u16 lcl_port, u16 rmt_port,
                               u8 proto, u32 thread_index)
{
  session_lookup_table_t *slt;
  session_kv4_t kv4;
  stream_session_t *s;
  int rv;

  slt = session_table_get_for_fib_index (fib_index);
  if (PREDICT_FALSE (!slt))
    return 0;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&slt->v4_session_hash, &kv4);
  if (rv == 0)
    {
      ASSERT ((u32) (kv4.value >> 32) == thread_index);
      s = session_get (kv4.value & 0xFFFFFFFFULL, thread_index);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = session_lookup_listener4_i (slt, lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_16_8 (&slt->v4_half_open_hash, &kv4);
  if (rv == 0)
    {
      u32 sst = session_type_from_proto_and_ip(proto, 1);
      return tp_vfts[sst].get_half_open (kv4.value & 0xFFFFFFFF);
    }
  return 0;
}

/**
 * Lookup connection with ip4 and transport layer information
 *
 * Not optimized. This is used on the fast path so it needs to be fast.
 * Thereby, duplication of code and 'hacks' allowed. Lookup logic is identical
 * to that of @ref session_lookup_connection_wt4
 *
 * @param fib_index	index of the fib wherein the connection was received
 * @param lcl		local ip4 address
 * @param rmt		remote ip4 address
 * @param lcl_port	local port
 * @param rmt_port	remote port
 * @param proto		transport protocol (e.g., tcp, udp)
 *
 * @return pointer to transport connection, if one is found, 0 otherwise
 */
transport_connection_t *
session_lookup_connection4 (u32 fib_index, ip4_address_t * lcl,
                            ip4_address_t * rmt, u16 lcl_port, u16 rmt_port,
                            u8 proto)
{
  session_lookup_table_t *slt;
  session_kv4_t kv4;
  stream_session_t *s;
  int rv;

  slt = session_table_get_for_fib_index (fib_index);
  if (PREDICT_FALSE (!slt))
    return 0;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&slt->v4_session_hash, &kv4);
  if (rv == 0)
    {
      s = session_get_from_handle (kv4.value);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      s->thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = session_lookup_listener4_i (slt, lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_16_8 (&slt->v4_half_open_hash, &kv4);
  if (rv == 0)
    {
      u32 sst = session_type_from_proto_and_ip(proto, 1);
      return tp_vfts[proto].get_half_open (kv4.value & 0xFFFFFFFF);
    }
  return 0;
}

/**
 * Lookup session with ip4 and transport layer information
 *
 * Lookup logic is identical to that of @ref session_lookup_connection_wt4 but
 * this returns a session as opposed to a transport connection;
 */
stream_session_t *
session_lookup4 (u32 fib_index, ip4_address_t * lcl, ip4_address_t * rmt,
                 u16 lcl_port, u16 rmt_port, u8 proto)
{
  session_lookup_table_t *slt;
  session_kv4_t kv4;
  stream_session_t *s;
  int rv;

  slt = session_table_get_for_fib_index (fib_index);
  if (PREDICT_FALSE (!slt))
    return 0;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&slt->v4_session_hash, &kv4);
  if (rv == 0)
    return session_get_from_handle (kv4.value);

  /* If nothing is found, check if any listener is available */
  if ((s = session_lookup_listener4_i (slt, lcl, lcl_port, proto)))
    return s;

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_16_8 (&slt->v4_half_open_hash, &kv4);
  if (rv == 0)
    return session_get_from_handle (kv4.value);
  return 0;
}

/**
 * Lookup connection with ip6 and transport layer information
 *
 * This is used on the fast path so it needs to be fast. Thereby,
 * duplication of code and 'hacks' allowed.
 *
 * The lookup is incremental and returns whenever something is matched. The
 * steps are:
 * - Try to find an established session
 * - Try to find a fully-formed or local source wildcarded (listener bound to
 *   all interfaces) listener session
 * - Try to find a half-open connection
 * - return 0
 *
 * @param fib_index	index of the fib wherein the connection was received
 * @param lcl		local ip6 address
 * @param rmt		remote ip6 address
 * @param lcl_port	local port
 * @param rmt_port	remote port
 * @param proto		transport protocol (e.g., tcp, udp)
 * @param thread_index	thread index for request
 *
 * @return pointer to transport connection, if one is found, 0 otherwise
 */
transport_connection_t *
session_lookup_connection_wt6 (u32 fib_index, ip6_address_t * lcl,
                               ip6_address_t * rmt, u16 lcl_port, u16 rmt_port,
                               u8 proto, u32 thread_index)
{
  session_lookup_table_t *slt;
  stream_session_t *s;
  session_kv6_t kv6;
  int rv;

  slt = session_table_get_for_fib_index (fib_index);
  if (PREDICT_FALSE (!slt))
    return 0;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&slt->v6_session_hash, &kv6);
  if (rv == 0)
    {
      ASSERT ((u32) (kv6.value >> 32) == thread_index);
      s = session_get (kv6.value & 0xFFFFFFFFULL, thread_index);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = session_lookup_listener6_i (slt, lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_48_8 (&slt->v6_half_open_hash, &kv6);
  if (rv == 0)
    {
      u32 sst = session_type_from_proto_and_ip(proto, 1);
      return tp_vfts[sst].get_half_open (kv6.value & 0xFFFFFFFF);
    }

  return 0;
}

/**
 * Lookup connection with ip6 and transport layer information
 *
 * Not optimized. This is used on the fast path so it needs to be fast.
 * Thereby, duplication of code and 'hacks' allowed. Lookup logic is identical
 * to that of @ref session_lookup_connection_wt4
 *
 * @param fib_index	index of the fib wherein the connection was received
 * @param lcl		local ip6 address
 * @param rmt		remote ip6 address
 * @param lcl_port	local port
 * @param rmt_port	remote port
 * @param proto		transport protocol (e.g., tcp, udp)
 *
 * @return pointer to transport connection, if one is found, 0 otherwise
 */
transport_connection_t *
session_lookup_connection6 (u32 fib_index, ip6_address_t * lcl,
                            ip6_address_t * rmt, u16 lcl_port, u16 rmt_port,
                            u8 proto)
{
  session_lookup_table_t *slt;
  stream_session_t *s;
  session_kv6_t kv6;
  int rv;

  slt = session_table_get_for_fib_index (fib_index);
  if (PREDICT_FALSE (!slt))
    return 0;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&slt->v6_session_hash, &kv6);
  if (rv == 0)
    {
      s = session_get_from_handle (kv6.value);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      s->thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = session_lookup_listener6 (lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_48_8 (&slt->v6_half_open_hash, &kv6);
  if (rv == 0)
    return tp_vfts[proto].get_half_open (kv6.value & 0xFFFFFFFF);

  return 0;
}

/**
 * Lookup session with ip6 and transport layer information
 *
 * Lookup logic is identical to that of @ref session_lookup_connection_wt6 but
 * this returns a session as opposed to a transport connection;
 */
stream_session_t *
session_lookup6 (u32 fib_index, ip6_address_t * lcl, ip6_address_t * rmt,
                 u16 lcl_port, u16 rmt_port, u8 proto)
{
  session_lookup_table_t *slt;
  session_kv6_t kv6;
  stream_session_t *s;
  int rv;

  slt = session_table_get_for_fib_index (fib_index);
  if (PREDICT_FALSE (!slt))
    return 0;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&slt->v6_session_hash, &kv6);
  if (rv == 0)
    return session_get_from_handle (kv6.value);

  /* If nothing is found, check if any listener is available */
  if ((s = session_lookup_listener6_i (slt, lcl, lcl_port, proto)))
    return s;

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_48_8 (&slt->v6_half_open_hash, &kv6);
  if (rv == 0)
    return session_get_from_handle (kv6.value);
  return 0;
}

#define foreach_hash_table_parameter            \
  _(v4,session,buckets,20000)                   \
  _(v4,session,memory,(64<<20))                 \
  _(v6,session,buckets,20000)                   \
  _(v6,session,memory,(64<<20))                 \
  _(v4,halfopen,buckets,20000)                  \
  _(v4,halfopen,memory,(64<<20))                \
  _(v6,halfopen,buckets,20000)                  \
  _(v6,halfopen,memory,(64<<20))

void
session_table_init (session_lookup_table_t *slt)
{
#define _(af,table,parm,value) 						\
  u32 configured_##af##_##table##_table_##parm = value;
  foreach_hash_table_parameter;
#undef _

#define _(af,table,parm,value)                                          \
  if (session_manager_main.configured_##af##_##table##_table_##parm)    \
    configured_##af##_##table##_table_##parm =                          \
      session_manager_main.configured_##af##_##table##_table_##parm;
  foreach_hash_table_parameter;
#undef _

  clib_bihash_init_16_8 (&slt->v4_session_hash, "v4 session table",
	                 configured_v4_session_table_buckets,
	                 configured_v4_session_table_memory);
  clib_bihash_init_48_8 (&slt->v6_session_hash, "v6 session table",
	                 configured_v6_session_table_buckets,
	                 configured_v6_session_table_memory);
  clib_bihash_init_16_8 (&slt->v4_half_open_hash, "v4 half-open table",
	                 configured_v4_halfopen_table_buckets,
	                 configured_v4_halfopen_table_memory);
  clib_bihash_init_48_8 (&slt->v6_half_open_hash, "v6 half-open table",
	                 configured_v6_halfopen_table_buckets,
	                 configured_v6_halfopen_table_memory);
}

void
session_lookup_init (void)
{
  /*
   * Allocate default table and map it to fib_index 0
   */
  session_lookup_table_t *slt = session_table_alloc ();
  vec_validate (nns_index_to_table_index, 0);
  nns_index_to_table_index[0] = 0;
  session_table_init (slt);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
