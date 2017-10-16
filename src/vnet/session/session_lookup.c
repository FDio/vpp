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
#include <vnet/session/application.h>

/**
 * External vector of per transport virtual functions table
 */
extern transport_proto_vft_t *tp_vfts;

/**
 * Network namespace index (i.e., fib index) to session lookup table. We
 * should have one per network protocol type but for now we only support IP4/6
 */
static u32 *fib_index_to_table_index[2];

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
		 session_type_from_proto_and_ip (t->proto, 1));
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
		 session_type_from_proto_and_ip (t->proto, 0));
}


static session_table_t *
session_table_get_or_alloc_for_connection (transport_connection_t * tc)
{
  session_table_t *st;
  u32 table_index, fib_proto = transport_connection_fib_proto (tc);
  if (vec_len (fib_index_to_table_index[fib_proto]) <= tc->fib_index)
    {
      st = session_table_alloc ();
      table_index = session_table_index (st);
      vec_validate (fib_index_to_table_index[fib_proto], tc->fib_index);
      fib_index_to_table_index[fib_proto][tc->fib_index] = table_index;
      return st;
    }
  else
    {
      table_index = fib_index_to_table_index[fib_proto][tc->fib_index];
      return session_table_get (table_index);
    }
}

static session_table_t *
session_table_get_for_connection (transport_connection_t * tc)
{
  u32 fib_proto = transport_connection_fib_proto (tc);
  if (vec_len (fib_index_to_table_index[fib_proto]) <= tc->fib_index)
    return 0;
  return
    session_table_get (fib_index_to_table_index[fib_proto][tc->fib_index]);
}

static session_table_t *
session_table_get_for_fib_index (u32 fib_proto, u32 fib_index)
{
  if (vec_len (fib_index_to_table_index[fib_proto]) <= fib_index)
    return 0;
  return session_table_get (fib_index_to_table_index[fib_proto][fib_index]);
}

u32
session_lookup_get_index_for_fib (u32 fib_proto, u32 fib_index)
{
  if (vec_len (fib_index_to_table_index[fib_proto]) <= fib_index)
    return SESSION_TABLE_INVALID_INDEX;
  return fib_index_to_table_index[fib_proto][fib_index];
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
session_lookup_add_connection (transport_connection_t * tc, u64 value)
{
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;

  st = session_table_get_or_alloc_for_connection (tc);
  if (!st)
    return -1;
  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      kv4.value = value;
      return clib_bihash_add_del_16_8 (&st->v4_session_hash, &kv4,
				       1 /* is_add */ );
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      kv6.value = value;
      return clib_bihash_add_del_48_8 (&st->v6_session_hash, &kv6,
				       1 /* is_add */ );
    }
}

int
session_lookup_add_session_endpoint (u32 table_index,
				     session_endpoint_t * sep, u64 value)
{
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;

  st = session_table_get (table_index);
  if (!st)
    return -1;
  if (sep->is_ip4)
    {
      make_v4_listener_kv (&kv4, &sep->ip.ip4, sep->port,
			   sep->transport_proto);
      kv4.value = value;
      return clib_bihash_add_del_16_8 (&st->v4_session_hash, &kv4, 1);
    }
  else
    {
      make_v6_listener_kv (&kv6, &sep->ip.ip6, sep->port,
			   sep->transport_proto);
      kv6.value = value;
      return clib_bihash_add_del_48_8 (&st->v6_session_hash, &kv6, 1);
    }
}

int
session_lookup_del_session_endpoint (u32 table_index,
				     session_endpoint_t * sep)
{
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;

  st = session_table_get (table_index);
  if (!st)
    return -1;
  if (sep->is_ip4)
    {
      make_v4_listener_kv (&kv4, &sep->ip.ip4, sep->port,
			   sep->transport_proto);
      return clib_bihash_add_del_16_8 (&st->v4_session_hash, &kv4, 0);
    }
  else
    {
      make_v6_listener_kv (&kv6, &sep->ip.ip6, sep->port,
			   sep->transport_proto);
      return clib_bihash_add_del_48_8 (&st->v6_session_hash, &kv6, 0);
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
session_lookup_del_connection (transport_connection_t * tc)
{
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;

  st = session_table_get_for_connection (tc);
  if (!st)
    return -1;
  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      return clib_bihash_add_del_16_8 (&st->v4_session_hash, &kv4,
				       0 /* is_add */ );
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      return clib_bihash_add_del_48_8 (&st->v6_session_hash, &kv6,
				       0 /* is_add */ );
    }
}

int
session_lookup_del_session (stream_session_t * s)
{
  transport_connection_t *ts;
  ts = tp_vfts[s->session_type].get_connection (s->connection_index,
						s->thread_index);
  return session_lookup_del_connection (ts);
}

u64
session_lookup_session_endpoint (u32 table_index, session_endpoint_t * sep)
{
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;
  int rv;

  st = session_table_get (table_index);
  if (!st)
    return SESSION_INVALID_HANDLE;
  if (sep->is_ip4)
    {
      make_v4_listener_kv (&kv4, &sep->ip.ip4, sep->port,
			   sep->transport_proto);
      rv = clib_bihash_search_inline_16_8 (&st->v4_session_hash, &kv4);
      if (rv == 0)
	return kv4.value;
    }
  else
    {
      make_v6_listener_kv (&kv6, &sep->ip.ip6, sep->port,
			   sep->transport_proto);
      rv = clib_bihash_search_inline_48_8 (&st->v6_session_hash, &kv6);
      if (rv == 0)
	return kv6.value;
    }
  return SESSION_INVALID_HANDLE;
}

stream_session_t *
session_lookup_global_session_endpoint (session_endpoint_t * sep)
{
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;
  u8 fib_proto;
  u32 table_index;
  int rv;

  fib_proto = session_endpoint_fib_proto (sep);
  table_index = session_lookup_get_index_for_fib (fib_proto, sep->fib_index);
  st = session_table_get (table_index);
  if (!st)
    return 0;
  if (sep->is_ip4)
    {
      make_v4_listener_kv (&kv4, &sep->ip.ip4, sep->port,
			   sep->transport_proto);
      rv = clib_bihash_search_inline_16_8 (&st->v4_session_hash, &kv4);
      if (rv == 0)
	return session_get_from_handle (kv4.value);
    }
  else
    {
      make_v6_listener_kv (&kv6, &sep->ip.ip6, sep->port,
			   sep->transport_proto);
      rv = clib_bihash_search_inline_48_8 (&st->v6_session_hash, &kv6);
      if (rv == 0)
	return session_get_from_handle (kv6.value);
    }
  return 0;
}

u32
session_lookup_local_session_endpoint (u32 table_index,
				       session_endpoint_t * sep)
{
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;
  int rv;

  st = session_table_get (table_index);
  if (!st)
    return SESSION_INVALID_INDEX;
  if (sep->is_ip4)
    {
      make_v4_listener_kv (&kv4, &sep->ip.ip4, sep->port,
			   sep->transport_proto);
      rv = clib_bihash_search_inline_16_8 (&st->v4_session_hash, &kv4);
      if (rv == 0)
	return (u32) kv4.value;

      /*
       * Zero out the ip. Logic is that connect to local ips, say
       * 127.0.0.1:port, can match 0.0.0.0:port
       */
      kv4.key[0] = 0;
      rv = clib_bihash_search_inline_16_8 (&st->v4_session_hash, &kv4);
      if (rv == 0)
	return (u32) kv4.value;
    }
  else
    {
      make_v6_listener_kv (&kv6, &sep->ip.ip6, sep->port,
			   sep->transport_proto);
      rv = clib_bihash_search_inline_48_8 (&st->v6_session_hash, &kv6);
      if (rv == 0)
	return (u32) kv6.value;

      /*
       * Zero out the ip. Same logic as above.
       */
      kv6.key[0] = kv6.key[1] = 0;
      rv = clib_bihash_search_inline_48_8 (&st->v6_session_hash, &kv6);
      if (rv == 0)
	return (u32) kv6.value;
    }
  return SESSION_INVALID_INDEX;
}

static stream_session_t *
session_lookup_listener4_i (session_table_t * st, ip4_address_t * lcl,
			    u16 lcl_port, u8 proto)
{
  session_kv4_t kv4;
  int rv;

  make_v4_listener_kv (&kv4, lcl, lcl_port, proto);
  rv = clib_bihash_search_inline_16_8 (&st->v4_session_hash, &kv4);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv4.value);

  /* Zero out the lcl ip */
  kv4.key[0] = 0;
  rv = clib_bihash_search_inline_16_8 (&st->v4_session_hash, &kv4);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv4.value);

  return 0;
}

stream_session_t *
session_lookup_listener4 (u32 fib_index, ip4_address_t * lcl, u16 lcl_port,
			  u8 proto)
{
  session_table_t *st;
  st = session_table_get_for_fib_index (FIB_PROTOCOL_IP4, fib_index);
  if (!st)
    return 0;
  return session_lookup_listener4_i (st, lcl, lcl_port, proto);
}

static stream_session_t *
session_lookup_listener6_i (session_table_t * st, ip6_address_t * lcl,
			    u16 lcl_port, u8 proto)
{
  session_kv6_t kv6;
  int rv;

  make_v6_listener_kv (&kv6, lcl, lcl_port, proto);
  rv = clib_bihash_search_inline_48_8 (&st->v6_session_hash, &kv6);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv6.value);

  /* Zero out the lcl ip */
  kv6.key[0] = kv6.key[1] = 0;
  rv = clib_bihash_search_inline_48_8 (&st->v6_session_hash, &kv6);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv6.value);

  return 0;
}

stream_session_t *
session_lookup_listener6 (u32 fib_index, ip6_address_t * lcl, u16 lcl_port,
			  u8 proto)
{
  session_table_t *st;
  st = session_table_get_for_fib_index (FIB_PROTOCOL_IP6, fib_index);
  if (!st)
    return 0;
  return session_lookup_listener6_i (st, lcl, lcl_port, proto);
}

stream_session_t *
session_lookup_listener (u32 table_index, session_endpoint_t * sep)
{
  session_table_t *st;
  st = session_table_get (table_index);
  if (!st)
    return 0;
  if (sep->is_ip4)
    return session_lookup_listener4_i (st, &sep->ip.ip4, sep->port,
				       sep->transport_proto);
  else
    return session_lookup_listener6_i (st, &sep->ip.ip6, sep->port,
				       sep->transport_proto);
  return 0;
}

int
session_lookup_add_half_open (transport_connection_t * tc, u64 value)
{
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;

  st = session_table_get_or_alloc_for_connection (tc);
  if (!st)
    return 0;
  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      kv4.value = value;
      return clib_bihash_add_del_16_8 (&st->v4_half_open_hash, &kv4,
				       1 /* is_add */ );
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      kv6.value = value;
      return clib_bihash_add_del_48_8 (&st->v6_half_open_hash, &kv6,
				       1 /* is_add */ );
    }
}

int
session_lookup_del_half_open (transport_connection_t * tc)
{
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;

  st = session_table_get_for_connection (tc);
  if (!st)
    return -1;
  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      return clib_bihash_add_del_16_8 (&st->v4_half_open_hash, &kv4,
				       0 /* is_add */ );
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      return clib_bihash_add_del_48_8 (&st->v6_half_open_hash, &kv6,
				       0 /* is_add */ );
    }
}

u64
session_lookup_half_open_handle (transport_connection_t * tc)
{
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;
  int rv;

  st = session_table_get_for_fib_index (transport_connection_fib_proto (tc),
					tc->fib_index);
  if (!st)
    return HALF_OPEN_LOOKUP_INVALID_VALUE;
  if (tc->is_ip4)
    {
      make_v4_ss_kv (&kv4, &tc->lcl_ip.ip4, &tc->rmt_ip.ip4, tc->lcl_port,
		     tc->rmt_port, tc->proto);
      rv = clib_bihash_search_inline_16_8 (&st->v4_half_open_hash, &kv4);
      if (rv == 0)
	return kv4.value;
    }
  else
    {
      make_v6_ss_kv (&kv6, &tc->lcl_ip.ip6, &tc->rmt_ip.ip6, tc->lcl_port,
		     tc->rmt_port, tc->proto);
      rv = clib_bihash_search_inline_48_8 (&st->v6_half_open_hash, &kv6);
      if (rv == 0)
	return kv6.value;
    }
  return HALF_OPEN_LOOKUP_INVALID_VALUE;
}

transport_connection_t *
session_lookup_half_open_connection (u64 handle, u8 proto, u8 is_ip4)
{
  u32 sst;

  if (handle != HALF_OPEN_LOOKUP_INVALID_VALUE)
    {
      sst = session_type_from_proto_and_ip (proto, is_ip4);
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
			       ip4_address_t * rmt, u16 lcl_port,
			       u16 rmt_port, u8 proto, u32 thread_index)
{
  session_table_t *st;
  session_kv4_t kv4;
  stream_session_t *s;
  int rv;

  st = session_table_get_for_fib_index (FIB_PROTOCOL_IP4, fib_index);
  if (PREDICT_FALSE (!st))
    return 0;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&st->v4_session_hash, &kv4);
  if (rv == 0)
    {
      ASSERT ((u32) (kv4.value >> 32) == thread_index);
      s = session_get (kv4.value & 0xFFFFFFFFULL, thread_index);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = session_lookup_listener4_i (st, lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_16_8 (&st->v4_half_open_hash, &kv4);
  if (rv == 0)
    {
      u32 sst = session_type_from_proto_and_ip (proto, 1);
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
  session_table_t *st;
  session_kv4_t kv4;
  stream_session_t *s;
  int rv;

  st = session_table_get_for_fib_index (FIB_PROTOCOL_IP4, fib_index);
  if (PREDICT_FALSE (!st))
    return 0;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&st->v4_session_hash, &kv4);
  if (rv == 0)
    {
      s = session_get_from_handle (kv4.value);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      s->thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = session_lookup_listener4_i (st, lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_16_8 (&st->v4_half_open_hash, &kv4);
  if (rv == 0)
    {
      u32 sst = session_type_from_proto_and_ip (proto, 1);
      return tp_vfts[sst].get_half_open (kv4.value & 0xFFFFFFFF);
    }
  return 0;
}

/**
 * Lookup session with ip4 and transport layer information
 *
 * Important note: this may look into another thread's pool table and
 * register as 'peeker'. Caller should call @ref session_pool_remove_peeker as
 * if needed as soon as possible.
 *
 * Lookup logic is similar to that of @ref session_lookup_connection_wt4 but
 * this returns a session as opposed to a transport connection and it does not
 * try to lookup half-open sessions.
 *
 * Typically used by dgram connections
 */
stream_session_t *
session_lookup_safe4 (u32 fib_index, ip4_address_t * lcl, ip4_address_t * rmt,
		      u16 lcl_port, u16 rmt_port, u8 proto)
{
  session_table_t *st;
  session_kv4_t kv4;
  stream_session_t *s;
  int rv;

  st = session_table_get_for_fib_index (FIB_PROTOCOL_IP4, fib_index);
  if (PREDICT_FALSE (!st))
    return 0;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&st->v4_session_hash, &kv4);
  if (rv == 0)
    return session_get_from_handle_safe (kv4.value);

  /* If nothing is found, check if any listener is available */
  if ((s = session_lookup_listener4_i (st, lcl, lcl_port, proto)))
    return s;
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
			       ip6_address_t * rmt, u16 lcl_port,
			       u16 rmt_port, u8 proto, u32 thread_index)
{
  session_table_t *st;
  stream_session_t *s;
  session_kv6_t kv6;
  int rv;

  st = session_table_get_for_fib_index (FIB_PROTOCOL_IP6, fib_index);
  if (PREDICT_FALSE (!st))
    return 0;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&st->v6_session_hash, &kv6);
  if (rv == 0)
    {
      ASSERT ((u32) (kv6.value >> 32) == thread_index);
      s = session_get (kv6.value & 0xFFFFFFFFULL, thread_index);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = session_lookup_listener6_i (st, lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_48_8 (&st->v6_half_open_hash, &kv6);
  if (rv == 0)
    {
      u32 sst = session_type_from_proto_and_ip (proto, 1);
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
  session_table_t *st;
  stream_session_t *s;
  session_kv6_t kv6;
  int rv;

  st = session_table_get_for_fib_index (FIB_PROTOCOL_IP6, fib_index);
  if (PREDICT_FALSE (!st))
    return 0;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&st->v6_session_hash, &kv6);
  if (rv == 0)
    {
      s = session_get_from_handle (kv6.value);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      s->thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = session_lookup_listener6 (fib_index, lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_48_8 (&st->v6_half_open_hash, &kv6);
  if (rv == 0)
    {
      u32 sst = session_type_from_proto_and_ip (proto, 1);
      return tp_vfts[sst].get_half_open (kv6.value & 0xFFFFFFFF);
    }

  return 0;
}

/**
 * Lookup session with ip6 and transport layer information
 *
 * Important note: this may look into another thread's pool table and
 * register as 'peeker'. Caller should call @ref session_pool_remove_peeker as
 * if needed as soon as possible.
 *
 * Lookup logic is similar to that of @ref session_lookup_connection_wt6 but
 * this returns a session as opposed to a transport connection and it does not
 * try to lookup half-open sessions.
 *
 * Typically used by dgram connections
 */
stream_session_t *
session_lookup_safe6 (u32 fib_index, ip6_address_t * lcl, ip6_address_t * rmt,
		      u16 lcl_port, u16 rmt_port, u8 proto)
{
  session_table_t *st;
  session_kv6_t kv6;
  stream_session_t *s;
  int rv;

  st = session_table_get_for_fib_index (FIB_PROTOCOL_IP6, fib_index);
  if (PREDICT_FALSE (!st))
    return 0;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&st->v6_session_hash, &kv6);
  if (rv == 0)
    return session_get_from_handle_safe (kv6.value);

  /* If nothing is found, check if any listener is available */
  if ((s = session_lookup_listener6_i (st, lcl, lcl_port, proto)))
    return s;
  return 0;
}

u64
session_lookup_local_listener_make_handle (session_endpoint_t * sep)
{
  return ((u64) SESSION_LOCAL_TABLE_PREFIX << 32
	  | (u32) sep->port << 16 | (u32) sep->transport_proto << 8
	  | (u32) sep->is_ip4);
}

u8
session_lookup_local_is_handle (u64 handle)
{
  if (handle >> 32 == SESSION_LOCAL_TABLE_PREFIX)
    return 1;
  return 0;
}

int
session_lookup_local_listener_parse_handle (u64 handle,
					    session_endpoint_t * sep)
{
  u32 local_table_handle;
  if (handle >> 32 != SESSION_LOCAL_TABLE_PREFIX)
    return -1;
  local_table_handle = handle & 0xFFFFFFFFULL;
  sep->is_ip4 = local_table_handle & 0xff;
  local_table_handle >>= 8;
  sep->transport_proto = local_table_handle & 0xff;
  sep->port = local_table_handle >> 8;
  return 0;
}

u8 *
format_ip4_session_lookup_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_16_8_t *kvp = va_arg (*args, clib_bihash_kv_16_8_t *);
  u32 is_local = va_arg (*args, u32);
  u8 *app_name, *str = 0;
  stream_session_t *session;
  v4_connection_key_t *key = (v4_connection_key_t *) kvp->key;

  char *proto = key->proto == TRANSPORT_PROTO_TCP ? "T" : "U";
  if (!is_local)
    {
      session = session_get_from_handle (kvp->value);
      app_name = application_name_from_index (session->app_index);
      str = format (0, "[%s] %U:%d->%U:%d", proto, format_ip4_address,
		    &key->src, clib_net_to_host_u16 (key->src_port),
		    format_ip4_address, &key->dst,
		    clib_net_to_host_u16 (key->dst_port));
      s = format (s, "%-40v%-30v", str, app_name);
    }
  else
    {
      app_name = application_name_from_index (kvp->value);
      str = format (0, "[%s] %U:%d", proto, format_ip4_address,
		    &key->src, clib_net_to_host_u16 (key->src_port));
      s = format (s, "%-30v%-30v", str, app_name);
    }
  vec_free (app_name);
  return s;
}

typedef struct _ip4_session_table_show_ctx_t
{
  vlib_main_t *vm;
  u8 is_local;
} ip4_session_table_show_ctx_t;

static int
ip4_session_table_show (clib_bihash_kv_16_8_t * kvp, void *arg)
{
  ip4_session_table_show_ctx_t *ctx = arg;
  vlib_cli_output (ctx->vm, "%U", format_ip4_session_lookup_kvp, kvp,
		   ctx->is_local);
  return 1;
}

void
session_lookup_show_table_entries (vlib_main_t * vm, session_table_t * table,
				   u8 type, u8 is_local)
{
  ip4_session_table_show_ctx_t ctx = {
    .vm = vm,
    .is_local = is_local,
  };
  if (!is_local)
    vlib_cli_output (vm, "%-40s%-30s", "Session", "Application");
  else
    vlib_cli_output (vm, "%-30s%-30s", "Listener", "Application");
  switch (type)
    {
      /* main table v4 */
    case 0:
      ip4_session_table_walk (&table->v4_session_hash, ip4_session_table_show,
			      &ctx);
      break;
    default:
      clib_warning ("not supported");
    }
}

void
session_lookup_init (void)
{
  /*
   * Allocate default table and map it to fib_index 0
   */
  session_table_t *st = session_table_alloc ();
  vec_validate (fib_index_to_table_index[FIB_PROTOCOL_IP4], 0);
  fib_index_to_table_index[FIB_PROTOCOL_IP4][0] = session_table_index (st);
  session_table_init (st);
  st = session_table_alloc ();
  vec_validate (fib_index_to_table_index[FIB_PROTOCOL_IP6], 0);
  fib_index_to_table_index[FIB_PROTOCOL_IP6][0] = session_table_index (st);
  session_table_init (st);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
