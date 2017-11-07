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
session_table_get_or_alloc (u8 fib_proto, u8 fib_index)
{
  session_table_t *st;
  u32 table_index;
  if (vec_len (fib_index_to_table_index[fib_proto]) <= fib_index)
    {
      st = session_table_alloc ();
      table_index = session_table_index (st);
      vec_validate (fib_index_to_table_index[fib_proto], fib_index);
      fib_index_to_table_index[fib_proto][fib_index] = table_index;
      st->active_fib_proto = fib_proto;
      return st;
    }
  else
    {
      table_index = fib_index_to_table_index[fib_proto][fib_index];
      return session_table_get (table_index);
    }
}

static session_table_t *
session_table_get_or_alloc_for_connection (transport_connection_t * tc)
{
  u32 fib_proto;
  fib_proto = transport_connection_fib_proto (tc);
  return session_table_get_or_alloc (fib_proto, tc->fib_index);
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

static u32
session_lookup_action_to_session (u32 action_index)
{
  if (action_index != SESSION_RULES_TABLE_ACTION_DROP)
    return action_index;
  return SESSION_INVALID_INDEX;
}

static stream_session_t *
session_lookup_app_listen_session (u32 app_index, u8 fib_proto,
				   u8 transport_proto)
{
  application_t *app;
  app = application_get (app_index);
  if (!app)
    return 0;

  return application_first_listener (app, fib_proto, transport_proto);
}

stream_session_t *
session_lookup_rules_table4 (session_table_t * st, u8 proto,
			     ip4_address_t * lcl, u16 lcl_port,
			     ip4_address_t * rmt, u16 rmt_port)
{
  session_rules_table_t *srt = &st->session_rules[proto];
  u32 action_index, session_index;
  action_index = session_rules_table_lookup4 (srt, lcl, rmt, lcl_port,
					      rmt_port);
  session_index = session_lookup_action_to_session (action_index);
  /* Nothing sophisticated for now, action index is app index */
  return session_lookup_app_listen_session (session_index, FIB_PROTOCOL_IP4,
					    proto);
}

stream_session_t *
session_lookup_rules_table6 (session_table_t * st, u8 proto,
			     ip6_address_t * lcl, u16 lcl_port,
			     ip6_address_t * rmt, u16 rmt_port)
{
  session_rules_table_t *srt = &st->session_rules[proto];
  u32 action_index, session_index;
  action_index = session_rules_table_lookup6 (srt, lcl, rmt, lcl_port,
					      rmt_port);
  session_index = session_lookup_action_to_session (action_index);
  return session_lookup_app_listen_session (session_index, FIB_PROTOCOL_IP6,
					    proto);
}

u64
session_lookup_session_endpoint (u32 table_index, session_endpoint_t * sep)
{
  session_rules_table_t *srt;
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;
  ip4_address_t lcl4;
  ip6_address_t lcl6;
  u32 ai;
  int rv;
  u8 sst;

  sst = session_type_from_proto_and_ip (sep->transport_proto, sep->is_ip4);
  st = session_table_get (table_index);
  if (!st)
    return SESSION_INVALID_HANDLE;
  if (sep->is_ip4)
    {
      make_v4_listener_kv (&kv4, &sep->ip.ip4, sep->port, sst);
      rv = clib_bihash_search_inline_16_8 (&st->v4_session_hash, &kv4);
      if (rv == 0)
	return kv4.value;

      memset (&lcl4, 0, sizeof (lcl4));
      srt = &st->session_rules[sep->transport_proto];
      ai = session_rules_table_lookup4 (srt, &lcl4, &sep->ip.ip4, 0,
					sep->port);
      if (ai != SESSION_RULES_TABLE_INVALID_INDEX)
	return session_lookup_action_to_session (ai);
    }
  else
    {
      make_v6_listener_kv (&kv6, &sep->ip.ip6, sep->port, sst);
      rv = clib_bihash_search_inline_48_8 (&st->v6_session_hash, &kv6);
      if (rv == 0)
	return kv6.value;

      memset (&lcl6, 0, sizeof (lcl6));
      srt = &st->session_rules[sep->transport_proto];
      ai = session_rules_table_lookup6 (srt, &lcl6, &sep->ip.ip6, 0,
					sep->port);
      if (ai != SESSION_RULES_TABLE_INVALID_INDEX)
	return session_lookup_action_to_session (ai);
    }
  return SESSION_INVALID_HANDLE;
}

stream_session_t *
session_lookup_global_session_endpoint (session_endpoint_t * sep)
{
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;
  ip4_address_t lcl4;
  ip6_address_t lcl6;
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
      memset (&lcl4, 0, sizeof (lcl4));
      return session_lookup_rules_table4 (st, sep->transport_proto, &lcl4, 0,
					  &sep->ip.ip4, sep->port);
    }
  else
    {
      make_v6_listener_kv (&kv6, &sep->ip.ip6, sep->port,
			   sep->transport_proto);
      rv = clib_bihash_search_inline_48_8 (&st->v6_session_hash, &kv6);
      if (rv == 0)
	return session_get_from_handle (kv6.value);
      memset (&lcl6, 0, sizeof (lcl6));
      return session_lookup_rules_table6 (st, sep->transport_proto, &lcl6, 0,
					  &sep->ip.ip6, sep->port);
    }
}

u32
session_lookup_local_session_endpoint (u32 table_index,
				       session_endpoint_t * sep)
{
  session_rules_table_t *srt;
  session_table_t *st;
  session_kv4_t kv4;
  session_kv6_t kv6;
  ip4_address_t lcl4;
  ip6_address_t lcl6;
  u32 ai;
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

      memset (&lcl4, 0, sizeof (lcl4));
      srt = &st->session_rules[sep->transport_proto];
      ai = session_rules_table_lookup4 (srt, &lcl4, &sep->ip.ip4, 0,
					sep->port);
      if (ai != SESSION_RULES_TABLE_INVALID_INDEX)
	return session_lookup_action_to_session (ai);
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

      memset (&lcl6, 0, sizeof (lcl6));
      srt = &st->session_rules[sep->transport_proto];
      ai = session_rules_table_lookup6 (srt, &lcl6, &sep->ip.ip6, 0,
					sep->port);
      if (ai != SESSION_RULES_TABLE_INVALID_INDEX)
	return session_lookup_action_to_session (ai);
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

static transport_connection_t *
session_lookup_rules_table_connection4 (session_table_t * st, u8 proto,
					ip4_address_t * lcl, u16 lcl_port,
					ip4_address_t * rmt, u16 rmt_port)
{
  stream_session_t *s;
  s = session_lookup_rules_table4 (st, proto, lcl, lcl_port, rmt, rmt_port);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);
  return 0;
}

static transport_connection_t *
session_lookup_rules_table_connection6 (session_table_t * srt, u8 proto,
					ip6_address_t * lcl, u16 lcl_port,
					ip6_address_t * rmt, u16 rmt_port)
{
  stream_session_t *s;
  s = session_lookup_rules_table6 (srt, proto, lcl, lcl_port, rmt, rmt_port);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);
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
 * - Try session rules table
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

  /* Try half-open connections */
  rv = clib_bihash_search_inline_16_8 (&st->v4_half_open_hash, &kv4);
  if (rv == 0)
    {
      u32 sst = session_type_from_proto_and_ip (proto, 1);
      return tp_vfts[sst].get_half_open (kv4.value & 0xFFFFFFFF);
    }

  /* Check the session rules table */
  return session_lookup_rules_table_connection4 (st, proto, lcl, lcl_port,
						 rmt, rmt_port);
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
  /* Check the session rules table */
  return session_lookup_rules_table_connection4 (st, proto, lcl, lcl_port,
						 rmt, rmt_port);
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
  return session_lookup_rules_table4 (st, proto, lcl,
				      lcl_port, rmt, rmt_port);
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
 * - Try session rules table
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

  return session_lookup_rules_table_connection6 (st, proto, lcl, lcl_port,
						 rmt, rmt_port);
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

  return session_lookup_rules_table_connection6 (st, proto, lcl, lcl_port,
						 rmt, rmt_port);
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
  return session_lookup_rules_table6 (st, proto, lcl,
				      lcl_port, rmt, rmt_port);
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

clib_error_t *
vnet_session_rule_add_del (session_rule_add_del_args_t * args)
{
  app_namespace_t *app_ns = app_namespace_get (args->appns_index);
  session_rules_table_t *srt;
  session_table_t *st;
  u32 fib_index;
  u8 fib_proto;
  clib_error_t *error;

  if (!app_ns)
    return clib_error_return_code (0, VNET_API_ERROR_APP_INVALID_NS, 0,
				   "invalid app ns");
  if (args->scope > 3)
    return clib_error_return_code (0, VNET_API_ERROR_INVALID_VALUE, 0,
				   "invalid scope");
  if (args->transport_proto != TRANSPORT_PROTO_TCP
      && args->transport_proto != TRANSPORT_PROTO_UDP)
    return clib_error_return_code (0, VNET_API_ERROR_INVALID_VALUE, 0,
				   "invalid transport proto");
  if ((args->scope & SESSION_RULE_SCOPE_GLOBAL) || args->scope == 0)
    {
      fib_proto = args->table_args.rmt.fp_proto;
      fib_index = app_namespace_get_fib_index (app_ns, fib_proto);
      st = session_table_get_for_fib_index (fib_proto, fib_index);
      srt = &st->session_rules[args->transport_proto];
      if ((error = session_rules_table_add_del (srt, &args->table_args)))
	{
	  clib_error_report (error);
	  return error;
	}
    }
  if (args->scope & SESSION_RULE_SCOPE_LOCAL)
    {
      st = app_namespace_get_local_table (app_ns);
      srt = &st->session_rules[args->transport_proto];
      error = session_rules_table_add_del (srt, &args->table_args);
    }
  return error;
}

/**
 * Mark (global) tables as pertaining to app ns
 */
void
session_lookup_set_tables_appns (app_namespace_t * app_ns)
{
  session_table_t *st;
  u32 fib_index;
  u8 fp;

  for (fp = 0; fp < ARRAY_LEN (fib_index_to_table_index); fp++)
    {
      fib_index = app_namespace_get_fib_index (app_ns, fp);
      st = session_table_get_for_fib_index (fp, fib_index);
      if (st)
	st->appns_index = app_namespace_index (app_ns);
    }
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

static clib_error_t *
session_rule_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  u32 proto = ~0, lcl_port, rmt_port, action = 0, lcl_plen = 0, rmt_plen = 0;
  u32 appns_index, scope = 0;
  ip46_address_t lcl_ip, rmt_ip;
  u8 is_ip4 = 1, conn_set = 0;
  u8 fib_proto, is_add = 1, *ns_id = 0;
  u8 *tag = 0;
  app_namespace_t *app_ns;
  clib_error_t *error;

  memset (&lcl_ip, 0, sizeof (lcl_ip));
  memset (&rmt_ip, 0, sizeof (rmt_ip));
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	;
      else if (unformat (input, "appns %_%v%_", &ns_id))
	;
      else if (unformat (input, "scope global"))
	scope = SESSION_RULE_SCOPE_GLOBAL;
      else if (unformat (input, "scope local"))
	scope = SESSION_RULE_SCOPE_LOCAL;
      else if (unformat (input, "scope all"))
	scope = SESSION_RULE_SCOPE_LOCAL | SESSION_RULE_SCOPE_GLOBAL;
      else if (unformat (input, "proto %U", unformat_transport_proto, &proto))
	;
      else if (unformat (input, "%U/%d %d %U/%d %d", unformat_ip4_address,
			 &lcl_ip.ip4, &lcl_plen, &lcl_port,
			 unformat_ip4_address, &rmt_ip.ip4, &rmt_plen,
			 &rmt_port))
	{
	  is_ip4 = 1;
	  conn_set = 1;
	}
      else if (unformat (input, "%U/%d %d %U/%d %d", unformat_ip6_address,
			 &lcl_ip.ip6, &lcl_plen, &lcl_port,
			 unformat_ip6_address, &rmt_ip.ip6, &rmt_plen,
			 &rmt_port))
	{
	  is_ip4 = 0;
	  conn_set = 1;
	}
      else if (unformat (input, "action %d", &action))
	;
      else if (unformat (input, "tag %_%v%_", &tag))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (proto == ~0)
    {
      vlib_cli_output (vm, "proto must be set");
      return 0;
    }
  if (is_add && !conn_set && action == ~0)
    {
      vlib_cli_output (vm, "connection and action must be set for add");
      return 0;
    }
  if (!is_add && !tag && !conn_set)
    {
      vlib_cli_output (vm, "connection or tag must be set for delete");
      return 0;
    }
  if (vec_len (tag) > SESSION_RULE_TAG_MAX_LEN)
    {
      vlib_cli_output (vm, "tag too long (max u64)");
      return 0;
    }

  if (ns_id)
    {
      app_ns = app_namespace_get_from_id (ns_id);
      if (!app_ns)
	{
	  vlib_cli_output (vm, "namespace %v does not exist", ns_id);
	  return 0;
	}
    }
  else
    {
      app_ns = app_namespace_get_default ();
    }
  appns_index = app_namespace_index (app_ns);

  fib_proto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  session_rule_add_del_args_t args = {
    .table_args.lcl.fp_addr = lcl_ip,
    .table_args.lcl.fp_len = lcl_plen,
    .table_args.lcl.fp_proto = fib_proto,
    .table_args.rmt.fp_addr = rmt_ip,
    .table_args.rmt.fp_len = rmt_plen,
    .table_args.rmt.fp_proto = fib_proto,
    .table_args.lcl_port = lcl_port,
    .table_args.rmt_port = rmt_port,
    .table_args.action_index = action,
    .table_args.is_add = is_add,
    .table_args.tag = tag,
    .appns_index = appns_index,
    .scope = scope,
  };
  error = vnet_session_rule_add_del (&args);
  vec_free (tag);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (session_rule_command, static) =
{
  .path = "session rule",
  .short_help = "session rule [add|del] appns <ns_id> proto <proto> "
      "<lcl-ip/plen> <lcl-port> <rmt-ip/plen> <rmt-port> action <action>",
  .function = session_rule_command_fn,
};
/* *INDENT-ON* */

void
session_lookup_dump_rules_table (u32 fib_index, u8 fib_proto,
				 u8 transport_proto)
{
  vlib_main_t *vm = vlib_get_main ();
  session_rules_table_t *srt;
  session_table_t *st;
  st = session_table_get_for_fib_index (fib_index, fib_proto);
  srt = &st->session_rules[transport_proto];
  session_rules_table_cli_dump (vm, srt, fib_proto);
}

void
session_lookup_dump_local_rules_table (u32 table_index, u8 fib_proto,
				       u8 transport_proto)
{
  vlib_main_t *vm = vlib_get_main ();
  session_rules_table_t *srt;
  session_table_t *st;
  st = session_table_get (table_index);
  srt = &st->session_rules[transport_proto];
  session_rules_table_cli_dump (vm, srt, fib_proto);
}

static clib_error_t *
show_session_rules_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  u32 transport_proto = ~0, lcl_port, rmt_port, lcl_plen, rmt_plen;
  u32 fib_index, scope = 0;
  ip46_address_t lcl_ip, rmt_ip;
  u8 is_ip4 = 1, show_one = 0;
  app_namespace_t *app_ns;
  session_rules_table_t *srt;
  session_table_t *st;
  u8 *ns_id = 0, fib_proto;

  memset (&lcl_ip, 0, sizeof (lcl_ip));
  memset (&rmt_ip, 0, sizeof (rmt_ip));
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_transport_proto, &transport_proto))
	;
      else if (unformat (input, "appns %_%v%_", &ns_id))
	;
      else if (unformat (input, "scope global"))
	scope = 1;
      else if (unformat (input, "scope local"))
	scope = 2;
      else if (unformat (input, "%U/%d %d %U/%d %d", unformat_ip4_address,
			 &lcl_ip.ip4, &lcl_plen, &lcl_port,
			 unformat_ip4_address, &rmt_ip.ip4, &rmt_plen,
			 &rmt_port))
	{
	  is_ip4 = 1;
	  show_one = 1;
	}
      else if (unformat (input, "%U/%d %d %U/%d %d", unformat_ip6_address,
			 &lcl_ip.ip6, &lcl_plen, &lcl_port,
			 unformat_ip6_address, &rmt_ip.ip6, &rmt_plen,
			 &rmt_port))
	{
	  is_ip4 = 0;
	  show_one = 1;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (transport_proto == ~0)
    {
      vlib_cli_output (vm, "transport proto must be set");
      return 0;
    }

  if (ns_id)
    {
      app_ns = app_namespace_get_from_id (ns_id);
      if (!app_ns)
	{
	  vlib_cli_output (vm, "appns %v doesn't exist", ns_id);
	  return 0;
	}
    }
  else
    {
      app_ns = app_namespace_get_default ();
    }

  if (scope == 1 || scope == 0)
    {
      fib_proto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
      fib_index = is_ip4 ? app_ns->ip4_fib_index : app_ns->ip6_fib_index;
      st = session_table_get_for_fib_index (fib_proto, fib_index);
    }
  else
    {
      st = app_namespace_get_local_table (app_ns);
    }

  if (show_one)
    {
      srt = &st->session_rules[transport_proto];
      session_rules_table_show_rule (vm, srt, &lcl_ip, lcl_port, &rmt_ip,
				     rmt_port, is_ip4);
      return 0;
    }

  vlib_cli_output (vm, "%U rules table", format_transport_proto,
		   transport_proto);
  srt = &st->session_rules[transport_proto];
  session_rules_table_cli_dump (vm, srt, FIB_PROTOCOL_IP4);
  session_rules_table_cli_dump (vm, srt, FIB_PROTOCOL_IP6);

  vec_free (ns_id);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_session_rules_command, static) =
{
  .path = "show session rules",
  .short_help = "show session rules [appns <id> proto <proto> <lcl-ip/plen>"
      " <lcl-port> <rmt-ip/plen> <rmt-port>]",
  .function = show_session_rules_command_fn,
};
/* *INDENT-ON* */

void
session_lookup_init (void)
{
  /*
   * Allocate default table and map it to fib_index 0
   */
  session_table_t *st = session_table_alloc ();
  vec_validate (fib_index_to_table_index[FIB_PROTOCOL_IP4], 0);
  fib_index_to_table_index[FIB_PROTOCOL_IP4][0] = session_table_index (st);
  st->active_fib_proto = FIB_PROTOCOL_IP4;
  session_table_init (st, FIB_PROTOCOL_IP4);
  st = session_table_alloc ();
  vec_validate (fib_index_to_table_index[FIB_PROTOCOL_IP6], 0);
  fib_index_to_table_index[FIB_PROTOCOL_IP6][0] = session_table_index (st);
  st->active_fib_proto = FIB_PROTOCOL_IP6;
  session_table_init (st, FIB_PROTOCOL_IP6);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
