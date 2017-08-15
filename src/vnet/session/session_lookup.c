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

static session_lookup_t session_lookup;
extern transport_proto_vft_t *tp_vfts;

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

/*
 * Session lookup key; (src-ip, dst-ip, src-port, dst-port, session-type)
 * Value: (owner thread index << 32 | session_index);
 */
void
stream_session_table_add_for_tc (transport_connection_t * tc, u64 value)
{
  session_lookup_t *sl = &session_lookup;
  session_kv4_t kv4;
  session_kv6_t kv6;

  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      kv4.value = value;
      clib_bihash_add_del_16_8 (&sl->v4_session_hash, &kv4, 1 /* is_add */ );
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      kv6.value = value;
      clib_bihash_add_del_48_8 (&sl->v6_session_hash, &kv6, 1 /* is_add */ );
    }
}

void
stream_session_table_add (session_manager_main_t * smm, stream_session_t * s,
			  u64 value)
{
  transport_connection_t *tc;

  tc = tp_vfts[s->session_type].get_connection (s->connection_index,
						s->thread_index);
  stream_session_table_add_for_tc (tc, value);
}

int
stream_session_table_del_for_tc (transport_connection_t * tc)
{
  session_lookup_t *sl = &session_lookup;
  session_kv4_t kv4;
  session_kv6_t kv6;

  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      return clib_bihash_add_del_16_8 (&sl->v4_session_hash, &kv4,
				       0 /* is_add */ );
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      return clib_bihash_add_del_48_8 (&sl->v6_session_hash, &kv6,
				       0 /* is_add */ );
    }

  return 0;
}

int
stream_session_table_del (stream_session_t * s)
{
  transport_connection_t *ts;
  ts = tp_vfts[s->session_type].get_connection (s->connection_index,
						s->thread_index);
  return stream_session_table_del_for_tc (ts);
}


void
stream_session_half_open_table_add (transport_connection_t * tc, u64 value)
{
  session_lookup_t *sl = &session_lookup;
  session_kv4_t kv4;
  session_kv6_t kv6;

  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      kv4.value = value;
      clib_bihash_add_del_16_8 (&sl->v4_half_open_hash, &kv4,
				1 /* is_add */ );
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      kv6.value = value;
      clib_bihash_add_del_48_8 (&sl->v6_half_open_hash, &kv6,
				1 /* is_add */ );
    }
}

void
stream_session_half_open_table_del (transport_connection_t * tc)
{
  session_lookup_t *sl = &session_lookup;
  session_kv4_t kv4;
  session_kv6_t kv6;

  if (tc->is_ip4)
    {
      make_v4_ss_kv_from_tc (&kv4, tc);
      clib_bihash_add_del_16_8 (&sl->v4_half_open_hash, &kv4,
				0 /* is_add */ );
    }
  else
    {
      make_v6_ss_kv_from_tc (&kv6, tc);
      clib_bihash_add_del_48_8 (&sl->v6_half_open_hash, &kv6,
				0 /* is_add */ );
    }
}

stream_session_t *
stream_session_lookup_listener4 (ip4_address_t * lcl, u16 lcl_port, u8 proto)
{
  session_lookup_t *sl = &session_lookup;
  session_kv4_t kv4;
  int rv;

  make_v4_listener_kv (&kv4, lcl, lcl_port, proto);
  rv = clib_bihash_search_inline_16_8 (&sl->v4_session_hash, &kv4);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv4.value);

  /* Zero out the lcl ip */
  kv4.key[0] = 0;
  rv = clib_bihash_search_inline_16_8 (&sl->v4_session_hash, &kv4);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv4.value);

  return 0;
}

/** Looks up a session based on the 5-tuple passed as argument.
 *
 * First it tries to find an established session, if this fails, it tries
 * finding a listener session if this fails, it tries a lookup with a
 * wildcarded local source (listener bound to all interfaces)
 */
stream_session_t *
stream_session_lookup4 (ip4_address_t * lcl, ip4_address_t * rmt,
			u16 lcl_port, u16 rmt_port, u8 proto)
{
  session_lookup_t *sl = &session_lookup;
  session_kv4_t kv4;
  stream_session_t *s;
  int rv;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&sl->v4_session_hash, &kv4);
  if (rv == 0)
    return stream_session_get_from_handle (kv4.value);

  /* If nothing is found, check if any listener is available */
  if ((s = stream_session_lookup_listener4 (lcl, lcl_port, proto)))
    return s;

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_16_8 (&sl->v4_half_open_hash, &kv4);
  if (rv == 0)
    return stream_session_get_from_handle (kv4.value);
  return 0;
}

stream_session_t *
stream_session_lookup_listener6 (ip6_address_t * lcl, u16 lcl_port, u8 proto)
{
  session_lookup_t *sl = &session_lookup;
  session_kv6_t kv6;
  int rv;

  make_v6_listener_kv (&kv6, lcl, lcl_port, proto);
  rv = clib_bihash_search_inline_48_8 (&sl->v6_session_hash, &kv6);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv6.value);

  /* Zero out the lcl ip */
  kv6.key[0] = kv6.key[1] = 0;
  rv = clib_bihash_search_inline_48_8 (&sl->v6_session_hash, &kv6);
  if (rv == 0)
    return session_manager_get_listener (proto, (u32) kv6.value);

  return 0;
}

/* Looks up a session based on the 5-tuple passed as argument.
 * First it tries to find an established session, if this fails, it tries
 * finding a listener session if this fails, it tries a lookup with a
 * wildcarded local source (listener bound to all interfaces) */
stream_session_t *
stream_session_lookup6 (ip6_address_t * lcl, ip6_address_t * rmt,
			u16 lcl_port, u16 rmt_port, u8 proto)
{
  session_lookup_t *sl = &session_lookup;
  session_kv6_t kv6;
  stream_session_t *s;
  int rv;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&sl->v6_session_hash, &kv6);
  if (rv == 0)
    return stream_session_get_from_handle (kv6.value);

  /* If nothing is found, check if any listener is available */
  if ((s = stream_session_lookup_listener6 (lcl, lcl_port, proto)))
    return s;

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_48_8 (&sl->v6_half_open_hash, &kv6);
  if (rv == 0)
    return stream_session_get_from_handle (kv6.value);
  return 0;
}

stream_session_t *
stream_session_lookup_listener (ip46_address_t * lcl, u16 lcl_port, u8 proto)
{
  switch (proto)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      return stream_session_lookup_listener4 (&lcl->ip4, lcl_port, proto);
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      return stream_session_lookup_listener6 (&lcl->ip6, lcl_port, proto);
      break;
    }
  return 0;
}

u64
stream_session_half_open_lookup_handle (ip46_address_t * lcl,
					ip46_address_t * rmt, u16 lcl_port,
					u16 rmt_port, u8 proto)
{
  session_lookup_t *sl = &session_lookup;
  session_kv4_t kv4;
  session_kv6_t kv6;
  int rv;

  switch (proto)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      make_v4_ss_kv (&kv4, &lcl->ip4, &rmt->ip4, lcl_port, rmt_port, proto);
      rv = clib_bihash_search_inline_16_8 (&sl->v4_half_open_hash, &kv4);

      if (rv == 0)
	return kv4.value;

      return HALF_OPEN_LOOKUP_INVALID_VALUE;
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      make_v6_ss_kv (&kv6, &lcl->ip6, &rmt->ip6, lcl_port, rmt_port, proto);
      rv = clib_bihash_search_inline_48_8 (&sl->v6_half_open_hash, &kv6);

      if (rv == 0)
	return kv6.value;

      return HALF_OPEN_LOOKUP_INVALID_VALUE;
      break;
    }
  return HALF_OPEN_LOOKUP_INVALID_VALUE;
}

transport_connection_t *
stream_session_half_open_lookup (ip46_address_t * lcl, ip46_address_t * rmt,
				 u16 lcl_port, u16 rmt_port, u8 proto)
{
  u64 handle;
  handle =
    stream_session_half_open_lookup_handle (lcl, rmt, lcl_port, rmt_port,
					    proto);
  if (handle != HALF_OPEN_LOOKUP_INVALID_VALUE)
    return tp_vfts[proto].get_half_open (handle & 0xFFFFFFFF);
  return 0;
}

always_inline stream_session_t *
stream_session_get_tsi (u64 ti_and_si, u32 thread_index)
{
  ASSERT ((u32) (ti_and_si >> 32) == thread_index);
  return pool_elt_at_index (session_manager_main.sessions[thread_index],
			    ti_and_si & 0xFFFFFFFFULL);
}

transport_connection_t *
stream_session_lookup_transport_wt4 (ip4_address_t * lcl, ip4_address_t * rmt,
				     u16 lcl_port, u16 rmt_port, u8 proto,
				     u32 my_thread_index)
{
  session_lookup_t *sl = &session_lookup;
  session_kv4_t kv4;
  stream_session_t *s;
  int rv;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&sl->v4_session_hash, &kv4);
  if (rv == 0)
    {
      s = stream_session_get_tsi (kv4.value, my_thread_index);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      my_thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = stream_session_lookup_listener4 (lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_16_8 (&sl->v4_half_open_hash, &kv4);
  if (rv == 0)
    return tp_vfts[proto].get_half_open (kv4.value & 0xFFFFFFFF);
  return 0;
}

transport_connection_t *
stream_session_lookup_transport4 (ip4_address_t * lcl, ip4_address_t * rmt,
				  u16 lcl_port, u16 rmt_port, u8 proto)
{
  session_lookup_t *sl = &session_lookup;
  session_kv4_t kv4;
  stream_session_t *s;
  int rv;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&sl->v4_session_hash, &kv4);
  if (rv == 0)
    {
      s = stream_session_get_from_handle (kv4.value);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      s->thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = stream_session_lookup_listener4 (lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_16_8 (&sl->v4_half_open_hash, &kv4);
  if (rv == 0)
    return tp_vfts[proto].get_half_open (kv4.value & 0xFFFFFFFF);
  return 0;
}

transport_connection_t *
stream_session_lookup_transport_wt6 (ip6_address_t * lcl, ip6_address_t * rmt,
				     u16 lcl_port, u16 rmt_port, u8 proto,
				     u32 my_thread_index)
{
  session_lookup_t *sl = &session_lookup;
  stream_session_t *s;
  session_kv6_t kv6;
  int rv;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&sl->v6_session_hash, &kv6);
  if (rv == 0)
    {
      s = stream_session_get_tsi (kv6.value, my_thread_index);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      my_thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = stream_session_lookup_listener6 (lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_48_8 (&sl->v6_half_open_hash, &kv6);
  if (rv == 0)
    return tp_vfts[proto].get_half_open (kv6.value & 0xFFFFFFFF);

  return 0;
}

transport_connection_t *
stream_session_lookup_transport6 (ip6_address_t * lcl, ip6_address_t * rmt,
				  u16 lcl_port, u16 rmt_port, u8 proto)
{
  session_lookup_t *sl = &session_lookup;
  stream_session_t *s;
  session_kv6_t kv6;
  int rv;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&sl->v6_session_hash, &kv6);
  if (rv == 0)
    {
      s = stream_session_get_from_handle (kv6.value);
      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      s->thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = stream_session_lookup_listener6 (lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_48_8 (&sl->v6_half_open_hash, &kv6);
  if (rv == 0)
    return tp_vfts[proto].get_half_open (kv6.value & 0xFFFFFFFF);

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
session_lookup_init (void)
{
  session_lookup_t *sl = &session_lookup;

#define _(af,table,parm,value) \
  u32 configured_##af##_##table##_table_##parm = value;
  foreach_hash_table_parameter;
#undef _

#define _(af,table,parm,value)                                          \
  if (session_manager_main.configured_##af##_##table##_table_##parm)    \
    configured_##af##_##table##_table_##parm =                          \
      session_manager_main.configured_##af##_##table##_table_##parm;
  foreach_hash_table_parameter;
#undef _

  clib_bihash_init_16_8 (&sl->v4_session_hash, "v4 session table",
			 configured_v4_session_table_buckets,
			 configured_v4_session_table_memory);
  clib_bihash_init_48_8 (&sl->v6_session_hash, "v6 session table",
			 configured_v6_session_table_buckets,
			 configured_v6_session_table_memory);
  clib_bihash_init_16_8 (&sl->v4_half_open_hash, "v4 half-open table",
			 configured_v4_halfopen_table_buckets,
			 configured_v4_halfopen_table_memory);
  clib_bihash_init_48_8 (&sl->v6_half_open_hash, "v6 half-open table",
			 configured_v6_halfopen_table_buckets,
			 configured_v6_halfopen_table_memory);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
