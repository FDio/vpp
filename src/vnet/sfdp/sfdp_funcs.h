/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#ifndef __included_sfdp_funcs_h__
#define __included_sfdp_funcs_h__
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/lookup/sfdp_bihashes.h>

static_always_inline void
sfdp_session_remove (sfdp_main_t *sfdp, sfdp_per_thread_data_t *ptd,
		     sfdp_session_t *session, u32 thread_index,
		     u32 session_index)
{
  clib_bihash_kv_8_8_t kv2 = { 0 };
  sfdp_bihash_kv46_t kv = { 0 };
  __clib_aligned (CLIB_CACHE_LINE_BYTES)
  u8 kvdata[SFDP_PARSER_MAX_KEY_SIZE + 8];
  uword parser_key_size;
  void *parser_table;
  sfdp_parser_data_t *parser;
  sfdp_parser_main_t *pm = &sfdp_parser_main;

  kv2.key = session->session_id;
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    {
      clib_memcpy_fast (&kv.kv4.key,
			&session->keys[SFDP_SESSION_KEY_PRIMARY].key4,
			sizeof (kv.kv4.key));
      clib_bihash_add_del_24_8 (&sfdp->table4, &kv.kv4, 0);
    }
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4)
    {
      clib_memcpy_fast (&kv.kv4.key,
			&session->keys[SFDP_SESSION_KEY_SECONDARY].key4,
			sizeof (kv.kv4.key));
      clib_bihash_add_del_24_8 (&sfdp->table4, &kv.kv4, 0);
    }
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6)
    {
      clib_memcpy_fast (&kv.kv6.key,
			&session->keys[SFDP_SESSION_KEY_PRIMARY].key6,
			sizeof (kv.kv6.key));
      clib_bihash_add_del_48_8 (&sfdp->table6, &kv.kv6, 0);
    }
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6)
    {
      clib_memcpy_fast (&kv.kv6.key,
			&session->keys[SFDP_SESSION_KEY_SECONDARY].key6,
			sizeof (kv.kv6.key));
      clib_bihash_add_del_48_8 (&sfdp->table6, &kv.kv6, 0);
    }
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_USER)
    {
      parser = vec_elt_at_index (
	pm->parsers, session->parser_index[SFDP_SESSION_KEY_PRIMARY]);
      parser_key_size = parser->key_size;
      parser_table = parser->bihash_table;
      clib_memcpy_fast (kvdata, &session->keys_data[SFDP_SESSION_KEY_PRIMARY],
			parser_key_size);
      SFDP_PARSER_BIHASH_CALL_FN (parser, sfdp_parser_bihash_add_del_fn,
				  parser_table, kvdata, 0);
    }
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_USER)
    {
      parser = vec_elt_at_index (
	pm->parsers, session->parser_index[SFDP_SESSION_KEY_SECONDARY]);
      parser_key_size = parser->key_size;
      parser_table = parser->bihash_table;
      clib_memcpy_fast (kvdata,
			&session->keys_data[SFDP_SESSION_KEY_SECONDARY],
			parser_key_size);
      SFDP_PARSER_BIHASH_CALL_FN (parser, sfdp_parser_bihash_add_del_fn,
				  parser_table, kvdata, 0);
    }
  clib_bihash_add_del_8_8 (&sfdp->session_index_by_id, &kv2, 0);
  vlib_increment_simple_counter (
    &sfdp->tenant_session_ctr[SFDP_TENANT_SESSION_COUNTER_REMOVED],
    thread_index, session->tenant_idx, 1);
  session->state = SFDP_SESSION_STATE_FREE;
  session->owning_thread_index = SFDP_UNBOUND_THREAD_INDEX;
  sfdp_free_session (sfdp, ptd, session_index);
}

static_always_inline int
sfdp_session_try_add_secondary_key (sfdp_main_t *sfdp, u32 thread_index,
				    u32 pseudo_flow_index,
				    sfdp_session_ip46_key_t *key,
				    ip46_type_t type, u64 *h)
{
  int rv;
  sfdp_bihash_kv46_t kv;
  u64 value;
  sfdp_session_t *session;
  u32 session_index;

  session_index = sfdp_session_from_flow_index (pseudo_flow_index);
  session = sfdp_session_at_index (session_index);
  value = sfdp_session_mk_table_value (thread_index, pseudo_flow_index,
				       session->session_version);

  if (type == IP46_TYPE_IP4)
    {
      kv.kv4.key[0] = key->key4.ip4_key.as_u64x2[0];
      kv.kv4.key[1] = key->key4.ip4_key.as_u64x2[1];
      kv.kv4.key[2] = key->key4.as_u64;
      kv.kv4.value = value;
      *h = clib_bihash_hash_24_8 (&kv.kv4);
      if ((rv = sfdp_bihash_add_del_inline_with_hash_24_8 (
	     &sfdp->table4, &kv.kv4, *h, 2)) == 0)
	{
	  session->keys[SFDP_SESSION_KEY_SECONDARY] = *key;
	  session->pseudo_dir[SFDP_SESSION_KEY_SECONDARY] =
	    pseudo_flow_index & 0x1;
	  session->key_flags |= SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4;
	}
    }
  else
    {
      kv.kv6.key[0] = key->key6.ip6_key.as_u64;
      kv.kv6.key[1] = key->key6.ip6_key.as_u64x4[0];
      kv.kv6.key[2] = key->key6.ip6_key.as_u64x4[1];
      kv.kv6.key[3] = key->key6.ip6_key.as_u64x4[2];
      kv.kv6.key[4] = key->key6.ip6_key.as_u64x4[3];
      kv.kv6.key[5] = key->key6.as_u64;
      kv.kv6.value = value;
      *h = clib_bihash_hash_48_8 (&kv.kv6);
      if ((rv = sfdp_bihash_add_del_inline_with_hash_48_8 (
	     &sfdp->table6, &kv.kv6, *h, 2)) == 0)
	{
	  session->keys[SFDP_SESSION_KEY_SECONDARY] = *key;
	  session->pseudo_dir[SFDP_SESSION_KEY_SECONDARY] =
	    pseudo_flow_index & 0x1;
	  session->key_flags |= SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6;
	}
    }

  return rv;
}

static_always_inline int
sfdp_parser_session_try_add_secondary_key_with_details (
  void *table, uword key_size, uword parser_index, u32 thread_index,
  u32 pseudo_flow_index, void *key, u64 *h)
{
  __clib_aligned (CLIB_CACHE_LINE_BYTES)
  u8 kvdata[SFDP_PARSER_MAX_KEY_SIZE + 8];
  int rv;
  u64 value;
  sfdp_session_t *session;
  u32 session_index;
  const struct
  {
    uword key_size;
  } p = { .key_size = key_size };

  session_index = sfdp_session_from_flow_index (pseudo_flow_index);
  session = sfdp_session_at_index (session_index);
  value = sfdp_session_mk_table_value (thread_index, pseudo_flow_index,
				       session->session_version);

  clib_memcpy_fast (kvdata, key, key_size);
  clib_memcpy_fast (kvdata + key_size, &value, sizeof (value));
  *h = SFDP_PARSER_BIHASH_CALL_FN (&p, sfdp_parser_bihash_hash_fn, kvdata);
  if ((rv = SFDP_PARSER_BIHASH_CALL_FN (&p, sfdp_parser_bihash_add_del_fn,
					table, kvdata, 2)) == 0)
    {
      clib_memcpy_fast (session->keys_data[SFDP_SESSION_KEY_SECONDARY], kvdata,
			key_size);
      session->pseudo_dir[SFDP_SESSION_KEY_SECONDARY] =
	pseudo_flow_index & 0x1;
      session->key_flags |= SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_USER;
      session->parser_index[SFDP_SESSION_KEY_SECONDARY] = parser_index;
    }
  return rv;
}

static_always_inline u8
sfdp_renormalise_ip4_key (sfdp_session_ip4_key_t *key, u32 old_pseudo)
{
  if (clib_net_to_host_u32 (key->ip4_key.ip_addr_hi) <
      clib_net_to_host_u32 (key->ip4_key.ip_addr_lo))
    {
      u32 tmp_ip4;
      u16 tmp_port;
      tmp_ip4 = key->ip4_key.ip_addr_hi;
      tmp_port = key->ip4_key.port_hi;
      key->ip4_key.ip_addr_hi = key->ip4_key.ip_addr_lo;
      key->ip4_key.port_hi = key->ip4_key.port_lo;
      key->ip4_key.ip_addr_lo = tmp_ip4;
      key->ip4_key.port_lo = tmp_port;
      old_pseudo ^= 0x1;
    }
  return old_pseudo;
}

static_always_inline void
sfdp_session_bind_keys_to_thread (sfdp_session_t *session, u32 session_index,
				  u16 thread_index)
{
  clib_bihash_kv_24_8_t kv4;
  clib_bihash_kv_48_8_t kv6;
  __clib_aligned (CLIB_CACHE_LINE_BYTES)
  u8 kvdata[SFDP_PARSER_MAX_KEY_SIZE + 8];
  uword parser_key_size;
  void *parser_table;
  sfdp_parser_data_t *parser;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_parser_main_t *pm = &sfdp_parser_main;
  u32 fi = session_index << 1;

  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    {
      clib_memcpy_fast (kv4.key, &session->keys[SFDP_SESSION_KEY_PRIMARY].key4,
			sizeof (kv4.key));
      kv4.value = sfdp_session_mk_table_value (
	thread_index, fi | session->pseudo_dir[SFDP_SESSION_KEY_PRIMARY],
	session->session_version);
      clib_bihash_add_del_24_8 (&sfdp->table4, &kv4, 1);
    }
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6)
    {
      clib_memcpy_fast (kv6.key, &session->keys[SFDP_SESSION_KEY_PRIMARY].key6,
			sizeof (kv6.key));
      kv6.value = sfdp_session_mk_table_value (
	thread_index, fi | session->pseudo_dir[SFDP_SESSION_KEY_PRIMARY],
	session->session_version);
      clib_bihash_add_del_48_8 (&sfdp->table6, &kv6, 1);
    }
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_USER)
    {
      parser = vec_elt_at_index (
	pm->parsers, session->parser_index[SFDP_SESSION_KEY_PRIMARY]);
      parser_key_size = parser->key_size;
      parser_table = parser->bihash_table;
      clib_memcpy_fast (kvdata, &session->keys_data[SFDP_SESSION_KEY_PRIMARY],
			parser_key_size);
      ((u64u *) (kvdata + parser_key_size))[0] = sfdp_session_mk_table_value (
	thread_index, fi | session->pseudo_dir[SFDP_SESSION_KEY_PRIMARY],
	session->session_version);
      SFDP_PARSER_BIHASH_CALL_FN (parser, sfdp_parser_bihash_add_del_fn,
				  parser_table, kvdata, 1);
    }
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4)
    {
      clib_memcpy_fast (kv4.key,
			&session->keys[SFDP_SESSION_KEY_SECONDARY].key4,
			sizeof (kv4.key));
      kv4.value = sfdp_session_mk_table_value (
	thread_index, fi | session->pseudo_dir[SFDP_SESSION_KEY_SECONDARY],
	session->session_version);
      clib_bihash_add_del_24_8 (&sfdp->table4, &kv4, 1);
    }
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6)
    {
      clib_memcpy_fast (kv6.key,
			&session->keys[SFDP_SESSION_KEY_SECONDARY].key6,
			sizeof (kv6.key));
      kv6.value = sfdp_session_mk_table_value (
	thread_index, fi | session->pseudo_dir[SFDP_SESSION_KEY_SECONDARY],
	session->session_version);
      clib_bihash_add_del_48_8 (&sfdp->table6, &kv6, 1);
    }
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_USER)
    {
      parser = vec_elt_at_index (
	pm->parsers, session->parser_index[SFDP_SESSION_KEY_SECONDARY]);
      parser_key_size = parser->key_size;
      parser_table = parser->bihash_table;
      clib_memcpy_fast (kvdata,
			&session->keys_data[SFDP_SESSION_KEY_SECONDARY],
			parser_key_size);
      ((u64u *) (kvdata + parser_key_size))[0] = sfdp_session_mk_table_value (
	thread_index, fi | session->pseudo_dir[SFDP_SESSION_KEY_SECONDARY],
	session->session_version);
      SFDP_PARSER_BIHASH_CALL_FN (parser, sfdp_parser_bihash_add_del_fn,
				  parser_table, kvdata, 1);
    }
}

static_always_inline int
sfdp_session_bind_to_thread (u32 session_index, u16 *thread_index,
			     u8 new_session)
{
  sfdp_session_t *session = sfdp_session_at_index (session_index);
  u16 expected = SFDP_UNBOUND_THREAD_INDEX;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_per_thread_data_t *ptd =
    vec_elt_at_index (sfdp->per_thread_data, *thread_index);

  if (clib_atomic_cmp_and_swap_acq_relax_n (&session->owning_thread_index,
					    &expected, *thread_index, 0) != 0)
    {
      *thread_index = expected; /* Return the actual thread index */
      return -1; /* The session was already bound to another thread */
    }

  ASSERT (*thread_index == vlib_get_thread_index ());

  sfdp_session_bind_keys_to_thread (session, session_index, *thread_index);
  if (new_session)
    {
      sfdp_notify_new_sessions (sfdp, &session_index, 1);
      sfdp_session_generate_and_set_id (sfdp, ptd, session);
    }
  return 0;
}
#endif
