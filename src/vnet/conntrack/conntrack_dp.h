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

#ifndef __CONN_TRACK_DP_H__
#define __CONN_TRACK_DP_H__

#include <vnet/conntrack/conntrack.h>
#include <vnet/classify/vnet_classify.h>

typedef u64 conn_hash_t;

static_always_inline index_t
conn_age_sieve_rotate (conn_age_sieve_t * sieve, u32 * slot, f64 now)
{
  index_t conni;

  *slot = sieve->cas_tail;
  conni = sieve->cas_buckets[sieve->cas_tail].casb_conn;
  sieve->cas_buckets[sieve->cas_tail].casb_time = now;

  sieve->cas_head = (sieve->cas_head + 1) & sieve->cas_mask;
  sieve->cas_tail = (sieve->cas_tail + 1) & sieve->cas_mask;

  return (conni);
}

static_always_inline void
conn_age_sieve_shake (conn_db_t * conn_db,
		      conn_age_sieve_t * sieve, conn_t * conn, f64 now)
{
  u32 slot, better_slot;	//, to_head, rand;
  conn_t *better_conn;
  index_t tmp;

  slot = conn->c_sieve_slot;

  if (slot == sieve->cas_head)
    {
      sieve->cas_buckets[slot].casb_time = now;
      return;
    }

#define USEC_IN_SEC 1000000
  /*
   * in order for this to work well there needs to be randomness in the shaking.
   * if the packet arrivals are not rnadom, i.e. it's sequential packets for
   * each flow, then the slot will just swap back and forwards. We can't control
   * packet arrivals, so we need to use another form of randomness - which is
   * which bucket/slot we exchange with. the random 'seed' in this case is the
   * time, which is used to randomly select the bucket.
   */
  /* if (!sieve->cas_counter) */
  /*   { */
  /*     to_head = ((sieve->cas_head - slot) - 1) & sieve->cas_mask; */
  /*     rand = now * USEC_IN_SEC; */
  /*     better_slot = (to_head & rand) + 1; */
  /*   } */
  /* else */
  better_slot = (slot + 1) & sieve->cas_mask;

  sieve->cas_counter++;
  tmp = sieve->cas_buckets[better_slot].casb_conn;

  better_conn = conn_get (conn_db, tmp);

  sieve->cas_buckets[better_slot].casb_conn =
    sieve->cas_buckets[slot].casb_conn;
  sieve->cas_buckets[slot].casb_time =
    sieve->cas_buckets[better_slot].casb_time;
  sieve->cas_buckets[better_slot].casb_time = now;

  sieve->cas_buckets[slot].casb_conn = tmp;

  conn->c_sieve_slot = better_slot;
  better_conn->c_sieve_slot = slot;
}

static_always_inline index_t
conn_track_find (index_t cdbi,
		 u32 thread_index, const u8 * h, conn_hash_t * chash, f64 now)
{
  const vnet_classify_entry_t *vc_entry;
  vnet_classify_table_t *vc_table;
  conn_db_t *conn_db;
  u64 hash;

  conn_db = conn_db_get (cdbi);
  vc_table = vnet_classify_table_get (conn_db->cd_table);

  hash = vnet_classify_hash_packet_inline (vc_table, h);
  vc_entry = vnet_classify_find_entry_inline (vc_table, h, hash, now);

  *chash = hash;

  if (PREDICT_TRUE (NULL != vc_entry))
    {
      conn_t *conn;

      conn = conn_get (conn_db, vc_entry->opaque_index);

      if (conn->c_flags & CONN_FLAG_STALE)
	return (INDEX_INVALID);

      if (thread_index == vc_entry->metadata)
	conn_age_sieve_shake (conn_db,
			      &conn_db->
			      cd_per_thread[thread_index].cdpt_sieve,
			      conn_get (conn_db, vc_entry->opaque_index),
			      now);

      return (vc_entry->opaque_index);
    }
  return (INDEX_INVALID);
}

static_always_inline index_t
conn_track_ip4_find (index_t cdbi,
		     u32 thread_index,
		     const ip4_header_t * hdr, conn_hash_t * chash, f64 now)
{
  return (conn_track_find (cdbi, thread_index, (u8 *) hdr, chash, now));
}

static_always_inline index_t
conn_track_ip6_find (index_t cdbi,
		     u32 thread_index,
		     const ip6_header_t * hdr, conn_hash_t * chash, f64 now)
{
  return (conn_track_find (cdbi, thread_index, (u8 *) hdr, chash, now));
}

static_always_inline void
conn_hdr_ip4_reverse (const conn_hdr_ip4_t * key, conn_hdr_ip4_t * rev_key)
{
  rev_key->ch4_ip.src_address = key->ch4_ip.dst_address;
  rev_key->ch4_ip.dst_address = key->ch4_ip.src_address;

  rev_key->ch4_ip.protocol = key->ch4_ip.protocol;

  rev_key->ch4_l4.src_port = key->ch4_l4.dst_port;
  rev_key->ch4_l4.dst_port = key->ch4_l4.src_port;
}

static_always_inline void
conn_hdr_ip6_reverse (const conn_hdr_ip6_t * key, conn_hdr_ip6_t * rev_key)
{
  rev_key->ch6_ip.src_address = key->ch6_ip.dst_address;
  rev_key->ch6_ip.dst_address = key->ch6_ip.src_address;

  rev_key->ch6_ip.protocol = key->ch6_ip.protocol;

  rev_key->ch6_l4.src_port = key->ch6_l4.dst_port;
  rev_key->ch6_l4.dst_port = key->ch6_l4.src_port;
}

static_always_inline void
conn_db_session_del (const conn_db_t * conn_db, const conn_t * conn)
{
  vnet_classify_add_del_session (&vnet_classify_main,
				 conn_db->cd_table,
				 (u8 *) & conn->c_keys[CONN_DIR_FORWARD],
				 0, 0, 0, 0, 0, 0);
  vnet_classify_add_del_session (&vnet_classify_main,
				 conn_db->cd_table,
				 (u8 *) & conn->c_keys[CONN_DIR_REVERSE],
				 0, 0, 0, 0, 0, 0);
}

static_always_inline void
conn_db_session_add (const conn_db_t * conn_db,
		     const conn_t * conn, index_t conni, u16 thread_index)
{
  int rv;
  rv = vnet_classify_add_del_session (&vnet_classify_main,
				      conn_db->cd_table,
				      (u8 *) & conn->c_keys[CONN_DIR_FORWARD],
				      ~0 /* hit_next_index */ ,
				      conni, 0 /* advance */ ,
				      0 /* action */ ,
				      thread_index /* metadata */ ,
				      1);
  ASSERT (0 == rv);

  rv = vnet_classify_add_del_session (&vnet_classify_main,
				      conn_db->cd_table,
				      (u8 *) & conn->c_keys[CONN_DIR_REVERSE],
				      ~0 /* hit_next_index */ ,
				      conni, 0 /* advance */ ,
				      0 /* action */ ,
				      thread_index /* metadata */ ,
				      1);
  ASSERT (0 == rv);
}

static_always_inline index_t
conn_track_ip4_add (index_t cdbi,
		    u32 thread_index,
		    conn_owner_t owner,
		    const ip4_header_t * hdr, conn_hash_t chash, f64 now)
{
  conn_db_per_thread_t *per_thread;
  conn_hdr_ip4_t rev_key;
  conn_db_t *conn_db;
  index_t conni;
  conn_t *conn;
  u32 slot;

  conn_db = conn_db_get (cdbi);
  per_thread = &conn_db->cd_per_thread[thread_index];
  per_thread->cdpt_n_adds++;

  /* pick a connection to [re]use, which is the last one in the sieve */
  conni = conn_age_sieve_rotate (&per_thread->cdpt_sieve, &slot, now);

  if (INDEX_INVALID != conni)
    {
      conn = conn_get (conn_db, conni);

      /* clear out the old sessions */
      if (!(conn->c_flags & CONN_FLAG_STALE))
	clib_bitmap_set (conn_db->cd_owners[conn->c_owner], conni, 0);

      conn_db_session_del (conn_db, conn);

      /* Create the new sessions */
      conn->c_sieve_slot = slot;
      conn->c_owner = owner;
      conn->c_flags &= ~CONN_FLAG_STALE;
      clib_bitmap_set (conn_db->cd_owners[conn->c_owner], conni, 1);

      conn_hdr_ip4_reverse ((conn_hdr_ip4_t *) hdr, &rev_key);

      clib_memcpy_fast (&conn->c_keys[CONN_DIR_FORWARD], hdr,
			sizeof (conn_hdr_ip4_t));
      clib_memcpy_fast (&conn->c_keys[CONN_DIR_REVERSE], &rev_key,
			sizeof (conn_hdr_ip4_t));

      conn_db_session_add (conn_db, conn, conni, thread_index);
    }

  return (conni);
}

static_always_inline index_t
conn_track_ip6_add (index_t cdbi,
		    u32 thread_index,
		    conn_owner_t owner,
		    const ip6_header_t * hdr, conn_hash_t chash, f64 now)
{
  conn_db_per_thread_t *per_thread;
  conn_hdr_ip6_t rev_key;
  conn_db_t *conn_db;
  index_t conni;
  conn_t *conn;
  u32 slot;

  conn_db = conn_db_get (cdbi);
  per_thread = &conn_db->cd_per_thread[thread_index];
  per_thread->cdpt_n_adds++;

  /* pick a connection to [re]use, which is the last one in the sieve */
  conni = conn_age_sieve_rotate (&per_thread->cdpt_sieve, &slot, now);

  if (INDEX_INVALID != conni)
    {
      conn = conn_get (conn_db, conni);

      /* clear out the old sessions */
      if (!(conn->c_flags & CONN_FLAG_STALE))
	clib_bitmap_set (conn_db->cd_owners[conn->c_owner], conni, 0);

      conn_db_session_del (conn_db, conn);

      /* Create the new sessions */
      conn->c_sieve_slot = slot;
      conn->c_owner = owner;
      conn->c_flags &= ~CONN_FLAG_STALE;
      clib_bitmap_set (conn_db->cd_owners[conn->c_owner], conni, 1);

      conn_hdr_ip6_reverse ((conn_hdr_ip6_t *) hdr, &rev_key);

      clib_memcpy_fast (&conn->c_keys[CONN_DIR_FORWARD], hdr,
			sizeof (conn_hdr_ip6_t));
      clib_memcpy_fast (&conn->c_keys[CONN_DIR_REVERSE], &rev_key,
			sizeof (conn_hdr_ip6_t));

      conn_db_session_add (conn_db, conn, conni, thread_index);
    }

  return (conni);
}

static_always_inline index_t
conn_track_add (index_t cdbi,
		u32 thread_index,
		conn_owner_t owner,
		ip_address_family_t af,
		const u8 * hdr, conn_hash_t chash, f64 now)
{
  if (AF_IP4 == af)
    return (conn_track_ip4_add (cdbi, thread_index, owner,
				(ip4_header_t *) hdr, chash, now));
  else
    return (conn_track_ip6_add (cdbi, thread_index, owner,
				(ip6_header_t *) hdr, chash, now));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
