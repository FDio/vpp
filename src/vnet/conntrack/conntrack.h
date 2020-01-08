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

#ifndef __CONN_TRACK_H__
#define __CONN_TRACK_H__

#include <vnet/ip/ip.h>
#include <vnet/classify/vnet_classify.h>

typedef u32 conn_owner_t;

typedef u32 conn_db_id_t;

/**
 * connection tracking directions.
 *  forward - the direction in which the connections are checked and added
 *  reverse - the direction in which the connection are only checked
 * This direction is orthoganal to, e.g. the interfaces ingress/rx, egress/tx
 */
#define foreach_conn_dir                        \
  _(FORWARD, "forward")                         \
  _(REVERSE, "reverse")                         \

typedef enum conn_dir_t_
{
#define _(a,b) CONN_DIR_##a,
  foreach_conn_dir
#undef _
} __clib_packed conn_dir_t;

#define CONN_N_DIR (CONN_DIR_REVERSE+1)

#define FOR_EACH_CONN_DIR(_dir) \
  for (_dir = CONN_DIR_FORWARD; _dir <= CONN_DIR_REVERSE; _dir++)

extern u8 *format_conn_dir (u8 * s, va_list * a);

typedef struct conn_ip4_hdr_t_
{
  ip4_header_t ch4_ip;
  udp_header_t ch4_l4;
  u8 __ch4_pad[4];
} conn_hdr_ip4_t;

STATIC_ASSERT_SIZEOF (conn_hdr_ip4_t, 2 * VNET_CLASSIFY_VECTOR_SIZE);

typedef struct conn_hdr_ip6_t_
{
  ip6_header_t ch6_ip;
  udp_header_t ch6_l4;
} conn_hdr_ip6_t;

STATIC_ASSERT_SIZEOF (conn_hdr_ip6_t, 3 * VNET_CLASSIFY_VECTOR_SIZE);

typedef union conn_key_t_
{
  conn_hdr_ip4_t ck_ip4;
  conn_hdr_ip6_t ck_ip6;
} conn_key_t;

#define foreach_conn_flag \
  _(STALE, 1, "stale")    \

typedef enum conn_flags_t_
{
#define _(a,b,c) CONN_FLAG_##a = b,
  foreach_conn_flag
#undef _
} conn_flags_t;

typedef struct conn_t_
{
  conn_key_t c_keys[CONN_N_DIR];
  u32 c_sieve_slot;
  conn_owner_t c_owner;
  conn_flags_t c_flags;
  u32 c_thread;
  // stats ?
} conn_t;

typedef struct conn_age_sieve_bucket_t_
{
  f64 casb_time;
  u32 casb_conn;
} conn_age_sieve_bucket_t;

typedef struct conn_age_sieve_t_
{
  u32 cas_head;
  u32 cas_tail;
  u32 cas_size;
  u32 cas_mask;
  u8 cas_counter;
  conn_age_sieve_bucket_t *cas_buckets;
} conn_age_sieve_t;

typedef struct conn_db_per_thread_t_
{
  u64 cdpt_n_adds;
  conn_age_sieve_t cdpt_sieve;
} conn_db_per_thread_t;

typedef enum conn_db_flags_t_
{
  CONN_DB_FLAG_NONE,
} conn_db_flags_t;

typedef struct conn_db_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  conn_db_per_thread_t *cd_per_thread;

  /* memory pool/vector for all the connections */
  conn_t *cd_conns;

  /* index of the vnet-classifier table that backs this DB */
  index_t cd_table;

  /** Bitmaps of who owns which connections */
  clib_bitmap_t **cd_owners;

  /*
   * CP only
   */

  /**
   * vnet-classifier mask that describes connections in this DB
   */
  const u8 *cd_mask;

  u8 *cd_tag;

  ip_address_family_t cd_af;
  conn_db_id_t cd_id;
  u32 cd_max;
  u32 cd_locks;

} conn_db_t;

extern conn_db_t *conn_db_pool;


extern u8 *format_conn_db (u8 * s, va_list * a);


typedef u32 conn_user_t;

extern conn_user_t conn_track_user_add (const char *user);

extern index_t conn_track_add_or_lock (conn_user_t user,
				       conn_db_id_t id,
				       u8 * tag,
				       ip_address_family_t af,
				       u32 n_conns_per_thread,
				       conn_db_flags_t flags);
extern void conn_track_unlock (conn_db_id_t id);
extern void conn_track_lock (conn_db_id_t id);

extern void conn_db_unlock (index_t * cdbi);
extern void conn_db_lock (index_t cdbi);


extern conn_owner_t conn_track_owner_add (index_t cdbi);
extern void conn_track_owner_flush (index_t cdbi, conn_owner_t owner);

static_always_inline conn_db_t *
conn_db_get (index_t cdbi)
{
  return (pool_elt_at_index (conn_db_pool, cdbi));
}

static_always_inline conn_t *
conn_get (conn_db_t * conn_db, index_t conni)
{
  return (&conn_db->cd_conns[conni]);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
