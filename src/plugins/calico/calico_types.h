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

#ifndef __CALICO_TYPES_H__
#define __CALICO_TYPES_H__

#include <vnet/fib/fib_node.h>
#include <vnet/fib/fib_source.h>
#include <vnet/ip/ip_types.h>

/* only in the default table for v4 and v6 */
#define CALICO_FIB_TABLE 0

/* default lifetime of NAT sessions (seconds) */
#define CALICO_DEFAULT_SESSION_MAX_AGE 30
/* lifetime of TCP conn NAT sessions after SYNACK (seconds) */
#define CALICO_DEFAULT_TCP_MAX_AGE 3600
/* lifetime of TCP conn NAT sessions after RST/FIN (seconds) */
#define CALICO_DEFAULT_TCP_RST_TIMEOUT 5
#define CALICO_DEFAULT_SCANNER_TIMEOUT (1.0)

#define CALICO_DEFAULT_SESSION_BUCKETS     1024
#define CALICO_DEFAULT_SESSION_MEMORY     (1 << 20)

#define CALICO_DEFAULT_TRANSLATION_BUCKETS     1024
#define CALICO_DEFAULT_TRANSLATION_MEMORY     (256 << 10)

/* This should be strictly lower than FIB_SOURCE_INTERFACE
 * from fib_source.h */
#define CALICO_FIB_SOURCE_PRIORITY  0x02

/* Initial refcnt for timestamps (2 : session & rsession) */
#define CALICO_TIMESTAMP_INIT_REFCNT 2

typedef struct calico_endpoint_t_
{
  ip_address_t ce_ip;
  u16 ce_port;
} calico_endpoint_t;

typedef struct calico_endpoint_tuple_t_
{
  calico_endpoint_t dst_ep;
  calico_endpoint_t src_ep;
} calico_endpoint_tuple_t;

typedef struct calico_main_
{
  /* Memory size of the session bihash */
  uword session_hash_memory;

  /* Number of buckets of the  session bihash */
  u32 session_hash_buckets;

  /* Memory size of the translation bihash */
  uword translation_hash_memory;

  /* Number of buckets of the  translation bihash */
  u32 translation_hash_buckets;

  /* Timeout after which to clear sessions (in seconds) */
  u32 session_max_age;

  /* Timeout after which to clear an established TCP
   * session (in seconds) */
  u32 tcp_max_age;

  /* delay in seconds between two scans of session/clients tables */
  f64 scanner_timeout;

  /* Lock for the timestamp pool */
  clib_rwlock_t ts_lock;
} calico_main_t;

typedef struct calico_timestamp_t_
{
  /* Last time said session was seen */
  f64 last_seen;
  /* expire after N seconds */
  u16 lifetime;
  /* Users refcount, initially 3 (session, rsession, dpo) */
  u16 refcnt;
} calico_timestamp_t;

extern u8 *format_calico_endpoint (u8 * s, va_list * args);
extern calico_timestamp_t *calico_timestamps;
extern fib_source_t calico_fib_source;
extern calico_main_t calico_main;

always_inline u32
calico_timestamp_new (f64 t)
{
  u32 index;
  calico_timestamp_t *ts;
  clib_rwlock_writer_lock (&calico_main.ts_lock);
  pool_get (calico_timestamps, ts);
  ts->last_seen = t;
  ts->lifetime = calico_main.session_max_age;
  ts->refcnt = CALICO_TIMESTAMP_INIT_REFCNT;
  index = ts - calico_timestamps;
  clib_rwlock_writer_unlock (&calico_main.ts_lock);
  return index;
}

always_inline void
calico_timestamp_update (u32 index, f64 t)
{
  clib_rwlock_reader_lock (&calico_main.ts_lock);
  calico_timestamp_t *ts = pool_elt_at_index (calico_timestamps, index);
  ts->last_seen = t;
  clib_rwlock_reader_unlock (&calico_main.ts_lock);
}

always_inline void
calico_timestamp_set_lifetime (u32 index, u16 lifetime)
{
  clib_rwlock_reader_lock (&calico_main.ts_lock);
  calico_timestamp_t *ts = pool_elt_at_index (calico_timestamps, index);
  ts->lifetime = lifetime;
  clib_rwlock_reader_unlock (&calico_main.ts_lock);
}

always_inline f64
calico_timestamp_exp (u32 index)
{
  f64 t;
  if (INDEX_INVALID == index)
    return -1;
  clib_rwlock_reader_lock (&calico_main.ts_lock);
  calico_timestamp_t *ts = pool_elt_at_index (calico_timestamps, index);
  t = ts->last_seen + (f64) ts->lifetime;
  clib_rwlock_reader_unlock (&calico_main.ts_lock);
  return t;
}

always_inline void
calico_timestamp_free (u32 index)
{
  if (INDEX_INVALID == index)
    return;
  clib_rwlock_writer_lock (&calico_main.ts_lock);
  calico_timestamp_t *ts = pool_elt_at_index (calico_timestamps, index);
  if (0 == clib_atomic_sub_fetch (&ts->refcnt, 1))
    pool_put (calico_timestamps, ts);
  clib_rwlock_writer_unlock (&calico_main.ts_lock);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
