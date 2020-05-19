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
#include <vnet/ip/ip.h>

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
#define CALICO_DEFAULT_TRANSLATION_BUCKETS 1024
#define CALICO_DEFAULT_SNAT_BUCKETS        1024

#define CALICO_DEFAULT_SESSION_MEMORY      (1 << 20)
#define CALICO_DEFAULT_TRANSLATION_MEMORY  (256 << 10)
#define CALICO_DEFAULT_SNAT_MEMORY         (64 << 20)

/* This should be strictly lower than FIB_SOURCE_INTERFACE
 * from fib_source.h */
#define CALICO_FIB_SOURCE_PRIORITY  0x02

/* Initial refcnt for timestamps (2 : session & rsession) */
#define CALICO_TIMESTAMP_INIT_REFCNT 2

#define MIN_SRC_PORT ((u16) 0xC000)

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



typedef struct
{
  u32 dst_address_length_refcounts[129];
  u16 *prefix_lengths_in_search_order;
  uword *non_empty_dst_address_length_bitmap;
} calico_snat_pfx_table_meta_t;

typedef struct
{
  /* Stores (ip family, prefix & mask) */
  clib_bihash_24_8_t ip_hash;
  /* family dependant cache */
  calico_snat_pfx_table_meta_t meta[2];
  /* Precomputed ip masks (ip4 & ip6) */
  ip6_address_t ip_masks[129];
} calico_snat_pfx_table_t;

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

  /* Memory size of the source NAT prefix bihash */
  uword snat_hash_memory;

  /* Number of buckets of the  source NAT prefix bihash */
  u32 snat_hash_buckets;

  /* Timeout after which to clear sessions (in seconds) */
  u32 session_max_age;

  /* Timeout after which to clear an established TCP
   * session (in seconds) */
  u32 tcp_max_age;

  /* delay in seconds between two scans of session/clients tables */
  f64 scanner_timeout;

  /* Lock for the timestamp pool */
  clib_rwlock_t ts_lock;

  /* Source ports bitmap for snat */
  clib_bitmap_t *src_ports;

  /* Lock for src_ports access */
  clib_spinlock_t src_ports_lock;

  /* Ip4 Address to use for source NATing */
  ip4_address_t snat_ip4;

  /* Ip6 Address to use for source NATing */
  ip6_address_t snat_ip6;

  /* Longest prefix Match table for source NATing */
  calico_snat_pfx_table_t snat_pfx_table;
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

typedef struct calico_node_ctx_t_
{
  f64 now;
  u64 seed;
  u32 thread_index;
  ip_address_family_t af;
  u8 do_trace;
} calico_node_ctx_t;

extern u8 *format_calico_endpoint (u8 * s, va_list * args);
extern uword unformat_calico_ep_tuple (unformat_input_t * input,
				       va_list * args);
extern uword unformat_calico_ep (unformat_input_t * input, va_list * args);
extern calico_timestamp_t *calico_timestamps;
extern fib_source_t calico_fib_source;
extern calico_main_t calico_main;
extern throttle_t calico_throttle;

extern char *calico_error_strings[];

typedef enum
{
#define calico_error(n,s) CALICO_ERROR_##n,
#include <calico/calico_error.def>
#undef calico_error
  CALICO_N_ERROR,
} calico_error_t;

/*
  Dataplane functions
*/

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
  return;
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

always_inline void
calico_free_port (u16 port)
{
  calico_main_t *cm = &calico_main;
  clib_spinlock_lock (&cm->src_ports_lock);
  clib_bitmap_set_no_check (cm->src_ports, port, 0);
  clib_spinlock_unlock (&cm->src_ports_lock);
}

always_inline int
calico_allocate_port (calico_main_t * cm, u16 * port)
{
  *port = clib_net_to_host_u16 (*port);
  if (*port == 0)
    *port = MIN_SRC_PORT;
  clib_spinlock_lock (&cm->src_ports_lock);
  if (clib_bitmap_get_no_check (cm->src_ports, *port))
    {
      *port = clib_bitmap_next_clear (cm->src_ports, *port);
      if (PREDICT_FALSE (*port >= UINT16_MAX))
	*port = clib_bitmap_next_clear (cm->src_ports, MIN_SRC_PORT);
      if (PREDICT_FALSE (*port >= UINT16_MAX))
	return -1;
    }
  clib_bitmap_set_no_check (cm->src_ports, *port, 1);
  *port = clib_host_to_net_u16 (*port);
  clib_spinlock_unlock (&cm->src_ports_lock);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
