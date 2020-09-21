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

#ifndef __CNAT_TYPES_H__
#define __CNAT_TYPES_H__

#include <vnet/fib/fib_node.h>
#include <vnet/fib/fib_source.h>
#include <vnet/ip/ip_types.h>
#include <vnet/ip/ip.h>

/* only in the default table for v4 and v6 */
#define CNAT_FIB_TABLE 0

/* default lifetime of NAT sessions (seconds) */
#define CNAT_DEFAULT_SESSION_MAX_AGE 30
/* lifetime of TCP conn NAT sessions after SYNACK (seconds) */
#define CNAT_DEFAULT_TCP_MAX_AGE 3600
/* lifetime of TCP conn NAT sessions after RST/FIN (seconds) */
#define CNAT_DEFAULT_TCP_RST_TIMEOUT 5
#define CNAT_DEFAULT_SCANNER_TIMEOUT (1.0)

#define CNAT_DEFAULT_SESSION_BUCKETS     1024
#define CNAT_DEFAULT_TRANSLATION_BUCKETS 1024
#define CNAT_DEFAULT_SNAT_BUCKETS        1024

#define CNAT_DEFAULT_SESSION_MEMORY      (1 << 20)
#define CNAT_DEFAULT_TRANSLATION_MEMORY  (256 << 10)
#define CNAT_DEFAULT_SNAT_MEMORY         (64 << 20)

/* This should be strictly lower than FIB_SOURCE_INTERFACE
 * from fib_source.h */
#define CNAT_FIB_SOURCE_PRIORITY  0x02

/* Initial refcnt for timestamps (2 : session & rsession) */
#define CNAT_TIMESTAMP_INIT_REFCNT 2

#define MIN_SRC_PORT ((u16) 0xC000)

typedef enum
{
  /* Endpoint addr has been resolved */
  CNAT_EP_FLAG_RESOLVED = 1,
} cnat_ep_flag_t;

typedef struct cnat_endpoint_t_
{
  ip_address_t ce_ip;
  u32 ce_sw_if_index;
  u16 ce_port;
  u8 ce_flags;
} cnat_endpoint_t;

typedef struct cnat_endpoint_tuple_t_
{
  cnat_endpoint_t dst_ep;
  cnat_endpoint_t src_ep;
} cnat_endpoint_tuple_t;

typedef struct
{
  u16 identifier;
  u16 sequence;
} cnat_echo_header_t;

typedef struct
{
  u32 dst_address_length_refcounts[129];
  u16 *prefix_lengths_in_search_order;
  uword *non_empty_dst_address_length_bitmap;
} cnat_snat_pfx_table_meta_t;

typedef struct
{
  /* Stores (ip family, prefix & mask) */
  clib_bihash_24_8_t ip_hash;
  /* family dependant cache */
  cnat_snat_pfx_table_meta_t meta[2];
  /* Precomputed ip masks (ip4 & ip6) */
  ip6_address_t ip_masks[129];
} cnat_snat_pfx_table_t;

typedef struct cnat_main_
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

  /* Ip4 Address to use for source NATing */
  cnat_endpoint_t snat_ip4;

  /* Ip6 Address to use for source NATing */
  cnat_endpoint_t snat_ip6;

  /* Longest prefix Match table for source NATing */
  cnat_snat_pfx_table_t snat_pfx_table;

  /* Index of the scanner process node */
  uword scanner_node_index;

  /* Did we do lazy init ? */
  u8 lazy_init_done;

  /* Enable or Disable the scanner on startup */
  u8 default_scanner_state;
} cnat_main_t;

typedef struct cnat_timestamp_t_
{
  /* Last time said session was seen */
  f64 last_seen;
  /* expire after N seconds */
  u16 lifetime;
  /* Users refcount, initially 3 (session, rsession, dpo) */
  u16 refcnt;
} cnat_timestamp_t;

typedef struct cnat_node_ctx_
{
  f64 now;
  u64 seed;
  u32 thread_index;
  ip_address_family_t af;
  u8 do_trace;
} cnat_node_ctx_t;

cnat_main_t *cnat_get_main ();
extern u8 *format_cnat_endpoint (u8 * s, va_list * args);
extern uword unformat_cnat_ep_tuple (unformat_input_t * input,
				     va_list * args);
extern uword unformat_cnat_ep (unformat_input_t * input, va_list * args);
extern cnat_timestamp_t *cnat_timestamps;
extern fib_source_t cnat_fib_source;
extern cnat_main_t cnat_main;
extern throttle_t cnat_throttle;

extern char *cnat_error_strings[];

typedef enum
{
#define cnat_error(n,s) CNAT_ERROR_##n,
#include <cnat/cnat_error.def>
#undef cnat_error
  CNAT_N_ERROR,
} cnat_error_t;

typedef enum cnat_scanner_cmd_t_
{
  CNAT_SCANNER_OFF,
  CNAT_SCANNER_ON,
} cnat_scanner_cmd_t;

/**
 * Lazy initialization when first adding a translation
 * or using snat
 */
extern void cnat_lazy_init ();

/**
 * Enable/Disable session cleanup
 */
extern void cnat_enable_disable_scanner (cnat_scanner_cmd_t event_type);

/**
 * Resolve endpoint address
 */
extern u8 cnat_resolve_ep (cnat_endpoint_t * ep);
extern u8 cnat_resolve_addr (u32 sw_if_index, ip_address_family_t af,
			     ip_address_t * addr);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
