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

#include <vppinfra/bihash_24_8.h>
#include <vnet/fib/fib_node.h>
#include <vnet/fib/fib_source.h>
#include <vnet/ip/ip_types.h>
#include <vnet/ip/ip.h>
#include <vnet/util/throttle.h>

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
#define CNAT_DEFAULT_SNAT_IF_MAP_LEN	 4096

#define CNAT_DEFAULT_SESSION_MEMORY      (1 << 20)
#define CNAT_DEFAULT_TRANSLATION_MEMORY  (256 << 10)
#define CNAT_DEFAULT_SNAT_MEMORY         (64 << 20)

/* Should be prime >~ 100 * numBackends */
#define CNAT_DEFAULT_MAGLEV_LEN 1009

/* This should be strictly lower than FIB_SOURCE_INTERFACE
 * from fib_source.h */
#define CNAT_FIB_SOURCE_PRIORITY  0x02

/* Initial refcnt for timestamps (2 : session & rsession) */
#define CNAT_TIMESTAMP_INIT_REFCNT 2

#define MIN_SRC_PORT ((u16) 0xC000)

typedef enum cnat_trk_flag_t_
{
  /* Endpoint is active (static or dhcp resolved) */
  CNAT_TRK_ACTIVE = (1 << 0),
  /* Don't translate this endpoint, but still
   * forward. Used by maglev for DSR */
  CNAT_TRK_FLAG_NO_NAT = (1 << 1),
} cnat_trk_flag_t;

typedef enum
{
  /* Endpoint addr has been resolved */
  CNAT_EP_FLAG_RESOLVED = (1 << 0),
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
  u8 ep_flags; /* cnat_trk_flag_t */
} cnat_endpoint_tuple_t;

typedef struct
{
  u16 identifier;
  u16 sequence;
} cnat_echo_header_t;

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

  /* Bit map for include / exclude sw_if_index
   * so max number of expected interfaces */
  u32 snat_if_map_length;

  /* Timeout after which to clear sessions (in seconds) */
  u32 session_max_age;

  /* Timeout after which to clear an established TCP
   * session (in seconds) */
  u32 tcp_max_age;

  /* delay in seconds between two scans of session/clients tables */
  f64 scanner_timeout;

  /* Lock for the timestamp pool */
  clib_rwlock_t ts_lock;

  /* Index of the scanner process node */
  uword scanner_node_index;

  /* Did we do lazy init ? */
  u8 lazy_init_done;

  /* Enable or Disable the scanner on startup */
  u8 default_scanner_state;

  /* Number of buckets for maglev, should be a
   * prime >= 100 * max num bakends */
  u32 maglev_len;
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
