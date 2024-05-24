/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef __CNAT_SESSION_H__
#define __CNAT_SESSION_H__

#include <vnet/udp/udp_packet.h>

#include <cnat/cnat_types.h>
#include <cnat/cnat_client.h>
#include <cnat/cnat_bihash.h>

/**
 * A session represents the memory of a translation.
 * In the tx direction (from behind to in front of the NAT), the
 * session is preserved so subsequent packets follow the same path
 * even if the translation has been updated. In the tx direction
 * the session represents the swap from the VIP to the server address
 * In the RX direction the swap is from the server address/port to VIP.
 *
 * A session exists only as key and value in the bihash, there is no
 * pool for this object. If there were a pool, one would need to be
 * concerned about what worker is using it.
 */
typedef struct cnat_session_t_
{
  /**
   * this key sits in the same memory location a 'key' in the bihash kvp
   */
  union
  {
    struct
    {
      /**
       * IP 4/6 address, ports in the rx/tx direction & iproto
       */
      cnat_5tuple_t cs_5tuple;
      u32 fib_index;
    };
    u64 as_u64[6];
  } key;
  /**
   * this value sits in the same memory location a 'value' in the bihash kvp
   */
  union
  {
    struct
    {
      u32 cs_session_index;
      u32 cs_flags;
    };
    u64 as_u64;
  } value;
} cnat_session_t;

typedef enum cnat_ts_rewrite_flag_t_
{
  /**
   * This session source port was allocated, we should think about
   * freeing it on cleanup
   */
  CNAT_TS_RW_FLAG_HAS_ALLOCATED_PORT = (1 << 1),

  /* Do not actually translate the packet but still forward it
   * Used for Maglev, with an encap */
  CNAT_TS_RW_FLAG_NO_NAT = (1 << 3),

  /* if set cnat_cksum_diff_t->l3 contains the L3 cksum delta
   * that needs to be applied for the translation */
  CNAT_TS_RW_FLAG_CACHE_TS_L3 = (1 << 4),

  /* if set cnat_cksum_diff_t->l4 contains the L4 cksum delta
   * that needs to be applied for the translation */
  CNAT_TS_RW_FLAG_CACHE_TS_L4 = (1 << 5),

} cnat_ts_rewrite_flag_t;

typedef enum cnat_session_flag_t_
{
  /**
   * This session has a client, free it on delete
   */
  CNAT_SESSION_FLAG_HAS_CLIENT = (1 << 0),

  /* This is a return session */
  CNAT_SESSION_IS_RETURN = (1 << 4),

  /** On conflicts when adding the return session, try to sNAT the
   * forward session, and dNAT the return session with a random port */
  CNAT_SESSION_RETRY_SNAT = (1 << 5),

} cnat_session_flag_t;

/* flags for vnet_buffer(b)->session.flags */
typedef enum cnat_buffer_session_flag_t_
{
  /* do not create a return session in output */
  CNAT_BUFFER_SESSION_FLAG_NO_RETURN = (1 << 1),
} cnat_buffer_session_flag_t;
STATIC_ASSERT (CNAT_BUFFER_SESSION_FLAG_NO_RETURN < (1 << 4), "Value too big");

extern u8 *format_cnat_timestamp (u8 *s, va_list *args);
extern u8 *format_cnat_session (u8 * s, va_list * args);
extern u8 *format_cnat_session_flags (u8 *s, va_list *args);

/**
 * Ensure the session object correctly overlays the bihash key/value pair
 */
STATIC_ASSERT (STRUCT_OFFSET_OF (cnat_session_t, key) ==
		 STRUCT_OFFSET_OF (cnat_bihash_kv_t, key),
	       "key overlaps");
STATIC_ASSERT (STRUCT_OFFSET_OF (cnat_session_t, value) ==
		 STRUCT_OFFSET_OF (cnat_bihash_kv_t, value),
	       "value overlaps");
STATIC_ASSERT (sizeof (cnat_session_t) == sizeof (cnat_bihash_kv_t),
	       "session kvp");

/**
 * The DB of sessions
 */
extern cnat_bihash_t cnat_session_db;

/**
 * Callback function invoked during a walk of all translations
 */
typedef walk_rc_t (*cnat_session_walk_cb_t) (const cnat_session_t *
					     session, void *ctx);

/**
 * Walk/visit each of the cnat session
 */
extern void cnat_session_walk (cnat_session_walk_cb_t cb, void *ctx);

/**
 * Scan the session DB for expired sessions
 */
extern u64 cnat_session_scan (vlib_main_t * vm, f64 start_time, int i);

/**
 * Purge all the sessions
 */
extern int cnat_session_purge (void);

/**
 * Free a session & update refcounts
 */
extern void cnat_session_free (cnat_session_t * session);

/**
 * Hash callback for session overwrite
 */
extern void cnat_session_free_stale_cb (cnat_bihash_kv_t *kv, void *opaque);

/**
 * Port cleanup callback
 */
extern void (*cnat_free_port_cb) (u32 fib_index, u16 port, ip_protocol_t iproto);

#endif
