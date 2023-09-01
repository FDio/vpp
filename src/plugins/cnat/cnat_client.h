/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef __CNAT_CLIENT_H__
#define __CNAT_CLIENT_H__

#include <cnat/cnat_types.h>
#include <vppinfra/bihash_24_8.h>

/**
 * A client is a representation of an IP address behind the NAT.
 * A client thus sends packet to a VIP.
 * Clients are learned in the Data-plane when they send packets,
 * but, since they make additions to the FIB they must be programmed
 * in the main thread. They are aged out when they become idle.
 *
 * A client interposes in the FIB graph for the prefix corresponding
 * to the client (e.g. client's-IP/32). As a result this client object
 * is cloned as the interpose DPO. The clones are removed when the lock
 * count drops to zero. The originals are removed when the client ages.
 * At forwarding time the client preforms the reverse translation and
 * then ships the packet to where the FIB would send it.
 */
typedef struct cnat_client_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * the client's IP address
   */
  ip_address_t cc_ip;

  /**
   * How to send packets to this client post translation
   */
  dpo_id_t cc_parent;

  /**
   * the FIB entry this client sources
   */
  fib_node_index_t cc_fei;

  /**
   * number of DPO locks
   */
  u32 cc_locks;

  /**
   * Translations refcount for cleanup
   */
  u32 tr_refcnt;

  /**
   * Session refcount for cleanup
   */
  u32 session_refcnt;

  /**
   * Parent cnat_client index if cloned via interpose
   * or own index if vanilla client.
   * Used to get translations & update session_refcnt
   */
  index_t parent_cci;

  /**
   * Client flags
   */
  u8 flags;
} cnat_client_t;

typedef struct cnat_client_learn_args_t_
{
  ip_address_t addr;
  u32 fib_index;
} cnat_client_learn_args_t;

extern u8 *format_cnat_client (u8 * s, va_list * args);
extern void cnat_client_free_by_ip (ip4_address_t *ip4, ip6_address_t *ip6, u8 af, u32 fib_index,
				    int is_session);

extern cnat_client_t *cnat_client_pool;
extern dpo_type_t cnat_client_dpo;

static_always_inline cnat_client_t *
cnat_client_get (index_t i)
{
  return (pool_elt_at_index (cnat_client_pool, i));
}

/**
 * A translation that references this VIP was deleted
 */
extern void cnat_client_translation_deleted (index_t cci, u32 fib_index);

/**
 * A translation that references this VIP was added
 */
extern void cnat_client_translation_added (index_t cci);
/**
 * Called in the main thread by RPC from the workers to learn a
 * new client
 */
extern void cnat_client_learn (const cnat_client_learn_args_t *args);

extern index_t cnat_client_add_pfx (const ip_address_t *pfx, u8 pfx_len, u32 fib_index, u8 flags);
extern index_t cnat_client_add (const ip_address_t *ip, u32 fib_index, u8 flags);

/**
 * Check all the clients were purged by translation & session purge
 */
extern int cnat_client_purge (void);

extern void cnat_client_throttle_pool_process ();

/**
 * DB of clients
 */
typedef struct cnat_client_db_t_
{
  clib_bihash_24_8_t cc_ip_id_hash;
  /* Pool of addresses that have been throttled
     and need to be refcounted before calling
     cnat_client_free_by_ip */
  clib_spinlock_t throttle_lock;
  uword *throttle_mem;
} cnat_client_db_t;

extern cnat_client_db_t cnat_client_db;

/**
 * Find a client from an IP4 address
 */
static_always_inline cnat_client_t *
cnat_client_ip4_find (const ip4_address_t *ip, u32 fib_index)
{
  clib_bihash_kv_24_8_t bkey, bval;

  bkey.key[0] = ip->as_u32;
  bkey.key[1] = 0;
  bkey.key[2] = fib_index;

  if (clib_bihash_search_24_8 (&cnat_client_db.cc_ip_id_hash, &bkey, &bval))
    return (NULL);

  return (pool_elt_at_index (cnat_client_pool, bval.value));
}

/**
 * Find a client from an IP6 address
 */
static_always_inline cnat_client_t *
cnat_client_ip6_find (const ip6_address_t *ip, u32 fib_index)
{
  clib_bihash_kv_24_8_t bkey, bval;

  bkey.key[0] = ip->as_u64[0];
  bkey.key[1] = ip->as_u64[1];
  bkey.key[2] = fib_index;

  if (clib_bihash_search_24_8 (&cnat_client_db.cc_ip_id_hash, &bkey, &bval))
    return (NULL);

  return (pool_elt_at_index (cnat_client_pool, bval.value));
}

/**
 * Add a session refcnt to this client
 */
static_always_inline u32
cnat_client_cnt_session (cnat_client_t * cc)
{
  cnat_client_t *ccp = cnat_client_get (cc->parent_cci);
  return clib_atomic_add_fetch (&ccp->session_refcnt, 1);
}

/**
 * Del a session refcnt to this client
 */
static_always_inline u32
cnat_client_uncnt_session (cnat_client_t * cc)
{
  cnat_client_t *ccp = cnat_client_get (cc->parent_cci);
  return clib_atomic_sub_fetch (&ccp->session_refcnt, 1);
}
#endif
