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

#ifndef __CNAT_CLIENT_H__
#define __CNAT_CLIENT_H__

#include <cnat/cnat_types.h>
#include <vppinfra/bihash_16_8.h>

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

extern u8 *format_cnat_client (u8 * s, va_list * args);
extern void cnat_client_free_by_ip (ip46_address_t * addr, u8 af);

extern cnat_client_t *cnat_client_pool;
extern dpo_type_t cnat_client_dpo;

#define CC_INDEX_INVALID ((u32)(~0))

static_always_inline cnat_client_t *
cnat_client_get (index_t i)
{
  return (pool_elt_at_index (cnat_client_pool, i));
}

/**
 * A translation that references this VIP was deleted
 */
extern void cnat_client_translation_deleted (index_t cci);

/**
 * A translation that references this VIP was added
 */
extern void cnat_client_translation_added (index_t cci);
/**
 * Called in the main thread by RPC from the workers to learn a
 * new client
 */
extern void cnat_client_learn (const ip_address_t *addr);

extern index_t cnat_client_add (const ip_address_t * ip, u8 flags);

/**
 * Check all the clients were purged by translation & session purge
 */
extern int cnat_client_purge (void);

/**
 * CNat Client (dpo) flags
 */
typedef enum
{
  /* IP already present in the FIB, need to interpose dpo */
  CNAT_FLAG_EXCLUSIVE = (1 << 1),
} cnat_entry_flag_t;


extern void cnat_client_throttle_pool_process ();

/**
 * DB of clients
 */
typedef struct cnat_client_db_t_
{
  clib_bihash_16_8_t cc_ip_id_hash;
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
cnat_client_ip4_find (const ip4_address_t * ip)
{
  clib_bihash_kv_16_8_t bkey, bval;

  bkey.key[0] = ip->as_u32;
  bkey.key[1] = 0;

  if (clib_bihash_search_16_8 (&cnat_client_db.cc_ip_id_hash, &bkey, &bval))
    return (NULL);

  return (pool_elt_at_index (cnat_client_pool, bval.value));
}

/**
 * Find a client from an IP6 address
 */
static_always_inline cnat_client_t *
cnat_client_ip6_find (const ip6_address_t * ip)
{
  clib_bihash_kv_16_8_t bkey, bval;

  bkey.key[0] = ip->as_u64[0];
  bkey.key[1] = ip->as_u64[1];

  if (clib_bihash_search_16_8 (&cnat_client_db.cc_ip_id_hash, &bkey, &bval))
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
