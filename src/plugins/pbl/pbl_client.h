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

#ifndef __PBL_CLIENT_H__
#define __PBL_CLIENT_H__

#include <vnet/ip/ip_types.h>

/* only in the default table for v4 and v6 */
#define PBL_FIB_TABLE 0

/* This should be strictly lower than FIB_SOURCE_INTERFACE
 * from fib_source.h */
#define PBL_FIB_SOURCE_PRIORITY FIB_SOURCE_SPECIAL

/**
 * A Translation represents the client of a VEP to one of a set
 * of real server addresses
 */
typedef struct pbl_client_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Linkage into the FIB graph */
  fib_node_t pc_node;

  /**
   * FIB hook for intercepting traffic
   */

  /* The address we intercept traffic to */
  ip_address_t pc_addr;

  /* How to send packets to this client post client */
  dpo_id_t pc_parent;

  /* the FIB entry this client sources */
  fib_node_index_t pc_fei;

  /* number of DPO locks */
  u32 pc_locks;

  /**
   * Parent pbl_client index if cloned via interpose
   * or own index if vanilla client.
   * Used to get clients & update session_refcnt
   */
  index_t clone_pci;

  /* Matched ports that will forward to pc_dpo */
  clib_bitmap_t *pc_port_map;

  /**
   * Forwarding
   */

  /* Sibling index on the path-list */
  u32 pc_sibling;

  /* The DPO actually used for forwarding */
  dpo_id_t pc_dpo;

  /* The path-list describing how to forward in case of a match */
  fib_node_index_t pc_pl;

  /* Own index (if copied for trace) */
  index_t pc_index;

  /* Client flags */
  u8 flags;

} pbl_client_t;

typedef enum pbl_client_flag_t_
{
  /* Has this translation been satcked ?
   * this allow not being called twice when
   * with more then FIB_PATH_LIST_POPULAR backends  */
  PBL_CLIENT_STACKED = (1 << 0),
} pbl_client_flag_t;

extern pbl_client_t *pbl_client_pool;

/**
 * create or update a client
 *
 * @param vip The Virtual Endpoint
 * @param ip_proto The ip protocol to translate
 * @param backends the backends to choose from
 *
 * @return the ID of the client. used to delete and gather stats
 */
extern u32 pbl_client_update (index_t pci, ip_address_t *addr,
			      clib_bitmap_t *port_map, u8 flags,
			      fib_route_path_t *rpaths);

/**
 * Delete a client
 *
 * @param id the ID as returned from the create
 */
extern int pbl_client_delete (u32 id);

/**
 * Callback function invoked during a walk of all clients
 */
typedef walk_rc_t (*pbl_client_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the clients
 */
extern void pbl_client_walk (pbl_client_walk_cb_t cb, void *ctx);

/**
 * Purge all the trahslations
 */
extern int pbl_client_purge (void);

/*
 * Data plane functions
 */

static_always_inline pbl_client_t *
pbl_client_get (index_t cti)
{
  return (pool_elt_at_index (pbl_client_pool, cti));
}

static_always_inline pbl_client_t *
pbl_client_get_if_exists (index_t cti)
{
  if (pool_is_free_index (pbl_client_pool, cti))
    return (NULL);
  return (pool_elt_at_index (pbl_client_pool, cti));
}

typedef enum
{
  /* IP already present in the FIB, need to interpose dpo */
  PBL_FLAG_EXCLUSIVE = (1 << 1),
} pbl_entry_flag_t;

/**
 * DB of clients
 */
typedef struct pbl_client_db_t_
{
  uword *crd_cip4;
  uword *crd_cip6;
  /* Pool of addresses that have been throttled
     and need to be refcounted before calling
     pbl_client_free_by_ip */
  clib_spinlock_t throttle_lock;
  uword *throttle_mem;
} pbl_client_db_t;

extern pbl_client_db_t pbl_client_db;

/**
 * Find a client from an IP4 address
 */
static_always_inline pbl_client_t *
pbl_client_ip4_find (const ip4_address_t *ip)
{
  uword *p;

  p = hash_get (pbl_client_db.crd_cip4, ip->as_u32);

  if (p)
    return (pool_elt_at_index (pbl_client_pool, p[0]));

  return (NULL);
}

static_always_inline u32
pbl_client_ip4_find_index (const ip4_address_t *ip)
{
  uword *p;

  p = hash_get (pbl_client_db.crd_cip4, ip->as_u32);

  if (p)
    return p[0];

  return -1;
}

/**
 * Find a client from an IP6 address
 */
static_always_inline pbl_client_t *
pbl_client_ip6_find (const ip6_address_t *ip)
{
  uword *p;

  p = hash_get_mem (pbl_client_db.crd_cip6, ip);

  if (p)
    return (pool_elt_at_index (pbl_client_pool, p[0]));

  return (NULL);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
