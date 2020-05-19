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

#ifndef __CALICO_CLIENT_H__
#define __CALICO_CLIENT_H__

#include <calico/calico_types.h>

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
typedef struct calico_client_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * the client's IP address
   */
  ip_address_t cc_ip;

  /**
   * How to sned packets to this client post translation
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
   * Timestamp we last heard from this client
   */
  f64 cc_timestamp;
} calico_client_t;

extern u8 *format_calico_client (u8 * s, va_list * args);

extern calico_client_t *calico_client_pool;

static_always_inline calico_client_t *
calico_client_get (index_t i)
{
  return (pool_elt_at_index (calico_client_pool, i));
}

/**
 * Data sent from the workers to learn a new client
 */
typedef struct calico_client_learn_t_
{
  ip46_address_t cl_ip;
  ip_address_family_t cl_af;
  index_t cl_cti;
} calico_client_learn_t;

/**
 * Called in the main thread by RPC from the workers to learn a
 * new client
 */
extern void calico_client_learn (const calico_client_learn_t * l);

/**
 * Purge all the clients
 */
extern int calico_client_purge (void);

/**
 * Scan all the clients for idle ones and removes them
 */
extern void calico_client_scan (f64 now);


/*
 * Data-Plane functions
 */

/**
 * DB of clients
 */
typedef struct calico_client_db_t_
{
  uword *crd_cip4;
  uword *crd_cip6;
} calico_client_db_t;

extern calico_client_db_t calico_client_db;

/**
 * Find a client from an IP4 address
 */
static_always_inline calico_client_t *
calico_client_ip4_find (const ip4_address_t * ip)
{
  uword *p;

  p = hash_get (calico_client_db.crd_cip4, ip->as_u32);

  if (p)
    return (pool_elt_at_index (calico_client_pool, p[0]));

  return (NULL);
}

/**
 * Find a client from an IP6 address
 */
static_always_inline calico_client_t *
calico_client_ip6_find (const ip6_address_t * ip)
{
  uword *p;

  p = hash_get_mem (calico_client_db.crd_cip6, ip);

  if (p)
    return (pool_elt_at_index (calico_client_pool, p[0]));

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
