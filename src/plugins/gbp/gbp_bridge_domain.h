/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __GBP_BRIDGE_DOMAIN_H__
#define __GBP_BRIDGE_DOMAIN_H__

#include <plugins/gbp/gbp_types.h>

#include <vnet/fib/fib_types.h>

/**
 * Bridge Domain Flags
 */
typedef enum gbp_bridge_domain_flags_t_
{
  GBP_BD_FLAG_NONE = 0,
  GBP_BD_FLAG_DO_NOT_LEARN = (1 << 0),
} gbp_bridge_domain_flags_t;

/**
 * A bridge Domain Representation.
 * This is a standard bridge-domain plus all the attributes it must
 * have to supprt the GBP model.
 */
typedef struct gbp_bridge_domain_t_
{
  /**
   * Bridge-domain ID
   */
  u32 gb_bd_id;
  u32 gb_bd_index;

  /**
   * Flags conttrolling behaviour
   */
  gbp_bridge_domain_flags_t gb_flags;

  /**
   * The BD's BVI interface (obligatory)
   */
  u32 gb_bvi_sw_if_index;

  /**
   * The BD's MAC spine-proxy interface (optional)
   */
  u32 gb_uu_fwd_sw_if_index;

  /**
   * The BD's VNI interface on which packets from unkown endpoints
   * arrive
   */
  u32 gb_vni_sw_if_index;

  /**
   * locks/references to the BD so it does not get deleted (from the API)
   * whilst it is still being used
   */
  u32 gb_locks;
} gbp_bridge_domain_t;

extern int gbp_bridge_domain_add_and_lock (u32 bd_id,
					   gbp_bridge_domain_flags_t flags,
					   u32 bvi_sw_if_index,
					   u32 uu_fwd_sw_if_index);
extern void gbp_bridge_domain_unlock (index_t gbi);
extern index_t gbp_bridge_domain_find_and_lock (u32 bd_id);
extern int gbp_bridge_domain_delete (u32 bd_id);

typedef int (*gbp_bridge_domain_cb_t) (gbp_bridge_domain_t * gb, void *ctx);
extern void gbp_bridge_domain_walk (gbp_bridge_domain_cb_t bgpe, void *ctx);

extern u8 *format_gbp_bridge_domain (u8 * s, va_list * args);

/**
 * DB of bridge_domains
 */
typedef struct gbp_bridge_domain_db_t
{
  uword *gbd_by_bd_id;
  index_t *gbd_by_bd_index;
} gbp_bridge_domain_db_t;

extern gbp_bridge_domain_db_t gbp_bridge_domain_db;
extern gbp_bridge_domain_t *gbp_bridge_domain_pool;

always_inline gbp_bridge_domain_t *
gbp_bridge_domain_get (index_t i)
{
  return (pool_elt_at_index (gbp_bridge_domain_pool, i));
}

always_inline gbp_bridge_domain_t *
gbp_bridge_domain_get_by_bd_index (u32 bd_index)
{
  return (gbp_bridge_domain_get
	  (gbp_bridge_domain_db.gbd_by_bd_index[bd_index]));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
