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
 * A bridge Domain Representation.
 * This is a standard bridge-domain plus all the attributes it must
 * have to supprt the GBP model.
 */
typedef struct gpb_bridge_domain_t_
{
  /**
   * Bridge-domain ID
   */
  u32 gb_bd_id;
  u32 gb_bd_index;

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

  u32 gb_locks;
} gbp_bridge_domain_t;

extern int gbp_bridge_domain_add_and_lock (u32 bd_id,
					   u32 bvi_sw_if_index,
					   u32 uu_fwd_sw_if_index);
extern void gbp_bridge_domain_unlock (index_t gbi);
extern index_t gbp_bridge_domain_find_and_lock (u32 bd_id);
extern index_t gbp_bridge_domain_find_by_bd_index (u32 bd_index);
extern int gbp_bridge_domain_delete (u32 bd_id);
extern gbp_bridge_domain_t *gbp_bridge_domain_get (index_t i);

typedef int (*gbp_bridge_domain_cb_t) (gbp_bridge_domain_t * gb, void *ctx);
extern void gbp_bridge_domain_walk (gbp_bridge_domain_cb_t bgpe, void *ctx);

extern u8 *format_gbp_bridge_domain (u8 * s, va_list * args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
