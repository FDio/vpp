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

#ifndef __GBP_ROUTE_DOMAIN_H__
#define __GBP_ROUTE_DOMAIN_H__

#include <plugins/gbp/gbp_types.h>

#include <vnet/fib/fib_types.h>
#include <vnet/ethernet/mac_address.h>

/**
 * A route Domain Representation.
 * This is a standard route-domain plus all the attributes it must
 * have to supprt the GBP model.
 */
typedef struct gpb_route_domain_t_
{
  /**
   * Route-domain ID
   */
  u32 grd_id;
  u32 grd_fib_index[FIB_PROTOCOL_IP_MAX];
  u32 grd_table_id[FIB_PROTOCOL_IP_MAX];

  /**
   * The RD's VNI interface on which packets from unkown endpoints
   * arrive
   */
  u32 grd_vni_sw_if_index;

  /**
   * The interfaces on which to send packets to unnknown EPs
   */
  u32 grd_uu_sw_if_index[FIB_PROTOCOL_IP_MAX];

  /**
   * adjacencies on the UU interfaces.
   */
  u32 grd_adj[FIB_PROTOCOL_IP_MAX];

  u32 grd_locks;
} gbp_route_domain_t;

extern int gbp_route_domain_add_and_lock (u32 rd_id,
					  u32 ip4_table_id,
					  u32 ip6_table_id,
					  u32 ip4_uu_sw_if_index,
					  u32 ip6_uu_sw_if_index);
extern void gbp_route_domain_unlock (index_t grdi);
extern index_t gbp_route_domain_find_and_lock (u32 rd_id);
extern index_t gbp_route_domain_find (u32 rd_id);

extern int gbp_route_domain_delete (u32 rd_id);
extern gbp_route_domain_t *gbp_route_domain_get (index_t i);

typedef int (*gbp_route_domain_cb_t) (gbp_route_domain_t * gb, void *ctx);
extern void gbp_route_domain_walk (gbp_route_domain_cb_t bgpe, void *ctx);

extern const mac_address_t *gbp_route_domain_get_local_mac (void);
extern const mac_address_t *gbp_route_domain_get_remote_mac (void);

extern u8 *format_gbp_route_domain (u8 * s, va_list * args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
