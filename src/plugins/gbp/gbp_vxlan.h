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

#ifndef __GBP_VXLAN_H__
#define __GBP_VXLAN_H__

#include <vnet/fib/fib_types.h>

#define forecah_gbp_vxlan_tunnel_layer          \
  _(L2, "l2")                                   \
  _(L3, "l3")

typedef enum gbp_vxlan_tunnel_layer_t_
{
#define _(s,n) GBP_VXLAN_TUN_##s,
  forecah_gbp_vxlan_tunnel_layer
#undef _
} gbp_vxlan_tunnel_layer_t;

struct gbp_vxlan_dep_t_;
/**
 * GBP VXLAN (template) tunnel
 */
typedef struct gbp_vxlan_tunnel_t_
{
  u32 gt_hw_if_index;
  u32 gt_sw_if_index;
  u32 gt_vni;
  u32 gt_bd_rd_id;
  gbp_vxlan_tunnel_layer_t gt_layer;
  union
  {
    u32 gt_bd_index;
    u32 gt_fib_index[FIB_PROTOCOL_IP_MAX];
  };

  index_t gt_gbd;
  index_t gt_grd;
  index_t gt_itf;
  struct gbp_vxlan_dep_t_ *gt_tuns;
} gbp_vxlan_tunnel_t;

extern int gbp_vxlan_tunnel_add (u32 vni, gbp_vxlan_tunnel_layer_t layer,
				 u32 bd_rd_id, u32 * sw_if_indexp);
extern int gbp_vxlan_tunnel_del (u32 vni);

typedef walk_rc_t (*gbp_vxlan_cb_t) (gbp_vxlan_tunnel_t * gt, void *ctx);
extern void gbp_vxlan_walk (gbp_vxlan_cb_t cb, void *ctx);
//extern void gbp_vxlan_scan (vlib_main_t * vm);

extern u8 *format_gbp_vxlan_tunnel (u8 * s, va_list * args);
extern u8 *format_gbp_vxlan_tunnel_layer (u8 * s, va_list * args);

extern gbp_vxlan_tunnel_t *gbp_vxlan_tunnel_pool;

always_inline gbp_vxlan_tunnel_t *
gbp_vxlan_tunnel_get (index_t gti)
{
  return (pool_elt_at_index (gbp_vxlan_tunnel_pool, gti));
}


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
