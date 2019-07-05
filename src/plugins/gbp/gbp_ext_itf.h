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

#ifndef __GBP_EXT_ITF_H__
#define __GBP_EXT_ITF_H__

#include <gbp/gbp.h>

enum
{
  GBP_EXT_ITF_F_NONE = 0,
  GBP_EXT_ITF_F_ANON = 1 << 0,
};

/**
 * An external interface maps directly to an oflex L3ExternalInterface.
 * The special characteristics of an external interface is the way the source
 * EPG is determined for input packets which, like a recirc interface, is via
 * a LPM.
 */
typedef struct gpb_ext_itf_t_
{
  /**
   * The interface
   */
  gbp_itf_hdl_t gx_itf;

  /**
   * The BD this external interface is a member of
   */
  index_t gx_bd;

  /**
   * The RD this external interface is a member of
   */
  index_t gx_rd;

  /**
   * cached FIB indices from the RD
   */
  u32 gx_fib_index[DPO_PROTO_NUM];

  /**
   * The associated flags
   */
  u32 gx_flags;

} gbp_ext_itf_t;


extern int gbp_ext_itf_add (u32 sw_if_index, u32 bd_id, u32 rd_id, u32 flags);
extern int gbp_ext_itf_delete (u32 sw_if_index);

extern u8 *format_gbp_ext_itf (u8 * s, va_list * args);

typedef walk_rc_t (*gbp_ext_itf_cb_t) (gbp_ext_itf_t * gbpe, void *ctx);
extern void gbp_ext_itf_walk (gbp_ext_itf_cb_t bgpe, void *ctx);


/**
 * Exposed types for the data-plane
 */
extern gbp_ext_itf_t *gbp_ext_itf_pool;
extern index_t *gbp_ext_itf_db;

always_inline gbp_ext_itf_t *
gbp_ext_itf_get (u32 sw_if_index)
{
  return (pool_elt_at_index (gbp_ext_itf_pool, gbp_ext_itf_db[sw_if_index]));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
