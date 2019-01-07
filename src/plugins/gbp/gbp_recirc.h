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

#ifndef __GBP_RECIRC_H__
#define __GBP_RECIRC_H__

#include <plugins/gbp/gbp_types.h>
#include <vnet/fib/fib_types.h>

/**
 * A GBP recirculation interface representation
 *  Thes interfaces join Bridge domains that are internal to those that are
 * NAT external, so the packets can be NAT translated and then undergo the
 * whole policy process again.
 */
typedef struct gpb_recirc_t_
{
  /**
   * EPG ID that packets will classify to when they arrive on this recirc
   */
  epg_id_t gr_epg;

  /**
   * The index of the EPG
   */
  index_t gr_epgi;

  /**
   * FIB indices the EPG is mapped to
   */
  u32 gr_fib_index[DPO_PROTO_NUM];

  /**
   * Is the interface for packets post-NAT translation (i.e. ext)
   * or pre-NAT translation (i.e. internal)
   */
  u8 gr_is_ext;

  /**
   */
  u32 gr_sw_if_index;
  u32 gr_itf;

  /**
   * The endpoint created to represent the reric interface
   */
  index_t gr_ep;
} gbp_recirc_t;

extern int gbp_recirc_add (u32 sw_if_index, epg_id_t epg_id, u8 is_ext);
extern int gbp_recirc_delete (u32 sw_if_index);

typedef walk_rc_t (*gbp_recirc_cb_t) (gbp_recirc_t * gbpe, void *ctx);
extern void gbp_recirc_walk (gbp_recirc_cb_t bgpe, void *ctx);

/**
 * Data plane functions
 */
extern gbp_recirc_t *gbp_recirc_pool;
extern index_t *gbp_recirc_db;

always_inline gbp_recirc_t *
gbp_recirc_get (u32 sw_if_index)
{
  return (pool_elt_at_index (gbp_recirc_pool, gbp_recirc_db[sw_if_index]));
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
