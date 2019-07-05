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

#ifndef __GBP_ENDPOINT_GROUP_H__
#define __GBP_ENDPOINT_GROUP_H__

#include <plugins/gbp/gbp_types.h>
#include <plugins/gbp/gbp_itf.h>

#include <vnet/fib/fib_types.h>

/**
 * Endpoint Retnetion Policy
 */
typedef struct gbp_endpoint_retention_t_
{
  /** Aging timeout for remote endpoints */
  u32 remote_ep_timeout;
} gbp_endpoint_retention_t;

/**
 * An Endpoint Group representation
 */
typedef struct gpb_endpoint_group_t_
{
  /**
   * ID
   */
  vnid_t gg_vnid;

  /**
   * Sclass. Could be unset => ~0
   */
  u16 gg_sclass;

  /**
   * Bridge-domain ID the EPG is in
   */
  index_t gg_gbd;

  /**
   * route-domain/IP-table ID the EPG is in
   */
  index_t gg_rd;

  /**
   * Is the EPG an external/NAT
   */
  u8 gg_is_ext;

  /**
   * the uplink interface dedicated to the EPG
   */
  u32 gg_uplink_sw_if_index;
  gbp_itf_hdl_t gg_uplink_itf;

  /**
   * The DPO used in the L3 path for forwarding internal subnets
   */
  dpo_id_t gg_dpo[FIB_PROTOCOL_IP_MAX];

  /**
   * Locks/references to this EPG
   */
  u32 gg_locks;

  /**
   * EP retention policy
   */
  gbp_endpoint_retention_t gg_retention;
} gbp_endpoint_group_t;

/**
 * EPG DB, key'd on EGP-ID
 */
typedef struct gbp_endpoint_group_db_t_
{
  uword *gg_hash_sclass;
} gbp_endpoint_group_db_t;

extern int gbp_endpoint_group_add_and_lock (vnid_t vnid,
					    u16 sclass,
					    u32 bd_id,
					    u32 rd_id,
					    u32 uplink_sw_if_index,
					    const gbp_endpoint_retention_t *
					    retention);
extern index_t gbp_endpoint_group_find (sclass_t sclass);
extern int gbp_endpoint_group_delete (sclass_t sclass);
extern void gbp_endpoint_group_unlock (index_t index);
extern void gbp_endpoint_group_lock (index_t index);
extern u32 gbp_endpoint_group_get_bd_id (const gbp_endpoint_group_t *);

extern gbp_endpoint_group_t *gbp_endpoint_group_get (index_t i);
extern index_t gbp_endpoint_group_get_fib_index (const gbp_endpoint_group_t *
						 gg, fib_protocol_t fproto);

typedef int (*gbp_endpoint_group_cb_t) (gbp_endpoint_group_t * gbpe,
					void *ctx);
extern void gbp_endpoint_group_walk (gbp_endpoint_group_cb_t bgpe, void *ctx);


extern u8 *format_gbp_endpoint_group (u8 * s, va_list * args);

/**
 * DP functions and databases
 */
extern gbp_endpoint_group_db_t gbp_endpoint_group_db;
extern gbp_endpoint_group_t *gbp_endpoint_group_pool;
extern uword *gbp_epg_sclass_db;

always_inline u32
gbp_epg_itf_lookup_sclass (sclass_t sclass)
{
  uword *p;

  p = hash_get (gbp_endpoint_group_db.gg_hash_sclass, sclass);

  if (NULL != p)
    {
      gbp_endpoint_group_t *gg;

      gg = pool_elt_at_index (gbp_endpoint_group_pool, p[0]);
      return (gg->gg_uplink_sw_if_index);
    }
  return (~0);
}

always_inline const dpo_id_t *
gbp_epg_dpo_lookup (sclass_t sclass, fib_protocol_t fproto)
{
  uword *p;

  p = hash_get (gbp_endpoint_group_db.gg_hash_sclass, sclass);

  if (NULL != p)
    {
      gbp_endpoint_group_t *gg;

      gg = pool_elt_at_index (gbp_endpoint_group_pool, p[0]);
      return (&gg->gg_dpo[fproto]);
    }
  return (NULL);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
