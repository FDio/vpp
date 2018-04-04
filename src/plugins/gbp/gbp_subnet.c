/*
 * gbp.h : Group Based Policy
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <plugins/gbp/gbp.h>
#include <plugins/gbp/gbp_fwd_dpo.h>
#include <plugins/gbp/gbp_policy_dpo.h>

#include <vnet/fib/fib_table.h>

static int
gbp_internal_subnet_add (u32 fib_index, const fib_prefix_t * pfx)
{
  dpo_id_t gfd = DPO_INVALID;

  gbp_fwd_dpo_add_or_lock (fib_proto_to_dpo (pfx->fp_proto), &gfd);

  fib_table_entry_special_dpo_update (fib_index,
				      pfx,
				      FIB_SOURCE_PLUGIN_HI,
				      FIB_ENTRY_FLAG_EXCLUSIVE, &gfd);

  dpo_reset (&gfd);

  return (0);
}

static int
gbp_external_subnet_add (u32 fib_index,
			 const fib_prefix_t * pfx,
			 u32 sw_if_index, epg_id_t epg)
{
  dpo_id_t gpd = DPO_INVALID;

  gbp_policy_dpo_add_or_lock (fib_proto_to_dpo (pfx->fp_proto),
			      epg, sw_if_index, &gpd);

  fib_table_entry_special_dpo_update (fib_index,
				      pfx,
				      FIB_SOURCE_PLUGIN_HI,
				      (FIB_ENTRY_FLAG_EXCLUSIVE |
				       FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT),
				      &gpd);

  dpo_reset (&gpd);

  return (0);
}

static int
gbp_subnet_del (u32 fib_index, const fib_prefix_t * pfx)
{
  fib_table_entry_delete (fib_index, pfx, FIB_SOURCE_PLUGIN_HI);

  return (0);
}

int
gbp_subnet_add_del (u32 table_id,
		    const fib_prefix_t * pfx,
		    u32 sw_if_index, epg_id_t epg, u8 is_add, u8 is_internal)
{
  u32 fib_index;

  fib_index = fib_table_find (pfx->fp_proto, table_id);

  if (~0 == fib_index)
    return (VNET_API_ERROR_NO_SUCH_FIB);

  if (is_internal && is_add)
    return (gbp_internal_subnet_add (fib_index, pfx));
  else if (!is_internal && is_add)
    return (gbp_external_subnet_add (fib_index, pfx, sw_if_index, epg));

  return (gbp_subnet_del (fib_index, pfx));
}

typedef struct gbp_subnet_fib_table_walk_ctx_t_
{
  gbp_subnet_cb_t cb;
  void *ctx;
} gbp_subnet_fib_table_walk_ctx_t;

static fib_table_walk_rc_t
gbp_subnet_fib_table_walk (fib_node_index_t fei, void *arg)
{
  //gbp_subnet_fib_table_walk_ctx_t *ctx = arg;

  //ctx->cb(ctx->ctx);
  return (FIB_TABLE_WALK_CONTINUE);
}

void
gbp_subnet_walk (gbp_subnet_cb_t cb, void *ctx)
{
  fib_table_t *fib_table;

  gbp_subnet_fib_table_walk_ctx_t wctx = {
    .cb = cb,
    .ctx = ctx,
  };

  pool_foreach (fib_table, ip4_main.fibs, (
					    {
					    fib_table_walk
					    (fib_table->ft_index,
					     FIB_PROTOCOL_IP4,
					     gbp_subnet_fib_table_walk,
					     &wctx);
					    }));

}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
