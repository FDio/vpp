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

#include <plugins/gbp/gbp.h>
#include <plugins/gbp/gbp_fwd_dpo.h>
#include <plugins/gbp/gbp_policy_dpo.h>

#include <vnet/fib/fib_table.h>
#include <vnet/dpo/load_balance.h>

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
  gbp_subnet_fib_table_walk_ctx_t *ctx = arg;
  const fib_prefix_t *pfx;
  const dpo_id_t *dpo;
  u32 table_id;

  pfx = fib_entry_get_prefix (fei);
  table_id = fib_table_get_table_id (fib_entry_get_fib_index (fei),
				     pfx->fp_proto);
  dpo = fib_entry_contribute_ip_forwarding (fei);

  if (DPO_LOAD_BALANCE == dpo->dpoi_type)
    {
      dpo = load_balance_get_bucket (dpo->dpoi_index, 0);

      if (dpo->dpoi_type == gbp_policy_dpo_get_type ())
	{
	  gbp_policy_dpo_t *gpd;

	  gpd = gbp_policy_dpo_get (dpo->dpoi_index);

          /* *INDENT-OFF* */
          ctx->cb (table_id, pfx,
                   gpd->gpd_sw_if_index,
                   gpd->gpd_epg,
                   0,	// is_internal
                   ctx->ctx);
          /* *INDENT-ON* */
	}
      else if (dpo->dpoi_type == gbp_fwd_dpo_get_type ())
	{
          /* *INDENT-OFF* */
          ctx->cb (table_id, pfx,
                   ~0,	// sw_if_index
                   ~0,  // epg
                   1,   // is_internal
                   ctx->ctx);
          /* *INDENT-ON* */
	}
    }

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

  /* *INDENT-OFF* */
  pool_foreach (fib_table, ip4_main.fibs,
  ({
    fib_table_walk(fib_table->ft_index,
                   FIB_PROTOCOL_IP4,
                   gbp_subnet_fib_table_walk,
                   &wctx);
  }));
  pool_foreach (fib_table, ip6_main.fibs,
  ({
    fib_table_walk(fib_table->ft_index,
                   FIB_PROTOCOL_IP6,
                   gbp_subnet_fib_table_walk,
                   &wctx);
  }));
  /* *INDENT-ON* */
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
