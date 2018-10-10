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
#include <plugins/gbp/gbp_route_domain.h>

#include <vnet/fib/fib_table.h>
#include <vnet/dpo/load_balance.h>

/**
 * a key for the DB
 */
typedef struct gbp_subnet_key_t_
{
  fib_prefix_t gsk_pfx;
  u32 gsk_fib_index;
} gbp_subnet_key_t;

/**
 * Subnet
 */
typedef struct gbp_subnet_t_
{
  gbp_subnet_key_t *gs_key;
  gbp_subnet_type_t gs_type;
  index_t gs_rd;

  union
  {
    struct
    {
      epg_id_t gs_epg;
      u32 gs_sw_if_index;
    } gs_stitched_external;
  };
} gbp_subnet_t;

/**
 * A DB of the subnets; key={pfx,fib-index}
 */
uword *gbp_subnet_db;

/**
 * pool of subnets
 */
gbp_subnet_t *gbp_subnet_pool;

static index_t
gbp_subnet_db_find (u32 fib_index, const fib_prefix_t * pfx)
{
  gbp_subnet_key_t key = {
    .gsk_pfx = *pfx,
    .gsk_fib_index = fib_index,
  };
  uword *p;

  p = hash_get_mem (gbp_subnet_db, &key);

  if (NULL != p)
    return p[0];

  return (INDEX_INVALID);
}

static void
gbp_subnet_db_add (u32 fib_index, const fib_prefix_t * pfx, gbp_subnet_t * gs)
{
  gbp_subnet_key_t *key;

  key = clib_mem_alloc (sizeof (*key));

  clib_memcpy (&(key->gsk_pfx), pfx, sizeof (*pfx));
  key->gsk_fib_index = fib_index;

  hash_set_mem (gbp_subnet_db, key, (gs - gbp_subnet_pool));

  gs->gs_key = key;
}

static void
gbp_subnet_db_del (gbp_subnet_t * gs)
{
  hash_unset_mem (gbp_subnet_db, gs->gs_key);

  clib_mem_free (gs->gs_key);
  gs->gs_key = NULL;
}


static int
gbp_subnet_transport_add (const gbp_subnet_t * gs)
{
  dpo_id_t gfd = DPO_INVALID;
  gbp_route_domain_t *grd;
  fib_protocol_t fproto;

  fproto = gs->gs_key->gsk_pfx.fp_proto;
  grd = gbp_route_domain_get (gs->gs_rd);

  fib_table_entry_update_one_path (gs->gs_key->gsk_fib_index,
				   &gs->gs_key->gsk_pfx,
				   FIB_SOURCE_PLUGIN_HI,
				   FIB_ENTRY_FLAG_NONE,
				   fib_proto_to_dpo (fproto),
				   &ADJ_BCAST_ADDR,
				   grd->grd_uu_sw_if_index[fproto],
				   ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);

  dpo_reset (&gfd);

  return (0);
}

static int
gbp_subnet_internal_add (const gbp_subnet_t * gs)
{
  dpo_id_t gfd = DPO_INVALID;

  gbp_fwd_dpo_add_or_lock (fib_proto_to_dpo (gs->gs_key->gsk_pfx.fp_proto),
			   &gfd);

  fib_table_entry_special_dpo_update (gs->gs_key->gsk_fib_index,
				      &gs->gs_key->gsk_pfx,
				      FIB_SOURCE_PLUGIN_HI,
				      FIB_ENTRY_FLAG_EXCLUSIVE, &gfd);

  dpo_reset (&gfd);

  return (0);
}

static int
gbp_subnet_external_add (gbp_subnet_t * gs, u32 sw_if_index, epg_id_t epg)
{
  dpo_id_t gpd = DPO_INVALID;

  gs->gs_stitched_external.gs_epg = epg;
  gs->gs_stitched_external.gs_sw_if_index = sw_if_index;

  gbp_policy_dpo_add_or_lock (fib_proto_to_dpo (gs->gs_key->gsk_pfx.fp_proto),
			      gs->gs_stitched_external.gs_epg,
			      gs->gs_stitched_external.gs_sw_if_index, &gpd);

  fib_table_entry_special_dpo_update (gs->gs_key->gsk_fib_index,
				      &gs->gs_key->gsk_pfx,
				      FIB_SOURCE_PLUGIN_HI,
				      (FIB_ENTRY_FLAG_EXCLUSIVE |
				       FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT),
				      &gpd);

  dpo_reset (&gpd);

  return (0);
}

int
gbp_subnet_del (u32 rd_id, const fib_prefix_t * pfx)
{
  gbp_route_domain_t *grd;
  index_t gsi, grdi;
  gbp_subnet_t *gs;
  u32 fib_index;

  grdi = gbp_route_domain_find (rd_id);

  if (~0 == grdi)
    return (VNET_API_ERROR_NO_SUCH_FIB);

  grd = gbp_route_domain_get (grdi);
  fib_index = grd->grd_fib_index[pfx->fp_proto];

  gsi = gbp_subnet_db_find (fib_index, pfx);

  if (INDEX_INVALID == gsi)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  gs = pool_elt_at_index (gbp_subnet_pool, gsi);

  fib_table_entry_delete (fib_index, pfx, FIB_SOURCE_PLUGIN_HI);

  gbp_subnet_db_del (gs);
  gbp_route_domain_unlock (gs->gs_rd);

  pool_put (gbp_subnet_pool, gs);

  return (0);
}

int
gbp_subnet_add (u32 rd_id,
		const fib_prefix_t * pfx,
		gbp_subnet_type_t type, u32 sw_if_index, epg_id_t epg)
{
  gbp_route_domain_t *grd;
  index_t grdi, gsi;
  gbp_subnet_t *gs;
  u32 fib_index;
  int rv;

  grdi = gbp_route_domain_find_and_lock (rd_id);

  if (~0 == grdi)
    return (VNET_API_ERROR_NO_SUCH_FIB);

  grd = gbp_route_domain_get (grdi);
  fib_index = grd->grd_fib_index[pfx->fp_proto];

  gsi = gbp_subnet_db_find (fib_index, pfx);

  if (INDEX_INVALID != gsi)
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  rv = -2;

  pool_get (gbp_subnet_pool, gs);

  gs->gs_type = type;
  gs->gs_rd = grdi;
  gbp_subnet_db_add (fib_index, pfx, gs);

  switch (type)
    {
    case GBP_SUBNET_STITCHED_INTERNAL:
      rv = gbp_subnet_internal_add (gs);
      break;
    case GBP_SUBNET_STITCHED_EXTERNAL:
      rv = gbp_subnet_external_add (gs, sw_if_index, epg);
      break;
    case GBP_SUBNET_TRANSPORT:
      rv = gbp_subnet_transport_add (gs);
      break;
    }

  return (rv);
}

void
gbp_subnet_walk (gbp_subnet_cb_t cb, void *ctx)
{
  gbp_route_domain_t *grd;
  gbp_subnet_t *gs;
  u32 sw_if_index;
  epg_id_t epg;

  /* *INDENT-OFF* */
  pool_foreach (gs, gbp_subnet_pool,
  ({
    grd = gbp_route_domain_get(gs->gs_rd);

    switch (gs->gs_type)
      {
      case GBP_SUBNET_STITCHED_INTERNAL:
      case GBP_SUBNET_TRANSPORT:
        epg = EPG_INVALID;
        sw_if_index = ~0;
        break;
      case GBP_SUBNET_STITCHED_EXTERNAL:
        sw_if_index = gs->gs_stitched_external.gs_sw_if_index;
        epg = gs->gs_stitched_external.gs_epg;
        break;
      }

    if (WALK_STOP == cb (grd->grd_id, &gs->gs_key->gsk_pfx,
                         gs->gs_type, epg, sw_if_index, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

typedef enum gsb_subnet_show_flags_t_
{
  GBP_SUBNET_SHOW_BRIEF,
  GBP_SUBNET_SHOW_DETAILS,
} gsb_subnet_show_flags_t;

static u8 *
format_gbp_subnet_type (u8 * s, va_list * args)
{
  gbp_subnet_type_t type = va_arg (*args, gbp_subnet_type_t);

  switch (type)
    {
    case GBP_SUBNET_STITCHED_INTERNAL:
      return (format (s, "stitched-internal"));
    case GBP_SUBNET_STITCHED_EXTERNAL:
      return (format (s, "stitched-external"));
    case GBP_SUBNET_TRANSPORT:
      return (format (s, "transport"));
    }

  return (format (s, "unknown"));
}

u8 *
format_gbp_subnet (u8 * s, va_list * args)
{
  index_t gsi = va_arg (*args, index_t);
  gsb_subnet_show_flags_t flags = va_arg (*args, gsb_subnet_show_flags_t);
  gbp_subnet_t *gs;
  u32 table_id;

  gs = pool_elt_at_index (gbp_subnet_pool, gsi);

  table_id = fib_table_get_table_id (gs->gs_key->gsk_fib_index,
				     gs->gs_key->gsk_pfx.fp_proto);

  s = format (s, "[%d] tbl:%d %U %U", gsi, table_id,
	      format_fib_prefix, &gs->gs_key->gsk_pfx,
	      format_gbp_subnet_type, gs->gs_type);

  switch (gs->gs_type)
    {
    case GBP_SUBNET_STITCHED_INTERNAL:
    case GBP_SUBNET_TRANSPORT:
      break;
    case GBP_SUBNET_STITCHED_EXTERNAL:
      s = format (s, " {epg:%d %U}", gs->gs_stitched_external.gs_epg,
		  format_vnet_sw_if_index_name,
		  vnet_get_main (), gs->gs_stitched_external.gs_sw_if_index);
      break;
    }

  switch (flags)
    {
    case GBP_SUBNET_SHOW_DETAILS:
      {
	fib_node_index_t fei;

	fei = fib_table_lookup_exact_match (gs->gs_key->gsk_fib_index,
					    &gs->gs_key->gsk_pfx);

	s =
	  format (s, "\n  %U", format_fib_entry, fei,
		  FIB_ENTRY_FORMAT_DETAIL);
      }
    case GBP_SUBNET_SHOW_BRIEF:
      break;
    }
  return (s);
}

static clib_error_t *
gbp_subnet_show (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 gsi;

  gsi = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &gsi))
	;
      else
	break;
    }

  if (INDEX_INVALID != gsi)
    {
      vlib_cli_output (vm, "%U", format_gbp_subnet, gsi,
		       GBP_SUBNET_SHOW_DETAILS);
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach_index(gsi, gbp_subnet_pool,
      ({
        vlib_cli_output (vm, "%U", format_gbp_subnet, gsi,
                         GBP_SUBNET_SHOW_BRIEF);
      }));
      /* *INDENT-ON* */
    }

  return (NULL);
}

/*?
 * Show Group Based Policy Subnets
 *
 * @cliexpar
 * @cliexstart{show gbp subnet}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_subnet_show_node, static) = {
  .path = "show gbp subnet",
  .short_help = "show gbp subnet\n",
  .function = gbp_subnet_show,
};
/* *INDENT-ON* */

static clib_error_t *
gbp_subnet_init (vlib_main_t * vm)
{
  gbp_subnet_db = hash_create_mem (0,
				   sizeof (gbp_subnet_key_t), sizeof (u32));

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_subnet_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
