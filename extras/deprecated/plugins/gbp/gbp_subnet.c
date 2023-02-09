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
      sclass_t gs_sclass;
      u32 gs_sw_if_index;
    } gs_stitched_external;
    struct
    {
      sclass_t gs_sclass;
    } gs_l3_out;
  };

  fib_node_index_t gs_fei;
} gbp_subnet_t;

/**
 * A DB of the subnets; key={pfx,fib-index}
 */
uword *gbp_subnet_db;

/**
 * pool of subnets
 */
gbp_subnet_t *gbp_subnet_pool;

static fib_source_t gbp_fib_source;

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
gbp_subnet_transport_add (gbp_subnet_t * gs)
{
  dpo_id_t gfd = DPO_INVALID;
  gbp_route_domain_t *grd;
  fib_protocol_t fproto;

  fproto = gs->gs_key->gsk_pfx.fp_proto;
  grd = gbp_route_domain_get (gs->gs_rd);

  if (~0 == grd->grd_uu_sw_if_index[fproto])
    return (VNET_API_ERROR_INVALID_SW_IF_INDEX);

  gs->gs_fei = fib_table_entry_update_one_path (gs->gs_key->gsk_fib_index,
						&gs->gs_key->gsk_pfx,
						gbp_fib_source,
						FIB_ENTRY_FLAG_NONE,
						fib_proto_to_dpo (fproto),
						&ADJ_BCAST_ADDR,
						grd->grd_uu_sw_if_index
						[fproto], ~0, 1, NULL,
						FIB_ROUTE_PATH_FLAG_NONE);

  dpo_reset (&gfd);

  return (0);
}

static int
gbp_subnet_internal_add (gbp_subnet_t * gs)
{
  dpo_id_t gfd = DPO_INVALID;

  gbp_fwd_dpo_add_or_lock (fib_proto_to_dpo (gs->gs_key->gsk_pfx.fp_proto),
			   &gfd);

  gs->gs_fei = fib_table_entry_special_dpo_update (gs->gs_key->gsk_fib_index,
						   &gs->gs_key->gsk_pfx,
						   gbp_fib_source,
						   FIB_ENTRY_FLAG_EXCLUSIVE,
						   &gfd);

  dpo_reset (&gfd);

  return (0);
}

static int
gbp_subnet_external_add (gbp_subnet_t * gs, u32 sw_if_index, sclass_t sclass)
{
  dpo_id_t gpd = DPO_INVALID;

  gs->gs_stitched_external.gs_sclass = sclass;
  gs->gs_stitched_external.gs_sw_if_index = sw_if_index;

  gbp_policy_dpo_add_or_lock (fib_proto_to_dpo (gs->gs_key->gsk_pfx.fp_proto),
			      gbp_route_domain_get_scope (gs->gs_rd),
			      gs->gs_stitched_external.gs_sclass,
			      gs->gs_stitched_external.gs_sw_if_index, &gpd);

  gs->gs_fei = fib_table_entry_special_dpo_update (gs->gs_key->gsk_fib_index,
						   &gs->gs_key->gsk_pfx,
						   gbp_fib_source,
						   (FIB_ENTRY_FLAG_EXCLUSIVE |
						    FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT),
						   &gpd);

  dpo_reset (&gpd);

  return (0);
}

static int
gbp_subnet_l3_out_add (gbp_subnet_t * gs, sclass_t sclass, int is_anon)
{
  fib_entry_flag_t flags;
  dpo_id_t gpd = DPO_INVALID;

  gs->gs_l3_out.gs_sclass = sclass;

  gbp_policy_dpo_add_or_lock (fib_proto_to_dpo (gs->gs_key->gsk_pfx.fp_proto),
			      gbp_route_domain_get_scope (gs->gs_rd),
			      gs->gs_l3_out.gs_sclass, ~0, &gpd);

  flags = FIB_ENTRY_FLAG_INTERPOSE;
  if (is_anon)
    flags |= FIB_ENTRY_FLAG_COVERED_INHERIT;

  gs->gs_fei = fib_table_entry_special_dpo_add (gs->gs_key->gsk_fib_index,
						&gs->gs_key->gsk_pfx,
						FIB_SOURCE_SPECIAL,
						flags, &gpd);

  dpo_reset (&gpd);

  return (0);
}

static void
gbp_subnet_del_i (index_t gsi)
{
  gbp_subnet_t *gs;

  gs = pool_elt_at_index (gbp_subnet_pool, gsi);

  fib_table_entry_delete_index (gs->gs_fei,
				(GBP_SUBNET_L3_OUT == gs->gs_type
				 || GBP_SUBNET_ANON_L3_OUT ==
				 gs->gs_type) ? FIB_SOURCE_SPECIAL :
				gbp_fib_source);

  gbp_subnet_db_del (gs);
  gbp_route_domain_unlock (gs->gs_rd);

  pool_put (gbp_subnet_pool, gs);
}

int
gbp_subnet_del (u32 rd_id, const fib_prefix_t * pfx)
{
  gbp_route_domain_t *grd;
  index_t gsi, grdi;
  u32 fib_index;

  grdi = gbp_route_domain_find (rd_id);

  if (~0 == grdi)
    return (VNET_API_ERROR_NO_SUCH_FIB);

  grd = gbp_route_domain_get (grdi);
  fib_index = grd->grd_fib_index[pfx->fp_proto];

  gsi = gbp_subnet_db_find (fib_index, pfx);

  if (INDEX_INVALID == gsi)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  gbp_subnet_del_i (gsi);

  return (0);
}

int
gbp_subnet_add (u32 rd_id,
		const fib_prefix_t * pfx,
		gbp_subnet_type_t type, u32 sw_if_index, sclass_t sclass)
{
  gbp_route_domain_t *grd;
  index_t grdi, gsi;
  gbp_subnet_t *gs;
  u32 fib_index;
  int rv;

  switch (type)
    {
    case GBP_SUBNET_TRANSPORT:
    case GBP_SUBNET_STITCHED_INTERNAL:
    case GBP_SUBNET_STITCHED_EXTERNAL:
    case GBP_SUBNET_L3_OUT:
    case GBP_SUBNET_ANON_L3_OUT:
      break;
    default:
      return (VNET_API_ERROR_INCORRECT_ADJACENCY_TYPE);
    }

  grdi = gbp_route_domain_find_and_lock (rd_id);

  if (~0 == grdi)
    return (VNET_API_ERROR_NO_SUCH_FIB);

  grd = gbp_route_domain_get (grdi);
  fib_index = grd->grd_fib_index[pfx->fp_proto];

  gsi = gbp_subnet_db_find (fib_index, pfx);

  /*
   * this is an update if the subnet already exists, so remove the old
   */
  if (INDEX_INVALID != gsi)
    gbp_subnet_del_i (gsi);

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
      rv = gbp_subnet_external_add (gs, sw_if_index, sclass);
      break;
    case GBP_SUBNET_TRANSPORT:
      rv = gbp_subnet_transport_add (gs);
      break;
    case GBP_SUBNET_L3_OUT:
      rv = gbp_subnet_l3_out_add (gs, sclass, 0 /* is_anon */ );
      break;
    case GBP_SUBNET_ANON_L3_OUT:
      rv = gbp_subnet_l3_out_add (gs, sclass, 1 /* is_anon */ );
      break;
    }

  return (rv);
}

static clib_error_t *
gbp_subnet_add_del_cli (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  fib_prefix_t pfx = {.fp_addr = ip46_address_initializer };
  int length;
  u32 rd_id = ~0;
  u32 sw_if_index = ~0;
  gbp_subnet_type_t type = ~0;
  u32 sclass = ~0;
  int is_add = 1;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "rd %d", &rd_id))
	;
      else
	if (unformat
	    (line_input, "prefix %U/%d", unformat_ip4_address,
	     &pfx.fp_addr.ip4, &length))
	pfx.fp_proto = FIB_PROTOCOL_IP4;
      else
	if (unformat
	    (line_input, "prefix %U/%d", unformat_ip6_address,
	     &pfx.fp_addr.ip6, &length))
	pfx.fp_proto = FIB_PROTOCOL_IP6;
      else if (unformat (line_input, "type transport"))
	type = GBP_SUBNET_TRANSPORT;
      else if (unformat (line_input, "type stitched-internal"))
	type = GBP_SUBNET_STITCHED_INTERNAL;
      else if (unformat (line_input, "type stitched-external"))
	type = GBP_SUBNET_STITCHED_EXTERNAL;
      else if (unformat (line_input, "type anon-l3-out"))
	type = GBP_SUBNET_ANON_L3_OUT;
      else if (unformat (line_input, "type l3-out"))
	type = GBP_SUBNET_L3_OUT;
      else
	if (unformat_user
	    (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "sclass %u", &sclass))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  pfx.fp_len = length;

  if (is_add)
    rv = gbp_subnet_add (rd_id, &pfx, type, sw_if_index, sclass);
  else
    rv = gbp_subnet_del (rd_id, &pfx);

  switch (rv)
    {
    case 0:
      return 0;
    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "no such FIB");
    }

  return clib_error_return (0, "unknown error %d", rv);
}

/*?
 * Add Group Based Policy Subnets
 *
 * @cliexpar
 * @cliexstart{gbp subnet [del] rd <ID> prefix <prefix> type <type> [<interface>] [sclass <sclass>]}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_subnet_add_del, static) = {
  .path = "gbp subnet",
  .short_help = "gbp subnet [del] rd <ID> prefix <prefix> type <type> [<interface>] [sclass <sclass>]\n",
  .function = gbp_subnet_add_del_cli,
};
/* *INDENT-ON* */



void
gbp_subnet_walk (gbp_subnet_cb_t cb, void *ctx)
{
  gbp_route_domain_t *grd;
  gbp_subnet_t *gs;
  u32 sw_if_index;
  sclass_t sclass;

  sclass = SCLASS_INVALID;
  sw_if_index = ~0;

  /* *INDENT-OFF* */
  pool_foreach (gs, gbp_subnet_pool)
   {
    grd = gbp_route_domain_get(gs->gs_rd);

    switch (gs->gs_type)
      {
      case GBP_SUBNET_STITCHED_INTERNAL:
      case GBP_SUBNET_TRANSPORT:
        /* use defaults above */
        break;
      case GBP_SUBNET_STITCHED_EXTERNAL:
        sw_if_index = gs->gs_stitched_external.gs_sw_if_index;
        sclass = gs->gs_stitched_external.gs_sclass;
        break;
      case GBP_SUBNET_L3_OUT:
      case GBP_SUBNET_ANON_L3_OUT:
        sclass = gs->gs_l3_out.gs_sclass;
        break;
      }

    if (WALK_STOP == cb (grd->grd_id, &gs->gs_key->gsk_pfx,
                         gs->gs_type, sw_if_index, sclass, ctx))
      break;
  }
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
    case GBP_SUBNET_L3_OUT:
      return (format (s, "l3-out"));
    case GBP_SUBNET_ANON_L3_OUT:
      return (format (s, "anon-l3-out"));
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

  s = format (s, "[%d] tbl:%u %U %U", gsi, table_id, format_fib_prefix,
	      &gs->gs_key->gsk_pfx, format_gbp_subnet_type, gs->gs_type);

  switch (gs->gs_type)
    {
    case GBP_SUBNET_STITCHED_INTERNAL:
    case GBP_SUBNET_TRANSPORT:
      break;
    case GBP_SUBNET_STITCHED_EXTERNAL:
      s = format (s, " {sclass:%d %U}", gs->gs_stitched_external.gs_sclass,
		  format_vnet_sw_if_index_name,
		  vnet_get_main (), gs->gs_stitched_external.gs_sw_if_index);
      break;
    case GBP_SUBNET_L3_OUT:
    case GBP_SUBNET_ANON_L3_OUT:
      s = format (s, " {sclass:%d}", gs->gs_l3_out.gs_sclass);
      break;
    }

  switch (flags)
    {
    case GBP_SUBNET_SHOW_DETAILS:
      {
	s = format (s, "\n  %U", format_fib_entry, gs->gs_fei,
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
      pool_foreach_index (gsi, gbp_subnet_pool)
       {
        vlib_cli_output (vm, "%U", format_gbp_subnet, gsi,
                         GBP_SUBNET_SHOW_BRIEF);
      }
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
  gbp_fib_source = fib_source_allocate ("gbp-subnet",
					FIB_SOURCE_PRIORITY_HI,
					FIB_SOURCE_BH_SIMPLE);

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
