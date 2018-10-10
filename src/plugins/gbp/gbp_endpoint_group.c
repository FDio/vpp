/*
 * gbp.h : Group Based Policy
 *
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

#include <plugins/gbp/gbp_endpoint_group.h>
#include <plugins/gbp/gbp_endpoint.h>
#include <plugins/gbp/gbp_bridge_domain.h>
#include <plugins/gbp/gbp_route_domain.h>

#include <vnet/dpo/dvr_dpo.h>
#include <vnet/fib/fib_table.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_bvi.h>

/**
 * Pool of GBP endpoint_groups
 */
gbp_endpoint_group_t *gbp_endpoint_group_pool;

/**
 * DB of endpoint_groups
 */
gbp_endpoint_group_db_t gbp_endpoint_group_db;
vlib_log_class_t gg_logger;

#define GBP_EPG_DBG(...)                           \
    vlib_log_notice (gg_logger, __VA_ARGS__);

gbp_endpoint_group_t *
gbp_endpoint_group_get (index_t i)
{
  return (pool_elt_at_index (gbp_endpoint_group_pool, i));
}

static void
gbp_endpoint_group_lock (index_t i)
{
  gbp_endpoint_group_t *gg;

  gg = gbp_endpoint_group_get (i);
  gg->gg_locks++;
}

index_t
gbp_endpoint_group_find (epg_id_t epg_id)
{
  uword *p;

  p = hash_get (gbp_endpoint_group_db.gg_hash, epg_id);

  if (NULL != p)
    return p[0];

  return (INDEX_INVALID);
}

index_t
gbp_endpoint_group_find_and_lock (epg_id_t epg_id)
{
  uword *p;

  p = hash_get (gbp_endpoint_group_db.gg_hash, epg_id);

  if (NULL != p)
    {
      gbp_endpoint_group_lock (p[0]);
      return p[0];
    }
  return (INDEX_INVALID);
}

int
gbp_endpoint_group_add_and_lock (epg_id_t epg_id,
				 u32 bd_id, u32 rd_id, u32 uplink_sw_if_index)
{
  gbp_endpoint_group_t *gg;
  index_t ggi;

  ggi = gbp_endpoint_group_find (epg_id);

  if (INDEX_INVALID == ggi)
    {
      gbp_bridge_domain_t *gb;
      fib_protocol_t fproto;
      index_t gbi, grdi;

      gbi = gbp_bridge_domain_find_and_lock (bd_id);

      if (~0 == gbi)
	return (VNET_API_ERROR_BD_NOT_MODIFIABLE);

      grdi = gbp_route_domain_find_and_lock (rd_id);

      if (~0 == grdi)
	{
	  gbp_bridge_domain_unlock (gbi);
	  return (VNET_API_ERROR_NO_SUCH_FIB);
	}

      gb = gbp_bridge_domain_get (gbi);

      pool_get_zero (gbp_endpoint_group_pool, gg);

      gg->gg_id = epg_id;
      gg->gg_rd = grdi;
      gg->gg_gbd = gbi;
      gg->gg_bd_index = gb->gb_bd_index;

      gg->gg_uplink_sw_if_index = uplink_sw_if_index;
      gg->gg_locks = 1;

      /*
       * an egress DVR dpo for internal subnets to use when sending
       * on the uplink interface
       */
      if (~0 != gg->gg_uplink_sw_if_index)
	{
	  FOR_EACH_FIB_IP_PROTOCOL (fproto)
	  {
	    dvr_dpo_add_or_lock (uplink_sw_if_index,
				 fib_proto_to_dpo (fproto),
				 &gg->gg_dpo[fproto]);
	  }

	  /*
	   * Add the uplink to the BD
	   * packets direct from the uplink have had policy applied
	   */
	  set_int_l2_mode (vlib_get_main (), vnet_get_main (),
			   MODE_L2_BRIDGE, gg->gg_uplink_sw_if_index,
			   gg->gg_bd_index, L2_BD_PORT_TYPE_NORMAL, 0, 0);
	  l2input_intf_bitmap_enable (gg->gg_uplink_sw_if_index,
				      L2INPUT_FEAT_GBP_NULL_CLASSIFY, 1);
	}

      hash_set (gbp_endpoint_group_db.gg_hash,
		gg->gg_id, gg - gbp_endpoint_group_pool);

    }
  else
    {
      gg = gbp_endpoint_group_get (ggi);
      gg->gg_locks++;
    }

  GBP_EPG_DBG ("add: %U", format_gbp_endpoint_group, gg);

  return (0);
}

void
gbp_endpoint_group_unlock (index_t ggi)
{
  gbp_endpoint_group_t *gg;

  gg = gbp_endpoint_group_get (ggi);

  gg->gg_locks--;

  if (0 == gg->gg_locks)
    {
      fib_protocol_t fproto;

      gg = pool_elt_at_index (gbp_endpoint_group_pool, ggi);

      if (~0 != gg->gg_uplink_sw_if_index)
	{
	  set_int_l2_mode (vlib_get_main (), vnet_get_main (),
			   MODE_L3, gg->gg_uplink_sw_if_index,
			   gg->gg_bd_index, L2_BD_PORT_TYPE_NORMAL, 0, 0);

	  l2input_intf_bitmap_enable (gg->gg_uplink_sw_if_index,
				      L2INPUT_FEAT_GBP_NULL_CLASSIFY, 0);
	}
      FOR_EACH_FIB_IP_PROTOCOL (fproto)
      {
	dpo_reset (&gg->gg_dpo[fproto]);
      }
      gbp_bridge_domain_unlock (gg->gg_gbd);
      gbp_route_domain_unlock (gg->gg_rd);

      hash_unset (gbp_endpoint_group_db.gg_hash, gg->gg_id);

      pool_put (gbp_endpoint_group_pool, gg);
    }
}

int
gbp_endpoint_group_delete (epg_id_t epg_id)
{
  index_t ggi;

  ggi = gbp_endpoint_group_find (epg_id);

  if (INDEX_INVALID != ggi)
    {
      GBP_EPG_DBG ("del: %U", format_gbp_endpoint_group,
		   gbp_endpoint_group_get (ggi));
      gbp_endpoint_group_unlock (ggi);

      return (0);
    }

  return (VNET_API_ERROR_NO_SUCH_ENTRY);
}

u32
gbp_endpoint_group_get_bd_id (const gbp_endpoint_group_t * gg)
{
  const gbp_bridge_domain_t *gb;

  gb = gbp_bridge_domain_get (gg->gg_gbd);

  return (gb->gb_bd_id);
}

index_t
gbp_endpoint_group_get_fib_index (gbp_endpoint_group_t * gg,
				  fib_protocol_t fproto)
{
  const gbp_route_domain_t *grd;

  grd = gbp_route_domain_get (gg->gg_rd);

  return (grd->grd_fib_index[fproto]);
}

u32
gbp_endpoint_group_get_bvi (gbp_endpoint_group_t * gg)
{
  const gbp_bridge_domain_t *gb;

  gb = gbp_bridge_domain_get (gg->gg_gbd);

  return (gb->gb_bvi_sw_if_index);
}

void
gbp_endpoint_group_walk (gbp_endpoint_group_cb_t cb, void *ctx)
{
  gbp_endpoint_group_t *gbpe;

  /* *INDENT-OFF* */
  pool_foreach(gbpe, gbp_endpoint_group_pool,
  {
    if (!cb(gbpe, ctx))
      break;
  });
  /* *INDENT-ON* */
}

static clib_error_t *
gbp_endpoint_group_cli (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  epg_id_t epg_id = EPG_INVALID;
  u32 uplink_sw_if_index = ~0;
  u32 bd_id = ~0;
  u32 rd_id = ~0;
  u8 add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &uplink_sw_if_index))
	;
      else if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "epg %d", &epg_id))
	;
      else if (unformat (input, "bd %d", &bd_id))
	;
      else if (unformat (input, "rd %d", &rd_id))
	;
      else
	break;
    }

  if (EPG_INVALID == epg_id)
    return clib_error_return (0, "EPG-ID must be specified");

  if (add)
    {
      if (~0 == uplink_sw_if_index)
	return clib_error_return (0, "interface must be specified");
      if (~0 == bd_id)
	return clib_error_return (0, "Bridge-domain must be specified");
      if (~0 == rd_id)
	return clib_error_return (0, "route-domain must be specified");

      gbp_endpoint_group_add_and_lock (epg_id, bd_id, rd_id,
				       uplink_sw_if_index);
    }
  else
    gbp_endpoint_group_delete (epg_id);

  return (NULL);
}

/*?
 * Configure a GBP Endpoint Group
 *
 * @cliexpar
 * @cliexstart{set gbp endpoint-group [del] epg <ID> bd <ID> <interface>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_endpoint_group_cli_node, static) = {
  .path = "gbp endpoint-group",
  .short_help = "gbp endpoint-group [del] epg <ID> bd <ID> rd <ID> <interface>",
  .function = gbp_endpoint_group_cli,
};

u8 *
format_gbp_endpoint_group (u8 * s, va_list * args)
{
  gbp_endpoint_group_t *gg = va_arg (*args, gbp_endpoint_group_t*);
  vnet_main_t *vnm = vnet_get_main ();

  if (NULL != gg)
    s = format (s, "%d, bd:[%d,%d], rd:[%d] uplink:%U locks:%d",
                gg->gg_id,
                gbp_endpoint_group_get_bd_id(gg), gg->gg_bd_index,
                gg->gg_rd,
                format_vnet_sw_if_index_name, vnm, gg->gg_uplink_sw_if_index,
                gg->gg_locks);
  else
    s = format (s, "NULL");

  return (s);
}

static int
gbp_endpoint_group_show_one (gbp_endpoint_group_t *gg, void *ctx)
{
  vlib_main_t *vm;

  vm = ctx;
  vlib_cli_output (vm, "  %U",format_gbp_endpoint_group, gg);

  return (1);
}

static clib_error_t *
gbp_endpoint_group_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "Endpoint-Groups:");
  gbp_endpoint_group_walk (gbp_endpoint_group_show_one, vm);

  return (NULL);
}


/*?
 * Show Group Based Policy Endpoint_Groups and derived information
 *
 * @cliexpar
 * @cliexstart{show gbp endpoint_group}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_endpoint_group_show_node, static) = {
  .path = "show gbp endpoint-group",
  .short_help = "show gbp endpoint-group\n",
  .function = gbp_endpoint_group_show,
};
/* *INDENT-ON* */

static clib_error_t *
gbp_endpoint_group_init (vlib_main_t * vm)
{
  gg_logger = vlib_log_register_class ("gbp", "epg");

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_endpoint_group_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
