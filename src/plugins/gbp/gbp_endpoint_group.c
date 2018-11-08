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

#include <vnet/dpo/dvr_dpo.h>
#include <vnet/fib/fib_table.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>

/**
 * Pool of GBP endpoint_groups
 */
gbp_endpoint_group_t *gbp_endpoint_group_pool;

/**
 * DB of endpoint_groups
 */
gbp_endpoint_group_db_t gbp_endpoint_group_db;

gbp_endpoint_group_t *
gbp_endpoint_group_find (epg_id_t epg_id)
{
  uword *p;

  p = hash_get (gbp_endpoint_group_db.gepg_hash, epg_id);

  if (NULL != p)
    return (pool_elt_at_index (gbp_endpoint_group_pool, p[0]));

  return (NULL);
}

int
gbp_endpoint_group_add (epg_id_t epg_id,
			u32 bd_id,
			u32 ip4_table_id,
			u32 ip6_table_id, u32 uplink_sw_if_index)
{
  gbp_endpoint_group_t *gepg;

  gepg = gbp_endpoint_group_find (epg_id);

  if (NULL == gepg)
    {
      fib_protocol_t fproto;

      pool_get (gbp_endpoint_group_pool, gepg);
      clib_memset (gepg, 0, sizeof (*gepg));

      gepg->gepg_id = epg_id;
      gepg->gepg_bd = bd_id;
      gepg->gepg_rd[FIB_PROTOCOL_IP4] = ip4_table_id;
      gepg->gepg_rd[FIB_PROTOCOL_IP6] = ip6_table_id;
      gepg->gepg_uplink_sw_if_index = uplink_sw_if_index;

      /*
       * an egress DVR dpo for internal subnets to use when sending
       * on the uplink interface
       */
      FOR_EACH_FIB_IP_PROTOCOL (fproto)
      {
	gepg->gepg_fib_index[fproto] =
	  fib_table_find_or_create_and_lock (fproto,
					     gepg->gepg_rd[fproto],
					     FIB_SOURCE_PLUGIN_HI);

	if (~0 == gepg->gepg_fib_index[fproto])
	  {
	    return (VNET_API_ERROR_NO_SUCH_FIB);
	  }

	dvr_dpo_add_or_lock (uplink_sw_if_index,
			     fib_proto_to_dpo (fproto),
			     &gepg->gepg_dpo[fproto]);
      }

      /*
       * packets direct from the uplink have had policy applied
       */
      l2input_intf_bitmap_enable (gepg->gepg_uplink_sw_if_index,
				  L2INPUT_FEAT_GBP_NULL_CLASSIFY, 1);

      hash_set (gbp_endpoint_group_db.gepg_hash,
		gepg->gepg_id, gepg - gbp_endpoint_group_pool);

    }

  return (0);
}

void
gbp_endpoint_group_delete (epg_id_t epg_id)
{
  gbp_endpoint_group_t *gepg;
  uword *p;

  p = hash_get (gbp_endpoint_group_db.gepg_hash, epg_id);

  if (NULL != p)
    {
      fib_protocol_t fproto;

      gepg = pool_elt_at_index (gbp_endpoint_group_pool, p[0]);

      l2input_intf_bitmap_enable (gepg->gepg_uplink_sw_if_index,
				  L2INPUT_FEAT_GBP_NULL_CLASSIFY, 0);

      FOR_EACH_FIB_IP_PROTOCOL (fproto)
      {
	dpo_reset (&gepg->gepg_dpo[fproto]);
	fib_table_unlock (gepg->gepg_fib_index[fproto],
			  fproto, FIB_SOURCE_PLUGIN_HI);
      }

      hash_unset (gbp_endpoint_group_db.gepg_hash, epg_id);

      pool_put (gbp_endpoint_group_pool, gepg);
    }
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

      gbp_endpoint_group_add (epg_id, bd_id, rd_id, rd_id,
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

static int
gbp_endpoint_group_show_one (gbp_endpoint_group_t *gepg, void *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm;

  vm = ctx;
  vlib_cli_output (vm, "  %d, bd:%d, ip4:%d ip6:%d uplink:%U",
                   gepg->gepg_id,
                   gepg->gepg_bd,
                   gepg->gepg_rd[FIB_PROTOCOL_IP4],
                   gepg->gepg_rd[FIB_PROTOCOL_IP6],
		   format_vnet_sw_if_index_name, vnm, gepg->gepg_uplink_sw_if_index);

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
