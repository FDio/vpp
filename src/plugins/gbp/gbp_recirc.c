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

#include <plugins/gbp/gbp_recirc.h>
#include <plugins/gbp/gbp_endpoint_group.h>
#include <plugins/gbp/gbp_endpoint.h>

#include <vnet/dpo/dvr_dpo.h>
#include <vnet/fib/fib_table.h>

/**
 * Pool of GBP recircs
 */
gbp_recirc_t *gbp_recirc_pool;

/**
 * Recirc configs keyed by sw_if_index
 */
index_t *gbp_recirc_db;

int
gbp_recirc_add (u32 sw_if_index, epg_id_t epg_id, u8 is_ext)
{
  gbp_recirc_t *gr;
  index_t gri;

  vec_validate_init_empty (gbp_recirc_db, sw_if_index, INDEX_INVALID);

  gri = gbp_recirc_db[sw_if_index];

  if (INDEX_INVALID == gri)
    {
      gbp_endpoint_group_t *gepg;
      fib_protocol_t fproto;

      pool_get (gbp_recirc_pool, gr);
      memset (gr, 0, sizeof (*gr));
      gri = gr - gbp_recirc_pool;

      gr->gr_epg = epg_id;
      gr->gr_is_ext = is_ext;
      gr->gr_sw_if_index = sw_if_index;

      /*
       * IP enable the recirc interface
       */
      ip4_sw_interface_enable_disable (gr->gr_sw_if_index, 1);
      ip6_sw_interface_enable_disable (gr->gr_sw_if_index, 1);

      /*
       * cache the FIB indicies of the EPG
       */
      gepg = gbp_endpoint_group_find (gr->gr_epg);

      if (NULL == gepg)
	return (VNET_API_ERROR_NO_SUCH_ENTRY);

      FOR_EACH_FIB_IP_PROTOCOL (fproto)
      {
	gr->gr_fib_index[fproto] = gepg->gepg_fib_index[fproto];
      }

      /*
       * Packets on the recirculation interface are subject to src-EPG
       * classification. Recirc interfaces are L2-emulation mode.
       *   for internal EPGs this is via an LPM on all external subnets.
       *   for external EPGs this is via a port mapping.
       */
      if (gr->gr_is_ext)
	{
	  /*
	   * recirc is for post-NAT translation packets going into
	   * the external EPG, these are classified to the NAT EPG
	   * based on its port
	   */
	  gbp_endpoint_update (gr->gr_sw_if_index,
			       NULL, NULL, gr->gr_epg, &gr->gr_ep);
	  vnet_feature_enable_disable ("ip4-unicast",
				       "ip4-gbp-src-classify",
				       gr->gr_sw_if_index, 1, 0, 0);
	  vnet_feature_enable_disable ("ip6-unicast",
				       "ip6-gbp-src-classify",
				       gr->gr_sw_if_index, 1, 0, 0);
	}
      else
	{
	  /*
	   * recirc is for pre-NAT translation packets coming from
	   * the external EPG, these are classified based on a LPM
	   * in the EPG's route-domain
	   */
	  vnet_feature_enable_disable ("ip4-unicast",
				       "ip4-gbp-lpm-classify",
				       gr->gr_sw_if_index, 1, 0, 0);
	  vnet_feature_enable_disable ("ip6-unicast",
				       "ip6-gbp-lpm-classify",
				       gr->gr_sw_if_index, 1, 0, 0);
	}

      gbp_recirc_db[sw_if_index] = gri;
    }

  return (0);
}

void
gbp_recirc_delete (u32 sw_if_index)
{
  gbp_recirc_t *gr;
  index_t gri;

  gri = gbp_recirc_db[sw_if_index];

  if (INDEX_INVALID != gri)
    {
      gr = pool_elt_at_index (gbp_recirc_pool, gri);

      if (gr->gr_is_ext)
	{
	  gbp_endpoint_delete (gr->gr_ep);
	  vnet_feature_enable_disable ("ip4-unicast",
				       "ip4-gbp-src-classify",
				       gr->gr_sw_if_index, 0, 0, 0);
	  vnet_feature_enable_disable ("ip6-unicast",
				       "ip6-gbp-src-classify",
				       gr->gr_sw_if_index, 0, 0, 0);
	}
      else
	{
	  vnet_feature_enable_disable ("ip4-unicast",
				       "ip4-gbp-lpm-classify",
				       gr->gr_sw_if_index, 0, 0, 0);
	  vnet_feature_enable_disable ("ip6-unicast",
				       "ip6-gbp-lpm-classify",
				       gr->gr_sw_if_index, 0, 0, 0);
	}

      ip4_sw_interface_enable_disable (gr->gr_sw_if_index, 0);
      ip6_sw_interface_enable_disable (gr->gr_sw_if_index, 0);

      gbp_recirc_db[sw_if_index] = INDEX_INVALID;
      pool_put (gbp_recirc_pool, gr);
    }
}

void
gbp_recirc_walk (gbp_recirc_cb_t cb, void *ctx)
{
  gbp_recirc_t *gbpe;

  /* *INDENT-OFF* */
  pool_foreach(gbpe, gbp_recirc_pool,
  {
    if (!cb(gbpe, ctx))
      break;
  });
  /* *INDENT-ON* */
}

static int
gbp_recirc_show_one (gbp_recirc_t * gr, void *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm;

  vm = ctx;
  vlib_cli_output (vm, "  %U, epg:%d, ext:%d",
		   format_vnet_sw_if_index_name, vnm,
		   gr->gr_sw_if_index, gr->gr_epg, gr->gr_is_ext);

  return (1);
}

static clib_error_t *
gbp_recirc_show (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "Recirculation-Interfaces:");
  gbp_recirc_walk (gbp_recirc_show_one, vm);

  return (NULL);
}


/*?
 * Show Group Based Policy Recircs and derived information
 *
 * @cliexpar
 * @cliexstart{show gbp recirc}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_recirc_show_node, static) = {
  .path = "show gbp recirc",
  .short_help = "show gbp recirc\n",
  .function = gbp_recirc_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
