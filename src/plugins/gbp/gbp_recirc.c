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
#include <plugins/gbp/gbp_itf.h>

#include <vnet/dpo/dvr_dpo.h>
#include <vnet/fib/fib_table.h>

#include <vlib/unix/plugin.h>

/**
 * Pool of GBP recircs
 */
gbp_recirc_t *gbp_recirc_pool;

/**
 * Recirc configs keyed by sw_if_index
 */
index_t *gbp_recirc_db;

/**
 * logger
 */
vlib_log_class_t gr_logger;

/**
 * L2 Emulation enable/disable symbols
 */
static void (*l2e_enable) (u32 sw_if_index);
static void (*l2e_disable) (u32 sw_if_index);

#define GBP_RECIRC_DBG(...)                           \
    vlib_log_debug (gr_logger, __VA_ARGS__);

u8 *
format_gbp_recirc (u8 * s, va_list * args)
{
  gbp_recirc_t *gr = va_arg (*args, gbp_recirc_t *);
  vnet_main_t *vnm = vnet_get_main ();

  return format (s, "  %U, epg:%d, ext:%d",
		 format_vnet_sw_if_index_name, vnm,
		 gr->gr_sw_if_index, gr->gr_epg, gr->gr_is_ext);
}

int
gbp_recirc_add (u32 sw_if_index, epg_id_t epg_id, u8 is_ext)
{
  gbp_recirc_t *gr;
  index_t gri;

  vec_validate_init_empty (gbp_recirc_db, sw_if_index, INDEX_INVALID);

  gri = gbp_recirc_db[sw_if_index];

  if (INDEX_INVALID == gri)
    {
      gbp_endpoint_group_t *gg;
      fib_protocol_t fproto;
      index_t ggi;

      ggi = gbp_endpoint_group_find (epg_id);

      if (INDEX_INVALID == ggi)
	return (VNET_API_ERROR_NO_SUCH_ENTRY);

      gbp_endpoint_group_lock (ggi);
      pool_get_zero (gbp_recirc_pool, gr);
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
      gr->gr_epgi = ggi;

      gg = gbp_endpoint_group_get (gr->gr_epgi);
      FOR_EACH_FIB_IP_PROTOCOL (fproto)
      {
	gr->gr_fib_index[fib_proto_to_dpo (fproto)] =
	  gbp_endpoint_group_get_fib_index (gg, fproto);
      }

      /*
       * bind to the bridge-domain of the EPG
       */
      gr->gr_itf = gbp_itf_add_and_lock (gr->gr_sw_if_index, gg->gg_bd_index);

      /*
       * set the interface into L2 emulation mode
       */
      l2e_enable (gr->gr_sw_if_index);

      /*
       * Packets on the recirculation interface are subject to src-EPG
       * classification. Recirc interfaces are L2-emulation mode.
       *   for internal EPGs this is via an LPM on all external subnets.
       *   for external EPGs this is via a port mapping.
       */
      if (gr->gr_is_ext)
	{
	  mac_address_t mac;
	  /*
	   * recirc is for post-NAT translation packets going into
	   * the external EPG, these are classified to the NAT EPG
	   * based on its port
	   */
	  mac_address_from_bytes (&mac,
				  vnet_sw_interface_get_hw_address
				  (vnet_get_main (), gr->gr_sw_if_index));
	  gbp_endpoint_update_and_lock (GBP_ENDPOINT_SRC_CP,
					gr->gr_sw_if_index,
					NULL, &mac, INDEX_INVALID,
					INDEX_INVALID, gr->gr_epg,
					GBP_ENDPOINT_FLAG_NONE,
					NULL, NULL, &gr->gr_ep);
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
  else
    {
      gr = gbp_recirc_get (gri);
    }

  GBP_RECIRC_DBG ("add: %U", format_gbp_recirc, gr);
  return (0);
}

int
gbp_recirc_delete (u32 sw_if_index)
{
  gbp_recirc_t *gr;
  index_t gri;

  if (vec_len (gbp_recirc_db) <= sw_if_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  gri = gbp_recirc_db[sw_if_index];

  if (INDEX_INVALID != gri)
    {
      gr = pool_elt_at_index (gbp_recirc_pool, gri);

      GBP_RECIRC_DBG ("del: %U", format_gbp_recirc, gr);

      if (gr->gr_is_ext)
	{
	  gbp_endpoint_unlock (GBP_ENDPOINT_SRC_CP, gr->gr_ep);
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
      l2e_disable (gr->gr_sw_if_index);

      gbp_itf_unlock (gr->gr_itf);

      gbp_endpoint_group_unlock (gr->gr_epgi);
      gbp_recirc_db[sw_if_index] = INDEX_INVALID;
      pool_put (gbp_recirc_pool, gr);
      return (0);
    }
  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

void
gbp_recirc_walk (gbp_recirc_cb_t cb, void *ctx)
{
  gbp_recirc_t *ge;

  /* *INDENT-OFF* */
  pool_foreach(ge, gbp_recirc_pool,
  {
    if (!cb(ge, ctx))
      break;
  });
  /* *INDENT-ON* */
}

static walk_rc_t
gbp_recirc_show_one (gbp_recirc_t * gr, void *ctx)
{
  vlib_cli_output (ctx, "  %U", format_gbp_recirc, gr);

  return (WALK_CONTINUE);
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

static clib_error_t *
gbp_recirc_init (vlib_main_t * vm)
{
  gr_logger = vlib_log_register_class ("gbp", "recirc");

  l2e_enable =
    vlib_get_plugin_symbol ("l2e_plugin.so", "l2_emulation_enable");
  l2e_disable =
    vlib_get_plugin_symbol ("l2e_plugin.so", "l2_emulation_disable");

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_recirc_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
