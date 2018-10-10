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

#include <plugins/gbp/gbp_route_domain.h>
#include <plugins/gbp/gbp_endpoint.h>

#include <vnet/dpo/dvr_dpo.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_neighbor.h>

/**
 * A fixed MAC address to use as the source MAC for packets L3 switched
 * onto the routed uu-fwd interfaces.
 * Magic values - origin lost to the mists of time...
 */
/* *INDENT-OFF* */
const static mac_address_t GBP_ROUTED_SRC_MAC = {
  .bytes = {
    0x0, 0x22, 0xBD, 0xF8, 0x19, 0xFF,
  }
};

const static mac_address_t GBP_ROUTED_DST_MAC = {
  .bytes = {
    00, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
  }
};
/* *INDENT-ON* */

/**
 * Pool of GBP route_domains
 */
gbp_route_domain_t *gbp_route_domain_pool;

/**
 * DB of route_domains
 */
typedef struct gbp_route_domain_db_t
{
  uword *gbd_by_rd_id;
} gbp_route_domain_db_t;

static gbp_route_domain_db_t gbp_route_domain_db;

/**
 * logger
 */
vlib_log_class_t grd_logger;

#define GBP_BD_DBG(...)                           \
    vlib_log_debug (grd_logger, __VA_ARGS__);

gbp_route_domain_t *
gbp_route_domain_get (index_t i)
{
  return (pool_elt_at_index (gbp_route_domain_pool, i));
}

static void
gbp_route_domain_lock (index_t i)
{
  gbp_route_domain_t *grd;

  grd = gbp_route_domain_get (i);
  grd->grd_locks++;
}

index_t
gbp_route_domain_find (u32 rd_id)
{
  uword *p;

  p = hash_get (gbp_route_domain_db.gbd_by_rd_id, rd_id);

  if (NULL != p)
    return p[0];

  return (INDEX_INVALID);
}

index_t
gbp_route_domain_find_and_lock (u32 rd_id)
{
  index_t grdi;

  grdi = gbp_route_domain_find (rd_id);

  if (INDEX_INVALID != grdi)
    {
      gbp_route_domain_lock (grdi);
    }
  return (grdi);
}

static void
gbp_route_domain_db_add (gbp_route_domain_t * grd)
{
  index_t grdi = grd - gbp_route_domain_pool;

  hash_set (gbp_route_domain_db.gbd_by_rd_id, grd->grd_id, grdi);
}

static void
gbp_route_domain_db_remove (gbp_route_domain_t * grd)
{
  hash_unset (gbp_route_domain_db.gbd_by_rd_id, grd->grd_id);
}

int
gbp_route_domain_add_and_lock (u32 rd_id,
			       u32 ip4_table_id,
			       u32 ip6_table_id,
			       u32 ip4_uu_sw_if_index, u32 ip6_uu_sw_if_index)
{
  gbp_route_domain_t *grd;
  index_t grdi;

  grdi = gbp_route_domain_find (rd_id);

  if (INDEX_INVALID == grdi)
    {
      fib_protocol_t fproto;

      pool_get_zero (gbp_route_domain_pool, grd);

      grd->grd_id = rd_id;
      grd->grd_table_id[FIB_PROTOCOL_IP4] = ip4_table_id;
      grd->grd_table_id[FIB_PROTOCOL_IP6] = ip6_table_id;
      grd->grd_uu_sw_if_index[FIB_PROTOCOL_IP4] = ip4_uu_sw_if_index;
      grd->grd_uu_sw_if_index[FIB_PROTOCOL_IP6] = ip6_uu_sw_if_index;

      FOR_EACH_FIB_IP_PROTOCOL (fproto)
      {
	grd->grd_fib_index[fproto] =
	  fib_table_find_or_create_and_lock (fproto,
					     grd->grd_table_id[fproto],
					     FIB_SOURCE_PLUGIN_HI);

	if (~0 != grd->grd_uu_sw_if_index[fproto])
	  {
	    ethernet_header_t *eth;
	    u8 *rewrite;

	    rewrite = NULL;
	    vec_validate (rewrite, sizeof (*eth) - 1);
	    eth = (ethernet_header_t *) rewrite;

	    eth->type = clib_host_to_net_u16 ((fproto == FIB_PROTOCOL_IP4 ?
					       ETHERNET_TYPE_IP4 :
					       ETHERNET_TYPE_IP6));

	    mac_address_to_bytes (gbp_route_domain_get_local_mac (),
				  eth->src_address);
	    mac_address_to_bytes (gbp_route_domain_get_remote_mac (),
				  eth->src_address);

	    /*
	     * create an adjacency out of the uu-fwd interfaces that will
	     * be used when adding subnet routes.
	     */
	    grd->grd_adj[fproto] =
	      adj_nbr_add_or_lock_w_rewrite (fproto,
					     fib_proto_to_link (fproto),
					     &ADJ_BCAST_ADDR,
					     grd->grd_uu_sw_if_index[fproto],
					     rewrite);
	  }
	else
	  {
	    grd->grd_adj[fproto] = INDEX_INVALID;
	  }
      }

      gbp_route_domain_db_add (grd);
    }
  else
    {
      grd = gbp_route_domain_get (grdi);
    }

  grd->grd_locks++;
  GBP_BD_DBG ("add: %U", format_gbp_route_domain, grd);

  return (0);
}

void
gbp_route_domain_unlock (index_t index)
{
  gbp_route_domain_t *grd;

  grd = gbp_route_domain_get (index);

  grd->grd_locks--;

  if (0 == grd->grd_locks)
    {
      fib_protocol_t fproto;

      GBP_BD_DBG ("destroy: %U", format_gbp_route_domain, grd);

      FOR_EACH_FIB_IP_PROTOCOL (fproto)
      {
	fib_table_unlock (grd->grd_fib_index[fproto],
			  fproto, FIB_SOURCE_PLUGIN_HI);
	if (INDEX_INVALID != grd->grd_adj[fproto])
	  adj_unlock (grd->grd_adj[fproto]);
      }

      gbp_route_domain_db_remove (grd);

      pool_put (gbp_route_domain_pool, grd);
    }
}

int
gbp_route_domain_delete (u32 rd_id)
{
  index_t grdi;

  GBP_BD_DBG ("del: %d", rd_id);
  grdi = gbp_route_domain_find (rd_id);

  if (INDEX_INVALID != grdi)
    {
      GBP_BD_DBG ("del: %U", format_gbp_route_domain,
		  gbp_route_domain_get (grdi));
      gbp_route_domain_unlock (grdi);

      return (0);
    }

  return (VNET_API_ERROR_NO_SUCH_ENTRY);
}

const mac_address_t *
gbp_route_domain_get_local_mac (void)
{
  return (&GBP_ROUTED_SRC_MAC);
}

const mac_address_t *
gbp_route_domain_get_remote_mac (void)
{
  return (&GBP_ROUTED_DST_MAC);
}

void
gbp_route_domain_walk (gbp_route_domain_cb_t cb, void *ctx)
{
  gbp_route_domain_t *gbpe;

  /* *INDENT-OFF* */
  pool_foreach(gbpe, gbp_route_domain_pool,
  {
    if (!cb(gbpe, ctx))
      break;
  });
  /* *INDENT-ON* */
}

static clib_error_t *
gbp_route_domain_cli (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 ip4_uu_sw_if_index = ~0;
  u32 ip6_uu_sw_if_index = ~0;
  u32 ip4_table_id = ~0;
  u32 ip6_table_id = ~0;
  u32 rd_id = ~0;
  u8 add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ip4-uu %U", unformat_vnet_sw_interface,
		    vnm, &ip4_uu_sw_if_index))
	;
      else if (unformat (input, "ip6-uu %U", unformat_vnet_sw_interface,
			 vnm, &ip6_uu_sw_if_index))
	;
      else if (unformat (input, "ip4-table-id %d", ip4_table_id))
	;
      else if (unformat (input, "ip6-table-id %d", ip6_table_id))
	;
      else if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "rd %d", &rd_id))
	;
      else
	break;
    }

  if (~0 == rd_id)
    return clib_error_return (0, "RD-ID must be specified");

  if (add)
    {
      if (~0 == ip4_table_id)
	return clib_error_return (0, "IP4 table-ID must be specified");
      if (~0 == ip6_table_id)
	return clib_error_return (0, "IP6 table-ID must be specified");

      gbp_route_domain_add_and_lock (rd_id, ip4_table_id,
				     ip6_table_id,
				     ip4_uu_sw_if_index, ip6_uu_sw_if_index);
    }
  else
    gbp_route_domain_delete (rd_id);

  return (NULL);
}

/*?
 * Configure a GBP route-domain
 *
 * @cliexpar
 * @cliexstart{set gbp route-domain [del] bd <ID> bvi <interface> uu-flood <interface>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_route_domain_cli_node, static) = {
  .path = "gbp route-domain",
  .short_help = "gbp route-domain [del] epg bd <ID> bvi <interface> uu-flood <interface>",
  .function = gbp_route_domain_cli,
};

u8 *
format_gbp_route_domain (u8 * s, va_list * args)
{
  gbp_route_domain_t *grd = va_arg (*args, gbp_route_domain_t*);
  vnet_main_t *vnm = vnet_get_main ();

  if (NULL != grd)
    s = format (s, "[%d] rd:%d ip4-uu:%U ip6-uu:%U locks:%d",
                grd - gbp_route_domain_pool,
                grd->grd_id,
                format_vnet_sw_if_index_name, vnm, grd->grd_uu_sw_if_index[FIB_PROTOCOL_IP4],
                format_vnet_sw_if_index_name, vnm, grd->grd_uu_sw_if_index[FIB_PROTOCOL_IP6],
                grd->grd_locks);
  else
    s = format (s, "NULL");

  return (s);
}

static int
gbp_route_domain_show_one (gbp_route_domain_t *gb, void *ctx)
{
  vlib_main_t *vm;

  vm = ctx;
  vlib_cli_output (vm, "  %U",format_gbp_route_domain, gb);

  return (1);
}

static clib_error_t *
gbp_route_domain_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "Route-Domains:");
  gbp_route_domain_walk (gbp_route_domain_show_one, vm);

  return (NULL);
}

/*?
 * Show Group Based Policy Route_Domains and derived information
 *
 * @cliexpar
 * @cliexstart{show gbp route_domain}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_route_domain_show_node, static) = {
  .path = "show gbp route-domain",
  .short_help = "show gbp route-domain\n",
  .function = gbp_route_domain_show,
};
/* *INDENT-ON* */

static clib_error_t *
gbp_route_domain_init (vlib_main_t * vm)
{
  grd_logger = vlib_log_register_class ("gbp", "rd");

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_route_domain_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
