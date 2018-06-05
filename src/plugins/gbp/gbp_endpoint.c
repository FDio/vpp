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

#include <plugins/gbp/gbp_endpoint.h>
#include <plugins/gbp/gbp_endpoint_group.h>

#include <vnet/ethernet/arp_packet.h>

/**
 * IP4 destintion address to destination EPG mapping table
 */
typedef struct gbp_ip4_to_epg_db_t_
{
  /**
   * use a simple hash table
   */
  uword *g4ie_hash;
} gbp_ip4_to_epg_db_t;

static gbp_ip4_to_epg_db_t gbp_ip4_to_epg_db;

/**
 * IP6 destintion address to destination EPG mapping table
 */
typedef struct gbp_ip6_to_epg_db_t_
{
  /**
   * use a memroy hash table
   */
  uword *g6ie_hash;
} gbp_ip6_to_epg_db_t;

static gbp_ip6_to_epg_db_t gbp_ip6_to_epg_db;


const static gbp_itf_t ITF_INVALID = {
  .gi_epg = EPG_INVALID,
  .gi_ref_count = 0,
};

gbp_itf_to_epg_db_t gbp_itf_to_epg_db;

/**
 * Pool of GBP endpoints
 */
static gbp_endpoint_t *gbp_endpoint_pool;

/**
 * DB of endpoints
 */
static uword *gbp_endpoint_db;

static void
gbp_ip_epg_update (const ip46_address_t * ip, epg_id_t epg_id)
{
  /*
   * we are dealing only with addresses here so this limited
   * is_ip4 check is ok
   */
  if (ip46_address_is_ip4 (ip))
    {
      hash_set (gbp_ip4_to_epg_db.g4ie_hash, ip->ip4.as_u32, epg_id);
    }
  else
    {
      hash_set_mem (gbp_ip6_to_epg_db.g6ie_hash, &ip->ip6, epg_id);
    }
}

static void
gbp_ip_epg_delete (const ip46_address_t * ip)
{
  if (ip46_address_is_ip4 (ip))
    {
      hash_unset (gbp_ip4_to_epg_db.g4ie_hash, ip->ip4.as_u32);
    }
  else
    {
      hash_unset_mem (gbp_ip6_to_epg_db.g6ie_hash, &ip->ip6);
    }
}

void
gbp_itf_epg_update (u32 sw_if_index, epg_id_t src_epg, u8 do_policy)
{
  vec_validate_init_empty (gbp_itf_to_epg_db.gte_vec,
			   sw_if_index, ITF_INVALID);

  if (0 == gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count)
    {
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_SRC_CLASSIFY,
				  1);
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_FWD, 1);
      if (do_policy)
	l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_GBP_POLICY,
				     1);
    }
  gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_epg = src_epg;
  gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count++;
}

void
gbp_itf_epg_delete (u32 sw_if_index)
{
  if (vec_len (gbp_itf_to_epg_db.gte_vec) <= sw_if_index)
    return;

  if (1 == gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count)
    {
      gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_epg = EPG_INVALID;

      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_SRC_CLASSIFY,
				  0);
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_FWD, 0);
      l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_GBP_POLICY, 0);
    }
  gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count--;
}

int
gbp_endpoint_update (u32 sw_if_index,
		     const ip46_address_t * ip, epg_id_t epg_id)
{
  gbp_endpoint_key_t key = {
    .gek_ip = *ip,
    .gek_sw_if_index = sw_if_index,
  };
  gbp_endpoint_group_t *gepg;
  gbp_endpoint_t *gbpe;
  uword *p;

  gepg = gbp_endpoint_group_find (epg_id);

  if (NULL == gepg)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  p = hash_get_mem (gbp_endpoint_db, &key);

  if (p)
    {
      gbpe = pool_elt_at_index (gbp_endpoint_pool, p[0]);
    }
  else
    {
      pool_get (gbp_endpoint_pool, gbpe);

      gbpe->ge_key = clib_mem_alloc (sizeof (gbp_endpoint_key_t));
      clib_memcpy (gbpe->ge_key, &key, sizeof (gbp_endpoint_key_t));

      hash_set_mem (gbp_endpoint_db, gbpe->ge_key, gbpe - gbp_endpoint_pool);
    }

  gbpe->ge_epg_id = epg_id;

  gbp_itf_epg_update (gbpe->ge_key->gek_sw_if_index, gbpe->ge_epg_id, 1);

  if (!ip46_address_is_zero (&gbpe->ge_key->gek_ip))
    gbp_ip_epg_update (&gbpe->ge_key->gek_ip, gbpe->ge_epg_id);

  /*
   * send a gratuitous ARP on the EPG's uplink. this is done so that if
   * this EP has moved from some other place in the 'fabric', upstream
   * devices are informed
   */
  if (ip46_address_is_ip4 (&gbpe->ge_key->gek_ip))
    send_ip4_garp_w_addr (vlib_get_main (),
			  &gbpe->ge_key->gek_ip.ip4,
			  gepg->gepg_uplink_sw_if_index);
  else
    send_ip6_na_w_addr (vlib_get_main (),
			&gbpe->ge_key->gek_ip.ip6,
			gepg->gepg_uplink_sw_if_index);

  return (0);
}

void
gbp_endpoint_delete (u32 sw_if_index, const ip46_address_t * ip)
{
  gbp_endpoint_key_t key = {
    .gek_ip = *ip,
    .gek_sw_if_index = sw_if_index,
  };
  gbp_endpoint_t *gbpe;
  uword *p;

  p = hash_get_mem (gbp_endpoint_db, &key);

  if (p)
    {
      gbpe = pool_elt_at_index (gbp_endpoint_pool, p[0]);

      hash_unset_mem (gbp_endpoint_db, gbpe->ge_key);

      gbp_itf_epg_delete (gbpe->ge_key->gek_sw_if_index);
      if (!ip46_address_is_zero (&gbpe->ge_key->gek_ip))
	gbp_ip_epg_delete (&gbpe->ge_key->gek_ip);

      clib_mem_free (gbpe->ge_key);

      pool_put (gbp_endpoint_pool, gbpe);
    }
}

void
gbp_endpoint_walk (gbp_endpoint_cb_t cb, void *ctx)
{
  gbp_endpoint_t *gbpe;

  /* *INDENT-OFF* */
  pool_foreach(gbpe, gbp_endpoint_pool,
  {
    if (!cb(gbpe, ctx))
      break;
  });
  /* *INDENT-ON* */
}

static clib_error_t *
gbp_endpoint_cli (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  epg_id_t epg_id = EPG_INVALID;
  ip46_address_t ip = { };
  u32 sw_if_index = ~0;
  u8 add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "epg %d", &epg_id))
	;
      else if (unformat (input, "ip %U", unformat_ip4_address, &ip.ip4))
	;
      else if (unformat (input, "ip %U", unformat_ip6_address, &ip.ip6))
	;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");
  if (EPG_INVALID == epg_id)
    return clib_error_return (0, "EPG-ID must be specified");
  if (ip46_address_is_zero (&ip))
    return clib_error_return (0, "IP address must be specified");

  if (add)
    gbp_endpoint_update (sw_if_index, &ip, epg_id);
  else
    gbp_endpoint_delete (sw_if_index, &ip);

  return (NULL);
}


/*?
 * Configure a GBP Endpoint
 *
 * @cliexpar
 * @cliexstart{set gbp endpoint [del] <interface> epg <ID> ip <IP>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_endpoint_cli_node, static) = {
  .path = "gbp endpoint",
  .short_help = "gbp endpoint [del] <interface> epg <ID> ip <IP>",
  .function = gbp_endpoint_cli,
};
/* *INDENT-ON* */

static int
gbp_endpoint_show_one (gbp_endpoint_t * gbpe, void *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm;

  vm = ctx;
  vlib_cli_output (vm, "  {%U, %U} -> %d",
		   format_vnet_sw_if_index_name, vnm,
		   gbpe->ge_key->gek_sw_if_index,
		   format_ip46_address, &gbpe->ge_key->gek_ip, IP46_TYPE_ANY,
		   gbpe->ge_epg_id);

  return (1);
}

static clib_error_t *
gbp_endpoint_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip46_address_t ip, *ipp;
  epg_id_t epg_id;
  u32 sw_if_index;

  vlib_cli_output (vm, "Endpoints:");
  gbp_endpoint_walk (gbp_endpoint_show_one, vm);

  vlib_cli_output (vm, "\nSource interface to EPG:");

  vec_foreach_index (sw_if_index, gbp_itf_to_epg_db.gte_vec)
  {
    if (EPG_INVALID != gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_epg)
      {
	vlib_cli_output (vm, "  %U -> %d",
			 format_vnet_sw_if_index_name, vnm, sw_if_index,
			 gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_epg);
      }
  }

  vlib_cli_output (vm, "\nDestination IP4 to EPG:");

  /* *INDENT-OFF* */
  hash_foreach (ip.ip4.as_u32, epg_id, gbp_ip4_to_epg_db.g4ie_hash,
  {
    vlib_cli_output (vm, "  %U -> %d", format_ip46_address, &ip,
                     IP46_TYPE_IP4, epg_id);
  });
  /* *INDENT-ON* */

  vlib_cli_output (vm, "\nDestination IP6 to EPG:");

  /* *INDENT-OFF* */
  hash_foreach_mem (ipp, epg_id, gbp_ip6_to_epg_db.g6ie_hash,
  {
    vlib_cli_output (vm, "  %U -> %d", format_ip46_address, ipp,
                     IP46_TYPE_IP6, epg_id);
  });
  /* *INDENT-ON* */

  return (NULL);
}


/*?
 * Show Group Based Policy Endpoints and derived information
 *
 * @cliexpar
 * @cliexstart{show gbp endpoint}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_endpoint_show_node, static) = {
  .path = "show gbp endpoint",
  .short_help = "show gbp endpoint\n",
  .function = gbp_endpoint_show,
};
/* *INDENT-ON* */

static clib_error_t *
gbp_endpoint_init (vlib_main_t * vm)
{
  gbp_endpoint_db = hash_create_mem (0,
				     sizeof (gbp_endpoint_key_t),
				     sizeof (u32));
  gbp_ip6_to_epg_db.g6ie_hash =
    hash_create_mem (0, sizeof (ip6_address_t), sizeof (u32));
  return 0;
}

VLIB_INIT_FUNCTION (gbp_endpoint_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
