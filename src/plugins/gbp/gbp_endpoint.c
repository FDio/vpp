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
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/feat_bitmap.h>

gbp_ep_by_itf_db_t gbp_ep_by_itf_db;
gbp_ep_by_mac_itf_db_t gbp_ep_by_mac_itf_db;
gbp_ep_by_ip_itf_db_t gbp_ep_by_ip_itf_db;

/**
 * Pool of GBP endpoints
 */
gbp_endpoint_t *gbp_endpoint_pool;

/* void */
/* gbp_itf_epg_update (u32 sw_if_index, epg_id_t src_epg, u8 do_policy) */
/* { */
/*   vec_validate_init_empty (gbp_itf_to_epg_db.gte_vec, */
/* 			   sw_if_index, ITF_INVALID); */

/*   if (0 == gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count) */
/*     { */
/*       l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_SRC_CLASSIFY, */
/* 				  1); */
/*       l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_FWD, 1); */
/*       if (do_policy) */
/* 	l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_GBP_POLICY, */
/* 				     1); */
/*     } */
/*   gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_epg = src_epg; */
/*   gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count++; */
/* } */

/* void */
/* gbp_itf_epg_delete (u32 sw_if_index) */
/* { */
/*   if (vec_len (gbp_itf_to_epg_db.gte_vec) <= sw_if_index) */
/*     return; */

/*   if (1 == gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count) */
/*     { */
/*       gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_epg = EPG_INVALID; */

/*       l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_SRC_CLASSIFY, */
/* 				  0); */
/*       l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_FWD, 0); */
/*       l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_GBP_POLICY, 0); */
/*     } */
/*   gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_ref_count--; */
/* } */

static void
gbp_endpoint_mk_key_mac_itf (const mac_address_t * mac,
			     u32 sw_if_index, clib_bihash_kv_16_8_t * key)
{
  key->key[0] = mac_address_as_u64 (mac);
  key->key[1] = sw_if_index;
}

static void
gbp_endpoint_extract_key_mac_itf (const clib_bihash_kv_16_8_t * key,
				  mac_address_t * mac, u32 * sw_if_index)
{
  mac_address_from_u64 (key->key[0], mac);
  *sw_if_index = key->key[1];
}

gbp_endpoint_t *
gbp_endpoint_find_mac_itf (const mac_address_t * mac, u32 sw_if_index)
{
  clib_bihash_kv_16_8_t key, value;
  int rv;

  gbp_endpoint_mk_key_mac_itf (mac, sw_if_index, &key);

  rv =
    clib_bihash_search_16_8 (&gbp_ep_by_mac_itf_db.gte_table, &key, &value);

  if (0 != rv)
    return NULL;

  return (gbp_endpoint_get (value.value));
}

static void
gbp_endpoint_mk_key_ip_itf (const ip46_address_t * ip,
			    u32 sw_if_index, clib_bihash_kv_24_8_t * key)
{
  key->key[0] = ip->as_u64[0];
  key->key[1] = ip->as_u64[1];
  key->key[2] = sw_if_index;
}

static void
gbp_endpoint_extract_key_ip_itf (const clib_bihash_kv_24_8_t * key,
				 ip46_address_t * ip, u32 * sw_if_index)
{
  ip->as_u64[0] = key->key[0];
  ip->as_u64[1] = key->key[1];
  *sw_if_index = key->key[2];
}

gbp_endpoint_t *
gbp_endpoint_find_ip_itf (const ip46_address_t * ip, u32 sw_if_index)
{
  clib_bihash_kv_24_8_t key, value;
  int rv;

  gbp_endpoint_mk_key_ip_itf (ip, sw_if_index, &key);

  rv = clib_bihash_search_24_8 (&gbp_ep_by_ip_itf_db.gte_table, &key, &value);

  if (0 != rv)
    return NULL;

  return (gbp_endpoint_get (value.value));
}

gbp_endpoint_t *
gbp_endpoint_find_itf (u32 sw_if_index)
{
  /* if (vec_len(gbp_ep_by_itf_db.gte_vec) >= sw_if_index) */
  /*   return NULL; */

  /* vec_search(gbp_ep_by_itf_db.gte_vec[sw_if_index],  */
  /* return (gbp_endpoint_get(gbp_ep_by_itf_db.gte_vec[sw_if_index][0])); */
  return (NULL);
}

static bool
gbp_endpoint_add_mac_itf (const mac_address_t * mac,
			  u32 sw_if_index, index_t gbpei)
{
  clib_bihash_kv_16_8_t key;
  int rv;

  gbp_endpoint_mk_key_mac_itf (mac, sw_if_index, &key);
  key.value = gbpei;

  rv = clib_bihash_add_del_16_8 (&gbp_ep_by_mac_itf_db.gte_table, &key, 1);

  return (0 == rv);
}

static bool
gbp_endpoint_add_ip_itf (const ip46_address_t * ip,
			 u32 sw_if_index, index_t gbpei)
{
  clib_bihash_kv_24_8_t key;
  int rv;

  gbp_endpoint_mk_key_ip_itf (ip, sw_if_index, &key);
  key.value = gbpei;

  rv = clib_bihash_add_del_24_8 (&gbp_ep_by_ip_itf_db.gte_table, &key, 1);

  return (0 == rv);
}

static void
gbp_endpoint_add_itf (u32 sw_if_index, index_t gbpei)
{
  vec_validate_init_empty (gbp_ep_by_itf_db.gte_vec, sw_if_index,
			   INDEX_INVALID);

  if (INDEX_INVALID == gbp_ep_by_itf_db.gte_vec[sw_if_index])
    {
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_SRC_CLASSIFY,
				  1);
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_FWD, 1);
      l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_GBP_POLICY, 1);
    }
  gbp_ep_by_itf_db.gte_vec[sw_if_index] = gbpei;
}

static void
gbp_endpoint_del_mac_itf (const mac_address_t * mac, u32 sw_if_index)
{
  clib_bihash_kv_16_8_t key;

  gbp_endpoint_mk_key_mac_itf (mac, sw_if_index, &key);

  clib_bihash_add_del_16_8 (&gbp_ep_by_mac_itf_db.gte_table, &key, 0);
}

static void
gbp_endpoint_del_ip_itf (const ip46_address_t * ip, u32 sw_if_index)
{
  clib_bihash_kv_24_8_t key;

  gbp_endpoint_mk_key_ip_itf (ip, sw_if_index, &key);

  clib_bihash_add_del_24_8 (&gbp_ep_by_ip_itf_db.gte_table, &key, 0);
}

static void
gbp_endpoint_del_itf (u32 sw_if_index)
{
  if (vec_len (gbp_ep_by_itf_db.gte_vec) <= sw_if_index)
    return;

  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_SRC_CLASSIFY, 0);
  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_GBP_FWD, 0);
  l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_GBP_POLICY, 0);

  gbp_ep_by_itf_db.gte_vec[sw_if_index] = INDEX_INVALID;
}

static index_t
gbp_endpoint_index (const gbp_endpoint_t * gbpe)
{
  return (gbpe - gbp_endpoint_pool);
}

int
gbp_endpoint_update (u32 sw_if_index,
		     const ip46_address_t * ips,
		     const mac_address_t * mac, epg_id_t epg_id, u32 * handle)
{
  gbp_endpoint_group_t *gepg;
  const ip46_address_t *ip;
  gbp_endpoint_t *gbpe;

  gbpe = NULL;
  gepg = gbp_endpoint_group_find (epg_id);

  if (NULL == gepg)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  /*
   * find an existing endpoint matching one of the key types
   */
  if (NULL != mac)
    {
      gbpe = gbp_endpoint_find_mac_itf (mac, sw_if_index);
    }
  if (NULL == gbpe && NULL != ips)
    {
      vec_foreach (ip, ips)
      {
	gbpe = gbp_endpoint_find_ip_itf (ip, sw_if_index);

	if (NULL != gbpe)
	  break;
      }
    }
  if (NULL == gbpe)
    {
      gbpe = gbp_endpoint_find_itf (sw_if_index);
    }

  if (NULL == gbpe)
    {
      index_t gbpei;
      u32 ii;
      /*
       * new entry
       */
      pool_get (gbp_endpoint_pool, gbpe);
      gbpei = gbp_endpoint_index (gbpe);

      gbpe->ge_epg_id = epg_id;
      gbpe->ge_sw_if_index = sw_if_index;
      gbp_endpoint_add_itf (gbpe->ge_sw_if_index, gbpei);

      if (NULL != mac)
	{
	  gbpe->ge_mac = *mac;

	  // FIXME ERROR
	  gbp_endpoint_add_mac_itf (mac, sw_if_index, gbpei);
	}

      if (NULL != ips)
	{
	  vec_validate (gbpe->ge_ips, vec_len (ips) - 1);
	  vec_foreach_index (ii, ips)
	  {
	    ip46_address_copy (&gbpe->ge_ips[ii], &ips[ii]);

	    // FIXME ERROR
	    gbp_endpoint_add_ip_itf (&ips[ii], sw_if_index, gbpei);

	    /*
	     * send a gratuitous ARP on the EPG's uplink. this is done so
	     * that if this EP has moved from some other place in the
	     * 'fabric', upstream devices are informed
	     */
	    if (ip46_address_is_ip4 (&ips[ii]))
	      send_ip4_garp_w_addr (vlib_get_main (),
				    &ips[ii].ip4,
				    gepg->gepg_uplink_sw_if_index);
	    else
	      send_ip6_na_w_addr (vlib_get_main (),
				  &ips[ii].ip6,
				  gepg->gepg_uplink_sw_if_index);
	  }
	}
    }
  else
    {
      /*
       * update existing entry..
       */
      ASSERT (0);
    }

  *handle = (gbpe - gbp_endpoint_pool);

  return (0);
}

void
gbp_endpoint_delete (u32 handle)
{
  gbp_endpoint_t *gbpe;

  if (pool_is_free_index (gbp_endpoint_pool, handle))
    return;

  gbpe = pool_elt_at_index (gbp_endpoint_pool, handle);

  gbp_endpoint_del_itf (gbpe->ge_sw_if_index);

  if (!mac_address_is_zero (&gbpe->ge_mac))
    {
      gbp_endpoint_del_mac_itf (&gbpe->ge_mac, gbpe->ge_sw_if_index);
    }

  if (NULL != gbpe->ge_ips)
    {
      const ip46_address_t *ip;

      vec_foreach (ip, gbpe->ge_ips)
      {
	gbp_endpoint_del_ip_itf (ip, gbpe->ge_sw_if_index);
      }
    }
  pool_put (gbp_endpoint_pool, gbpe);
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
  ip46_address_t ip = ip46_address_initializer, *ips = NULL;
  mac_address_t mac = ZERO_MAC_ADDRESS;
  vnet_main_t *vnm = vnet_get_main ();
  epg_id_t epg_id = EPG_INVALID;
  u32 handle = INDEX_INVALID;
  u32 sw_if_index = ~0;
  u8 add = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      ip46_address_reset (&ip);

      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "epg %d", &epg_id))
	;
      else if (unformat (input, "handle %d", &handle))
	;
      else if (unformat (input, "ip %U", unformat_ip4_address, &ip.ip4))
	vec_add1 (ips, ip);
      else if (unformat (input, "ip %U", unformat_ip6_address, &ip.ip6))
	vec_add1 (ips, ip);
      else if (unformat (input, "mac %U", unformat_mac_address, &mac))
	;
      else
	break;
    }

  if (add)
    {
      if (~0 == sw_if_index)
	return clib_error_return (0, "interface must be specified");
      if (EPG_INVALID == epg_id)
	return clib_error_return (0, "EPG-ID must be specified");

      rv = gbp_endpoint_update (sw_if_index, ips, &mac, epg_id, &handle);

      if (rv)
	return clib_error_return (0, "GBP Endpoint update returned %d", rv);
      else
	vlib_cli_output (vm, "handle %d\n", handle);
    }
  else
    {
      if (INDEX_INVALID == handle)
	return clib_error_return (0, "handle must be specified");

      gbp_endpoint_delete (handle);
    }

  vec_free (ips);

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
  .short_help = "gbp endpoint [del] <interface> epg <ID> ip <IP> mac <MAC>",
  .function = gbp_endpoint_cli,
};
/* *INDENT-ON* */

u8 *
format_gbp_endpoint (u8 * s, va_list * args)
{
  index_t gbpei = va_arg (*args, index_t);
  vnet_main_t *vnm = vnet_get_main ();
  const ip46_address_t *ip;
  gbp_endpoint_t *gbpe;

  gbpe = gbp_endpoint_get (gbpei);

  s = format (s, "[@%d] ", gbpei);
  s =
    format (s, "%U", format_vnet_sw_if_index_name, vnm, gbpe->ge_sw_if_index);
  s = format (s, ", IPs:[");

  vec_foreach (ip, gbpe->ge_ips)
  {
    s = format (s, "%U, ", format_ip46_address, ip, IP46_TYPE_ANY);
  }
  s = format (s, "]");

  s = format (s, " MAC:%U", format_mac_address_t, &gbpe->ge_mac);
  s = format (s, " EPG-ID:%d", gbpe->ge_epg_id);

  return s;
}

static walk_rc_t
gbp_endpoint_show_one (gbp_endpoint_t * gbpe, void *ctx)
{
  vlib_main_t *vm;

  vm = ctx;
  vlib_cli_output (vm, " %U", format_gbp_endpoint, gbp_endpoint_index (gbpe));

  return (WALK_CONTINUE);
}

static void
gbp_endpoint_walk_ip_itf (const clib_bihash_kv_24_8_t * kvp, void *arg)
{
  ip46_address_t ip;
  vlib_main_t *vm;
  u32 sw_if_index;

  vm = arg;

  gbp_endpoint_extract_key_ip_itf (kvp, &ip, &sw_if_index);

  vlib_cli_output (vm, " {%U, %U} -> %d",
		   format_ip46_address, &ip, IP46_TYPE_ANY,
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index, kvp->value);
}

static void
gbp_endpoint_walk_mac_itf (const clib_bihash_kv_16_8_t * kvp, void *arg)
{
  mac_address_t mac;
  vlib_main_t *vm;
  u32 sw_if_index;

  vm = arg;

  gbp_endpoint_extract_key_mac_itf (kvp, &mac, &sw_if_index);

  vlib_cli_output (vm, " {%U, %U} -> %d",
		   format_mac_address_t, &mac,
		   format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index, kvp->value);
}

static clib_error_t *
gbp_endpoint_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 sw_if_index, show_dbs, handle;

  handle = INDEX_INVALID;
  show_dbs = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &handle))
	;
      else if (unformat (input, "db", &handle))
	show_dbs = 1;
      else
	break;
    }

  if (INDEX_INVALID != handle)
    {
      vlib_cli_output (vm, "%U", format_gbp_endpoint, handle);
    }
  else if (show_dbs)
    {
      vlib_cli_output (vm, "\nDatabases:");
      clib_bihash_foreach_key_value_pair_24_8 (&gbp_ep_by_ip_itf_db.gte_table,
					       gbp_endpoint_walk_ip_itf, vm);
      clib_bihash_foreach_key_value_pair_16_8
	(&gbp_ep_by_mac_itf_db.gte_table, gbp_endpoint_walk_mac_itf, vm);

      vec_foreach_index (sw_if_index, gbp_ep_by_itf_db.gte_vec)
      {
	if (INDEX_INVALID != gbp_ep_by_itf_db.gte_vec[sw_if_index])
	  vlib_cli_output (vm, " {%U} -> %d",
			   format_vnet_sw_if_index_name, vnet_get_main (),
			   sw_if_index,
			   gbp_ep_by_itf_db.gte_vec[sw_if_index]);
      }
    }
  else
    {
      vlib_cli_output (vm, "Endpoints:");
      gbp_endpoint_walk (gbp_endpoint_show_one, vm);
    }

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

#define GBP_EP_HASH_NUM_BUCKETS (2 * 1024)
#define GBP_EP_HASH_MEMORY_SIZE (1 << 20)

static clib_error_t *
gbp_endpoint_init (vlib_main_t * vm)
{
  clib_bihash_init_24_8 (&gbp_ep_by_ip_itf_db.gte_table,
			 "GBP Endpoints - IP/Interface",
			 GBP_EP_HASH_NUM_BUCKETS, GBP_EP_HASH_MEMORY_SIZE);

  clib_bihash_init_16_8 (&gbp_ep_by_mac_itf_db.gte_table,
			 "GBP Endpoints - MAC/Interface",
			 GBP_EP_HASH_NUM_BUCKETS, GBP_EP_HASH_MEMORY_SIZE);

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_endpoint_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
