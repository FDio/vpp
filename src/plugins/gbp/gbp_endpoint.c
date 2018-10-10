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
#include <plugins/gbp/gbp_itf.h>
#include <plugins/gbp/gbp_scanner.h>
#include <plugins/gbp/gbp_bridge_domain.h>
#include <plugins/gbp/gbp_route_domain.h>
#include <plugins/gbp/gbp_policy_dpo.h>
#include <plugins/gbp/gbp_vxlan.h>

#include <vnet/ethernet/arp.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_neighbor.h>

static const char *gbp_endpoint_attr_names[] = GBP_ENDPOINT_ATTR_NAMES;

/**
 * EP DBs
 */
gbp_ep_db_t gbp_ep_db;

vlib_log_class_t gbp_ep_logger;

#define GBP_ENDPOINT_DBG(...)                           \
    vlib_log_debug (gbp_ep_logger, __VA_ARGS__);

#define GBP_ENDPOINT_INFO(...)                          \
    vlib_log_notice (gbp_ep_logger, __VA_ARGS__);

/**
 * GBP Endpoint inactive timeout (in seconds)
 * If a dynamically learned Endpoint has not been heard from in this
 * amount of time it is considered inactive and discarded
 */
static u32 GBP_ENDPOINT_INACTIVE_TIME = 30;

/**
 * Pool of GBP endpoints
 */
gbp_endpoint_t *gbp_endpoint_pool;

/**
 * A count of the number of dynamic entries
 */
static u32 gbp_n_learnt_endpoints;

#define FOR_EACH_GBP_ENDPOINT_ATTR(_item)		\
    for (_item = GBP_ENDPOINT_ATTR_FIRST;		\
	 _item < GBP_ENDPOINT_ATTR_LAST;		\
	 _item++)

u8 *
format_gbp_endpoint_flags (u8 * s, va_list * args)
{
  gbp_endpoint_attr_t attr;
  gbp_endpoint_flags_t flags = va_arg (*args, gbp_endpoint_flags_t);

  FOR_EACH_GBP_ENDPOINT_ATTR (attr)
  {
    if ((1 << attr) & flags)
      {
	s = format (s, "%s,", gbp_endpoint_attr_names[attr]);
      }
  }

  return (s);
}

int
gbp_endpoint_is_remote (const gbp_endpoint_t * ge)
{
  return (ge->ge_flags & GBP_ENDPOINT_FLAG_REMOTE);
}

static void
gbp_endpoint_extract_key_mac_itf (const clib_bihash_kv_16_8_t * key,
				  mac_address_t * mac, u32 * sw_if_index)
{
  mac_address_from_u64 (key->key[0], mac);
  *sw_if_index = key->key[1];
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
gbp_endpoint_find_ip (const ip46_address_t * ip, u32 fib_index)
{
  clib_bihash_kv_24_8_t key, value;
  int rv;

  gbp_endpoint_mk_key_ip (ip, fib_index, &key);

  rv = clib_bihash_search_24_8 (&gbp_ep_db.ged_by_ip_rd, &key, &value);

  if (0 != rv)
    return NULL;

  return (gbp_endpoint_get (value.value));
}

static void
gbp_endpoint_add_itf (u32 sw_if_index, index_t gei)
{
  vec_validate_init_empty (gbp_ep_db.ged_by_sw_if_index, sw_if_index, ~0);

  gbp_ep_db.ged_by_sw_if_index[sw_if_index] = gei;
}

static bool
gbp_endpoint_add_mac (const mac_address_t * mac, u32 bd_index, index_t gei)
{
  clib_bihash_kv_16_8_t key;
  int rv;

  gbp_endpoint_mk_key_mac (mac->bytes, bd_index, &key);
  key.value = gei;

  rv = clib_bihash_add_del_16_8 (&gbp_ep_db.ged_by_mac_bd, &key, 1);


  return (0 == rv);
}

static bool
gbp_endpoint_add_ip (const ip46_address_t * ip, u32 fib_index, index_t gei)
{
  clib_bihash_kv_24_8_t key;
  int rv;

  gbp_endpoint_mk_key_ip (ip, fib_index, &key);
  key.value = gei;

  rv = clib_bihash_add_del_24_8 (&gbp_ep_db.ged_by_ip_rd, &key, 1);

  return (0 == rv);
}

static void
gbp_endpoint_del_mac (const mac_address_t * mac, u32 bd_index)
{
  clib_bihash_kv_16_8_t key;

  gbp_endpoint_mk_key_mac (mac->bytes, bd_index, &key);

  clib_bihash_add_del_16_8 (&gbp_ep_db.ged_by_mac_bd, &key, 0);
}

static void
gbp_endpoint_del_ip (const ip46_address_t * ip, u32 fib_index)
{
  clib_bihash_kv_24_8_t key;

  gbp_endpoint_mk_key_ip (ip, fib_index, &key);

  clib_bihash_add_del_24_8 (&gbp_ep_db.ged_by_ip_rd, &key, 0);
}

static index_t
gbp_endpoint_index (const gbp_endpoint_t * ge)
{
  return (ge - gbp_endpoint_pool);
}

static ip46_type_t
ip46_address_get_type (const ip46_address_t * a)
{
  return (ip46_address_is_ip4 (a) ? IP46_TYPE_IP4 : IP46_TYPE_IP6);
}

static ip46_type_t
ip46_address_get_len (const ip46_address_t * a)
{
  return (ip46_address_is_ip4 (a) ? 32 : 128);
}

static gbp_endpoint_t *
gbp_endpoint_alloc (epg_id_t epg_id,
		    index_t ggi, u32 sw_if_index, gbp_endpoint_flags_t flags,
		    const ip46_address_t * tun_src,
		    const ip46_address_t * tun_dst)
{
  gbp_endpoint_t *ge;

  pool_get_zero (gbp_endpoint_pool, ge);

  ge->ge_epg = ggi;
  ge->ge_epg_id = epg_id;
  ge->ge_flags = flags;
  ge->ge_sw_if_index = sw_if_index;
  ge->ge_last_time = vlib_time_now (vlib_get_main ());

  gbp_endpoint_group_find_and_lock (epg_id);

  if (gbp_endpoint_is_remote (ge))
    {
      if (NULL != tun_src)
	ip46_address_copy (&ge->tun.ge_src, tun_src);
      if (NULL != tun_dst)
	ip46_address_copy (&ge->tun.ge_dst, tun_dst);

      /*
       * the input interface may be the parent GBP-vxlan interface,
       * create a child vlxan-gbp tunnel and use that as the endpoint's
       * interface.
       */
      switch (gbp_vxlan_tunnel_get_type (sw_if_index))
	{
	case GBP_VXLAN_TEMPLATE_TUNNEL:
	  ge->tun.ge_parent_sw_if_index = sw_if_index;
	  ge->ge_sw_if_index =
	    gbp_vxlan_tunnel_clone_and_lock (sw_if_index, tun_src, tun_dst);
	  break;
	case VXLAN_GBP_TUNNEL:
	  ge->tun.ge_parent_sw_if_index =
	    vxlan_gbp_tunnel_get_parent (sw_if_index);
	  ge->ge_sw_if_index = sw_if_index;
	  vxlan_gbp_tunnel_lock (ge->ge_sw_if_index);
	  break;
	}
    }

  return (ge);
}

int
gbp_endpoint_update (u32 sw_if_index,
		     const ip46_address_t * ips,
		     const mac_address_t * mac,
		     epg_id_t epg_id,
		     gbp_endpoint_flags_t flags,
		     const ip46_address_t * tun_src,
		     const ip46_address_t * tun_dst, u32 * handle)
{
  gbp_endpoint_group_t *gg;
  gbp_endpoint_t *ge;
  index_t ggi, gei;

  if (~0 == sw_if_index)
    return (VNET_API_ERROR_INVALID_SW_IF_INDEX);

  ge = NULL;
  ggi = gbp_endpoint_group_find_and_lock (epg_id);

  if (INDEX_INVALID == ggi)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  gg = gbp_endpoint_group_get (ggi);

  /*
   * L2 EP
   */
  if (NULL != mac && !mac_address_is_zero (mac))
    {
      /*
       * find an existing endpoint matching one of the key types
       */
      ge = gbp_endpoint_find_mac (mac->bytes, gg->gg_bd_index);
      if (NULL == ge)
	{
	  /*
	   * new entry
	   */
	  ge = gbp_endpoint_alloc (epg_id, ggi, sw_if_index, flags,
				   tun_src, tun_dst);
	  gei = gbp_endpoint_index (ge);
	  mac_address_copy (&ge->ge_mac, mac);

	  ge->ge_itf = gbp_itf_add_and_lock (ge->ge_sw_if_index,
					     gg->gg_bd_index);

	  gbp_itf_set_l2_input_feature (ge->ge_itf, gei,
					L2INPUT_FEAT_GBP_FWD);

	  if (gbp_endpoint_is_remote (ge))
	    {
	      gbp_itf_set_l2_output_feature (ge->ge_itf, gei,
					     L2OUTPUT_FEAT_GBP_POLICY_MAC);
	    }
	  else
	    {
	      gbp_endpoint_add_itf (ge->ge_sw_if_index, gei);
	      gbp_itf_set_l2_output_feature (ge->ge_itf, gei,
					     L2OUTPUT_FEAT_GBP_POLICY_PORT);
	    }

	  gbp_endpoint_add_mac (mac, gg->gg_bd_index, gei);

	  l2fib_add_entry (mac->bytes, gg->gg_bd_index, ge->ge_sw_if_index,
			   L2FIB_ENTRY_RESULT_FLAG_STATIC);
	}
      else
	{
	  /*
	   * update existing entry..
	   */
	  ge->ge_flags = flags;
	  gei = gbp_endpoint_index (ge);
	  goto out;
	}
    }

  /*
   * L3 EP
   */
  if (NULL != ips && !ip46_address_is_zero (ips))
    {
      const ip46_address_t *ip;
      fib_protocol_t fproto;
      gbp_endpoint_t *l3_ge;
      u32 ii;

      /*
       * look for a matching EP by any of the address
       * An EP's IP addresses cannot change so we can search based on
       * the first
       */
      fproto = fib_proto_from_ip46 (ip46_address_get_type (&ips[0]));

      l3_ge = gbp_endpoint_find_ip (&ips[0],
				    gbp_endpoint_group_get_fib_index (gg,
								      fproto));
      if (NULL == l3_ge)
	{
	  if (NULL == ge)
	    {
	      ge = gbp_endpoint_alloc (epg_id, ggi, sw_if_index, flags,
				       tun_src, tun_dst);
	      ge->ge_itf = gbp_itf_add_and_lock (sw_if_index, ~0);
	    }
	  else
	    /* L2 EP with IPs */
	    gei = gbp_endpoint_index (ge);
	}
      else
	{
	  /* modify */
	  ge = l3_ge;
	  ge->ge_flags = flags;
	  gei = gbp_endpoint_index (ge);
	  goto out;
	}

      gei = gbp_endpoint_index (ge);
      ge->ge_ips = ips;
      vec_validate (ge->ge_adjs, vec_len (ips) - 1);

      vec_foreach_index (ii, ge->ge_ips)
      {
	ethernet_header_t *eth;
	u32 ip_sw_if_index;
	u8 *rewrite;

	rewrite = NULL;
	ip = &ge->ge_ips[ii];
	fproto = fib_proto_from_ip46 (ip46_address_get_type (ip));

	bd_add_del_ip_mac (gg->gg_bd_index,
			   ip,
			   ge->ge_mac.bytes, !ip46_address_is_ip4 (ip), 1);

	// FIXME - check error
	gbp_endpoint_add_ip (ip,
			     gbp_endpoint_group_get_fib_index (gg, fproto),
			     gei);

	/*
	 * add a host route via the EPG's BVI we need this because the
	 * adj fib does not install, due to cover refinement check, since
	 * the BVI's prefix is /32
	 */
	fib_prefix_t pfx = {
	  .fp_proto = fproto,
	  .fp_len = ip46_address_get_len (ip),
	  .fp_addr = *ip,
	};
	vec_validate (rewrite, sizeof (*eth) - 1);
	eth = (ethernet_header_t *) rewrite;

	eth->type = clib_host_to_net_u16 ((fproto == FIB_PROTOCOL_IP4 ?
					   ETHERNET_TYPE_IP4 :
					   ETHERNET_TYPE_IP6));

	if (gbp_endpoint_is_remote (ge))
	  {
	    /*
	     * for dynamic EPs we msut add the IP adjacency via the learned
	     * tunnel since the BD will not contain the EP's MAC since it was
	     * L3 learned. The dst MAC address used is the 'BD's MAC'.
	     */
	    ip_sw_if_index = ge->ge_sw_if_index;

	    clib_memcpy (eth->src_address,
			 gbp_route_domain_get_local_mac ()->bytes,
			 sizeof (mac_address_t));
	    clib_memcpy (eth->dst_address,
			 gbp_route_domain_get_remote_mac ()->bytes,
			 sizeof (mac_address_t));
	  }
	else
	  {
	    /*
	     * for the static EPs we add the IP adjacency via the BVI
	     * knowing that the BD has the MAC address to route to and
	     * that policy will be applied on egress to the EP's port
	     */
	    ip_sw_if_index = gbp_endpoint_group_get_bvi (gg);

	    clib_memcpy (eth->src_address,
			 vnet_sw_interface_get_hw_address (vnet_get_main (),
							   ip_sw_if_index),
			 sizeof (mac_address_t));
	    clib_memcpy (eth->dst_address,
			 ge->ge_mac.bytes, sizeof (mac_address_t));
	  }

	fib_table_entry_path_add
	  (gbp_endpoint_group_get_fib_index (gg, fproto),
	   &pfx, FIB_SOURCE_PLUGIN_LOW,
	   FIB_ENTRY_FLAG_NONE,
	   fib_proto_to_dpo (fproto), ip, ip_sw_if_index,
	   ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);

	ge->ge_adjs[ii] = adj_nbr_add_or_lock_w_rewrite (fproto,
							 fib_proto_to_link
							 (fproto), ip,
							 ip_sw_if_index,
							 rewrite);

	if (gbp_endpoint_is_remote (ge))
	  {
	    dpo_id_t policy_dpo = DPO_INVALID;

	    /*
	     * interpose a policy DPO from the endpoint so that policy
	     * is applied
	     */
	    gbp_policy_dpo_add_or_lock (fib_proto_to_dpo (fproto),
					gg->gg_id, ~0, &policy_dpo);

	    fib_table_entry_special_dpo_add
	      (gbp_endpoint_group_get_fib_index (gg, fproto),
	       &pfx,
	       FIB_SOURCE_PLUGIN_HI, FIB_ENTRY_FLAG_INTERPOSE, &policy_dpo);
	  }

	/*
	 * send a gratuitous ARP on the EPG's uplink. this is done so
	 * that if this EP has moved from some other place in the
	 * 'fabric', upstream devices are informed
	 */
	if (!(gbp_endpoint_is_remote (ge)) && ~0 != gg->gg_uplink_sw_if_index)
	  {
	    gbp_endpoint_add_itf (sw_if_index, gei);

	    if (ip46_address_is_ip4 (ip))
	      send_ip4_garp_w_addr (vlib_get_main (),
				    &ip->ip4, gg->gg_uplink_sw_if_index);
	    else
	      send_ip6_na_w_addr (vlib_get_main (),
				  &ip->ip6, gg->gg_uplink_sw_if_index);
	  }
      }
    }

  if (NULL == ge)
    return (0);

  /*
   * count the number of dynamic entries and kick off the scanner
   * process is this is our first.
   */
  if (gbp_endpoint_is_remote (ge))
    {
      gbp_n_learnt_endpoints++;

      if (1 == gbp_n_learnt_endpoints)
	{
	  vlib_process_signal_event (vlib_get_main (),
				     gbp_scanner_node.index,
				     GBP_ENDPOINT_SCAN_START, 0);
	}
    }
  else
    {
      /*
       * non-remote endpoints (i.e. those not arriving on iVXLAN
       * tunnels) need to be classifed based on the the input interface.
       * We enable the GBP-FWD feature only is the group has an uplink
       * interface (on which the GBP-FWD feature would send UU traffic).
       */
      l2input_feat_masks_t feats = L2INPUT_FEAT_GBP_SRC_CLASSIFY;

      if (~0 != gg->gg_uplink_sw_if_index)
	feats |= L2INPUT_FEAT_GBP_FWD;
      gbp_itf_set_l2_input_feature (ge->ge_itf, gbp_endpoint_index (ge),
				    feats);
    }
out:

  if (handle)
    *handle = (ge - gbp_endpoint_pool);

  gbp_endpoint_group_unlock (ggi);
  GBP_ENDPOINT_INFO ("update: %U", format_gbp_endpoint, gei);

  return (0);
}

void
gbp_endpoint_delete (index_t gei)
{
  gbp_endpoint_group_t *gg;
  gbp_endpoint_t *ge;

  if (pool_is_free_index (gbp_endpoint_pool, gei))
    return;

  GBP_ENDPOINT_INFO ("delete: %U", format_gbp_endpoint, gei);

  ge = gbp_endpoint_get (gei);
  gg = gbp_endpoint_group_get (ge->ge_epg);

  gbp_endpoint_del_mac (&ge->ge_mac, gg->gg_bd_index);
  l2fib_del_entry (ge->ge_mac.bytes, gg->gg_bd_index, ge->ge_sw_if_index);
  gbp_itf_set_l2_input_feature (ge->ge_itf, gei, (L2INPUT_FEAT_NONE));
  gbp_itf_set_l2_output_feature (ge->ge_itf, gei, L2OUTPUT_FEAT_NONE);

  if (NULL != ge->ge_ips)
    {
      const ip46_address_t *ip;
      index_t *ai;

      vec_foreach (ai, ge->ge_adjs)
      {
	adj_unlock (*ai);
      }
      vec_foreach (ip, ge->ge_ips)
      {
	fib_protocol_t fproto;

	fproto = fib_proto_from_ip46 (ip46_address_get_type (ip));

	gbp_endpoint_del_ip (ip,
			     gbp_endpoint_group_get_fib_index (gg, fproto));

	bd_add_del_ip_mac (gg->gg_bd_index,
			   ip,
			   ge->ge_mac.bytes, !ip46_address_is_ip4 (ip), 0);

	/*
	 * remove a host route via the EPG's BVI
	 */
	fib_prefix_t pfx = {
	  .fp_proto = fproto,
	  .fp_len = ip46_address_get_len (ip),
	  .fp_addr = *ip,
	};

	if (gbp_endpoint_is_remote (ge))
	  {
	    fib_table_entry_special_remove
	      (gbp_endpoint_group_get_fib_index (gg, fproto),
	       &pfx, FIB_SOURCE_PLUGIN_HI);
	  }

	fib_table_entry_path_remove
	  (gbp_endpoint_group_get_fib_index (gg, fproto),
	   &pfx, FIB_SOURCE_PLUGIN_LOW,
	   fib_proto_to_dpo (fproto), ip,
	   (gbp_endpoint_is_remote (ge) ?
	    ge->ge_sw_if_index :
	    gbp_endpoint_group_get_bvi (gg)),
	   ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);
      }
    }

  if (ge->ge_flags & GBP_ENDPOINT_FLAG_LEARNT)
    {
      gbp_n_learnt_endpoints--;

      if (0 == gbp_n_learnt_endpoints)
	{
	  vlib_process_signal_event (vlib_get_main (),
				     gbp_scanner_node.index,
				     GBP_ENDPOINT_SCAN_STOP, 0);
	}
    }

  gbp_itf_unlock (ge->ge_itf);
  if (gbp_endpoint_is_remote (ge))
    {
      vxlan_gbp_tunnel_unlock (ge->ge_sw_if_index);
    }
  gbp_endpoint_group_unlock (ge->ge_epg);
  pool_put (gbp_endpoint_pool, ge);
}

typedef struct gbp_endpoint_flush_ctx_t_
{
  u32 sw_if_index;
  index_t *geis;
} gbp_endpoint_flush_ctx_t;

static walk_rc_t
gbp_endpoint_flush_cb (index_t gei, void *args)
{
  gbp_endpoint_flush_ctx_t *ctx = args;
  gbp_endpoint_t *ge;

  ge = gbp_endpoint_get (gei);

  if (gbp_endpoint_is_remote (ge) &&
      ctx->sw_if_index == ge->tun.ge_parent_sw_if_index)
    {
      vec_add1 (ctx->geis, gei);
    }

  return (WALK_CONTINUE);
}

/**
 * remove all learnt endpoints using the interface
 */
void
gbp_endpoint_flush (u32 sw_if_index)
{
  gbp_endpoint_flush_ctx_t ctx = {
    .sw_if_index = sw_if_index,
  };
  index_t *gei;

  gbp_endpoint_walk (gbp_endpoint_flush_cb, &ctx);

  vec_foreach (gei, ctx.geis)
  {
    gbp_endpoint_delete (*gei);
  }

  vec_free (ctx.geis);
}

void
gbp_endpoint_walk (gbp_endpoint_cb_t cb, void *ctx)
{
  u32 index;

  /* *INDENT-OFF* */
  pool_foreach_index(index, gbp_endpoint_pool,
  {
    if (!cb(index, ctx))
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
  u32 epg_id = EPG_INVALID;
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

      rv =
	gbp_endpoint_update (sw_if_index, ips, &mac, epg_id,
			     GBP_ENDPOINT_FLAG_NONE, NULL, NULL, &handle);

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
  index_t gei = va_arg (*args, index_t);
  const ip46_address_t *ip;
  gbp_endpoint_t *ge;

  ge = gbp_endpoint_get (gei);

  s = format (s, "[@%d] ", gei);
  s = format (s, "IPs:[");

  vec_foreach (ip, ge->ge_ips)
  {
    s = format (s, "%U, ", format_ip46_address, ip, IP46_TYPE_ANY);
  }
  s = format (s, "]");

  s = format (s, " MAC:%U", format_mac_address_t, &ge->ge_mac);
  s = format (s, " EPG-ID:%d", ge->ge_epg_id);
  if (GBP_ENDPOINT_FLAG_NONE != ge->ge_flags)
    {
      s = format (s, " flags:%U", format_gbp_endpoint_flags, ge->ge_flags);
    }

  s = format (s, " itf:[%U]", format_gbp_itf, ge->ge_itf);
  s = format (s, " last-time:[%f]", ge->ge_last_time);

  return s;
}

static walk_rc_t
gbp_endpoint_show_one (index_t gei, void *ctx)
{
  vlib_main_t *vm;

  vm = ctx;
  vlib_cli_output (vm, " %U", format_gbp_endpoint, gei);

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
  u32 show_dbs, handle;

  handle = INDEX_INVALID;
  show_dbs = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &handle))
	;
      else if (unformat (input, "db"))
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
      clib_bihash_foreach_key_value_pair_24_8 (&gbp_ep_db.ged_by_ip_rd,
					       gbp_endpoint_walk_ip_itf, vm);
      clib_bihash_foreach_key_value_pair_16_8
	(&gbp_ep_db.ged_by_mac_bd, gbp_endpoint_walk_mac_itf, vm);
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

static void
gbp_endpoint_check (index_t gei, f64 start_time)
{
  gbp_endpoint_t *ge;

  ge = gbp_endpoint_get (gei);

  GBP_ENDPOINT_DBG ("scan at:%f -> %U", start_time, format_gbp_endpoint, gei);

  if ((ge->ge_flags & GBP_ENDPOINT_FLAG_LEARNT) &&
      ((start_time - ge->ge_last_time) > GBP_ENDPOINT_INACTIVE_TIME))
    {
      gbp_endpoint_delete (gei);
    }
}

static void
gbp_endpoint_scan_l2 (vlib_main_t * vm)
{
  clib_bihash_16_8_t *gte_table = &gbp_ep_db.ged_by_mac_bd;
  f64 last_start, start_time, delta_t;
  int i, j, k;

  delta_t = 0;
  last_start = start_time = vlib_time_now (vm);

  for (i = 0; i < gte_table->nbuckets; i++)
    {
      clib_bihash_bucket_16_8_t *b;
      clib_bihash_value_16_8_t *v;

      /* allow no more than 20us without a pause */
      delta_t = vlib_time_now (vm) - last_start;
      if (delta_t > 20e-6)
	{
	  /* suspend for 100 us */
	  vlib_process_suspend (vm, 100e-6);
	  last_start = vlib_time_now (vm);
	}

      b = &gte_table->buckets[i];
      if (b->offset == 0)
	continue;
      v = clib_bihash_get_value_16_8 (gte_table, b->offset);

      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
	    {
	      if (clib_bihash_is_free_16_8 (&v->kvp[k]))
		continue;

	      gbp_endpoint_check (v->kvp[k].value, start_time);

	      /*
	       * Note: we may have just freed the bucket's backing
	       * storage, so check right here...
	       */
	      if (b->offset == 0)
		goto doublebreak;
	    }
	  v++;
	}
    doublebreak:
      ;
    }
}

static void
gbp_endpoint_scan_l3 (vlib_main_t * vm)
{
  clib_bihash_24_8_t *gte_table = &gbp_ep_db.ged_by_ip_rd;
  f64 last_start, start_time, delta_t;
  int i, j, k;

  delta_t = 0;
  last_start = start_time = vlib_time_now (vm);

  for (i = 0; i < gte_table->nbuckets; i++)
    {
      clib_bihash_bucket_24_8_t *b;
      clib_bihash_value_24_8_t *v;

      /* allow no more than 20us without a pause */
      delta_t = vlib_time_now (vm) - last_start;
      if (delta_t > 20e-6)
	{
	  /* suspend for 100 us */
	  vlib_process_suspend (vm, 100e-6);
	  last_start = vlib_time_now (vm);
	}

      b = &gte_table->buckets[i];
      if (b->offset == 0)
	continue;
      v = clib_bihash_get_value_24_8 (gte_table, b->offset);

      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
	    {
	      if (clib_bihash_is_free_24_8 (&v->kvp[k]))
		continue;

	      gbp_endpoint_check (v->kvp[k].value, start_time);

	      /*
	       * Note: we may have just freed the bucket's backing
	       * storage, so check right here...
	       */
	      if (b->offset == 0)
		goto doublebreak;
	    }
	  v++;
	}
    doublebreak:
      ;
    }
}

void
gbp_endpoint_scan (vlib_main_t * vm)
{
  gbp_endpoint_scan_l2 (vm);
  gbp_endpoint_scan_l3 (vm);
}

void
gbp_learn_set_inactive_threshold (u32 threshold)
{
  GBP_ENDPOINT_INACTIVE_TIME = threshold;
}

f64
gbp_endpoint_scan_threshold (void)
{
  return (GBP_ENDPOINT_INACTIVE_TIME);
}

#define GBP_EP_HASH_NUM_BUCKETS (2 * 1024)
#define GBP_EP_HASH_MEMORY_SIZE (1 << 20)

static clib_error_t *
gbp_endpoint_init (vlib_main_t * vm)
{
  clib_bihash_init_24_8 (&gbp_ep_db.ged_by_ip_rd,
			 "GBP Endpoints - IP/RD",
			 GBP_EP_HASH_NUM_BUCKETS, GBP_EP_HASH_MEMORY_SIZE);

  clib_bihash_init_16_8 (&gbp_ep_db.ged_by_mac_bd,
			 "GBP Endpoints - MAC/BD",
			 GBP_EP_HASH_NUM_BUCKETS, GBP_EP_HASH_MEMORY_SIZE);

  gbp_ep_logger = vlib_log_register_class ("gbp", "ep");

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
