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
#include <vnet/fib/fib_walk.h>

static const char *gbp_endpoint_attr_names[] = GBP_ENDPOINT_ATTR_NAMES;

/**
 * EP DBs
 */
gbp_ep_db_t gbp_ep_db;

fib_node_type_t gbp_endpoint_fib_type;

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
  return (ge->ge_fwd.gef_flags & GBP_ENDPOINT_FLAG_REMOTE);
}

static void
gbp_endpoint_extract_key_mac_itf (const clib_bihash_kv_16_8_t * key,
				  mac_address_t * mac, u32 * sw_if_index)
{
  mac_address_from_u64 (mac, key->key[0]);
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

static int
gbp_endpoint_ip_is_equal (const fib_prefix_t * fp, const ip46_address_t * ip)
{
  return (ip46_address_is_equal (ip, &fp->fp_addr));
}

static void
gbp_endpoint_ips_update (gbp_endpoint_t * ge,
			 const ip46_address_t * ips,
			 const gbp_route_domain_t * grd)
{
  const ip46_address_t *ip;
  index_t gei, grdi;

  gei = gbp_endpoint_index (ge);
  grdi = gbp_route_domain_index (grd);

  ASSERT ((ge->ge_key.gek_grd == INDEX_INVALID) ||
	  (ge->ge_key.gek_grd == grdi));

  vec_foreach (ip, ips)
  {
    if (~0 == vec_search_with_function (ge->ge_key.gek_ips, ip,
					gbp_endpoint_ip_is_equal))
      {
	fib_prefix_t *pfx;

	vec_add2 (ge->ge_key.gek_ips, pfx, 1);
	fib_prefix_from_ip46_addr (ip, pfx);

	gbp_endpoint_add_ip (&pfx->fp_addr,
			     grd->grd_fib_index[pfx->fp_proto], gei);
      }
    ge->ge_key.gek_grd = grdi;
  }
}

static gbp_endpoint_t *
gbp_endpoint_alloc (const ip46_address_t * ips,
		    const gbp_route_domain_t * grd,
		    const mac_address_t * mac,
		    const gbp_bridge_domain_t * gbd)
{
  gbp_endpoint_t *ge;
  index_t gei;

  pool_get_zero (gbp_endpoint_pool, ge);

  fib_node_init (&ge->ge_node, gbp_endpoint_fib_type);
  gei = gbp_endpoint_index (ge);
  ge->ge_key.gek_gbd =
    ge->ge_key.gek_grd = ge->ge_fwd.gef_itf = INDEX_INVALID;
  ge->ge_last_time = vlib_time_now (vlib_get_main ());
  ge->ge_key.gek_gbd = gbp_bridge_domain_index (gbd);

  if (NULL != mac)
    {
      mac_address_copy (&ge->ge_key.gek_mac, mac);
      gbp_endpoint_add_mac (mac, gbd->gb_bd_index, gei);
    }
  gbp_endpoint_ips_update (ge, ips, grd);

  return (ge);
}

static int
gbp_endpoint_loc_is_equal (gbp_endpoint_loc_t * a, gbp_endpoint_loc_t * b)
{
  return (a->gel_src == b->gel_src);
}

static int
gbp_endpoint_loc_cmp_for_sort (gbp_endpoint_loc_t * a, gbp_endpoint_loc_t * b)
{
  return (a->gel_src - b->gel_src);
}

static gbp_endpoint_loc_t *
gbp_endpoint_loc_find (gbp_endpoint_t * ge, gbp_endpoint_src_t src)
{
  gbp_endpoint_loc_t gel = {
    .gel_src = src,
  };
  u32 pos;

  pos = vec_search_with_function (ge->ge_locs, &gel,
				  gbp_endpoint_loc_is_equal);

  if (~0 != pos)
    return (&ge->ge_locs[pos]);

  return NULL;
}

static int
gbp_endpoint_loc_unlock (gbp_endpoint_t * ge, gbp_endpoint_loc_t * gel)
{
  u32 pos;

  gel->gel_locks--;

  if (0 == gel->gel_locks)
    {
      pos = gel - ge->ge_locs;

      vec_del1 (ge->ge_locs, pos);
      if (vec_len (ge->ge_locs) > 1)
	vec_sort_with_function (ge->ge_locs, gbp_endpoint_loc_cmp_for_sort);

      /* This could be the last lock, so don't access the EP from
       * this point on */
      fib_node_unlock (&ge->ge_node);

      return (1);
    }
  return (0);
}

static void
gbp_endpoint_loc_destroy (gbp_endpoint_loc_t * gel)
{
  gbp_endpoint_group_unlock (gel->gel_epg);

  if (gel->gel_flags & GBP_ENDPOINT_FLAG_REMOTE)
    {
      vxlan_gbp_tunnel_unlock (gel->gel_sw_if_index);
    }
}

static gbp_endpoint_loc_t *
gbp_endpoint_loc_find_or_add (gbp_endpoint_t * ge, gbp_endpoint_src_t src)
{
  gbp_endpoint_loc_t gel = {
    .gel_src = src,
    .gel_epg = INDEX_INVALID,
    .gel_sw_if_index = INDEX_INVALID,
    .gel_locks = 0,
  };
  u32 pos;

  pos = vec_search_with_function (ge->ge_locs, &gel,
				  gbp_endpoint_loc_is_equal);

  if (~0 == pos)
    {
      vec_add1 (ge->ge_locs, gel);

      if (vec_len (ge->ge_locs) > 1)
	{
	  vec_sort_with_function (ge->ge_locs, gbp_endpoint_loc_cmp_for_sort);

	  pos = vec_search_with_function (ge->ge_locs, &gel,
					  gbp_endpoint_loc_is_equal);
	}
      else
	pos = 0;

      /*
       * it's the sources and children that lock the endpoints
       */
      fib_node_lock (&ge->ge_node);
    }

  return (&ge->ge_locs[pos]);
}

/**
 * Find an EP inthe DBs and check that if we find it in the L2 DB
 * it has the same IPs as this update
 */
static int
gbp_endpoint_find_for_update (const ip46_address_t * ips,
			      const gbp_route_domain_t * grd,
			      const mac_address_t * mac,
			      const gbp_bridge_domain_t * gbd,
			      gbp_endpoint_t ** ge)
{
  gbp_endpoint_t *l2_ge, *l3_ge, *tmp;

  l2_ge = l3_ge = NULL;

  if (NULL != mac && !mac_address_is_zero (mac))
    {
      ASSERT (gbd);
      l2_ge = gbp_endpoint_find_mac (mac->bytes, gbd->gb_bd_index);
    }
  if (NULL != ips && !ip46_address_is_zero (ips))
    {
      const ip46_address_t *ip;
      fib_protocol_t fproto;

      ASSERT (grd);
      vec_foreach (ip, ips)
      {
	fproto = fib_proto_from_ip46 (ip46_address_get_type (ip));

	tmp = gbp_endpoint_find_ip (ip, grd->grd_fib_index[fproto]);

	if (NULL == tmp)
	  /* not found */
	  continue;
	else if (NULL == l3_ge)
	  /* first match against an IP address */
	  l3_ge = tmp;
	else if (tmp == l3_ge)
	  /* another match against IP address that is the same endpoint */
	  continue;
	else
	  {
	    /*
	     *  a match agains a different endpoint.
	     * this means the KEY of the EP is changing which is not allowed
	     */
	    return (-1);
	  }
      }
    }

  if (NULL == l2_ge && NULL == l3_ge)
    /* not found */
    *ge = NULL;
  else if (NULL == l2_ge)
    /* found at L3 */
    *ge = l3_ge;
  else if (NULL == l3_ge)
    /* found at L2 */
    *ge = l2_ge;
  else
    {
      /* found both L3 and L2 - they must be the same else the KEY
       * is changing
       */
      if (l2_ge == l3_ge)
	*ge = l2_ge;
      else
	return (-1);
    }

  return (0);
}

static gbp_endpoint_src_t
gbp_endpoint_get_best_src (const gbp_endpoint_t * ge)
{
  if (0 == vec_len (ge->ge_locs))
    return (GBP_ENDPOINT_SRC_MAX);

  return (ge->ge_locs[0].gel_src);
}

static void
gbp_endpoint_n_learned (int n)
{
  gbp_n_learnt_endpoints += n;

  if (n > 0 && 1 == gbp_n_learnt_endpoints)
    {
      vlib_process_signal_event (vlib_get_main (),
				 gbp_scanner_node.index,
				 GBP_ENDPOINT_SCAN_START, 0);
    }
  if (n < 0 && 0 == gbp_n_learnt_endpoints)
    {
      vlib_process_signal_event (vlib_get_main (),
				 gbp_scanner_node.index,
				 GBP_ENDPOINT_SCAN_STOP, 0);
    }
}

static void
gbp_endpoint_loc_update (gbp_endpoint_loc_t * gel,
			 u32 sw_if_index,
			 index_t ggi,
			 gbp_endpoint_flags_t flags,
			 const ip46_address_t * tun_src,
			 const ip46_address_t * tun_dst)
{
  int was_learnt, is_learnt;

  gel->gel_locks++;
  was_learnt = ! !(gel->gel_flags & GBP_ENDPOINT_FLAG_REMOTE);
  gel->gel_flags = flags;
  is_learnt = ! !(gel->gel_flags & GBP_ENDPOINT_FLAG_REMOTE);

  gbp_endpoint_n_learned (is_learnt - was_learnt);

  if (INDEX_INVALID == gel->gel_epg)
    {
      gel->gel_epg = ggi;
      if (INDEX_INVALID != gel->gel_epg)
	{
	  gbp_endpoint_group_lock (gel->gel_epg);
	}
    }
  else
    {
      ASSERT (gel->gel_epg == ggi);
    }

  if (gel->gel_flags & GBP_ENDPOINT_FLAG_REMOTE)
    {
      if (NULL != tun_src)
	ip46_address_copy (&gel->tun.gel_src, tun_src);
      if (NULL != tun_dst)
	ip46_address_copy (&gel->tun.gel_dst, tun_dst);

      /*
       * the input interface may be the parent GBP-vxlan interface,
       * create a child vlxan-gbp tunnel and use that as the endpoint's
       * interface.
       */
      if (~0 != gel->gel_sw_if_index)
	vxlan_gbp_tunnel_unlock (gel->gel_sw_if_index);

      switch (gbp_vxlan_tunnel_get_type (sw_if_index))
	{
	case GBP_VXLAN_TEMPLATE_TUNNEL:
	  gel->tun.gel_parent_sw_if_index = sw_if_index;
	  gel->gel_sw_if_index =
	    gbp_vxlan_tunnel_clone_and_lock (sw_if_index,
					     &gel->tun.gel_src,
					     &gel->tun.gel_dst);
	  break;
	case VXLAN_GBP_TUNNEL:
	  gel->tun.gel_parent_sw_if_index =
	    vxlan_gbp_tunnel_get_parent (sw_if_index);
	  gel->gel_sw_if_index = sw_if_index;
	  vxlan_gbp_tunnel_lock (gel->gel_sw_if_index);
	  break;
	}
    }
  else
    {
      gel->gel_sw_if_index = sw_if_index;
    }
}

static void
gbb_endpoint_fwd_reset (gbp_endpoint_t * ge)
{
  const gbp_route_domain_t *grd;
  const gbp_bridge_domain_t *gbd;
  gbp_endpoint_fwd_t *gef;
  const fib_prefix_t *pfx;
  index_t *ai;
  index_t gei;

  gei = gbp_endpoint_index (ge);
  gbd = gbp_bridge_domain_get (ge->ge_key.gek_gbd);
  gef = &ge->ge_fwd;

  vec_foreach (pfx, ge->ge_key.gek_ips)
  {
    u32 fib_index;

    grd = gbp_route_domain_get (ge->ge_key.gek_grd);
    fib_index = grd->grd_fib_index[pfx->fp_proto];

    bd_add_del_ip_mac (gbd->gb_bd_index, fib_proto_to_ip46 (pfx->fp_proto),
		       &pfx->fp_addr, &ge->ge_key.gek_mac, 0);

    /*
     * remove a host route
     */
    if (gbp_endpoint_is_remote (ge))
      {
	fib_table_entry_special_remove (fib_index, pfx, FIB_SOURCE_PLUGIN_HI);
      }

    fib_table_entry_delete (fib_index, pfx, FIB_SOURCE_PLUGIN_LOW);
  }
  vec_foreach (ai, gef->gef_adjs)
  {
    adj_unlock (*ai);
  }

  if (INDEX_INVALID != gef->gef_itf)
    {
      l2fib_del_entry (ge->ge_key.gek_mac.bytes,
		       gbd->gb_bd_index, gef->gef_itf);
      gbp_itf_set_l2_input_feature (gef->gef_itf, gei, (L2INPUT_FEAT_NONE));
      gbp_itf_set_l2_output_feature (gef->gef_itf, gei, L2OUTPUT_FEAT_NONE);

      gbp_itf_unlock (gef->gef_itf);
      gef->gef_itf = INDEX_INVALID;
    }

  vec_free (gef->gef_adjs);
}

static void
gbb_endpoint_fwd_recalc (gbp_endpoint_t * ge)
{
  const gbp_route_domain_t *grd;
  const gbp_bridge_domain_t *gbd;
  const gbp_endpoint_group_t *gg;
  gbp_endpoint_loc_t *gel;
  gbp_endpoint_fwd_t *gef;
  const fib_prefix_t *pfx;
  index_t gei;

  /*
   * locations are sort in source priority order
   */
  gei = gbp_endpoint_index (ge);
  gel = &ge->ge_locs[0];
  gef = &ge->ge_fwd;
  gbd = gbp_bridge_domain_get (ge->ge_key.gek_gbd);

  gef->gef_flags = gel->gel_flags;

  if (INDEX_INVALID != gel->gel_epg)
    {
      gg = gbp_endpoint_group_get (gel->gel_epg);
      gef->gef_epg_id = gg->gg_id;
    }
  else
    {
      gg = NULL;
    }

  gef->gef_itf = gbp_itf_add_and_lock (gel->gel_sw_if_index,
				       gbd->gb_bd_index);

  if (!mac_address_is_zero (&ge->ge_key.gek_mac))
    {
      gbp_itf_set_l2_input_feature (gef->gef_itf, gei, L2INPUT_FEAT_GBP_FWD);

      if (gbp_endpoint_is_remote (ge))
	{
	  gbp_itf_set_l2_output_feature (gef->gef_itf, gei,
					 L2OUTPUT_FEAT_GBP_POLICY_MAC);
	}
      else
	{
	  gbp_endpoint_add_itf (gef->gef_itf, gei);
	  gbp_itf_set_l2_output_feature (gef->gef_itf, gei,
					 L2OUTPUT_FEAT_GBP_POLICY_PORT);
	}
      l2fib_add_entry (ge->ge_key.gek_mac.bytes,
		       gbd->gb_bd_index,
		       gef->gef_itf, L2FIB_ENTRY_RESULT_FLAG_STATIC);
    }

  vec_foreach (pfx, ge->ge_key.gek_ips)
  {
    ethernet_header_t *eth;
    u32 ip_sw_if_index;
    u32 fib_index;
    u8 *rewrite;
    index_t ai;

    rewrite = NULL;
    grd = gbp_route_domain_get (ge->ge_key.gek_grd);
    fib_index = grd->grd_fib_index[pfx->fp_proto];

    bd_add_del_ip_mac (gbd->gb_bd_index, fib_proto_to_ip46 (pfx->fp_proto),
		       &pfx->fp_addr, &ge->ge_key.gek_mac, 1);

    /*
     * add a host route via the EPG's BVI we need this because the
     * adj fib does not install, due to cover refinement check, since
     * the BVI's prefix is /32
     */
    vec_validate (rewrite, sizeof (*eth) - 1);
    eth = (ethernet_header_t *) rewrite;

    eth->type = clib_host_to_net_u16 ((pfx->fp_proto == FIB_PROTOCOL_IP4 ?
				       ETHERNET_TYPE_IP4 :
				       ETHERNET_TYPE_IP6));

    if (gbp_endpoint_is_remote (ge))
      {
	/*
	 * for dynamic EPs we must add the IP adjacency via the learned
	 * tunnel since the BD will not contain the EP's MAC since it was
	 * L3 learned. The dst MAC address used is the 'BD's MAC'.
	 */
	ip_sw_if_index = gef->gef_itf;

	mac_address_to_bytes (gbp_route_domain_get_local_mac (),
			      eth->src_address);
	mac_address_to_bytes (gbp_route_domain_get_remote_mac (),
			      eth->dst_address);
      }
    else
      {
	/*
	 * for the static EPs we add the IP adjacency via the BVI
	 * knowing that the BD has the MAC address to route to and
	 * that policy will be applied on egress to the EP's port
	 */
	ip_sw_if_index = gbd->gb_bvi_sw_if_index;

	clib_memcpy (eth->src_address,
		     vnet_sw_interface_get_hw_address (vnet_get_main (),
						       ip_sw_if_index),
		     sizeof (eth->src_address));
	mac_address_to_bytes (&ge->ge_key.gek_mac, eth->dst_address);
      }

    fib_table_entry_path_add (fib_index, pfx,
			      FIB_SOURCE_PLUGIN_LOW,
			      FIB_ENTRY_FLAG_NONE,
			      fib_proto_to_dpo (pfx->fp_proto),
			      &pfx->fp_addr, ip_sw_if_index,
			      ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);

    ai = adj_nbr_add_or_lock_w_rewrite (pfx->fp_proto,
					fib_proto_to_link (pfx->fp_proto),
					&pfx->fp_addr,
					ip_sw_if_index, rewrite);
    vec_add1 (gef->gef_adjs, ai);

    if (NULL != gg)
      {
	if (gbp_endpoint_is_remote (ge))
	  {
	    dpo_id_t policy_dpo = DPO_INVALID;

	    /*
	     * interpose a policy DPO from the endpoint so that policy
	     * is applied
	     */
	    gbp_policy_dpo_add_or_lock (fib_proto_to_dpo (pfx->fp_proto),
					gg->gg_id, ~0, &policy_dpo);

	    fib_table_entry_special_dpo_add (fib_index, pfx,
					     FIB_SOURCE_PLUGIN_HI,
					     FIB_ENTRY_FLAG_INTERPOSE,
					     &policy_dpo);
	  }

	/*
	 * send a gratuitous ARP on the EPG's uplink. this is done so
	 * that if this EP has moved from some other place in the
	 * 'fabric', upstream devices are informed
	 */
	if (!gbp_endpoint_is_remote (ge) && ~0 != gg->gg_uplink_sw_if_index)
	  {
	    gbp_endpoint_add_itf (gef->gef_itf, gei);
	    if (FIB_PROTOCOL_IP4 == pfx->fp_proto)
	      send_ip4_garp_w_addr (vlib_get_main (),
				    &pfx->fp_addr.ip4,
				    gg->gg_uplink_sw_if_index);
	    else
	      send_ip6_na_w_addr (vlib_get_main (),
				  &pfx->fp_addr.ip6,
				  gg->gg_uplink_sw_if_index);
	  }
      }
  }

  if (!gbp_endpoint_is_remote (ge))
    {
      /*
       * non-remote endpoints (i.e. those not arriving on iVXLAN
       * tunnels) need to be classifed based on the the input interface.
       * We enable the GBP-FWD feature only if the group has an uplink
       * interface (on which the GBP-FWD feature would send UU traffic).
       */
      l2input_feat_masks_t feats = L2INPUT_FEAT_GBP_SRC_CLASSIFY;

      if (NULL != gg && ~0 != gg->gg_uplink_sw_if_index)
	feats |= L2INPUT_FEAT_GBP_FWD;
      gbp_itf_set_l2_input_feature (gef->gef_itf, gei, feats);
    }

  /*
   * update children with the new forwarding info
   */
  fib_node_back_walk_ctx_t bw_ctx = {
    .fnbw_reason = FIB_NODE_BW_REASON_FLAG_EVALUATE,
    .fnbw_flags = FIB_NODE_BW_FLAG_FORCE_SYNC,
  };

  fib_walk_sync (gbp_endpoint_fib_type, gei, &bw_ctx);
}

int
gbp_endpoint_update_and_lock (gbp_endpoint_src_t src,
			      u32 sw_if_index,
			      const ip46_address_t * ips,
			      const mac_address_t * mac,
			      index_t gbdi, index_t grdi, epg_id_t epg_id,
			      gbp_endpoint_flags_t flags,
			      const ip46_address_t * tun_src,
			      const ip46_address_t * tun_dst, u32 * handle)
{
  gbp_bridge_domain_t *gbd;
  gbp_endpoint_group_t *gg;
  gbp_endpoint_src_t best;
  gbp_route_domain_t *grd;
  gbp_endpoint_loc_t *gel;
  gbp_endpoint_t *ge;
  index_t ggi, gei;
  int rv;

  if (~0 == sw_if_index)
    return (VNET_API_ERROR_INVALID_SW_IF_INDEX);

  ge = NULL;
  gg = NULL;

  /*
   * we need to determine the bridge-domain, either from the EPG or
   * the BD passed
   */
  if (EPG_INVALID != epg_id)
    {
      ggi = gbp_endpoint_group_find (epg_id);

      if (INDEX_INVALID == ggi)
	return (VNET_API_ERROR_NO_SUCH_ENTRY);

      gg = gbp_endpoint_group_get (ggi);
      gbdi = gg->gg_gbd;
      grdi = gg->gg_rd;
    }
  else
    {
      if (INDEX_INVALID == gbdi)
	return (VNET_API_ERROR_NO_SUCH_ENTRY);
      if (INDEX_INVALID == grdi)
	return (VNET_API_ERROR_NO_SUCH_FIB);
      ggi = INDEX_INVALID;
    }

  gbd = gbp_bridge_domain_get (gbdi);
  grd = gbp_route_domain_get (grdi);
  rv = gbp_endpoint_find_for_update (ips, grd, mac, gbd, &ge);

  if (0 != rv)
    return (rv);

  if (NULL == ge)
    {
      ge = gbp_endpoint_alloc (ips, grd, mac, gbd);
    }
  else
    {
      gbp_endpoint_ips_update (ge, ips, grd);
    }

  best = gbp_endpoint_get_best_src (ge);
  gei = gbp_endpoint_index (ge);
  gel = gbp_endpoint_loc_find_or_add (ge, src);

  gbp_endpoint_loc_update (gel, sw_if_index, ggi, flags, tun_src, tun_dst);

  if (src <= best)
    {
      /*
       * either the best source has been updated or we have a new best source
       */
      gbb_endpoint_fwd_reset (ge);
      gbb_endpoint_fwd_recalc (ge);
    }
  else
    {
      /*
       * an update to a lower priority source, so we need do nothing
       */
    }

  if (handle)
    *handle = gei;

  GBP_ENDPOINT_INFO ("update: %U", format_gbp_endpoint, gei);

  return (0);
}

void
gbp_endpoint_unlock (gbp_endpoint_src_t src, index_t gei)
{
  gbp_endpoint_loc_t *gel, gel_copy;
  gbp_endpoint_src_t best;
  gbp_endpoint_t *ge;
  int removed;

  if (pool_is_free_index (gbp_endpoint_pool, gei))
    return;

  GBP_ENDPOINT_INFO ("delete: %U", format_gbp_endpoint, gei);

  ge = gbp_endpoint_get (gei);

  gel = gbp_endpoint_loc_find (ge, src);

  if (NULL == gel)
    return;

  /*
   * lock the EP so we can control when it is deleted
   */
  fib_node_lock (&ge->ge_node);
  best = gbp_endpoint_get_best_src (ge);

  /*
   * copy the location info since we'll lose it when it's removed from
   * the vector
   */
  clib_memcpy (&gel_copy, gel, sizeof (gel_copy));

  /*
   * remove the source we no longer need
   */
  removed = gbp_endpoint_loc_unlock (ge, gel);

  if (src == best)
    {
      /*
       * we have removed the old best source => recalculate fwding
       */
      if (0 == vec_len (ge->ge_locs))
	{
	  /*
	   * if there are no more sources left, then we need only release
	   * the fwding resources held and then this EP is gawn.
	   */
	  gbb_endpoint_fwd_reset (ge);
	}
      else
	{
	  /*
	   * else there are more sources. release the old and get new
	   * fwding objects
	   */
	  gbb_endpoint_fwd_reset (ge);
	  gbb_endpoint_fwd_recalc (ge);
	}
    }
  /*
   * else
   *  we removed a lower priority source so we need to do nothing
   */

  /*
   * clear up any resources held by the source
   */
  if (removed)
    gbp_endpoint_loc_destroy (&gel_copy);

  /*
   * remove the lock taken above
   */
  fib_node_unlock (&ge->ge_node);
  /*
   *  We may have removed the last source and so this EP is now TOAST
   *  DO NOTHING BELOW HERE
   */
}

u32
gbp_endpoint_child_add (index_t gei,
			fib_node_type_t type, fib_node_index_t index)
{
  return (fib_node_child_add (gbp_endpoint_fib_type, gei, type, index));
}

void
gbp_endpoint_child_remove (index_t gei, u32 sibling)
{
  return (fib_node_child_remove (gbp_endpoint_fib_type, gei, sibling));
}

typedef struct gbp_endpoint_flush_ctx_t_
{
  u32 sw_if_index;
  gbp_endpoint_src_t src;
  index_t *geis;
} gbp_endpoint_flush_ctx_t;

static walk_rc_t
gbp_endpoint_flush_cb (index_t gei, void *args)
{
  gbp_endpoint_flush_ctx_t *ctx = args;
  gbp_endpoint_loc_t *gel;
  gbp_endpoint_t *ge;

  ge = gbp_endpoint_get (gei);
  gel = gbp_endpoint_loc_find (ge, ctx->src);

  if ((NULL != gel) && ctx->sw_if_index == gel->tun.gel_parent_sw_if_index)
    {
      vec_add1 (ctx->geis, gei);
    }

  return (WALK_CONTINUE);
}

/**
 * remove all learnt endpoints using the interface
 */
void
gbp_endpoint_flush (gbp_endpoint_src_t src, u32 sw_if_index)
{
  gbp_endpoint_flush_ctx_t ctx = {
    .sw_if_index = sw_if_index,
    .src = src,
  };
  index_t *gei;

  GBP_ENDPOINT_INFO ("flush: %U %U",
		     format_gbp_endpoint_src, src,
		     format_vnet_sw_if_index_name, vnet_get_main (),
		     sw_if_index);
  gbp_endpoint_walk (gbp_endpoint_flush_cb, &ctx);

  vec_foreach (gei, ctx.geis)
  {
    gbp_endpoint_unlock (src, *gei);
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
	gbp_endpoint_update_and_lock (GBP_ENDPOINT_SRC_CP,
				      sw_if_index, ips, &mac,
				      INDEX_INVALID, INDEX_INVALID,
				      epg_id,
				      GBP_ENDPOINT_FLAG_NONE,
				      NULL, NULL, &handle);

      if (rv)
	return clib_error_return (0, "GBP Endpoint update returned %d", rv);
      else
	vlib_cli_output (vm, "handle %d\n", handle);
    }
  else
    {
      if (INDEX_INVALID == handle)
	return clib_error_return (0, "handle must be specified");

      gbp_endpoint_unlock (GBP_ENDPOINT_SRC_CP, handle);
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
format_gbp_endpoint_src (u8 * s, va_list * args)
{
  gbp_endpoint_src_t action = va_arg (*args, gbp_endpoint_src_t);

  switch (action)
    {
#define _(v,a) case GBP_ENDPOINT_SRC_##v: return (format (s, "%s", a));
      foreach_gbp_endpoint_src
#undef _
    }

  return (format (s, "unknown"));
}

static u8 *
format_gbp_endpoint_fwd (u8 * s, va_list * args)
{
  gbp_endpoint_fwd_t *gef = va_arg (*args, gbp_endpoint_fwd_t *);

  s = format (s, "fwd:");
  s = format (s, "\n   itf:[%U]", format_gbp_itf, gef->gef_itf);
  if (GBP_ENDPOINT_FLAG_NONE != gef->gef_flags)
    {
      s = format (s, " flags:%U", format_gbp_endpoint_flags, gef->gef_flags);
    }

  return (s);
}

static u8 *
format_gbp_endpoint_key (u8 * s, va_list * args)
{
  gbp_endpoint_key_t *gek = va_arg (*args, gbp_endpoint_key_t *);
  const fib_prefix_t *pfx;

  s = format (s, "ips:[");

  vec_foreach (pfx, gek->gek_ips)
  {
    s = format (s, "%U, ", format_fib_prefix, pfx);
  }
  s = format (s, "]");

  s = format (s, " mac:%U", format_mac_address_t, &gek->gek_mac);

  return (s);
}

static u8 *
format_gbp_endpoint_loc (u8 * s, va_list * args)
{
  gbp_endpoint_loc_t *gel = va_arg (*args, gbp_endpoint_loc_t *);

  s = format (s, "%U", format_gbp_endpoint_src, gel->gel_src);
  s =
    format (s, "\n    %U", format_vnet_sw_if_index_name, vnet_get_main (),
	    gel->gel_sw_if_index);
  s = format (s, " EPG:%d", gel->gel_epg);

  if (GBP_ENDPOINT_FLAG_NONE != gel->gel_flags)
    {
      s = format (s, " flags:%U", format_gbp_endpoint_flags, gel->gel_flags);
    }
  if (GBP_ENDPOINT_FLAG_REMOTE & gel->gel_flags)
    {
      s = format (s, " tun:[");
      s = format (s, "parent:%U", format_vnet_sw_if_index_name,
		  vnet_get_main (), gel->tun.gel_parent_sw_if_index);
      s = format (s, " {%U,%U}]",
		  format_ip46_address, &gel->tun.gel_src, IP46_TYPE_ANY,
		  format_ip46_address, &gel->tun.gel_dst, IP46_TYPE_ANY);
    }

  return (s);
}

u8 *
format_gbp_endpoint (u8 * s, va_list * args)
{
  index_t gei = va_arg (*args, index_t);
  gbp_endpoint_loc_t *gel;
  gbp_endpoint_t *ge;

  ge = gbp_endpoint_get (gei);

  s = format (s, "[@%d] %U", gei, format_gbp_endpoint_key, &ge->ge_key);
  s = format (s, " last-time:[%f]", ge->ge_last_time);

  vec_foreach (gel, ge->ge_locs)
  {
    s = format (s, "\n  %U", format_gbp_endpoint_loc, gel);
  }
  s = format (s, "\n  %U", format_gbp_endpoint_fwd, &ge->ge_fwd);

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
  gbp_endpoint_loc_t *gel;
  gbp_endpoint_t *ge;

  ge = gbp_endpoint_get (gei);
  gel = gbp_endpoint_loc_find (ge, GBP_ENDPOINT_SRC_DP);

  if ((NULL != gel) &&
      ((start_time - ge->ge_last_time) > GBP_ENDPOINT_INACTIVE_TIME))
    {
      gbp_endpoint_unlock (GBP_ENDPOINT_SRC_DP, gei);
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

static fib_node_t *
gbp_endpoint_get_node (fib_node_index_t index)
{
  gbp_endpoint_t *ge;

  ge = gbp_endpoint_get (index);

  return (&ge->ge_node);
}

static gbp_endpoint_t *
gbp_endpoint_from_fib_node (fib_node_t * node)
{
  ASSERT (gbp_endpoint_fib_type == node->fn_type);
  return ((gbp_endpoint_t *) node);
}

static void
gbp_endpoint_last_lock_gone (fib_node_t * node)
{
  const gbp_bridge_domain_t *gbd;
  const gbp_route_domain_t *grd;
  const fib_prefix_t *pfx;
  gbp_endpoint_t *ge;

  ge = gbp_endpoint_from_fib_node (node);

  ASSERT (0 == vec_len (ge->ge_locs));

  gbd = gbp_bridge_domain_get (ge->ge_key.gek_gbd);

  /*
   * we have removed the last source. this EP is toast
   */
  if (INDEX_INVALID != ge->ge_key.gek_gbd)
    {
      gbp_endpoint_del_mac (&ge->ge_key.gek_mac, gbd->gb_bd_index);
    }
  vec_foreach (pfx, ge->ge_key.gek_ips)
  {
    grd = gbp_route_domain_get (ge->ge_key.gek_grd);
    gbp_endpoint_del_ip (&pfx->fp_addr, grd->grd_fib_index[pfx->fp_proto]);
  }
  pool_put (gbp_endpoint_pool, ge);
}

static fib_node_back_walk_rc_t
gbp_endpoint_back_walk_notify (fib_node_t * node,
			       fib_node_back_walk_ctx_t * ctx)
{
  ASSERT (0);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The FIB path's graph node virtual function table
 */
static const fib_node_vft_t gbp_endpoint_vft = {
  .fnv_get = gbp_endpoint_get_node,
  .fnv_last_lock = gbp_endpoint_last_lock_gone,
  .fnv_back_walk = gbp_endpoint_back_walk_notify,
  // .fnv_mem_show = fib_path_memory_show,
};

static clib_error_t *
gbp_endpoint_init (vlib_main_t * vm)
{
#define GBP_EP_HASH_NUM_BUCKETS (2 * 1024)
#define GBP_EP_HASH_MEMORY_SIZE (1 << 20)

  clib_bihash_init_24_8 (&gbp_ep_db.ged_by_ip_rd,
			 "GBP Endpoints - IP/RD",
			 GBP_EP_HASH_NUM_BUCKETS, GBP_EP_HASH_MEMORY_SIZE);

  clib_bihash_init_16_8 (&gbp_ep_db.ged_by_mac_bd,
			 "GBP Endpoints - MAC/BD",
			 GBP_EP_HASH_NUM_BUCKETS, GBP_EP_HASH_MEMORY_SIZE);

  gbp_ep_logger = vlib_log_register_class ("gbp", "ep");
  gbp_endpoint_fib_type = fib_node_register_new_type (&gbp_endpoint_vft);

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
