/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/lisp-gpe/lisp_gpe.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/load_balance.h>

lisp_gpe_main_t lisp_gpe_main;

static lisp_gpe_sub_tunnel_t *lisp_gpe_sub_tunnel_pool;

static int
lisp_gpe_rewrite (lisp_gpe_tunnel_t * t, lisp_gpe_sub_tunnel_t * st,
		  locator_pair_t * lp)
{
  u8 *rw = 0;
  lisp_gpe_header_t *lisp0;
  int len;

  if (ip_addr_version (&lp->lcl_loc) == IP4)
    {
      ip4_header_t *ip0;
      ip4_udp_lisp_gpe_header_t *h0;
      len = sizeof (*h0);

      vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

      h0 = (ip4_udp_lisp_gpe_header_t *) rw;

      /* Fixed portion of the (outer) ip4 header */
      ip0 = &h0->ip4;
      ip0->ip_version_and_header_length = 0x45;
      ip0->ttl = 254;
      ip0->protocol = IP_PROTOCOL_UDP;

      /* we fix up the ip4 header length and checksum after-the-fact */
      ip_address_copy_addr (&ip0->src_address, &lp->lcl_loc);
      ip_address_copy_addr (&ip0->dst_address, &lp->rmt_loc);
      ip0->checksum = ip4_header_checksum (ip0);

      /* UDP header, randomize src port on something, maybe? */
      h0->udp.src_port = clib_host_to_net_u16 (4341);
      h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_lisp_gpe);

      /* LISP-gpe header */
      lisp0 = &h0->lisp;
    }
  else
    {
      ip6_header_t *ip0;
      ip6_udp_lisp_gpe_header_t *h0;
      len = sizeof (*h0);

      vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

      h0 = (ip6_udp_lisp_gpe_header_t *) rw;

      /* Fixed portion of the (outer) ip6 header */
      ip0 = &h0->ip6;
      ip0->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (0x6 << 28);
      ip0->hop_limit = 254;
      ip0->protocol = IP_PROTOCOL_UDP;

      /* we fix up the ip6 header length after-the-fact */
      ip_address_copy_addr (&ip0->src_address, &lp->lcl_loc);
      ip_address_copy_addr (&ip0->dst_address, &lp->rmt_loc);

      /* UDP header, randomize src port on something, maybe? */
      h0->udp.src_port = clib_host_to_net_u16 (4341);
      h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_lisp_gpe);

      /* LISP-gpe header */
      lisp0 = &h0->lisp;
    }

  lisp0->flags = t->flags;
  lisp0->ver_res = t->ver_res;
  lisp0->res = t->res;
  lisp0->next_protocol = t->next_protocol;
  lisp0->iid = clib_host_to_net_u32 (t->vni);

  st->is_ip4 = ip_addr_version (&lp->lcl_loc) == IP4;
  st->rewrite = rw;
  return 0;
}

/**
 * @brief Stack the tunnel's midchain on the IP forwarding chain of the via
 */
static void
lisp_gpe_midchain_stack (lisp_gpe_sub_tunnel_t * st)
{
  dpo_id_t tmp = DPO_NULL;
  fib_link_t linkt;

  fib_entry_contribute_forwarding (st->fib_entry_index,
				   FIB_FORW_CHAIN_TYPE_UNICAST_IP, &tmp);
  FOR_EACH_FIB_IP_LINK (linkt)
  {
    adj_nbr_midchain_stack (st->midchain[linkt], &tmp);
  }
  dpo_reset (&tmp);
}

static void
create_sub_tunnels (lisp_gpe_main_t * lgm,
		    lisp_gpe_tunnel_t * t, vnet_hw_interface_t * hi)
{
  lisp_gpe_sub_tunnel_t *st;
  locator_pair_t *lp = 0;
  fib_prefix_t dst_pfx;
  fib_link_t linkt;
  int i;

  /* create sub-tunnels for all locator pairs */
  for (i = 0; i < vec_len (t->locator_pairs); i++)
    {
      lp = &t->locator_pairs[i];

      pool_get (lisp_gpe_sub_tunnel_pool, st);

      st->locator_pair_index = i;
      st->parent_index = t - lgm->tunnels;
      st->weight = lp->weight;

      /* compute rewrite for sub-tunnel */
      lisp_gpe_rewrite (t, st, lp);
      vec_add1 (t->sub_tunnels, st - lisp_gpe_sub_tunnel_pool);

      ip_address_to_fib_prefix (&lp->rmt_loc, &dst_pfx);

      st->fib_entry_index = fib_table_entry_special_add (t->encap_fib_index,
							 &dst_pfx,
							 FIB_SOURCE_RR,
							 FIB_ENTRY_FLAG_NONE,
							 ADJ_INDEX_INVALID);
      st->sibling = fib_entry_child_add (st->fib_entry_index,
					 FIB_NODE_TYPE_LISP_GPE_TUNNEL,
					 st - lisp_gpe_sub_tunnel_pool);
      FOR_EACH_FIB_IP_LINK (linkt)
      {
	st->midchain[linkt] = adj_nbr_add_or_lock (dst_pfx.fp_proto,
						   linkt,
						   &dst_pfx.fp_addr,
						   hi->sw_if_index);
	adj_nbr_midchain_update_rewrite (st->midchain[linkt],
					 hi->tx_node_index, st->rewrite);
      }

      lisp_gpe_midchain_stack (st);
    }
}

static void
delete_sub_tunnels (lisp_gpe_tunnel_t * t)
{
  fib_link_t linkt;
  u32 *index;

  vec_foreach (index, t->sub_tunnels)
  {
    lisp_gpe_sub_tunnel_t *st;

    st = pool_elt_at_index (lisp_gpe_sub_tunnel_pool, *index);

    fib_entry_child_remove (st->fib_entry_index, st->sibling);
    fib_table_entry_delete_index (st->fib_entry_index, FIB_SOURCE_RR);
    FOR_EACH_FIB_IP_LINK (linkt)
    {
      adj_unlock (st->midchain[linkt]);
    }
    vec_free (st->rewrite);

    pool_put (lisp_gpe_sub_tunnel_pool, st);
  }
}

#define foreach_copy_field                      \
_(encap_fib_index)                              \
_(decap_fib_index)                              \
_(decap_next_index)                             \
_(vni)                                          \
_(action)


/**
 * @brief Get a pointer to a tunnel from a pointer to a FIB node
 */
static lisp_gpe_sub_tunnel_t *
lisp_gpe_sub_tunnel_from_fib_node (const fib_node_t * node)
{
  return ((lisp_gpe_sub_tunnel_t *)
	  ((char *) node -
	   STRUCT_OFFSET_OF (lisp_gpe_sub_tunnel_t, fib_node)));
}

/**
 * @brief LISP GPE tunnel back walk
 *
 * The FIB entry through which this tunnel resolves has been updated.
 * re-stack the midchain on the new forwarding.
 */
static fib_node_back_walk_rc_t
lisp_gpe_sub_tunnel_back_walk (fib_node_t * node,
			       fib_node_back_walk_ctx_t * ctx)
{
  lisp_gpe_midchain_stack (lisp_gpe_sub_tunnel_from_fib_node (node));

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

static int
add_del_ip_tunnel (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
		   u8 is_l2, u32 * tun_index_res, u32 * src_fib_index)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  lisp_gpe_tunnel_t *t = 0;
  lisp_gpe_tunnel_key_t key;
  tunnel_lookup_t *l3_ifaces = &lgm->l3_ifaces;
  uword *p;

  /* prepare tunnel key */
  memset (&key, 0, sizeof (key));

  /* fill in the key's remote eid */
  if (!is_l2)
    ip_prefix_copy (&key.rmt.ippref, &gid_address_ippref (&a->rmt_eid));
  else
    mac_copy (&key.rmt.mac, &gid_address_mac (&a->rmt_eid));

  key.vni = clib_host_to_net_u32 (a->vni);

  p = mhash_get (&lgm->lisp_gpe_tunnel_by_key, &key);

  if (a->is_add)
    {
      uword *lgpe_hw_if_index;
      vnet_hw_interface_t *hi;

      /* adding a tunnel: tunnel must not already exist */
      if (p)
	return VNET_API_ERROR_INVALID_VALUE;

      if (a->decap_next_index >= LISP_GPE_INPUT_N_NEXT)
	return VNET_API_ERROR_INVALID_DECAP_NEXT;

      pool_get_aligned (lgm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));
      t->l2_path_list = FIB_NODE_INDEX_INVALID;

      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _

      t->locator_pairs = vec_dup (a->locator_pairs);

      /* if vni is non-default */
      if (a->vni)
	t->flags = LISP_GPE_FLAGS_I;

      /* work in lisp-gpe not legacy mode */
      t->flags |= LISP_GPE_FLAGS_P;

      /* next proto */
      if (!is_l2)
	t->next_protocol = ip_prefix_version (&key.rmt.ippref) == IP4 ?
	  LISP_GPE_NEXT_PROTO_IP4 : LISP_GPE_NEXT_PROTO_IP6;
      else
	t->next_protocol = LISP_GPE_NEXT_PROTO_ETHERNET;

      /* send packets that hit this adj to lisp-gpe interface output node in
       * requested vrf. */
      lgpe_hw_if_index = hash_get (l3_ifaces->hw_if_index_by_dp_table,
				   a->table_id);
      hi = vnet_get_hw_interface (vnet_get_main (), lgpe_hw_if_index[0]);

      t->sw_if_index = hi->sw_if_index;

      /* build sub-tunnels for lowest priority locator-pairs */
      if (!a->is_negative)
	create_sub_tunnels (lgm, t, hi);

      mhash_set (&lgm->lisp_gpe_tunnel_by_key, &key, t - lgm->tunnels, 0);

      /* return tunnel index */
      if (tun_index_res)
	tun_index_res[0] = t - lgm->tunnels;
    }
  else
    {
      /* deleting a tunnel: tunnel must exist */
      if (!p)
	{
	  clib_warning ("Tunnel for eid %U doesn't exist!",
			format_gid_address, &a->rmt_eid);
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      t = pool_elt_at_index (lgm->tunnels, p[0]);

      if (NULL != src_fib_index)
	*src_fib_index = t->src_fib_index;

      mhash_unset (&lgm->lisp_gpe_tunnel_by_key, &key, 0);
      delete_sub_tunnels (t);

      vec_free (t->sub_tunnels);
      vec_free (t->locator_pairs);
      pool_put (lgm->tunnels, t);
    }

  return 0;
}

static int
add_del_ip_fwd_entry (lisp_gpe_main_t * lgm,
		      vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
{
  ip_prefix_t *rmt_pref, *lcl_pref;
  lisp_gpe_tunnel_t *t;
  u32 rv, tun_index = ~0, src_fib_index;

  rmt_pref = &gid_address_ippref (&a->rmt_eid);
  lcl_pref = &gid_address_ippref (&a->lcl_eid);

  /* add/del tunnel to tunnels pool and prepares rewrite */
  if (0 != a->locator_pairs)
    {
      rv = add_del_ip_tunnel (a, 0 /* is_l2 */ , &tun_index, &src_fib_index);
      if (rv)
	{
	  clib_warning ("failed to build tunnel!");
	  return rv;
	}
    }
  else
    {
      clib_warning ("no locators to build tunnel!");
      return -1;
    }

  /* fix the case where the local version is not set correctly
   * because the address is all zeros */
  if (ip_prefix_version (rmt_pref) != ip_prefix_version (lcl_pref))
    ip_prefix_version (lcl_pref) = ip_prefix_version (rmt_pref);

  if (!a->is_add)
    {
      ip_src_dst_fib_del_route (src_fib_index,
				lcl_pref, a->table_id, rmt_pref);
    }
  else
    {
      ASSERT (~0 != tun_index);
      t = pool_elt_at_index (lgm->tunnels, tun_index);

      ip_dst_fib_add_route (a->table_id,
			    rmt_pref, lcl_pref, &t->src_fib_index);

      if (a->is_negative)
	{
	  dpo_id_t dpo = DPO_NULL;

	  switch (a->action)
	    {
	    case LISP_NO_ACTION:
	      /* TODO update timers? */
	    case LISP_FORWARD_NATIVE:
	      /* TODO check if route/next-hop for eid exists in fib and add
	       * more specific for the eid with the next-hop found */
	    case LISP_SEND_MAP_REQUEST:
	      /* insert tunnel that always sends map-request */
	      dpo_set (&dpo,
		       DPO_LISP_CP, 0,
		       (ip_prefix_version (rmt_pref) == IP4 ?
			FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6));
	      break;
	    case LISP_DROP:
	      /* for drop fwd entries, just add route, no need to add encap tunnel */
	      dpo_copy (&dpo,
			drop_dpo_get ((ip_prefix_version (rmt_pref) == IP4 ?
				       DPO_PROTO_IP4 : DPO_PROTO_IP6)));
	    }
	  ip_src_fib_add_route_w_dpo (t->src_fib_index, lcl_pref, &dpo);
	  dpo_reset (&dpo);
	}
      else
	{
	  ip_src_fib_add_route (t->src_fib_index, lcl_pref, t);
	}
    }

  return 0;
}

static void
make_mac_fib_key (BVT (clib_bihash_kv) * kv, u16 bd_index, u8 src_mac[6],
		  u8 dst_mac[6])
{
  kv->key[0] = (((u64) bd_index) << 48) | mac_to_u64 (dst_mac);
  kv->key[1] = mac_to_u64 (src_mac);
  kv->key[2] = 0;
}

index_t
lisp_l2_fib_lookup (lisp_gpe_main_t * lgm, u16 bd_index, u8 src_mac[6],
		    u8 dst_mac[6])
{
  int rv;
  BVT (clib_bihash_kv) kv, value;

  make_mac_fib_key (&kv, bd_index, src_mac, dst_mac);
  rv = BV (clib_bihash_search_inline_2) (&lgm->l2_fib, &kv, &value);

  /* no match, try with src 0, catch all for dst */
  if (rv != 0)
    {
      kv.key[1] = 0;
      rv = BV (clib_bihash_search_inline_2) (&lgm->l2_fib, &kv, &value);
      if (rv == 0)
	return value.value;
    }

  return lisp_gpe_main.l2_lb_miss;
}

u32
lisp_l2_fib_add_del_entry (lisp_gpe_main_t * lgm, u16 bd_index, u8 src_mac[6],
			   u8 dst_mac[6], u32 val, u8 is_add)
{
  BVT (clib_bihash_kv) kv, value;
  u32 old_val = ~0;

  make_mac_fib_key (&kv, bd_index, src_mac, dst_mac);

  if (BV (clib_bihash_search) (&lgm->l2_fib, &kv, &value) == 0)
    old_val = value.value;

  if (!is_add)
    BV (clib_bihash_add_del) (&lgm->l2_fib, &kv, 0 /* is_add */ );
  else
    {
      kv.value = val;
      BV (clib_bihash_add_del) (&lgm->l2_fib, &kv, 1 /* is_add */ );
    }
  return old_val;
}

static void
l2_fib_init (lisp_gpe_main_t * lgm)
{
  BV (clib_bihash_init) (&lgm->l2_fib, "l2 fib",
			 1 << max_log2 (L2_FIB_DEFAULT_HASH_NUM_BUCKETS),
			 L2_FIB_DEFAULT_HASH_MEMORY_SIZE);

  /*
   * the result from a 'miss' in a L2 Table
   */
  lgm->l2_lb_miss = load_balance_create (1, DPO_PROTO_IP4, 0);
  load_balance_set_bucket (lgm->l2_lb_miss, 0, drop_dpo_get (DPO_PROTO_IP4));
}

fib_route_path_t *
lisp_gpe_mk_paths_for_sub_tunnels (lisp_gpe_tunnel_t * t)
{
  fib_route_path_t *rpaths = NULL;
  ip_adjacency_t *adj;
  u32 ii;

  vec_validate (rpaths, vec_len (t->sub_tunnels) - 1);

  vec_foreach_index (ii, t->sub_tunnels)
  {
    lisp_gpe_sub_tunnel_t *st;

    st = pool_elt_at_index (lisp_gpe_sub_tunnel_pool, ii);
    adj = adj_get (st->midchain[FIB_LINK_IP4]);

    rpaths[ii].frp_proto =
      (IP4 ==
       ip_addr_version (&t->locator_pairs[0].lcl_loc) ? FIB_PROTOCOL_IP4 :
       FIB_PROTOCOL_IP6);
    rpaths[ii].frp_addr = adj->sub_type.midchain.next_hop;
    rpaths[ii].frp_sw_if_index = t->sw_if_index;
    rpaths[ii].frp_weight = (st->weight ? st->weight : 1);
    rpaths[ii].frp_label = MPLS_LABEL_INVALID;
  }

  return (rpaths);
}

static int
add_del_l2_fwd_entry (lisp_gpe_main_t * lgm,
		      vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
{
  int rv;
  u32 tun_index;
  fib_node_index_t old_path_list;
  bd_main_t *bdm = &bd_main;
  fib_route_path_t *rpaths;
  lisp_gpe_tunnel_t *t;
  const dpo_id_t *dpo;
  uword *bd_indexp;
  index_t lbi;

  /* create tunnel */
  rv = add_del_ip_tunnel (a, 1 /* is_l2 */ , &tun_index, NULL);
  if (rv)
    return rv;

  bd_indexp = hash_get (bdm->bd_index_by_bd_id, a->bd_id);
  if (!bd_indexp)
    {
      clib_warning ("bridge domain %d doesn't exist", a->bd_id);
      return -1;
    }

  t = pool_elt_at_index (lgm->tunnels, tun_index);
  old_path_list = t->l2_path_list;

  if (LISP_NO_ACTION == t->action)
    {
      rpaths = lisp_gpe_mk_paths_for_sub_tunnels (t);

      t->l2_path_list = fib_path_list_create (FIB_PATH_LIST_FLAG_NONE,
					      rpaths);

      vec_free (rpaths);
      fib_path_list_lock (t->l2_path_list);

      dpo = fib_path_list_contribute_forwarding (t->l2_path_list,
						 FIB_FORW_CHAIN_TYPE_UNICAST_IP);
      lbi = dpo->dpoi_index;
    }
  else if (LISP_SEND_MAP_REQUEST == t->action)
    {
      lbi = lgm->l2_lb_cp_lkup;
    }
  else
    {
      lbi = lgm->l2_lb_miss;
    }
  fib_path_list_unlock (old_path_list);

  /* add entry to l2 lisp fib */
  lisp_l2_fib_add_del_entry (lgm, bd_indexp[0], gid_address_mac (&a->lcl_eid),
			     gid_address_mac (&a->rmt_eid), lbi, a->is_add);
  return 0;
}


int
vnet_lisp_gpe_add_del_fwd_entry (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
				 u32 * hw_if_indexp)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  u8 type;

  if (vnet_lisp_gpe_enable_disable_status () == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLED;
    }

  type = gid_address_type (&a->rmt_eid);
  switch (type)
    {
    case GID_ADDR_IP_PREFIX:
      return add_del_ip_fwd_entry (lgm, a);
    case GID_ADDR_MAC:
      return add_del_l2_fwd_entry (lgm, a);
    default:
      clib_warning ("Forwarding entries for type %d not supported!", type);
      return -1;
    }
}

static clib_error_t *
lisp_gpe_add_del_fwd_entry_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  ip_address_t lloc, rloc;
  clib_error_t *error = 0;
  gid_address_t _reid, *reid = &_reid, _leid, *leid = &_leid;
  u8 reid_set = 0, leid_set = 0, is_negative = 0, vrf_set = 0, vni_set = 0;
  u32 vni, vrf, action = ~0, p, w;
  locator_pair_t pair, *pairs = 0;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "leid %U", unformat_gid_address, leid))
	{
	  leid_set = 1;
	}
      else if (unformat (line_input, "reid %U", unformat_gid_address, reid))
	{
	  reid_set = 1;
	}
      else if (unformat (line_input, "vni %u", &vni))
	{
	  gid_address_vni (leid) = vni;
	  gid_address_vni (reid) = vni;
	  vni_set = 1;
	}
      else if (unformat (line_input, "vrf %u", &vrf))
	{
	  vrf_set = 1;
	}
      else if (unformat (line_input, "negative action %U",
			 unformat_negative_mapping_action, &action))
	{
	  is_negative = 1;
	}
      else if (unformat (line_input, "loc-pair %U %U p %d w %d",
			 unformat_ip_address, &lloc,
			 unformat_ip_address, &rloc, &p, &w))
	{
	  pair.lcl_loc = lloc;
	  pair.rmt_loc = rloc;
	  pair.priority = p;
	  pair.weight = w;
	  vec_add1 (pairs, pair);
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }
  unformat_free (line_input);

  if (!vni_set || !vrf_set)
    {
      error = clib_error_return (0, "vni and vrf must be set!");
      goto done;
    }

  if (!reid_set)
    {
      error = clib_error_return (0, "remote eid must be set!");
      goto done;
    }

  if (is_negative)
    {
      if (~0 == action)
	{
	  error = clib_error_return (0, "no action set for negative tunnel!");
	  goto done;
	}
    }
  else
    {
      if (vec_len (pairs) == 0)
	{
	  error = clib_error_return (0, "expected ip4/ip6 locators.");
	  goto done;
	}
    }

  if (!leid_set)
    {
      /* if leid not set, make sure it's the same AFI like reid */
      gid_address_type (leid) = gid_address_type (reid);
      if (GID_ADDR_IP_PREFIX == gid_address_type (reid))
	gid_address_ip_version (leid) = gid_address_ip_version (reid);
    }

  /* add fwd entry */
  vnet_lisp_gpe_add_del_fwd_entry_args_t _a, *a = &_a;
  memset (a, 0, sizeof (a[0]));

  a->is_add = is_add;
  a->vni = vni;
  a->table_id = vrf;
  gid_address_copy (&a->lcl_eid, leid);
  gid_address_copy (&a->rmt_eid, reid);
  a->locator_pairs = pairs;

  rv = vnet_lisp_gpe_add_del_fwd_entry (a, 0);
  if (0 != rv)
    {
      error = clib_error_return (0, "failed to %s gpe tunnel!",
				 is_add ? "add" : "delete");
    }

done:
  vec_free (pairs);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_gpe_add_del_fwd_entry_command, static) = {
  .path = "lisp gpe tunnel",
  .short_help = "lisp gpe tunnel add/del vni <vni> vrf <vrf> [leid <leid>]"
      "reid <reid> [lloc <sloc> rloc <rloc>] [negative action <action>]",
  .function = lisp_gpe_add_del_fwd_entry_command_fn,
};
/* *INDENT-ON* */

static u8 *
format_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case LISP_GPE_INPUT_NEXT_DROP:
      return format (s, "drop");
    case LISP_GPE_INPUT_NEXT_IP4_INPUT:
      return format (s, "ip4");
    case LISP_GPE_INPUT_NEXT_IP6_INPUT:
      return format (s, "ip6");
    default:
      return format (s, "unknown %d", next_index);
    }
  return s;
}

u8 *
format_lisp_gpe_tunnel (u8 * s, va_list * args)
{
  lisp_gpe_tunnel_t *t = va_arg (*args, lisp_gpe_tunnel_t *);
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  lisp_gpe_sub_tunnel_t *st;
  locator_pair_t *lp = 0;
  u32 *index;

  s =
    format (s, "tunnel %d vni %d (0x%x)\n", t - lgm->tunnels, t->vni, t->vni);
  s =
    format (s, " fibs: encap %d, decap %d decap next %U\n",
	    t->encap_fib_index, t->decap_fib_index, format_decap_next,
	    t->decap_next_index);
  s = format (s, " lisp ver %d ", (t->ver_res >> 6));

#define _(n,v) if (t->flags & v) s = format (s, "%s-bit ", #n);
  foreach_lisp_gpe_flag_bit;
#undef _

  s = format (s, "next_protocol %d ver_res %x res %x\n",
	      t->next_protocol, t->ver_res, t->res);

  s = format (s, " locator-pairs:\n");
  vec_foreach (lp, t->locator_pairs)
  {
    s = format (s, "  local: %U remote: %U weight %d\n",
		format_ip_address, &lp->lcl_loc, format_ip_address,
		&lp->rmt_loc, lp->weight);
  }

  s = format (s, " active sub-tunnels:\n");
  vec_foreach (index, t->sub_tunnels)
  {
    st = pool_elt_at_index (lisp_gpe_sub_tunnel_pool, *index);
    lp = vec_elt_at_index (t->locator_pairs, st->locator_pair_index);
    s = format (s, "  local: %U remote: %U weight %d\n", format_ip_address,
		&lp->lcl_loc, format_ip_address, &lp->rmt_loc, st->weight);
  }
  return s;
}

static clib_error_t *
show_lisp_gpe_tunnel_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  lisp_gpe_tunnel_t *t;

  if (pool_elts (lgm->tunnels) == 0)
    vlib_cli_output (vm, "No lisp-gpe tunnels configured...");

  /* *INDENT-OFF* */
  pool_foreach (t, lgm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_lisp_gpe_tunnel, t);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_lisp_gpe_tunnel_command, static) =
{
  .path = "show lisp gpe tunnel",
  .function = show_lisp_gpe_tunnel_command_fn,
};
/* *INDENT-ON* */

u8
vnet_lisp_gpe_enable_disable_status (void)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;

  return lgm->is_en;
}

clib_error_t *
vnet_lisp_gpe_enable_disable (vnet_lisp_gpe_enable_disable_args_t * a)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;

  if (a->is_en)
    {
      lgm->is_en = 1;
    }
  else
    {
      CLIB_UNUSED (uword * val);
      hash_pair_t *p;
      u32 *dp_tables = 0, *dp_table;
      lisp_gpe_tunnel_key_t *tunnels = 0, *tunnel;
      vnet_lisp_gpe_add_del_fwd_entry_args_t _at, *at = &_at;
      vnet_lisp_gpe_add_del_iface_args_t _ai, *ai = &_ai;

      /* remove all tunnels */

      /* *INDENT-OFF* */
      mhash_foreach(tunnel, val, &lgm->lisp_gpe_tunnel_by_key, ({
        vec_add1(tunnels, tunnel[0]);
      }));
      /* *INDENT-ON* */

      vec_foreach (tunnel, tunnels)
      {
	memset (at, 0, sizeof (at[0]));
	at->is_add = 0;
	if (tunnel->rmt.type == GID_ADDR_IP_PREFIX)
	  {
	    gid_address_type (&at->rmt_eid) = GID_ADDR_IP_PREFIX;
	    ip_prefix_copy (&gid_address_ippref (&at->rmt_eid),
			    &tunnel->rmt.ippref);
	  }
	else
	  {
	    gid_address_type (&at->rmt_eid) = GID_ADDR_MAC;
	    mac_copy (&gid_address_mac (&at->rmt_eid), &tunnel->rmt.mac);
	  }
	vnet_lisp_gpe_add_del_fwd_entry (at, 0);
      }
      vec_free (tunnels);

      /* disable all l3 ifaces */

      /* *INDENT-OFF* */
      hash_foreach_pair(p, lgm->l3_ifaces.hw_if_index_by_dp_table, ({
        vec_add1(dp_tables, p->key);
      }));
      /* *INDENT-ON* */

      vec_foreach (dp_table, dp_tables)
      {
	ai->is_add = 0;
	ai->table_id = dp_table[0];
	ai->is_l2 = 0;

	/* disables interface and removes defaults */
	vnet_lisp_gpe_add_del_iface (ai, 0);
      }

      /* disable all l2 ifaces */
      _vec_len (dp_tables) = 0;

      /* *INDENT-OFF* */
      hash_foreach_pair(p, lgm->l2_ifaces.hw_if_index_by_dp_table, ({
        vec_add1(dp_tables, p->key);
      }));
      /* *INDENT-ON* */

      vec_foreach (dp_table, dp_tables)
      {
	ai->is_add = 0;
	ai->bd_id = dp_table[0];
	ai->is_l2 = 1;

	/* disables interface and removes defaults */
	vnet_lisp_gpe_add_del_iface (ai, 0);
      }

      vec_free (dp_tables);
      lgm->is_en = 0;
    }

  return 0;
}

static clib_error_t *
lisp_gpe_enable_disable_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_en = 1;
  vnet_lisp_gpe_enable_disable_args_t _a, *a = &_a;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	is_en = 1;
      else if (unformat (line_input, "disable"))
	is_en = 0;
      else
	{
	  return clib_error_return (0, "parse error: '%U'",
				    format_unformat_error, line_input);
	}
    }
  a->is_en = is_en;
  return vnet_lisp_gpe_enable_disable (a);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (enable_disable_lisp_gpe_command, static) = {
  .path = "lisp gpe",
  .short_help = "lisp gpe [enable|disable]",
  .function = lisp_gpe_enable_disable_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
lisp_show_iface_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  hash_pair_t *p;

  vlib_cli_output (vm, "%=10s%=12s", "vrf", "hw_if_index");

  /* *INDENT-OFF* */
  hash_foreach_pair (p, lgm->l3_ifaces.hw_if_index_by_dp_table, ({
    vlib_cli_output (vm, "%=10d%=10d", p->key, p->value[0]);
  }));
  /* *INDENT-ON* */

  if (0 != lgm->l2_ifaces.hw_if_index_by_dp_table)
    {
      vlib_cli_output (vm, "%=10s%=12s", "bd_id", "hw_if_index");
      /* *INDENT-OFF* */
      hash_foreach_pair (p, lgm->l2_ifaces.hw_if_index_by_dp_table, ({
        vlib_cli_output (vm, "%=10d%=10d", p->key, p->value[0]);
      }));
      /* *INDENT-ON* */
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_show_iface_command) = {
    .path = "show lisp gpe interface",
    .short_help = "show lisp gpe interface",
    .function = lisp_show_iface_command_fn,
};
/* *INDENT-ON* */

u8 *
format_vnet_lisp_gpe_status (u8 * s, va_list * args)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  return format (s, "%s", lgm->is_en ? "enabled" : "disabled");
}


static void
lisp_gpe_sub_tunnel_last_lock_gone (fib_node_t * node)
{
  /*
   * no children so we are not counting locks. no-op.
   */
}

static fib_node_t *
lisp_gpe_sub_tunnel_get_fib_node (fib_node_index_t index)
{
  lisp_gpe_sub_tunnel_t *st;

  st = pool_elt_at_index (lisp_gpe_sub_tunnel_pool, index);
  return (&st->fib_node);
}

const static fib_node_vft_t lisp_gpe_tuennel_vft = {
  .fnv_get = lisp_gpe_sub_tunnel_get_fib_node,
  .fnv_back_walk = lisp_gpe_sub_tunnel_back_walk,
  .fnv_last_lock = lisp_gpe_sub_tunnel_last_lock_gone,
};

clib_error_t *
lisp_gpe_init (vlib_main_t * vm)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  clib_error_t *error = 0;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;

  lgm->vnet_main = vnet_get_main ();
  lgm->vlib_main = vm;
  lgm->im4 = &ip4_main;
  lgm->im6 = &ip6_main;
  lgm->lm4 = &ip4_main.lookup_main;
  lgm->lm6 = &ip6_main.lookup_main;

  mhash_init (&lgm->lisp_gpe_tunnel_by_key, sizeof (uword),
	      sizeof (lisp_gpe_tunnel_key_t));

  l2_fib_init (lgm);

  fib_node_register_type (FIB_NODE_TYPE_LISP_GPE_TUNNEL,
			  &lisp_gpe_tuennel_vft);
  udp_register_dst_port (vm, UDP_DST_PORT_lisp_gpe,
			 lisp_gpe_ip4_input_node.index, 1 /* is_ip4 */ );
  udp_register_dst_port (vm, UDP_DST_PORT_lisp_gpe6,
			 lisp_gpe_ip6_input_node.index, 0 /* is_ip4 */ );
  return 0;
}

VLIB_INIT_FUNCTION (lisp_gpe_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
