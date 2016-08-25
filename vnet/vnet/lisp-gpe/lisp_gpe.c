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
/**
 * @file
 * @brief Common utility functions for IPv4, IPv6 and L2 LISP-GPE tunnels.
 *
 */

#include <vnet/lisp-gpe/lisp_gpe.h>
#include <vnet/lisp-gpe/lisp_gpe_adjacency.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/load_balance.h>

/** LISP-GPE global state */
lisp_gpe_main_t lisp_gpe_main;

/**
 * @brief A Pool of all LISP forwarding entries
 */
static lisp_fwd_entry_t *lisp_fwd_entry_pool;

/**
 * DB of all forwarding entries. The Key is:{l-EID,r-EID,vni}
 * where the EID encodes L2 or L3
 */
static uword *lisp_gpe_fwd_entries;

static void
create_fib_entries (lisp_fwd_entry_t * lfe)
{
  dpo_proto_t dproto;

  dproto = (ip_prefix_version (&lfe->key->rmt.ippref) == IP4 ?
	    FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);

  lfe->src_fib_index = ip_dst_fib_add_route (lfe->eid_fib_index,
					     &lfe->key->rmt.ippref);

  if (LISP_FWD_ENTRY_TYPE_NEGATIVE == lfe->type)
    {
      dpo_id_t dpo = DPO_NULL;

      switch (lfe->action)
	{
	case LISP_NO_ACTION:
	  /* TODO update timers? */
	case LISP_FORWARD_NATIVE:
	  /* TODO check if route/next-hop for eid exists in fib and add
	   * more specific for the eid with the next-hop found */
	case LISP_SEND_MAP_REQUEST:
	  /* insert tunnel that always sends map-request */
	  dpo_set (&dpo, DPO_LISP_CP, 0, dproto);
	  break;
	case LISP_DROP:
	  /* for drop fwd entries, just add route, no need to add encap tunnel */
	  dpo_copy (&dpo, drop_dpo_get (dproto));
	  break;
	}
      ip_src_fib_add_route_w_dpo (lfe->src_fib_index,
				  &lfe->key->lcl.ippref, &dpo);
      dpo_reset (&dpo);
    }
  else
    {
      ip_src_fib_add_route (lfe->src_fib_index,
			    &lfe->key->lcl.ippref, lfe->paths);
    }
}

static void
delete_fib_entries (lisp_fwd_entry_t * lfe)
{
  ip_src_dst_fib_del_route (lfe->src_fib_index,
			    &lfe->key->lcl.ippref,
			    lfe->eid_fib_index, &lfe->key->rmt.ippref);
}

static void
gid_to_dp_address (gid_address_t * g, dp_address_t * d)
{
  switch (gid_address_type (g))
    {
    case GID_ADDR_IP_PREFIX:
    case GID_ADDR_SRC_DST:
      ip_prefix_copy (&d->ippref, &gid_address_ippref (g));
      d->type = FID_ADDR_IP_PREF;
      break;
    case GID_ADDR_MAC:
    default:
      mac_copy (&d->mac, &gid_address_mac (g));
      d->type = FID_ADDR_MAC;
      break;
    }
}

static lisp_fwd_entry_t *
find_fwd_entry (lisp_gpe_main_t * lgm,
		vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
		lisp_gpe_fwd_entry_key_t * key)
{
  uword *p;

  memset (key, 0, sizeof (*key));

  if (GID_ADDR_IP_PREFIX == gid_address_type (&a->rmt_eid))
    {
      /*
       * the ip version of the source is not set to ip6 when the
       * source is all zeros. force it.
       */
      ip_prefix_version (&gid_address_ippref (&a->lcl_eid)) =
	ip_prefix_version (&gid_address_ippref (&a->rmt_eid));
    }

  gid_to_dp_address (&a->rmt_eid, &key->rmt);
  gid_to_dp_address (&a->lcl_eid, &key->lcl);
  key->vni = a->vni;

  p = hash_get_mem (lisp_gpe_fwd_entries, key);

  if (NULL != p)
    {
      return (pool_elt_at_index (lisp_fwd_entry_pool, p[0]));
    }
  return (NULL);
}

static int
lisp_gpe_fwd_entry_path_sort (void *a1, void *a2)
{
  lisp_fwd_path_t *p1 = a1, *p2 = a2;

  return (p1->priority - p2->priority);
}

/**
 * @brief Add/Delete LISP IP forwarding entry.
 *
 * creation of forwarding entries for IP LISP overlay:
 *
 * @param[in]   lgm     Reference to @ref lisp_gpe_main_t.
 * @param[in]   a       Parameters for building the forwarding entry.
 *
 * @return 0 on success.
 */
static int
add_ip_fwd_entry (lisp_gpe_main_t * lgm,
		  vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
{
  lisp_gpe_fwd_entry_key_t key;
  lisp_fwd_entry_t *lfe;
  fib_protocol_t fproto;

  lfe = find_fwd_entry (lgm, a, &key);

  if (NULL != lfe)
    /* don't support updates */
    return VNET_API_ERROR_INVALID_VALUE;

  pool_get (lisp_fwd_entry_pool, lfe);
  memset (lfe, 0, sizeof (*lfe));
  lfe->key = clib_mem_alloc (sizeof (key));
  memcpy (lfe->key, &key, sizeof (key));

  hash_set_mem (lisp_gpe_fwd_entries, lfe->key, lfe - lisp_fwd_entry_pool);

  fproto = (IP4 == ip_prefix_version (&fid_addr_ippref (&lfe->key->rmt)) ?
	    FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);

  lfe->type = (a->is_negative ?
	       LISP_FWD_ENTRY_TYPE_NEGATIVE : LISP_FWD_ENTRY_TYPE_NORMAL);
  lfe->eid_table_id = a->table_id;
  lfe->eid_fib_index = fib_table_find_or_create_and_lock (fproto,
							  lfe->eid_table_id);

  if (LISP_FWD_ENTRY_TYPE_NEGATIVE != lfe->type)
    {
      lisp_fwd_path_t *path;
      u32 index;

      vec_validate (lfe->paths, vec_len (a->locator_pairs) - 1);

      vec_foreach_index (index, a->locator_pairs)
      {
	path = &lfe->paths[index];

	path->priority = a->locator_pairs[index].priority;
	path->weight = a->locator_pairs[index].weight;

	path->lisp_adj =
	  lisp_gpe_adjacency_find_or_create_and_lock (&a->locator_pairs
						      [index],
						      lfe->eid_table_id,
						      lfe->key->vni);
      }
      vec_sort_with_function (lfe->paths, lisp_gpe_fwd_entry_path_sort);
    }

  create_fib_entries (lfe);

  return (0);
}

static void
del_ip_fwd_entry_i (lisp_fwd_entry_t * lfe)
{
  lisp_fwd_path_t *path;
  fib_protocol_t fproto;

  vec_foreach (path, lfe->paths)
  {
    lisp_gpe_adjacency_unlock (path->lisp_adj);
  }

  delete_fib_entries (lfe);

  fproto = (IP4 == ip_prefix_version (&fid_addr_ippref (&lfe->key->rmt)) ?
	    FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);
  fib_table_unlock (lfe->eid_fib_index, fproto);

  hash_unset_mem (lisp_gpe_fwd_entries, lfe->key);
  clib_mem_free (lfe->key);
  pool_put (lisp_fwd_entry_pool, lfe);
}

/**
 * @brief Add/Delete LISP IP forwarding entry.
 *
 * removal of forwarding entries for IP LISP overlay:
 *
 * @param[in]   lgm     Reference to @ref lisp_gpe_main_t.
 * @param[in]   a       Parameters for building the forwarding entry.
 *
 * @return 0 on success.
 */
static int
del_ip_fwd_entry (lisp_gpe_main_t * lgm,
		  vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
{
  lisp_gpe_fwd_entry_key_t key;
  lisp_fwd_entry_t *lfe;

  lfe = find_fwd_entry (lgm, a, &key);

  if (NULL == lfe)
    /* no such entry */
    return VNET_API_ERROR_INVALID_VALUE;

  del_ip_fwd_entry_i (lfe);

  return (0);
}

static void
make_mac_fib_key (BVT (clib_bihash_kv) * kv, u16 bd_index, u8 src_mac[6],
		  u8 dst_mac[6])
{
  kv->key[0] = (((u64) bd_index) << 48) | mac_to_u64 (dst_mac);
  kv->key[1] = mac_to_u64 (src_mac);
  kv->key[2] = 0;
}

/**
 * @brief Lookup L2 SD FIB entry
 *
 * Does a vni + dest + source lookup in the L2 LISP FIB. If the lookup fails
 * it tries a second time with source set to 0 (i.e., a simple dest lookup).
 *
 * @param[in]   lgm             Reference to @ref lisp_gpe_main_t.
 * @param[in]   bd_index        Bridge domain index.
 * @param[in]   src_mac         Source mac address.
 * @param[in]   dst_mac         Destination mac address.
 *
 * @return index of mapping matching the lookup key.
 */
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

/**
 * @brief Add/del L2 SD FIB entry
 *
 * Inserts value in L2 FIB keyed by vni + dest + source. If entry is
 * overwritten the associated value is returned.
 *
 * @param[in]   lgm             Reference to @ref lisp_gpe_main_t.
 * @param[in]   bd_index        Bridge domain index.
 * @param[in]   src_mac         Source mac address.
 * @param[in]   dst_mac         Destination mac address.
 * @param[in]   val             Value to add.
 * @param[in]   is_add          Add/del flag.
 *
 * @return ~0 or value of overwritten entry.
 */
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

/**
 * @brief Add/Delete LISP L2 forwarding entry.
 *
 * Coordinates the creation/removal of forwarding entries for L2 LISP overlay:
 * creates lisp-gpe tunnel and injects new entry in Source/Dest L2 FIB.
 *
 * @param[in]   lgm     Reference to @ref lisp_gpe_main_t.
 * @param[in]   a       Parameters for building the forwarding entry.
 *
 * @return 0 on success.
 */
static int
add_del_l2_fwd_entry (lisp_gpe_main_t * lgm,
		      vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
{
  /* lisp_gpe_fwd_entry_key_t key; */
  /* lisp_fwd_entry_t *lfe; */
  /* fib_protocol_t fproto; */
  /* uword *bd_indexp; */

  /* bd_indexp = hash_get (bdm->bd_index_by_bd_id, a->bd_id); */
  /* if (!bd_indexp) */
  /*   { */
  /*     clib_warning ("bridge domain %d doesn't exist", a->bd_id); */
  /*     return -1; */
  /*   } */

  /* lfe = find_fwd_entry(lgm, a, &key); */

  /* if (NULL != lfe) */
  /*   /\* don't support updates *\/ */
  /*   return VNET_API_ERROR_INVALID_VALUE; */

  /* int rv; */
  /* u32 tun_index; */
  /* fib_node_index_t old_path_list; */
  /* bd_main_t *bdm = &bd_main; */
  /* fib_route_path_t *rpaths; */
  /* lisp_gpe_tunnel_t *t; */
  /* const dpo_id_t *dpo; */
  /* index_t lbi; */

  /* /\* create tunnel *\/ */
  /* rv = add_del_ip_tunnel (a, 1 /\* is_l2 *\/ , &tun_index, NULL); */
  /* if (rv) */
  /*   return rv; */

  /* bd_indexp = hash_get (bdm->bd_index_by_bd_id, a->bd_id); */
  /* if (!bd_indexp) */
  /*   { */
  /*     clib_warning ("bridge domain %d doesn't exist", a->bd_id); */
  /*     return -1; */
  /*   } */

  /* t = pool_elt_at_index (lgm->tunnels, tun_index); */
  /* old_path_list = t->l2_path_list; */

  /* if (LISP_NO_ACTION == t->action) */
  /*   { */
  /*     rpaths = lisp_gpe_mk_paths_for_sub_tunnels (t); */

  /*     t->l2_path_list = fib_path_list_create (FIB_PATH_LIST_FLAG_NONE, */
  /*                                          rpaths); */

  /*     vec_free (rpaths); */
  /*     fib_path_list_lock (t->l2_path_list); */

  /*     dpo = fib_path_list_contribute_forwarding (t->l2_path_list, */
  /*                                             FIB_FORW_CHAIN_TYPE_UNICAST_IP); */
  /*     lbi = dpo->dpoi_index; */
  /*   } */
  /* else if (LISP_SEND_MAP_REQUEST == t->action) */
  /*   { */
  /*     lbi = lgm->l2_lb_cp_lkup; */
  /*   } */
  /* else */
  /*   { */
  /*     lbi = lgm->l2_lb_miss; */
  /*   } */
  /* fib_path_list_unlock (old_path_list); */

  /* /\* add entry to l2 lisp fib *\/ */
  /* lisp_l2_fib_add_del_entry (lgm, bd_indexp[0], gid_address_mac (&a->lcl_eid), */
  /*                         gid_address_mac (&a->rmt_eid), lbi, a->is_add); */
  return 0;
}

/**
 * @brief Forwarding entry create/remove dispatcher.
 *
 * Calls l2 or l3 forwarding entry add/del function based on input data.
 *
 * @param[in]   a       Forwarding entry parameters.
 * @param[out]  hw_if_indexp    NOT USED
 *
 * @return 0 on success.
 */
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
      if (a->is_add)
	return add_ip_fwd_entry (lgm, a);
      else
	return del_ip_fwd_entry (lgm, a);
      break;
    case GID_ADDR_MAC:
      return add_del_l2_fwd_entry (lgm, a);
    default:
      clib_warning ("Forwarding entries for type %d not supported!", type);
      return -1;
    }
}

/** CLI command to add/del forwarding entry. */
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
  .path = "lisp gpe entry",
  .short_help = "lisp gpe entry add/del vni <vni> vrf <vrf> [leid <leid>]"
      "reid <reid> [loc-pair <lloc> <rloc> p <priority> w <weight>] "
      "[negative action <action>]",
  .function = lisp_gpe_add_del_fwd_entry_command_fn,
};
/* *INDENT-ON* */

static u8 *
format_lisp_fwd_path (u8 * s, va_list ap)
{
  lisp_fwd_path_t *lfp = va_arg (ap, lisp_fwd_path_t *);

  s = format (s, "pirority:%d weight:%d ", lfp->priority, lfp->weight);
  s = format (s, "adj:[%U]\n",
	      format_lisp_gpe_adjacency,
	      lisp_gpe_adjacency_get (lfp->lisp_adj),
	      LISP_GPE_ADJ_FORMAT_FLAG_NONE);

  return (s);
}

static u8 *
format_lisp_gpe_fwd_entry (u8 * s, va_list ap)
{
  lisp_fwd_entry_t *lfe = va_arg (ap, lisp_fwd_entry_t *);

  s = format (s, "VNI:%d VRF:%d EID: %U -> %U",
	      lfe->key->vni, lfe->eid_table_id,
	      format_fid_address, &lfe->key->lcl,
	      format_fid_address, &lfe->key->rmt);
  if (LISP_FWD_ENTRY_TYPE_NEGATIVE == lfe->type)
    {
      s = format (s, "\n Negative - action:%U",
		  format_negative_mapping_action, lfe->action);
    }
  else
    {
      lisp_fwd_path_t *path;

      s = format (s, "\n via:");
      vec_foreach (path, lfe->paths)
      {
	s = format (s, "\n  %U", format_lisp_fwd_path, path);
      }
    }

  return (s);
}

static clib_error_t *
lisp_gpe_fwd_entry_show (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lisp_fwd_entry_t *lfe;

/* *INDENT-OFF* */
  pool_foreach (lfe, lisp_fwd_entry_pool,
  ({
    vlib_cli_output (vm, "%U", format_lisp_gpe_fwd_entry, lfe);
  }));
/* *INDENT-ON* */

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_gpe_fwd_entry_show_command, static) = {
  .path = "show lisp gpe entry",
  .short_help = "show lisp gpe entry vni <vni> vrf <vrf> [leid <leid>] reid <reid>",
  .function = lisp_gpe_fwd_entry_show,
};
/* *INDENT-ON* */

/** Check if LISP-GPE is enabled. */
u8
vnet_lisp_gpe_enable_disable_status (void)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;

  return lgm->is_en;
}

/** Enable/disable LISP-GPE. */
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
      vnet_lisp_gpe_add_del_iface_args_t _ai, *ai = &_ai;
      lisp_fwd_entry_t *lfe;

      /* remove all entries */
      /* *INDENT-OFF* */
      pool_foreach (lfe, lisp_fwd_entry_pool,
      ({
	del_ip_fwd_entry_i (lfe);
      }));
      /* *INDENT-ON* */

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

/** CLI command to enable/disable LISP-GPE. */
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

/** CLI command to show LISP-GPE interfaces. */
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

/** Format LISP-GPE status. */
u8 *
format_vnet_lisp_gpe_status (u8 * s, va_list * args)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  return format (s, "%s", lgm->is_en ? "enabled" : "disabled");
}


/** LISP-GPE init function. */
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

  lisp_gpe_fwd_entries = hash_create_mem (0,
					  sizeof (lisp_gpe_fwd_entry_key_t),
					  sizeof (uword));

  l2_fib_init (lgm);

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
