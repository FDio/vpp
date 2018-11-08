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

#include <vnet/lisp-gpe/lisp_gpe_fwd_entry.h>
#include <vnet/lisp-gpe/lisp_gpe_adjacency.h>
#include <vnet/lisp-gpe/lisp_gpe_tenant.h>
#include <vnet/lisp-cp/lisp_cp_dpo.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/adj/adj_midchain.h>

/**
 * @brief Add route to IP4 or IP6 Destination FIB.
 *
 * Add a route to the destination FIB that results in the lookup
 * in the SRC FIB. The SRC FIB is created is it does not yet exist.
 *
 * @param[in]   dst_table_id    Destination FIB Table-ID
 * @param[in]   dst_prefix      Destination IP prefix.
 *
 * @return  src_fib_index   The index/ID of the SRC FIB created.
 */
static u32
ip_dst_fib_add_route (u32 dst_fib_index, const ip_prefix_t * dst_prefix)
{
  fib_node_index_t src_fib_index;
  fib_prefix_t dst_fib_prefix;
  fib_node_index_t dst_fei;

  ASSERT (NULL != dst_prefix);

  ip_prefix_to_fib_prefix (dst_prefix, &dst_fib_prefix);

  /*
   * lookup the destination prefix in the VRF table and retrieve the
   * LISP associated data
   */
  dst_fei = fib_table_lookup_exact_match (dst_fib_index, &dst_fib_prefix);

  /*
   * If the FIB entry is not present, or not LISP sourced, add it
   */
  if (dst_fei == FIB_NODE_INDEX_INVALID ||
      NULL == fib_entry_get_source_data (dst_fei, FIB_SOURCE_LISP))
    {
      dpo_id_t src_lkup_dpo = DPO_INVALID;

      /* create a new src FIB.  */
      src_fib_index =
	fib_table_create_and_lock (dst_fib_prefix.fp_proto,
				   FIB_SOURCE_LISP,
				   "LISP-src for [%d,%U]",
				   dst_fib_index,
				   format_fib_prefix, &dst_fib_prefix);
      /*
       * add src fib default route
       */
      fib_prefix_t prefix = {
	.fp_proto = dst_fib_prefix.fp_proto,
      };
      fib_table_entry_special_dpo_add (src_fib_index, &prefix,
				       FIB_SOURCE_LISP,
				       FIB_ENTRY_FLAG_EXCLUSIVE,
				       lisp_cp_dpo_get (fib_proto_to_dpo
							(dst_fib_prefix.fp_proto)));
      /*
       * create a data-path object to perform the source address lookup
       * in the SRC FIB
       */
      lookup_dpo_add_or_lock_w_fib_index (src_fib_index,
					  (ip_prefix_version (dst_prefix) ==
					   IP6 ? DPO_PROTO_IP6 :
					   DPO_PROTO_IP4),
					  LOOKUP_UNICAST,
					  LOOKUP_INPUT_SRC_ADDR,
					  LOOKUP_TABLE_FROM_CONFIG,
					  &src_lkup_dpo);

      /*
       * add the entry to the destination FIB that uses the lookup DPO
       */
      dst_fei = fib_table_entry_special_dpo_add (dst_fib_index,
						 &dst_fib_prefix,
						 FIB_SOURCE_LISP,
						 FIB_ENTRY_FLAG_EXCLUSIVE,
						 &src_lkup_dpo);

      /*
       * the DPO is locked by the FIB entry, and we have no further
       * need for it.
       */
      dpo_unlock (&src_lkup_dpo);

      /*
       * save the SRC FIB index on the entry so we can retrieve it for
       * subsequent routes.
       */
      fib_entry_set_source_data (dst_fei, FIB_SOURCE_LISP, &src_fib_index);
    }
  else
    {
      /*
       * destination FIB entry already present
       */
      src_fib_index = *(u32 *) fib_entry_get_source_data (dst_fei,
							  FIB_SOURCE_LISP);
    }

  return (src_fib_index);
}

/**
 * @brief Del route to IP4 or IP6 SD FIB.
 *
 * Remove routes from both destination and source FIBs.
 *
 * @param[in]   src_fib_index   The index/ID of the SRC FIB
 * @param[in]   src_prefix      Source IP prefix.
 * @param[in]   dst_fib_index   The index/ID of the DST FIB
 * @param[in]   dst_prefix      Destination IP prefix.
 */
static void
ip_src_dst_fib_del_route (u32 src_fib_index,
			  const ip_prefix_t * src_prefix,
			  u32 dst_fib_index, const ip_prefix_t * dst_prefix)
{
  fib_prefix_t dst_fib_prefix, src_fib_prefix;
  u8 have_default = 0;
  u32 n_entries;

  ASSERT (NULL != dst_prefix);
  ASSERT (NULL != src_prefix);

  ip_prefix_to_fib_prefix (dst_prefix, &dst_fib_prefix);
  ip_prefix_to_fib_prefix (src_prefix, &src_fib_prefix);

  fib_table_entry_delete (src_fib_index, &src_fib_prefix, FIB_SOURCE_LISP);

  /* check if only default left or empty */
  fib_prefix_t default_pref = {
    .fp_proto = dst_fib_prefix.fp_proto
  };

  if (fib_table_lookup_exact_match (src_fib_index,
				    &default_pref) != FIB_NODE_INDEX_INVALID)
    have_default = 1;

  n_entries = fib_table_get_num_entries (src_fib_index,
					 src_fib_prefix.fp_proto,
					 FIB_SOURCE_LISP);
  if (n_entries == 0 || (have_default && n_entries == 1))
    {
      /*
       * remove src FIB default route
       */
      if (have_default)
	fib_table_entry_special_remove (src_fib_index, &default_pref,
					FIB_SOURCE_LISP);

      /*
       * there's nothing left now, unlock the source FIB and the
       * destination route
       */
      fib_table_entry_special_remove (dst_fib_index,
				      &dst_fib_prefix, FIB_SOURCE_LISP);
      fib_table_unlock (src_fib_index, src_fib_prefix.fp_proto,
			FIB_SOURCE_LISP);
    }
}

/**
 * @brief Add route to IP4 or IP6 SRC FIB.
 *
 * Adds a route to in the LISP SRC FIB with the result of the route
 * being the DPO passed.
 *
 * @param[in]   src_fib_index   The index/ID of the SRC FIB
 * @param[in]   src_prefix      Source IP prefix.
 * @param[in]   src_dpo         The DPO the route will link to.
 *
 * @return fib index of the inserted prefix
 */
static fib_node_index_t
ip_src_fib_add_route_w_dpo (u32 src_fib_index,
			    const ip_prefix_t * src_prefix,
			    const dpo_id_t * src_dpo)
{
  fib_node_index_t fei = ~0;
  fib_prefix_t src_fib_prefix;

  ip_prefix_to_fib_prefix (src_prefix, &src_fib_prefix);

  /*
   * add the entry into the source fib.
   */
  fib_node_index_t src_fei;

  src_fei = fib_table_lookup_exact_match (src_fib_index, &src_fib_prefix);

  if (FIB_NODE_INDEX_INVALID == src_fei ||
      !fib_entry_is_sourced (src_fei, FIB_SOURCE_LISP))
    {
      fei = fib_table_entry_special_dpo_add (src_fib_index,
					     &src_fib_prefix,
					     FIB_SOURCE_LISP,
					     FIB_ENTRY_FLAG_EXCLUSIVE,
					     src_dpo);
    }
  return fei;
}

static fib_route_path_t *
lisp_gpe_mk_fib_paths (const lisp_fwd_path_t * paths)
{
  const lisp_gpe_adjacency_t *ladj;
  fib_route_path_t *rpaths = NULL;
  fib_protocol_t fp;
  u8 best_priority;
  u32 ii;

  vec_validate (rpaths, vec_len (paths) - 1);

  best_priority = paths[0].priority;

  vec_foreach_index (ii, paths)
  {
    if (paths[0].priority != best_priority)
      break;

    ladj = lisp_gpe_adjacency_get (paths[ii].lisp_adj);

    ip_address_to_46 (&ladj->remote_rloc, &rpaths[ii].frp_addr, &fp);

    rpaths[ii].frp_proto = fib_proto_to_dpo (fp);
    rpaths[ii].frp_sw_if_index = ladj->sw_if_index;
    rpaths[ii].frp_weight = (paths[ii].weight ? paths[ii].weight : 1);
  }

  ASSERT (0 != vec_len (rpaths));

  return (rpaths);
}

/**
 * @brief Add route to IP4 or IP6 SRC FIB.
 *
 * Adds a route to in the LISP SRC FIB for the tunnel.
 *
 * @param[in]   src_fib_index   The index/ID of the SRC FIB
 * @param[in]   src_prefix      Source IP prefix.
 * @param[in]   paths           The paths from which to construct the
 *                              load balance
 */
static fib_node_index_t
ip_src_fib_add_route (u32 src_fib_index,
		      const ip_prefix_t * src_prefix,
		      const lisp_fwd_path_t * paths)
{
  fib_prefix_t src_fib_prefix;
  fib_route_path_t *rpaths;

  ip_prefix_to_fib_prefix (src_prefix, &src_fib_prefix);

  rpaths = lisp_gpe_mk_fib_paths (paths);

  fib_node_index_t fib_entry_index =
    fib_table_entry_update (src_fib_index, &src_fib_prefix, FIB_SOURCE_LISP,
			    FIB_ENTRY_FLAG_NONE, rpaths);
  vec_free (rpaths);
  return fib_entry_index;
}

static void
gpe_native_fwd_add_del_lfe (lisp_gpe_fwd_entry_t * lfe, u8 is_add)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  u8 found = 0, ip_version;
  u32 *lfei, new_lfei;
  ip_version = ip_prefix_version (&lfe->key->rmt.ippref);

  new_lfei = lfe - lgm->lisp_fwd_entry_pool;
  vec_foreach (lfei, lgm->native_fwd_lfes[ip_version])
  {
    lfe = pool_elt_at_index (lgm->lisp_fwd_entry_pool, lfei[0]);
    if (lfei[0] == new_lfei)
      {
	found = 1;
	break;
      }
  }

  if (is_add)
    {
      if (!found)
	vec_add1 (lgm->native_fwd_lfes[ip_version], new_lfei);
    }
  else
    {
      if (found)
	vec_del1 (lgm->native_fwd_lfes[ip_version], lfei[0]);
    }
}

static index_t
create_fib_entries (lisp_gpe_fwd_entry_t * lfe)
{
  fib_node_index_t fi;
  fib_entry_t *fe;
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  dpo_proto_t dproto;
  ip_prefix_t ippref;
  fib_prefix_t fib_prefix;
  u8 ip_version = ip_prefix_version (&lfe->key->rmt.ippref);
  dproto = (ip_version == IP4 ? DPO_PROTO_IP4 : DPO_PROTO_IP6);

  if (lfe->is_src_dst)
    {
      lfe->src_fib_index = ip_dst_fib_add_route (lfe->eid_fib_index,
						 &lfe->key->rmt.ippref);
      memcpy (&ippref, &lfe->key->lcl.ippref, sizeof (ippref));
    }
  else
    {
      lfe->src_fib_index = lfe->eid_fib_index;
      memcpy (&ippref, &lfe->key->rmt.ippref, sizeof (ippref));
    }

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE == lfe->type)
    {
      dpo_id_t dpo = DPO_INVALID;

      switch (lfe->action)
	{
	case LISP_FORWARD_NATIVE:
	  /* TODO handle route overlaps with fib and default route */
	  if (vec_len (lgm->native_fwd_rpath[ip_version]))
	    {
	      ip_prefix_to_fib_prefix (&lfe->key->rmt.ippref, &fib_prefix);
	      fi = fib_table_entry_update (lfe->eid_fib_index, &fib_prefix,
					   FIB_SOURCE_LISP,
					   FIB_ENTRY_FLAG_NONE,
					   lgm->native_fwd_rpath[ip_version]);
	      gpe_native_fwd_add_del_lfe (lfe, 1);
	      goto done;
	    }
	case LISP_NO_ACTION:
	  /* TODO update timers? */
	case LISP_SEND_MAP_REQUEST:
	  /* insert tunnel that always sends map-request */
	  dpo_copy (&dpo, lisp_cp_dpo_get (dproto));
	  break;
	case LISP_DROP:
	  /* for drop fwd entries, just add route, no need to add encap tunnel */
	  dpo_copy (&dpo, drop_dpo_get (dproto));
	  break;
	}
      fi = ip_src_fib_add_route_w_dpo (lfe->src_fib_index, &ippref, &dpo);
      dpo_reset (&dpo);
    }
  else
    {
      fi = ip_src_fib_add_route (lfe->src_fib_index, &ippref, lfe->paths);
    }
done:
  fe = fib_entry_get (fi);
  return fe->fe_lb.dpoi_index;
}

static void
delete_fib_entries (lisp_gpe_fwd_entry_t * lfe)
{
  fib_prefix_t dst_fib_prefix;

  if (lfe->is_src_dst)
    ip_src_dst_fib_del_route (lfe->src_fib_index,
			      &lfe->key->lcl.ippref,
			      lfe->eid_fib_index, &lfe->key->rmt.ippref);
  else
    {
      ip_prefix_to_fib_prefix (&lfe->key->rmt.ippref, &dst_fib_prefix);
      fib_table_entry_delete (lfe->src_fib_index, &dst_fib_prefix,
			      FIB_SOURCE_LISP);
      gpe_native_fwd_add_del_lfe (lfe, 0);
    }
}

static lisp_gpe_fwd_entry_t *
find_fwd_entry (lisp_gpe_main_t * lgm,
		vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
		lisp_gpe_fwd_entry_key_t * key)
{
  uword *p;

  clib_memset (key, 0, sizeof (*key));

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

  p = hash_get_mem (lgm->lisp_gpe_fwd_entries, key);

  if (NULL != p)
    {
      return (pool_elt_at_index (lgm->lisp_fwd_entry_pool, p[0]));
    }
  return (NULL);
}

static int
lisp_gpe_fwd_entry_path_sort (void *a1, void *a2)
{
  lisp_fwd_path_t *p1 = a1, *p2 = a2;

  return (p1->priority - p2->priority);
}

static void
lisp_gpe_fwd_entry_mk_paths (lisp_gpe_fwd_entry_t * lfe,
			     vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
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
						  a->dp_table, lfe->key->vni);
  }
  vec_sort_with_function (lfe->paths, lisp_gpe_fwd_entry_path_sort);
}

void
vnet_lisp_gpe_add_fwd_counters (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
				u32 fwd_entry_index)
{
  const lisp_gpe_adjacency_t *ladj;
  lisp_fwd_path_t *path;
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  u8 *dummy_elt;
  lisp_gpe_fwd_entry_t *lfe;
  lisp_gpe_fwd_entry_key_t fe_key;
  lisp_stats_key_t key;

  lfe = find_fwd_entry (lgm, a, &fe_key);

  if (!lfe)
    return;

  if (LISP_GPE_FWD_ENTRY_TYPE_NORMAL != lfe->type)
    return;

  clib_memset (&key, 0, sizeof (key));
  key.fwd_entry_index = fwd_entry_index;

  vec_foreach (path, lfe->paths)
  {
    ladj = lisp_gpe_adjacency_get (path->lisp_adj);
    key.tunnel_index = ladj->tunnel_index;
    lisp_stats_key_t *key_copy = clib_mem_alloc (sizeof (*key_copy));
    memcpy (key_copy, &key, sizeof (*key_copy));
    pool_get (lgm->dummy_stats_pool, dummy_elt);
    hash_set_mem (lgm->lisp_stats_index_by_key, key_copy,
		  dummy_elt - lgm->dummy_stats_pool);

    vlib_validate_combined_counter (&lgm->counters,
				    dummy_elt - lgm->dummy_stats_pool);
    vlib_zero_combined_counter (&lgm->counters,
				dummy_elt - lgm->dummy_stats_pool);
  }
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
  lisp_gpe_fwd_entry_t *lfe;
  fib_protocol_t fproto;

  lfe = find_fwd_entry (lgm, a, &key);

  if (NULL != lfe)
    /* don't support updates */
    return VNET_API_ERROR_INVALID_VALUE;

  pool_get (lgm->lisp_fwd_entry_pool, lfe);
  clib_memset (lfe, 0, sizeof (*lfe));
  lfe->key = clib_mem_alloc (sizeof (key));
  memcpy (lfe->key, &key, sizeof (key));

  hash_set_mem (lgm->lisp_gpe_fwd_entries, lfe->key,
		lfe - lgm->lisp_fwd_entry_pool);
  a->fwd_entry_index = lfe - lgm->lisp_fwd_entry_pool;

  fproto = (IP4 == ip_prefix_version (&fid_addr_ippref (&lfe->key->rmt)) ?
	    FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);

  lfe->type = (a->is_negative ?
	       LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE :
	       LISP_GPE_FWD_ENTRY_TYPE_NORMAL);
  lfe->tenant = lisp_gpe_tenant_find_or_create (lfe->key->vni);
  lfe->eid_table_id = a->table_id;
  lfe->eid_fib_index = fib_table_find_or_create_and_lock (fproto,
							  lfe->eid_table_id,
							  FIB_SOURCE_LISP);
  lfe->is_src_dst = a->is_src_dst;

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE != lfe->type)
    {
      lisp_gpe_fwd_entry_mk_paths (lfe, a);
    }
  else
    {
      lfe->action = a->action;
    }

  lfe->dpoi_index = create_fib_entries (lfe);
  return (0);
}

static void
del_ip_fwd_entry_i (lisp_gpe_main_t * lgm, lisp_gpe_fwd_entry_t * lfe)
{
  lisp_fwd_path_t *path;
  fib_protocol_t fproto;

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE != lfe->type)
    {
      vec_foreach (path, lfe->paths)
      {
	lisp_gpe_adjacency_unlock (path->lisp_adj);
      }
    }

  delete_fib_entries (lfe);

  fproto = (IP4 == ip_prefix_version (&fid_addr_ippref (&lfe->key->rmt)) ?
	    FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);
  fib_table_unlock (lfe->eid_fib_index, fproto, FIB_SOURCE_LISP);

  hash_unset_mem (lgm->lisp_gpe_fwd_entries, lfe->key);
  clib_mem_free (lfe->key);
  pool_put (lgm->lisp_fwd_entry_pool, lfe);
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
  lisp_gpe_fwd_entry_t *lfe;

  lfe = find_fwd_entry (lgm, a, &key);

  if (NULL == lfe)
    /* no such entry */
    return VNET_API_ERROR_INVALID_VALUE;

  del_ip_fwd_entry_i (lgm, lfe);

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
  else
    return value.value;

  return lisp_gpe_main.l2_lb_cp_lkup.dpoi_index;
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
static u32
lisp_l2_fib_add_del_entry (u16 bd_index, u8 src_mac[6],
			   u8 dst_mac[6], const dpo_id_t * dpo, u8 is_add)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  BVT (clib_bihash_kv) kv, value;
  u32 old_val = ~0;

  make_mac_fib_key (&kv, bd_index, src_mac, dst_mac);

  if (BV (clib_bihash_search) (&lgm->l2_fib, &kv, &value) == 0)
    old_val = value.value;

  if (!is_add)
    BV (clib_bihash_add_del) (&lgm->l2_fib, &kv, 0 /* is_add */ );
  else
    {
      kv.value = dpo->dpoi_index;
      BV (clib_bihash_add_del) (&lgm->l2_fib, &kv, 1 /* is_add */ );
    }
  return old_val;
}

#define L2_FIB_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define L2_FIB_DEFAULT_HASH_MEMORY_SIZE (32<<20)

static void
l2_fib_init (lisp_gpe_main_t * lgm)
{
  index_t lbi;

  BV (clib_bihash_init) (&lgm->l2_fib, "l2 fib",
			 1 << max_log2 (L2_FIB_DEFAULT_HASH_NUM_BUCKETS),
			 L2_FIB_DEFAULT_HASH_MEMORY_SIZE);

  /*
   * the result from a 'miss' in a L2 Table
   */
  lbi = load_balance_create (1, DPO_PROTO_ETHERNET, 0);
  load_balance_set_bucket (lbi, 0, lisp_cp_dpo_get (DPO_PROTO_ETHERNET));

  dpo_set (&lgm->l2_lb_cp_lkup, DPO_LOAD_BALANCE, DPO_PROTO_ETHERNET, lbi);
}

static void
del_l2_fwd_entry_i (lisp_gpe_main_t * lgm, lisp_gpe_fwd_entry_t * lfe)
{
  lisp_fwd_path_t *path;

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE != lfe->type)
    {
      vec_foreach (path, lfe->paths)
      {
	lisp_gpe_adjacency_unlock (path->lisp_adj);
      }
      fib_path_list_child_remove (lfe->l2.path_list_index,
				  lfe->l2.child_index);
    }

  lisp_l2_fib_add_del_entry (lfe->l2.eid_bd_index,
			     fid_addr_mac (&lfe->key->lcl),
			     fid_addr_mac (&lfe->key->rmt), NULL, 0);

  hash_unset_mem (lgm->lisp_gpe_fwd_entries, lfe->key);
  clib_mem_free (lfe->key);
  pool_put (lgm->lisp_fwd_entry_pool, lfe);
}

/**
 * @brief Delete LISP L2 forwarding entry.
 *
 * Coordinates the removal of forwarding entries for L2 LISP overlay:
 *
 * @param[in]   lgm     Reference to @ref lisp_gpe_main_t.
 * @param[in]   a       Parameters for building the forwarding entry.
 *
 * @return 0 on success.
 */
static int
del_l2_fwd_entry (lisp_gpe_main_t * lgm,
		  vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
{
  lisp_gpe_fwd_entry_key_t key;
  lisp_gpe_fwd_entry_t *lfe;

  lfe = find_fwd_entry (lgm, a, &key);

  if (NULL == lfe)
    return VNET_API_ERROR_INVALID_VALUE;

  del_l2_fwd_entry_i (lgm, lfe);

  return (0);
}

/**
 * @brief Construct and insert the forwarding information used by an L2 entry
 */
static void
lisp_gpe_l2_update_fwding (lisp_gpe_fwd_entry_t * lfe)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  dpo_id_t dpo = DPO_INVALID;

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE != lfe->type)
    {
      fib_path_list_contribute_forwarding (lfe->l2.path_list_index,
					   FIB_FORW_CHAIN_TYPE_ETHERNET,
					   FIB_PATH_LIST_FWD_FLAG_NONE,
					   &lfe->l2.dpo);
      dpo_copy (&dpo, &lfe->l2.dpo);
    }
  else
    {
      switch (lfe->action)
	{
	case SEND_MAP_REQUEST:
	  dpo_copy (&dpo, &lgm->l2_lb_cp_lkup);
	  break;
	case NO_ACTION:
	case FORWARD_NATIVE:
	case DROP:
	  dpo_copy (&dpo, drop_dpo_get (DPO_PROTO_ETHERNET));
	}
    }

  /* add entry to l2 lisp fib */
  lisp_l2_fib_add_del_entry (lfe->l2.eid_bd_index,
			     fid_addr_mac (&lfe->key->lcl),
			     fid_addr_mac (&lfe->key->rmt), &dpo, 1);
  lfe->dpoi_index = dpo.dpoi_index;

  dpo_reset (&dpo);
}

/**
 * @brief Add LISP L2 forwarding entry.
 *
 * Coordinates the creation of forwarding entries for L2 LISP overlay:
 * creates lisp-gpe tunnel and injects new entry in Source/Dest L2 FIB.
 *
 * @param[in]   lgm     Reference to @ref lisp_gpe_main_t.
 * @param[in]   a       Parameters for building the forwarding entry.
 *
 * @return 0 on success.
 */
static int
add_l2_fwd_entry (lisp_gpe_main_t * lgm,
		  vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
{
  lisp_gpe_fwd_entry_key_t key;
  bd_main_t *bdm = &bd_main;
  lisp_gpe_fwd_entry_t *lfe;
  uword *bd_indexp;

  bd_indexp = hash_get (bdm->bd_index_by_bd_id, a->bd_id);
  if (!bd_indexp)
    {
      clib_warning ("bridge domain %d doesn't exist", a->bd_id);
      return -1;
    }

  lfe = find_fwd_entry (lgm, a, &key);

  if (NULL != lfe)
    /* don't support updates */
    return VNET_API_ERROR_INVALID_VALUE;

  pool_get (lgm->lisp_fwd_entry_pool, lfe);
  clib_memset (lfe, 0, sizeof (*lfe));
  lfe->key = clib_mem_alloc (sizeof (key));
  memcpy (lfe->key, &key, sizeof (key));

  hash_set_mem (lgm->lisp_gpe_fwd_entries, lfe->key,
		lfe - lgm->lisp_fwd_entry_pool);
  a->fwd_entry_index = lfe - lgm->lisp_fwd_entry_pool;

  lfe->type = (a->is_negative ?
	       LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE :
	       LISP_GPE_FWD_ENTRY_TYPE_NORMAL);
  lfe->l2.eid_bd_id = a->bd_id;
  lfe->l2.eid_bd_index = bd_indexp[0];
  lfe->tenant = lisp_gpe_tenant_find_or_create (lfe->key->vni);

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE != lfe->type)
    {
      fib_route_path_t *rpaths;

      /*
       * Make the sorted array of LISP paths with their resp. adjacency
       */
      lisp_gpe_fwd_entry_mk_paths (lfe, a);

      /*
       * From the LISP paths, construct a FIB path list that will
       * contribute a load-balance.
       */
      rpaths = lisp_gpe_mk_fib_paths (lfe->paths);

      lfe->l2.path_list_index =
	fib_path_list_create (FIB_PATH_LIST_FLAG_NONE, rpaths);

      /*
       * become a child of the path-list so we receive updates when
       * its forwarding state changes. this includes an implicit lock.
       */
      lfe->l2.child_index =
	fib_path_list_child_add (lfe->l2.path_list_index,
				 FIB_NODE_TYPE_LISP_GPE_FWD_ENTRY,
				 lfe - lgm->lisp_fwd_entry_pool);
    }
  else
    {
      lfe->action = a->action;
    }

  lisp_gpe_l2_update_fwding (lfe);

  return 0;
}

/**
 * @brief Lookup NSH SD FIB entry
 *
 * Does an SPI+SI lookup in the NSH LISP FIB.
 *
 * @param[in]   lgm             Reference to @ref lisp_gpe_main_t.
 * @param[in]   spi_si          SPI + SI.
 *
 * @return next node index.
 */
const dpo_id_t *
lisp_nsh_fib_lookup (lisp_gpe_main_t * lgm, u32 spi_si_net_order)
{
  int rv;
  BVT (clib_bihash_kv) kv, value;

  clib_memset (&kv, 0, sizeof (kv));
  kv.key[0] = spi_si_net_order;
  rv = BV (clib_bihash_search_inline_2) (&lgm->nsh_fib, &kv, &value);

  if (rv != 0)
    {
      return lgm->nsh_cp_lkup;
    }
  else
    {
      lisp_gpe_fwd_entry_t *lfe;
      lfe = pool_elt_at_index (lgm->lisp_fwd_entry_pool, value.value);
      return &lfe->nsh.choice;
    }
}

/**
 * @brief Add/del NSH FIB entry
 *
 * Inserts value in NSH FIB keyed by SPI+SI. If entry is
 * overwritten the associated value is returned.
 *
 * @param[in]   lgm             Reference to @ref lisp_gpe_main_t.
 * @param[in]   spi_si          SPI + SI.
 * @param[in]   dpo             Load balanced mapped to SPI + SI
 *
 * @return ~0 or value of overwritten entry.
 */
static u32
lisp_nsh_fib_add_del_entry (u32 spi_si_host_order, u32 lfei, u8 is_add)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  BVT (clib_bihash_kv) kv, value;
  u32 old_val = ~0;

  clib_memset (&kv, 0, sizeof (kv));
  kv.key[0] = clib_host_to_net_u32 (spi_si_host_order);
  kv.value = 0ULL;

  if (BV (clib_bihash_search) (&lgm->nsh_fib, &kv, &value) == 0)
    old_val = value.value;

  if (!is_add)
    BV (clib_bihash_add_del) (&lgm->nsh_fib, &kv, 0 /* is_add */ );
  else
    {
      kv.value = lfei;
      BV (clib_bihash_add_del) (&lgm->nsh_fib, &kv, 1 /* is_add */ );
    }
  return old_val;
}

#define NSH_FIB_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define NSH_FIB_DEFAULT_HASH_MEMORY_SIZE (32<<20)

static void
nsh_fib_init (lisp_gpe_main_t * lgm)
{
  BV (clib_bihash_init) (&lgm->nsh_fib, "nsh fib",
			 1 << max_log2 (NSH_FIB_DEFAULT_HASH_NUM_BUCKETS),
			 NSH_FIB_DEFAULT_HASH_MEMORY_SIZE);

  /*
   * the result from a 'miss' in a NSH Table
   */
  lgm->nsh_cp_lkup = lisp_cp_dpo_get (DPO_PROTO_NSH);
}

static void
del_nsh_fwd_entry_i (lisp_gpe_main_t * lgm, lisp_gpe_fwd_entry_t * lfe)
{
  lisp_fwd_path_t *path;

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE != lfe->type)
    {
      vec_foreach (path, lfe->paths)
      {
	lisp_gpe_adjacency_unlock (path->lisp_adj);
      }
      fib_path_list_child_remove (lfe->nsh.path_list_index,
				  lfe->nsh.child_index);
      dpo_reset (&lfe->nsh.choice);
    }

  lisp_nsh_fib_add_del_entry (fid_addr_nsh (&lfe->key->rmt), (u32) ~ 0, 0);

  hash_unset_mem (lgm->lisp_gpe_fwd_entries, lfe->key);
  clib_mem_free (lfe->key);
  pool_put (lgm->lisp_fwd_entry_pool, lfe);
}

/**
 * @brief Delete LISP NSH forwarding entry.
 *
 * Coordinates the removal of forwarding entries for NSH LISP overlay:
 *
 * @param[in]   lgm     Reference to @ref lisp_gpe_main_t.
 * @param[in]   a       Parameters for building the forwarding entry.
 *
 * @return 0 on success.
 */
static int
del_nsh_fwd_entry (lisp_gpe_main_t * lgm,
		   vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
{
  lisp_gpe_fwd_entry_key_t key;
  lisp_gpe_fwd_entry_t *lfe;

  lfe = find_fwd_entry (lgm, a, &key);

  if (NULL == lfe)
    return VNET_API_ERROR_INVALID_VALUE;

  del_nsh_fwd_entry_i (lgm, lfe);

  return (0);
}

/**
 * @brief Construct and insert the forwarding information used by an NSH entry
 */
static void
lisp_gpe_nsh_update_fwding (lisp_gpe_fwd_entry_t * lfe)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  dpo_id_t dpo = DPO_INVALID;
  vnet_hw_interface_t *hi;
  uword *hip;

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE != lfe->type)
    {
      fib_path_list_contribute_forwarding (lfe->nsh.path_list_index,
					   FIB_FORW_CHAIN_TYPE_NSH,
					   FIB_PATH_LIST_FWD_FLAG_NONE,
					   &lfe->nsh.dpo);

      /*
       * LISP encap is always the same for this SPI+SI so we do that hash now
       * and stack on the choice.
       */
      if (DPO_LOAD_BALANCE == lfe->nsh.dpo.dpoi_type)
	{
	  const dpo_id_t *tmp;
	  const load_balance_t *lb;
	  int hash;

	  lb = load_balance_get (lfe->nsh.dpo.dpoi_index);
	  hash = fid_addr_nsh (&lfe->key->rmt) % lb->lb_n_buckets;
	  tmp =
	    load_balance_get_bucket_i (lb, hash & lb->lb_n_buckets_minus_1);

	  dpo_copy (&dpo, tmp);
	}
    }
  else
    {
      switch (lfe->action)
	{
	case SEND_MAP_REQUEST:
	  dpo_copy (&dpo, lgm->nsh_cp_lkup);
	  break;
	case NO_ACTION:
	case FORWARD_NATIVE:
	case DROP:
	  dpo_copy (&dpo, drop_dpo_get (DPO_PROTO_NSH));
	}
    }

  /* We have only one nsh-lisp interface (no NSH virtualization) */
  hip = hash_get (lgm->nsh_ifaces.hw_if_index_by_dp_table, 0);
  if (hip)
    {
      hi = vnet_get_hw_interface (lgm->vnet_main, hip[0]);
      dpo_stack_from_node (hi->tx_node_index, &lfe->nsh.choice, &dpo);
    }
  /* add entry to nsh lisp fib */
  lisp_nsh_fib_add_del_entry (fid_addr_nsh (&lfe->key->rmt),
			      lfe - lgm->lisp_fwd_entry_pool, 1);
  dpo_reset (&dpo);

}

/**
 * @brief Add LISP NSH forwarding entry.
 *
 * Coordinates the creation of forwarding entries for L2 LISP overlay:
 * creates lisp-gpe tunnel and injects new entry in Source/Dest L2 FIB.
 *
 * @param[in]   lgm     Reference to @ref lisp_gpe_main_t.
 * @param[in]   a       Parameters for building the forwarding entry.
 *
 * @return 0 on success.
 */
static int
add_nsh_fwd_entry (lisp_gpe_main_t * lgm,
		   vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
{
  lisp_gpe_fwd_entry_key_t key;
  lisp_gpe_fwd_entry_t *lfe;

  lfe = find_fwd_entry (lgm, a, &key);

  if (NULL != lfe)
    /* don't support updates */
    return VNET_API_ERROR_INVALID_VALUE;

  pool_get (lgm->lisp_fwd_entry_pool, lfe);
  clib_memset (lfe, 0, sizeof (*lfe));
  lfe->key = clib_mem_alloc (sizeof (key));
  memcpy (lfe->key, &key, sizeof (key));

  hash_set_mem (lgm->lisp_gpe_fwd_entries, lfe->key,
		lfe - lgm->lisp_fwd_entry_pool);
  a->fwd_entry_index = lfe - lgm->lisp_fwd_entry_pool;

  lfe->type = (a->is_negative ?
	       LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE :
	       LISP_GPE_FWD_ENTRY_TYPE_NORMAL);
  lfe->tenant = 0;

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE != lfe->type)
    {
      fib_route_path_t *rpaths;

      /*
       * Make the sorted array of LISP paths with their resp. adjacency
       */
      lisp_gpe_fwd_entry_mk_paths (lfe, a);

      /*
       * From the LISP paths, construct a FIB path list that will
       * contribute a load-balance.
       */
      rpaths = lisp_gpe_mk_fib_paths (lfe->paths);

      lfe->nsh.path_list_index =
	fib_path_list_create (FIB_PATH_LIST_FLAG_NONE, rpaths);

      /*
       * become a child of the path-list so we receive updates when
       * its forwarding state changes. this includes an implicit lock.
       */
      lfe->nsh.child_index =
	fib_path_list_child_add (lfe->nsh.path_list_index,
				 FIB_NODE_TYPE_LISP_GPE_FWD_ENTRY,
				 lfe - lgm->lisp_fwd_entry_pool);
    }
  else
    {
      lfe->action = a->action;
    }

  lisp_gpe_nsh_update_fwding (lfe);

  return 0;
}

/**
 * @brief conver from the embedded fib_node_t struct to the LSIP entry
 */
static lisp_gpe_fwd_entry_t *
lisp_gpe_fwd_entry_from_fib_node (fib_node_t * node)
{
  return ((lisp_gpe_fwd_entry_t *) (((char *) node) -
				    STRUCT_OFFSET_OF (lisp_gpe_fwd_entry_t,
						      node)));
}

/**
 * @brief Function invoked during a backwalk of the FIB graph
 */
static fib_node_back_walk_rc_t
lisp_gpe_fib_node_back_walk (fib_node_t * node,
			     fib_node_back_walk_ctx_t * ctx)
{
  lisp_gpe_fwd_entry_t *lfe = lisp_gpe_fwd_entry_from_fib_node (node);

  if (fid_addr_type (&lfe->key->rmt) == FID_ADDR_MAC)
    lisp_gpe_l2_update_fwding (lfe);
  else if (fid_addr_type (&lfe->key->rmt) == FID_ADDR_NSH)
    lisp_gpe_nsh_update_fwding (lfe);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * @brief Get a fib_node_t struct from the index of a LISP fwd entry
 */
static fib_node_t *
lisp_gpe_fwd_entry_get_fib_node (fib_node_index_t index)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  lisp_gpe_fwd_entry_t *lfe;

  lfe = pool_elt_at_index (lgm->lisp_fwd_entry_pool, index);

  return (&(lfe->node));
}

/**
 * @brief An indication from the graph that the last lock has gone
 */
static void
lisp_gpe_fwd_entry_fib_node_last_lock_gone (fib_node_t * node)
{
  /* We don't manage the locks of the LISP objects via the graph, since
   * this object has no children. so this is a no-op. */
}

/**
 * @brief Virtual function table to register with FIB for the LISP type
 */
const static fib_node_vft_t lisp_fwd_vft = {
  .fnv_get = lisp_gpe_fwd_entry_get_fib_node,
  .fnv_last_lock = lisp_gpe_fwd_entry_fib_node_last_lock_gone,
  .fnv_back_walk = lisp_gpe_fib_node_back_walk,
};

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
      if (a->is_add)
	return add_l2_fwd_entry (lgm, a);
      else
	return del_l2_fwd_entry (lgm, a);
    case GID_ADDR_NSH:
      if (a->is_add)
	return add_nsh_fwd_entry (lgm, a);
      else
	return del_nsh_fwd_entry (lgm, a);
    default:
      clib_warning ("Forwarding entries for type %d not supported!", type);
      return -1;
    }
}

int
vnet_lisp_flush_stats (void)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  vlib_combined_counter_main_t *cm = &lgm->counters;
  u32 i;

  if (cm->counters == NULL)
    return 0;

  for (i = 0; i < vlib_combined_counter_n_counters (cm); i++)
    vlib_zero_combined_counter (cm, i);

  return 0;
}

static void
lisp_del_adj_stats (lisp_gpe_main_t * lgm, u32 fwd_entry_index, u32 ti)
{
  hash_pair_t *hp;
  lisp_stats_key_t key;
  void *key_copy;
  uword *p;
  u8 *s;

  clib_memset (&key, 0, sizeof (key));
  key.fwd_entry_index = fwd_entry_index;
  key.tunnel_index = ti;

  p = hash_get_mem (lgm->lisp_stats_index_by_key, &key);
  if (p)
    {
      s = pool_elt_at_index (lgm->dummy_stats_pool, p[0]);
      hp = hash_get_pair (lgm->lisp_stats_index_by_key, &key);
      key_copy = (void *) (hp->key);
      hash_unset_mem (lgm->lisp_stats_index_by_key, &key);
      clib_mem_free (key_copy);
      pool_put (lgm->dummy_stats_pool, s);
    }
}

void
vnet_lisp_gpe_del_fwd_counters (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
				u32 fwd_entry_index)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  lisp_gpe_fwd_entry_key_t fe_key;
  lisp_gpe_fwd_entry_t *lfe;
  lisp_fwd_path_t *path;
  const lisp_gpe_adjacency_t *ladj;

  lfe = find_fwd_entry (lgm, a, &fe_key);
  if (!lfe)
    return;

  if (LISP_GPE_FWD_ENTRY_TYPE_NORMAL != lfe->type)
    return;

  vec_foreach (path, lfe->paths)
  {
    ladj = lisp_gpe_adjacency_get (path->lisp_adj);
    lisp_del_adj_stats (lgm, fwd_entry_index, ladj->tunnel_index);
  }
}

/**
 * @brief Flush all the forwrding entries
 */
void
vnet_lisp_gpe_fwd_entry_flush (void)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  lisp_gpe_fwd_entry_t *lfe;

  /* *INDENT-OFF* */
  pool_foreach (lfe, lgm->lisp_fwd_entry_pool,
  ({
    switch (fid_addr_type(&lfe->key->rmt))
      {
      case FID_ADDR_MAC:
	del_l2_fwd_entry_i (lgm, lfe);
	break;
      case FID_ADDR_IP_PREF:
	del_ip_fwd_entry_i (lgm, lfe);
	break;
      case FID_ADDR_NSH:
        del_nsh_fwd_entry_i (lgm, lfe);
        break;
      }
  }));
  /* *INDENT-ON* */
}

static u8 *
format_lisp_fwd_path (u8 * s, va_list * ap)
{
  lisp_fwd_path_t *lfp = va_arg (*ap, lisp_fwd_path_t *);

  s = format (s, "weight:%d ", lfp->weight);
  s = format (s, "adj:[%U]\n",
	      format_lisp_gpe_adjacency,
	      lisp_gpe_adjacency_get (lfp->lisp_adj),
	      LISP_GPE_ADJ_FORMAT_FLAG_NONE);

  return (s);
}

typedef enum lisp_gpe_fwd_entry_format_flag_t_
{
  LISP_GPE_FWD_ENTRY_FORMAT_NONE = (0 << 0),
  LISP_GPE_FWD_ENTRY_FORMAT_DETAIL = (1 << 1),
} lisp_gpe_fwd_entry_format_flag_t;


static u8 *
format_lisp_gpe_fwd_entry (u8 * s, va_list * ap)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  lisp_gpe_fwd_entry_t *lfe = va_arg (*ap, lisp_gpe_fwd_entry_t *);
  lisp_gpe_fwd_entry_format_flag_t flags =
    va_arg (*ap, lisp_gpe_fwd_entry_format_flag_t);

  s = format (s, "VNI:%d VRF:%d EID: %U -> %U  [index:%d]",
	      lfe->key->vni, lfe->eid_table_id,
	      format_fid_address, &lfe->key->lcl,
	      format_fid_address, &lfe->key->rmt,
	      lfe - lgm->lisp_fwd_entry_pool);

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE == lfe->type)
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

  if (flags & LISP_GPE_FWD_ENTRY_FORMAT_DETAIL)
    {
      switch (fid_addr_type (&lfe->key->rmt))
	{
	case FID_ADDR_MAC:
	  s = format (s, " fib-path-list:%d\n", lfe->l2.path_list_index);
	  s = format (s, " dpo:%U\n", format_dpo_id, &lfe->l2.dpo, 0);
	  break;
	case FID_ADDR_NSH:
	  s = format (s, " fib-path-list:%d\n", lfe->nsh.path_list_index);
	  s = format (s, " dpo:%U\n", format_dpo_id, &lfe->nsh.dpo, 0);
	  break;
	case FID_ADDR_IP_PREF:
	  break;
	}
    }

  return (s);
}

static clib_error_t *
lisp_gpe_fwd_entry_show (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  lisp_gpe_fwd_entry_t *lfe;
  index_t index;
  u32 vni = ~0;

  if (unformat (input, "vni %d", &vni))
    ;
  else if (unformat (input, "%d", &index))
    {
      if (!pool_is_free_index (lgm->lisp_fwd_entry_pool, index))
	{
	  lfe = pool_elt_at_index (lgm->lisp_fwd_entry_pool, index);

	  vlib_cli_output (vm, "[%d@] %U",
			   index,
			   format_lisp_gpe_fwd_entry, lfe,
			   LISP_GPE_FWD_ENTRY_FORMAT_DETAIL);
	}
      else
	{
	  vlib_cli_output (vm, "entry %d invalid", index);
	}

      return (NULL);
    }

  /* *INDENT-OFF* */
  pool_foreach (lfe, lgm->lisp_fwd_entry_pool,
  ({
    if ((vni == ~0) ||
	(lfe->key->vni == vni))
      vlib_cli_output (vm, "%U", format_lisp_gpe_fwd_entry, lfe,
		       LISP_GPE_FWD_ENTRY_FORMAT_NONE);
  }));
  /* *INDENT-ON* */

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lisp_gpe_fwd_entry_show_command, static) = {
  .path = "show gpe entry",
  .short_help = "show gpe entry vni <vni> vrf <vrf> [leid <leid>] reid <reid>",
  .function = lisp_gpe_fwd_entry_show,
};
/* *INDENT-ON* */

clib_error_t *
lisp_gpe_fwd_entry_init (vlib_main_t * vm)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  clib_error_t *error = NULL;

  if ((error = vlib_call_init_function (vm, lisp_cp_dpo_module_init)))
    return (error);

  l2_fib_init (lgm);
  nsh_fib_init (lgm);

  fib_node_register_type (FIB_NODE_TYPE_LISP_GPE_FWD_ENTRY, &lisp_fwd_vft);

  return (error);
}

u32 *
vnet_lisp_gpe_get_fwd_entry_vnis (void)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  lisp_gpe_fwd_entry_t *lfe;
  u32 *vnis = 0;

  /* *INDENT-OFF* */
  pool_foreach (lfe, lgm->lisp_fwd_entry_pool,
  ({
    hash_set (vnis, lfe->key->vni, 0);
  }));
  /* *INDENT-ON* */

  return vnis;
}

lisp_api_gpe_fwd_entry_t *
vnet_lisp_gpe_fwd_entries_get_by_vni (u32 vni)
{
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  lisp_gpe_fwd_entry_t *lfe;
  lisp_api_gpe_fwd_entry_t *entries = 0, e;

  /* *INDENT-OFF* */
  pool_foreach (lfe, lgm->lisp_fwd_entry_pool,
  ({
    if (lfe->key->vni == vni)
      {
        clib_memset (&e, 0, sizeof (e));
        e.dp_table = lfe->eid_table_id;
        e.vni = lfe->key->vni;
        if (lfe->type == LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE)
          e.action = lfe->action;
        e.fwd_entry_index = lfe - lgm->lisp_fwd_entry_pool;
        memcpy (&e.reid, &lfe->key->rmt, sizeof (e.reid));
        memcpy (&e.leid, &lfe->key->lcl, sizeof (e.leid));
        vec_add1 (entries, e);
      }
  }));
  /* *INDENT-ON* */

  return entries;
}

int
vnet_lisp_gpe_get_fwd_stats (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
			     vlib_counter_t * c)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  lisp_gpe_fwd_entry_t *lfe;
  lisp_gpe_fwd_entry_key_t unused;

  lfe = find_fwd_entry (lgm, a, &unused);
  if (NULL == lfe)
    return -1;

  if (LISP_GPE_FWD_ENTRY_TYPE_NEGATIVE == lfe->type)
    return -1;

  if (~0 == lfe->dpoi_index)
    return -1;

  vlib_get_combined_counter (&load_balance_main.lbm_to_counters,
			     lfe->dpoi_index, c);
  return 0;
}

VLIB_INIT_FUNCTION (lisp_gpe_fwd_entry_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
