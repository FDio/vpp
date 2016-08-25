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

#include <vnet/lisp-gpe/lisp_gpe_adjacency.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/dpo/load_balance.h>

/**
 * @brief Add route to IP4 or IP6 Destination FIB.
 *
 * Add a route to the destination FIB that results in the lookup
 * in the SRC FIB. The SRC FIB is created is it does not yet exist.
 *
 * @param[in]   dst_table_id    Destination FIB Table-ID
 * @param[in]   dst_prefix      Destination IP prefix.
 * @param[out]  src_fib_index   The index/ID of the SRC FIB created.
 */
u32
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
      dpo_id_t src_lkup_dpo = DPO_NULL;

      /* create a new src FIB.  */
      src_fib_index =
	fib_table_create_and_lock (dst_fib_prefix.fp_proto,
				   "LISP-src for [%d,%U]",
				   dst_fib_index,
				   format_fib_prefix, &dst_fib_prefix);

      /*
       * create a data-path object to perform the source address lookup
       * in the SRC FIB
       */
      lookup_dpo_add_or_lock_w_fib_index (src_fib_index,
					  (ip_prefix_version (dst_prefix) ==
					   IP6 ? DPO_PROTO_IP6 :
					   DPO_PROTO_IP4),
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
void
ip_src_dst_fib_del_route (u32 src_fib_index,
			  const ip_prefix_t * src_prefix,
			  u32 dst_fib_index, const ip_prefix_t * dst_prefix)
{
  fib_prefix_t dst_fib_prefix, src_fib_prefix;

  ASSERT (NULL != dst_prefix);
  ASSERT (NULL != src_prefix);

  ip_prefix_to_fib_prefix (dst_prefix, &dst_fib_prefix);
  ip_prefix_to_fib_prefix (src_prefix, &src_fib_prefix);

  fib_table_entry_delete (src_fib_index, &src_fib_prefix, FIB_SOURCE_LISP);

  if (0 == fib_table_get_num_entries (src_fib_index,
				      src_fib_prefix.fp_proto,
				      FIB_SOURCE_LISP))
    {
      /*
       * there's nothing left, unlock the source FIB and the
       * destination route
       */
      fib_table_entry_special_remove (dst_fib_index,
				      &dst_fib_prefix, FIB_SOURCE_LISP);
      fib_table_unlock (src_fib_index, src_fib_prefix.fp_proto);
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
 */
void
ip_src_fib_add_route_w_dpo (u32 src_fib_index,
			    const ip_prefix_t * src_prefix,
			    const dpo_id_t * src_dpo)
{
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
      fib_table_entry_special_dpo_add (src_fib_index,
				       &src_fib_prefix,
				       FIB_SOURCE_LISP,
				       FIB_ENTRY_FLAG_EXCLUSIVE, src_dpo);
    }
}

static void
ip_address_to_46 (const ip_address_t * addr,
		  ip46_address_t * a, fib_protocol_t * proto)
{
  *proto = (IP4 == ip_addr_version (addr) ?
	    FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);
  switch (*proto)
    {
    case FIB_PROTOCOL_IP4:
      a->ip4 = addr->ip.v4;
      break;
    case FIB_PROTOCOL_IP6:
      a->ip6 = addr->ip.v6;
      break;
    default:
      ASSERT (0);
      break;
    }
}

static fib_route_path_t *
ip_src_fib_mk_paths (const lisp_fwd_path_t * paths)
{
  const lisp_gpe_adjacency_t *ladj;
  fib_route_path_t *rpaths = NULL;
  u8 best_priority;
  u32 ii;

  vec_validate (rpaths, vec_len (paths) - 1);

  best_priority = paths[0].priority;

  vec_foreach_index (ii, paths)
  {
    if (paths[0].priority != best_priority)
      break;

    ladj = lisp_gpe_adjacency_get (paths[ii].lisp_adj);

    ip_address_to_46 (&ladj->remote_rloc,
		      &rpaths[ii].frp_addr, &rpaths[ii].frp_proto);

    rpaths[ii].frp_sw_if_index = ladj->sw_if_index;
    rpaths[ii].frp_weight = (paths[ii].weight ? paths[ii].weight : 1);
    rpaths[ii].frp_label = MPLS_LABEL_INVALID;
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
void
ip_src_fib_add_route (u32 src_fib_index,
		      const ip_prefix_t * src_prefix,
		      const lisp_fwd_path_t * paths)
{
  fib_prefix_t src_fib_prefix;
  fib_route_path_t *rpaths;

  ip_prefix_to_fib_prefix (src_prefix, &src_fib_prefix);

  rpaths = ip_src_fib_mk_paths (paths);

  fib_table_entry_update (src_fib_index,
			  &src_fib_prefix,
			  FIB_SOURCE_LISP, FIB_ENTRY_FLAG_NONE, rpaths);
  vec_free (rpaths);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
