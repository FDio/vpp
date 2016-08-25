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
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/dpo/load_balance.h>

void
ip_dst_fib_add_route (u32 dst_table_id,
		      ip_prefix_t * dst_prefix,
		      ip_prefix_t * src_prefix,
		      fib_node_index_t * src_fib_index)
{
  fib_prefix_t dst_fib_prefix, src_fib_prefix;
  fib_node_index_t dst_fei;
  u32 dst_fib_index;

  ASSERT (NULL != src_prefix);
  ASSERT (NULL != dst_prefix);

  ip_prefix_to_fib_prefix (dst_prefix, &dst_fib_prefix);
  ip_prefix_to_fib_prefix (src_prefix, &src_fib_prefix);

  /*
   * lookup the destination prefix in the VRF table and retrieve the adj
   * for the LISP source
   */
  dst_fib_index = fib_table_get_from_table_id (dst_fib_prefix.fp_proto,
					       dst_table_id);
  dst_fei = fib_table_lookup_exact_match (dst_fib_index, &dst_fib_prefix);

  /*
   * If the FIB entry is not present, or not LISP sourced, add it
   */
  if (dst_fei == FIB_NODE_INDEX_INVALID ||
      NULL == fib_entry_get_source_data (dst_fei, FIB_SOURCE_LISP))
    {
      dpo_id_t src_lkup_dpo = DPO_NULL;

      /* create a new src FIB.  */
      *src_fib_index =
	fib_table_create_and_lock (src_fib_prefix.fp_proto,
				   "LISP-src for [%d,%U]",
				   dst_fib_index,
				   format_fib_prefix, &dst_fib_prefix);

      /*
       * create a data-path object to perform the source address lookup
       * in the SRC FIB
       */
      lookup_dpo_add_or_lock_w_fib_index (*src_fib_index,
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
      *src_fib_index = *(u32 *) fib_entry_get_source_data (dst_fei,
							   FIB_SOURCE_LISP);
    }
}

void
ip_src_fib_add_route_w_dpo (u32 src_fib_index,
			    ip_prefix_t * src_prefix,
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

void
ip_src_dst_fib_del_route (u32 src_fib_index,
			  ip_prefix_t * src_prefix,
			  u32 dst_table_id, ip_prefix_t * dst_prefix)
{
  fib_prefix_t dst_fib_prefix, src_fib_prefix;
  u32 dst_fib_index;

  ASSERT (NULL != dst_prefix);
  ASSERT (NULL != src_prefix);

  ip_prefix_to_fib_prefix (dst_prefix, &dst_fib_prefix);
  ip_prefix_to_fib_prefix (src_prefix, &src_fib_prefix);

  dst_fib_index = fib_table_get_from_table_id (dst_fib_prefix.fp_proto,
					       dst_table_id);

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

void
ip_src_fib_add_route (u32 src_fib_index,
		      ip_prefix_t * src_prefix, lisp_gpe_tunnel_t * t)
{
  fib_prefix_t src_fib_prefix;
  fib_route_path_t *rpaths;

  ip_prefix_to_fib_prefix (src_prefix, &src_fib_prefix);

  rpaths = lisp_gpe_mk_paths_for_sub_tunnels (t);

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
