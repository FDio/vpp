/*
 * nsh_node.c - nsh nodes
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <nsh/nsh.h>

always_inline void
nsh_md2_encap (vlib_buffer_t * b, nsh_base_header_t * hdr,
	       nsh_entry_t * nsh_entry)
{
  nsh_main_t *nm = &nsh_main;
  nsh_base_header_t *nsh_base;
  nsh_tlv_header_t *opt0;
  nsh_tlv_header_t *limit0;
  nsh_tlv_header_t *nsh_md2;
  nsh_option_map_t *nsh_option;
  u8 old_option_size = 0;
  u8 new_option_size = 0;

  /* Populate the NSH Header */
  opt0 = (nsh_tlv_header_t *) (nsh_entry->tlvs_data);
  limit0 = (nsh_tlv_header_t *) (nsh_entry->tlvs_data + nsh_entry->tlvs_len);

  nsh_md2 = (nsh_tlv_header_t *) ((u8 *) hdr /*nsh_entry->rewrite */  +
				  sizeof (nsh_base_header_t));
  nsh_entry->rewrite_size = sizeof (nsh_base_header_t);

  /* Scan the set of variable metadata, process ones that we understand */
  while (opt0 < limit0)
    {
      old_option_size = sizeof (nsh_tlv_header_t) + opt0->length;
      /* round to 4-byte */
      old_option_size = ((old_option_size + 3) >> 2) << 2;

      nsh_option = nsh_md2_lookup_option (opt0->class, opt0->type);
      if (nsh_option == NULL)
	{
	  goto next_tlv_md2;
	}

      if (nm->options[nsh_option->option_id])
	{
	  if ((*nm->options[nsh_option->option_id]) (b, nsh_md2))
	    {
	      goto next_tlv_md2;
	    }

	  /* option length may be varied */
	  new_option_size = sizeof (nsh_tlv_header_t) + nsh_md2->length;
	  /* round to 4-byte */
	  new_option_size = ((new_option_size + 3) >> 2) << 2;
	  nsh_entry->rewrite_size += new_option_size;

	  nsh_md2 = (nsh_tlv_header_t *) (((u8 *) nsh_md2) + new_option_size);
	  opt0 = (nsh_tlv_header_t *) (((u8 *) opt0) + old_option_size);

	}
      else
	{
	next_tlv_md2:
	  opt0 = (nsh_tlv_header_t *) (((u8 *) opt0) + old_option_size);
	}
    }

  /* update nsh header's length */
  nsh_base = (nsh_base_header_t *) nsh_entry->rewrite;
  nsh_base->length = (nsh_base->length & NSH_TTL_L2_MASK) |
    ((nsh_entry->rewrite_size >> 2) & NSH_LEN_MASK);
  return;
}

always_inline void
nsh_md2_swap (vlib_buffer_t * b,
	      nsh_base_header_t * hdr,
	      u32 header_len,
	      nsh_entry_t * nsh_entry, u32 * next, u32 drop_node_val)
{
  nsh_main_t *nm = &nsh_main;
  nsh_base_header_t *nsh_base;
  nsh_tlv_header_t *opt0;
  nsh_tlv_header_t *limit0;
  nsh_tlv_header_t *nsh_md2;
  nsh_option_map_t *nsh_option;
  u8 old_option_size = 0;
  u8 new_option_size = 0;

  /* Populate the NSH Header */
  opt0 = (nsh_md2_data_t *) (hdr + 1);
  limit0 = (nsh_md2_data_t *) ((u8 *) hdr + header_len);

  nsh_md2 =
    (nsh_tlv_header_t *) (nsh_entry->rewrite + sizeof (nsh_base_header_t));
  nsh_entry->rewrite_size = sizeof (nsh_base_header_t);

  /* Scan the set of variable metadata, process ones that we understand */
  while (opt0 < limit0)
    {
      old_option_size = sizeof (nsh_tlv_header_t) + opt0->length;
      /* round to 4-byte */
      old_option_size = ((old_option_size + 3) >> 2) << 2;

      nsh_option = nsh_md2_lookup_option (opt0->class, opt0->type);
      if (nsh_option == NULL)
	{
	  goto next_tlv_md2;
	}

      if (nm->swap_options[nsh_option->option_id])
	{
	  if ((*nm->swap_options[nsh_option->option_id]) (b, opt0, nsh_md2))
	    {
	      goto next_tlv_md2;
	    }

	  /* option length may be varied */
	  new_option_size = sizeof (nsh_tlv_header_t) + nsh_md2->length;
	  /* round to 4-byte */
	  new_option_size = ((new_option_size + 3) >> 2) << 2;
	  nsh_entry->rewrite_size += new_option_size;
	  nsh_md2 = (nsh_tlv_header_t *) (((u8 *) nsh_md2) + new_option_size);

	  opt0 = (nsh_tlv_header_t *) (((u8 *) opt0) + old_option_size);

	}
      else
	{
	next_tlv_md2:
	  opt0 = (nsh_tlv_header_t *) (((u8 *) opt0) + old_option_size);
	}
    }

  /* update nsh header's length */
  nsh_base = (nsh_base_header_t *) nsh_entry->rewrite;
  nsh_base->length = (nsh_base->length & NSH_TTL_L2_MASK) |
    ((nsh_entry->rewrite_size >> 2) & NSH_LEN_MASK);
  return;
}

always_inline void
nsh_md2_decap (vlib_buffer_t * b,
	       nsh_base_header_t * hdr,
	       u32 * header_len, u32 * next, u32 drop_node_val)
{
  nsh_main_t *nm = &nsh_main;
  nsh_md2_data_t *opt0;
  nsh_md2_data_t *limit0;
  nsh_option_map_t *nsh_option;
  u8 option_len = 0;

  /* Populate the NSH Header */
  opt0 = (nsh_md2_data_t *) (hdr + 1);
  limit0 = (nsh_md2_data_t *) ((u8 *) hdr + *header_len);

  /* Scan the set of variable metadata, process ones that we understand */
  while (opt0 < limit0)
    {
      nsh_option = nsh_md2_lookup_option (opt0->class, opt0->type);
      if (nsh_option == NULL)
	{
	  *next = drop_node_val;
	  return;
	}

      if (nm->pop_options[nsh_option->option_id])
	{
	  if ((*nm->pop_options[nsh_option->option_id]) (b, opt0))
	    {
	      *next = drop_node_val;
	      return;
	    }
	}
      /* round to 4-byte */
      option_len = ((opt0->length + 3) >> 2) << 2;
      opt0 =
	(nsh_md2_data_t *) (((u8 *) opt0) + sizeof (nsh_md2_data_t) +
			    option_len);
      *next =
	(nm->decap_v4_next_override) ? (nm->decap_v4_next_override) : (*next);
      *header_len = (nm->decap_v4_next_override) ? 0 : (*header_len);
    }

  return;
}

static uword
nsh_input_map (vlib_main_t * vm,
	       vlib_node_runtime_t * node,
	       vlib_frame_t * from_frame, u32 node_type)
{
  u32 n_left_from, next_index, *from, *to_next;
  nsh_main_t *nm = &nsh_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0 = NSH_NODE_NEXT_DROP, next1 = NSH_NODE_NEXT_DROP;
	  uword *entry0, *entry1;
	  nsh_base_header_t *hdr0 = 0, *hdr1 = 0;
	  u32 header_len0 = 0, header_len1 = 0;
	  u32 nsp_nsi0, nsp_nsi1;
	  u32 ttl0, ttl1;
	  u32 error0, error1;
	  nsh_map_t *map0 = 0, *map1 = 0;
	  nsh_entry_t *nsh_entry0 = 0, *nsh_entry1 = 0;
	  nsh_base_header_t *encap_hdr0 = 0, *encap_hdr1 = 0;
	  u32 encap_hdr_len0 = 0, encap_hdr_len1 = 0;
	  nsh_proxy_session_by_key_t key0, key1;
	  uword *p0, *p1;
	  nsh_proxy_session_t *proxy0, *proxy1;
	  u32 sw_if_index0 = 0, sw_if_index1 = 0;
	  ethernet_header_t placeholder_eth0, placeholder_eth1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  error0 = 0;
	  error1 = 0;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  hdr0 = vlib_buffer_get_current (b0);
	  hdr1 = vlib_buffer_get_current (b1);

	  /* Process packet 0 */
	  if (node_type == NSH_INPUT_TYPE)
	    {
	      nsp_nsi0 = hdr0->nsp_nsi;
	      header_len0 = (hdr0->length & NSH_LEN_MASK) * 4;
	      ttl0 = (hdr0->ver_o_c & NSH_TTL_H4_MASK) << 2 |
		(hdr0->length & NSH_TTL_L2_MASK) >> 6;
	      ttl0 = ttl0 - 1;
	      if (PREDICT_FALSE (ttl0 == 0))
		{
		  error0 = NSH_NODE_ERROR_INVALID_TTL;
		  goto trace0;
		}
	    }
	  else if (node_type == NSH_CLASSIFIER_TYPE)
	    {
	      nsp_nsi0 =
		clib_host_to_net_u32 (vnet_buffer (b0)->
				      l2_classify.opaque_index);
	    }
	  else if (node_type == NSH_AWARE_VNF_PROXY_TYPE)
	    {
	      /* Push placeholder Eth header */
	      char placeholder_dst_address[6] =
		{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	      char placeholder_src_address[6] =
		{ 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc };
	      clib_memcpy_fast (placeholder_eth0.dst_address,
				placeholder_dst_address, 6);
	      clib_memcpy_fast (placeholder_eth0.src_address,
				placeholder_src_address, 6);
	      placeholder_eth0.type = 0x0800;
	      vlib_buffer_advance (b0, -(word) sizeof (ethernet_header_t));
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy_fast (hdr0, &placeholder_eth0,
				(word) sizeof (ethernet_header_t));

	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      nsp_nsi0 = nm->tunnel_index_by_sw_if_index[sw_if_index0];
	    }
	  else
	    {
	      clib_memset (&key0, 0, sizeof (key0));
	      key0.transport_type = NSH_NODE_NEXT_ENCAP_VXLAN4;
	      key0.transport_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	      p0 = hash_get_mem (nm->nsh_proxy_session_by_key, &key0);
	      if (PREDICT_FALSE (p0 == 0))
		{
		  error0 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace0;
		}

	      proxy0 = pool_elt_at_index (nm->nsh_proxy_sessions, p0[0]);
	      if (PREDICT_FALSE (proxy0 == 0))
		{
		  error0 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace0;
		}
	      nsp_nsi0 = proxy0->nsp_nsi;
	    }

	  entry0 = hash_get_mem (nm->nsh_mapping_by_key, &nsp_nsi0);
	  if (PREDICT_FALSE (entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace0;
	    }

	  /* Entry should point to a mapping ... */
	  map0 = pool_elt_at_index (nm->nsh_mappings, entry0[0]);
	  if (PREDICT_FALSE (map0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace0;
	    }

	  /* set up things for next node to transmit ie which node to handle it and where */
	  next0 = map0->next_node;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = map0->sw_if_index;
	  vnet_buffer (b0)->ip.adj_index = map0->adj_index;

	  if (PREDICT_FALSE (map0->nsh_action == NSH_ACTION_POP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr0->md_type == 2))
		{
		  nsh_md2_decap (b0, hdr0, &header_len0, &next0,
				 NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next0 == NSH_NODE_NEXT_DROP))
		    {
		      error0 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace0;
		    }
		  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
		    map0->rx_sw_if_index;
		}

	      /* Pop NSH header */
	      vlib_buffer_advance (b0, (word) header_len0);
	      goto trace0;
	    }

	  entry0 = hash_get_mem (nm->nsh_entry_by_key, &map0->mapped_nsp_nsi);
	  if (PREDICT_FALSE (entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_ENTRY;
	      goto trace0;
	    }

	  nsh_entry0 =
	    (nsh_entry_t *) pool_elt_at_index (nm->nsh_entries, entry0[0]);
	  encap_hdr0 = (nsh_base_header_t *) (nsh_entry0->rewrite);
	  /* rewrite_size should equal to (encap_hdr0->length * 4) */
	  encap_hdr_len0 = nsh_entry0->rewrite_size;

	  if (PREDICT_TRUE (map0->nsh_action == NSH_ACTION_SWAP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr0->md_type == 2))
		{
		  nsh_md2_swap (b0, hdr0, header_len0, nsh_entry0,
				&next0, NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next0 == NSH_NODE_NEXT_DROP))
		    {
		      error0 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace0;
		    }
		}

	      /* Pop old NSH header */
	      vlib_buffer_advance (b0, (word) header_len0);

	      /* After processing, md2's length may be varied */
	      encap_hdr_len0 = nsh_entry0->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b0, -(word) encap_hdr_len0);
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy_fast (hdr0, encap_hdr0, (word) encap_hdr_len0);

	      goto trace0;
	    }

	  if (PREDICT_TRUE (map0->nsh_action == NSH_ACTION_PUSH))
	    {
	      /* After processing, md2's length may be varied */
	      encap_hdr_len0 = nsh_entry0->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b0, -(word) encap_hdr_len0);
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy_fast (hdr0, encap_hdr0, (word) encap_hdr_len0);

	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (nsh_entry0->nsh_base.md_type == 2))
		{
		  nsh_md2_encap (b0, hdr0, nsh_entry0);
		}

	    }

	trace0:
	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      nsh_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy_fast (&(tr->trace_data), hdr0,
				((hdr0->length & NSH_LEN_MASK) * 4));
	    }

	  /* Process packet 1 */
	  if (node_type == NSH_INPUT_TYPE)
	    {
	      nsp_nsi1 = hdr1->nsp_nsi;
	      header_len1 = (hdr1->length & NSH_LEN_MASK) * 4;
	      ttl1 = (hdr1->ver_o_c & NSH_TTL_H4_MASK) << 2 |
		(hdr1->length & NSH_TTL_L2_MASK) >> 6;
	      ttl1 = ttl1 - 1;
	      if (PREDICT_FALSE (ttl1 == 0))
		{
		  error1 = NSH_NODE_ERROR_INVALID_TTL;
		  goto trace1;
		}
	    }
	  else if (node_type == NSH_CLASSIFIER_TYPE)
	    {
	      nsp_nsi1 =
		clib_host_to_net_u32 (vnet_buffer (b1)->
				      l2_classify.opaque_index);
	    }
	  else if (node_type == NSH_AWARE_VNF_PROXY_TYPE)
	    {
	      /* Push placeholder Eth header */
	      char placeholder_dst_address[6] =
		{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	      char placeholder_src_address[6] =
		{ 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc };
	      clib_memcpy_fast (placeholder_eth1.dst_address,
				placeholder_dst_address, 6);
	      clib_memcpy_fast (placeholder_eth1.src_address,
				placeholder_src_address, 6);
	      placeholder_eth1.type = 0x0800;
	      vlib_buffer_advance (b1, -(word) sizeof (ethernet_header_t));
	      hdr1 = vlib_buffer_get_current (b1);
	      clib_memcpy_fast (hdr1, &placeholder_eth1,
				(word) sizeof (ethernet_header_t));

	      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];
	      nsp_nsi1 = nm->tunnel_index_by_sw_if_index[sw_if_index1];
	    }
	  else
	    {
	      clib_memset (&key1, 0, sizeof (key1));
	      key1.transport_type = NSH_NODE_NEXT_ENCAP_VXLAN4;
	      key1.transport_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	      p1 = hash_get_mem (nm->nsh_proxy_session_by_key, &key1);
	      if (PREDICT_FALSE (p1 == 0))
		{
		  error1 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace1;
		}

	      proxy1 = pool_elt_at_index (nm->nsh_proxy_sessions, p1[0]);
	      if (PREDICT_FALSE (proxy1 == 0))
		{
		  error1 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace1;
		}
	      nsp_nsi1 = proxy1->nsp_nsi;
	    }

	  entry1 = hash_get_mem (nm->nsh_mapping_by_key, &nsp_nsi1);
	  if (PREDICT_FALSE (entry1 == 0))
	    {
	      error1 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace1;
	    }

	  /* Entry should point to a mapping ... */
	  map1 = pool_elt_at_index (nm->nsh_mappings, entry1[0]);
	  if (PREDICT_FALSE (map1 == 0))
	    {
	      error1 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace1;
	    }

	  /* set up things for next node to transmit ie which node to handle it and where */
	  next1 = map1->next_node;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = map1->sw_if_index;
	  vnet_buffer (b1)->ip.adj_index = map1->adj_index;

	  if (PREDICT_FALSE (map1->nsh_action == NSH_ACTION_POP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr1->md_type == 2))
		{
		  nsh_md2_decap (b1, hdr1, &header_len1, &next1,
				 NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next1 == NSH_NODE_NEXT_DROP))
		    {
		      error1 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace1;
		    }
		  vnet_buffer (b1)->sw_if_index[VLIB_RX] =
		    map1->rx_sw_if_index;
		}

	      /* Pop NSH header */
	      vlib_buffer_advance (b1, (word) header_len1);
	      goto trace1;
	    }

	  entry1 = hash_get_mem (nm->nsh_entry_by_key, &map1->mapped_nsp_nsi);
	  if (PREDICT_FALSE (entry1 == 0))
	    {
	      error1 = NSH_NODE_ERROR_NO_ENTRY;
	      goto trace1;
	    }

	  nsh_entry1 =
	    (nsh_entry_t *) pool_elt_at_index (nm->nsh_entries, entry1[0]);
	  encap_hdr1 = (nsh_base_header_t *) (nsh_entry1->rewrite);
	  /* rewrite_size should equal to (encap_hdr0->length * 4) */
	  encap_hdr_len1 = nsh_entry1->rewrite_size;

	  if (PREDICT_TRUE (map1->nsh_action == NSH_ACTION_SWAP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr1->md_type == 2))
		{
		  nsh_md2_swap (b1, hdr1, header_len1, nsh_entry1,
				&next1, NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next1 == NSH_NODE_NEXT_DROP))
		    {
		      error1 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace1;
		    }
		}

	      /* Pop old NSH header */
	      vlib_buffer_advance (b1, (word) header_len1);

	      /* After processing, md2's length may be varied */
	      encap_hdr_len1 = nsh_entry1->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b1, -(word) encap_hdr_len1);
	      hdr1 = vlib_buffer_get_current (b1);
	      clib_memcpy_fast (hdr1, encap_hdr1, (word) encap_hdr_len1);

	      goto trace1;
	    }

	  if (PREDICT_FALSE (map1->nsh_action == NSH_ACTION_PUSH))
	    {
	      /* After processing, md2's length may be varied */
	      encap_hdr_len1 = nsh_entry1->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b1, -(word) encap_hdr_len1);
	      hdr1 = vlib_buffer_get_current (b1);
	      clib_memcpy_fast (hdr1, encap_hdr1, (word) encap_hdr_len1);

	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (nsh_entry1->nsh_base.md_type == 2))
		{
		  nsh_md2_encap (b1, hdr1, nsh_entry1);
		}

	    }

	trace1:
	  b1->error = error1 ? node->errors[error1] : 0;

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      nsh_input_trace_t *tr =
		vlib_add_trace (vm, node, b1, sizeof (*tr));
	      clib_memcpy_fast (&(tr->trace_data), hdr1,
				((hdr1->length & NSH_LEN_MASK) * 4));
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);

	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = 0;
	  vlib_buffer_t *b0 = NULL;
	  u32 next0 = NSH_NODE_NEXT_DROP;
	  uword *entry0;
	  nsh_base_header_t *hdr0 = 0;
	  u32 header_len0 = 0;
	  u32 nsp_nsi0;
	  u32 ttl0;
	  u32 error0;
	  nsh_map_t *map0 = 0;
	  nsh_entry_t *nsh_entry0 = 0;
	  nsh_base_header_t *encap_hdr0 = 0;
	  u32 encap_hdr_len0 = 0;
	  nsh_proxy_session_by_key_t key0;
	  uword *p0;
	  nsh_proxy_session_t *proxy0 = 0;
	  u32 sw_if_index0 = 0;
	  ethernet_header_t placeholder_eth0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  error0 = 0;

	  b0 = vlib_get_buffer (vm, bi0);
	  hdr0 = vlib_buffer_get_current (b0);

	  if (node_type == NSH_INPUT_TYPE)
	    {
	      nsp_nsi0 = hdr0->nsp_nsi;
	      header_len0 = (hdr0->length & NSH_LEN_MASK) * 4;
	      ttl0 = (hdr0->ver_o_c & NSH_TTL_H4_MASK) << 2 |
		(hdr0->length & NSH_TTL_L2_MASK) >> 6;
	      ttl0 = ttl0 - 1;
	      if (PREDICT_FALSE (ttl0 == 0))
		{
		  error0 = NSH_NODE_ERROR_INVALID_TTL;
		  goto trace00;
		}
	    }
	  else if (node_type == NSH_CLASSIFIER_TYPE)
	    {
	      nsp_nsi0 =
		clib_host_to_net_u32 (vnet_buffer (b0)->
				      l2_classify.opaque_index);
	    }
	  else if (node_type == NSH_AWARE_VNF_PROXY_TYPE)
	    {
	      /* Push placeholder Eth header */
	      char placeholder_dst_address[6] =
		{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	      char placeholder_src_address[6] =
		{ 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc };
	      clib_memcpy_fast (placeholder_eth0.dst_address,
				placeholder_dst_address, 6);
	      clib_memcpy_fast (placeholder_eth0.src_address,
				placeholder_src_address, 6);
	      placeholder_eth0.type = 0x0800;
	      vlib_buffer_advance (b0, -(word) sizeof (ethernet_header_t));
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy_fast (hdr0, &placeholder_eth0,
				(word) sizeof (ethernet_header_t));

	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      nsp_nsi0 = nm->tunnel_index_by_sw_if_index[sw_if_index0];
	    }
	  else
	    {
	      clib_memset (&key0, 0, sizeof (key0));
	      key0.transport_type = NSH_NODE_NEXT_ENCAP_VXLAN4;
	      key0.transport_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	      p0 = hash_get_mem (nm->nsh_proxy_session_by_key, &key0);
	      if (PREDICT_FALSE (p0 == 0))
		{
		  error0 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace00;
		}

	      proxy0 = pool_elt_at_index (nm->nsh_proxy_sessions, p0[0]);
	      if (PREDICT_FALSE (proxy0 == 0))
		{
		  error0 = NSH_NODE_ERROR_NO_PROXY;
		  goto trace00;
		}
	      nsp_nsi0 = proxy0->nsp_nsi;
	    }

	  entry0 = hash_get_mem (nm->nsh_mapping_by_key, &nsp_nsi0);

	  if (PREDICT_FALSE (entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace00;
	    }

	  /* Entry should point to a mapping ... */
	  map0 = pool_elt_at_index (nm->nsh_mappings, entry0[0]);

	  if (PREDICT_FALSE (map0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace00;
	    }

	  /* set up things for next node to transmit ie which node to handle it and where */
	  next0 = map0->next_node;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = map0->sw_if_index;
	  vnet_buffer (b0)->ip.adj_index = map0->adj_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = map0->nsh_sw_if;

	  if (PREDICT_FALSE (map0->nsh_action == NSH_ACTION_POP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr0->md_type == 2))
		{
		  nsh_md2_decap (b0, hdr0, &header_len0, &next0,
				 NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next0 == NSH_NODE_NEXT_DROP))
		    {
		      error0 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace00;
		    }
		  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
		    map0->rx_sw_if_index;
		}

	      /* Pop NSH header */
	      vlib_buffer_advance (b0, (word) header_len0);
	      goto trace00;
	    }

	  entry0 = hash_get_mem (nm->nsh_entry_by_key, &map0->mapped_nsp_nsi);
	  if (PREDICT_FALSE (entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_ENTRY;
	      goto trace00;
	    }

	  nsh_entry0 =
	    (nsh_entry_t *) pool_elt_at_index (nm->nsh_entries, entry0[0]);
	  encap_hdr0 = (nsh_base_header_t *) (nsh_entry0->rewrite);
	  /* rewrite_size should equal to (encap_hdr0->length * 4) */
	  encap_hdr_len0 = nsh_entry0->rewrite_size;

	  if (PREDICT_TRUE (map0->nsh_action == NSH_ACTION_SWAP))
	    {
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (hdr0->md_type == 2))
		{
		  nsh_md2_swap (b0, hdr0, header_len0, nsh_entry0,
				&next0, NSH_NODE_NEXT_DROP);
		  if (PREDICT_FALSE (next0 == NSH_NODE_NEXT_DROP))
		    {
		      error0 = NSH_NODE_ERROR_INVALID_OPTIONS;
		      goto trace00;
		    }
		}

	      /* Pop old NSH header */
	      vlib_buffer_advance (b0, (word) header_len0);

	      /* After processing, md2's length may be varied */
	      encap_hdr_len0 = nsh_entry0->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b0, -(word) encap_hdr_len0);
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy_fast (hdr0, encap_hdr0, (word) encap_hdr_len0);

	      goto trace00;
	    }

	  if (PREDICT_TRUE (map0->nsh_action == NSH_ACTION_PUSH))
	    {
	      /* After processing, md2's length may be varied */
	      encap_hdr_len0 = nsh_entry0->rewrite_size;
	      /* Push new NSH header */
	      vlib_buffer_advance (b0, -(word) encap_hdr_len0);
	      hdr0 = vlib_buffer_get_current (b0);
	      clib_memcpy_fast (hdr0, encap_hdr0, (word) encap_hdr_len0);
	      /* Manipulate MD2 */
	      if (PREDICT_FALSE (nsh_entry0->nsh_base.md_type == 2))
		{
		  nsh_md2_encap (b0, hdr0, nsh_entry0);
		}

	    }

	trace00:b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      nsh_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy_fast (&(tr->trace_data[0]), hdr0,
				((hdr0->length & NSH_LEN_MASK) * 4));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

    }

  return from_frame->n_vectors;
}

/**
 * @brief Graph processing dispatch function for NSH Input
 *
 * @node nsh_input
 * @param *vm
 * @param *node
 * @param *from_frame
 *
 * @return from_frame->n_vectors
 *
 */
VLIB_NODE_FN (nsh_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * from_frame)
{
  return nsh_input_map (vm, node, from_frame, NSH_INPUT_TYPE);
}

/**
 * @brief Graph processing dispatch function for NSH-Proxy
 *
 * @node nsh_proxy
 * @param *vm
 * @param *node
 * @param *from_frame
 *
 * @return from_frame->n_vectors
 *
 */
VLIB_NODE_FN (nsh_proxy_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * from_frame)
{
  return nsh_input_map (vm, node, from_frame, NSH_PROXY_TYPE);
}

/**
 * @brief Graph processing dispatch function for NSH Classifier
 *
 * @node nsh_classifier
 * @param *vm
 * @param *node
 * @param *from_frame
 *
 * @return from_frame->n_vectors
 *
 */
VLIB_NODE_FN (nsh_classifier_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * from_frame)
{
  return nsh_input_map (vm, node, from_frame, NSH_CLASSIFIER_TYPE);
}

/**
 * @brief Graph processing dispatch function for NSH-AWARE-VNF-PROXY
 *
 * @node nsh_aware_vnf_proxy
 * @param *vm
 * @param *node
 * @param *from_frame
 *
 * @return from_frame->n_vectors
 *
 */
VLIB_NODE_FN (nsh_aware_vnf_proxy_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  return nsh_input_map (vm, node, from_frame, NSH_AWARE_VNF_PROXY_TYPE);
}

static char *nsh_node_error_strings[] = {
#define _(sym,string) string,
  foreach_nsh_node_error
#undef _
};

/* *INDENT-OFF* */

/* register nsh-input node */
VLIB_REGISTER_NODE (nsh_input_node) = {
  .name = "nsh-input",
  .vector_size = sizeof (u32),
  .format_trace = format_nsh_node_map_trace,
  .format_buffer = format_nsh_header,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nsh_node_error_strings),
  .error_strings = nsh_node_error_strings,
  .n_next_nodes = NSH_NODE_N_NEXT,
  .next_nodes = {
#define _(s,n) [NSH_NODE_NEXT_##s] = n,
    foreach_nsh_node_next
#undef _
  },
};

/* register nsh-proxy node */
VLIB_REGISTER_NODE (nsh_proxy_node) =
{
  .name = "nsh-proxy",
  .vector_size = sizeof (u32),
  .format_trace = format_nsh_node_map_trace,
  .format_buffer = format_nsh_header,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nsh_node_error_strings),
  .error_strings = nsh_node_error_strings,
  .n_next_nodes = NSH_NODE_N_NEXT,
  .next_nodes = {
#define _(s,n) [NSH_NODE_NEXT_##s] = n,
    foreach_nsh_node_next
#undef _
  },
};

/* register nsh-classifier node */
VLIB_REGISTER_NODE (nsh_classifier_node) =
{
  .name = "nsh-classifier",
  .vector_size = sizeof (u32),
  .format_trace = format_nsh_node_map_trace,
  .format_buffer = format_nsh_header,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nsh_node_error_strings),
  .error_strings = nsh_node_error_strings,
  .n_next_nodes = NSH_NODE_N_NEXT,
  .next_nodes = {
#define _(s,n) [NSH_NODE_NEXT_##s] = n,
    foreach_nsh_node_next
#undef _
  },
};

/* register nsh-aware-vnf-proxy node */
VLIB_REGISTER_NODE (nsh_aware_vnf_proxy_node) =
{
  .name = "nsh-aware-vnf-proxy",
  .vector_size = sizeof (u32),
  .format_trace = format_nsh_node_map_trace,
  .format_buffer = format_nsh_header,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nsh_node_error_strings),
  .error_strings = nsh_node_error_strings,
  .n_next_nodes = NSH_NODE_N_NEXT,
  .next_nodes = {
#define _(s,n) [NSH_NODE_NEXT_##s] = n,
    foreach_nsh_node_next
#undef _
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
