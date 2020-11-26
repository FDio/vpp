/*
 * nsh_pop.c - nsh POP only processing
 *
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vnet/gre/packet.h>
#include <vnet/vxlan/vxlan.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/l2/l2_classify.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

extern nsh_option_map_t * nsh_md2_lookup_option (u16 class, u8 type);

extern u8 * format_nsh_header (u8 * s, va_list * args);
extern u8 * format_nsh_node_map_trace (u8 * s, va_list * args);
extern u8 * format_nsh_pop_header (u8 * s, va_list * args);
extern u8 * format_nsh_pop_node_map_trace (u8 * s, va_list * args);

static uword
nsh_pop_inline (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  nsh_main_t * nm = &nsh_main;

  from = vlib_frame_vector_args(from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t * b0, *b1;
	  u32 next0 = NSH_NODE_NEXT_DROP, next1 = NSH_NODE_NEXT_DROP;
	  uword * entry0, *entry1;
	  nsh_base_header_t * hdr0 = 0, *hdr1 = 0;
	  u32 header_len0 = 0, header_len1 = 0;
	  u32 nsp_nsi0, nsp_nsi1;
	  u32 error0, error1;
	  nsh_map_t * map0 = 0, *map1 = 0;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, *p3;

	    p2 = vlib_get_buffer(vm, from[2]);
	    p3 = vlib_get_buffer(vm, from[3]);

	    vlib_prefetch_buffer_header(p2, LOAD);
	    vlib_prefetch_buffer_header(p3, LOAD);

	    CLIB_PREFETCH(p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH(p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
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

	  b0 = vlib_get_buffer(vm, bi0);
	  b1 = vlib_get_buffer(vm, bi1);
	  hdr0 = vlib_buffer_get_current(b0);
          nsp_nsi0 = hdr0->nsp_nsi;
          header_len0 = hdr0->length * 4;

          hdr1 = vlib_buffer_get_current(b1);
	  nsp_nsi1 = hdr1->nsp_nsi;
	  header_len1 = hdr1->length * 4;

	  /* Process packet 0 */
	  entry0 = hash_get_mem(nm->nsh_mapping_by_key, &nsp_nsi0);
	  if (PREDICT_FALSE(entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace0;
	    }

	  /* Entry should point to a mapping ...*/
	  map0 = pool_elt_at_index(nm->nsh_mappings, entry0[0]);
	  if (PREDICT_FALSE(map0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace0;
	    }

	  /* set up things for next node to transmit ie which node to handle it and where */
	  next0 = map0->next_node;
	  //vnet_buffer(b0)->sw_if_index[VLIB_TX] = map0->sw_if_index;

	  if(PREDICT_FALSE(map0->nsh_action == NSH_ACTION_POP))
	    {
	      /* Manipulate MD2 */
              if(PREDICT_FALSE(hdr0->md_type == 2))
        	{
        	  if (PREDICT_FALSE(next0 == NSH_NODE_NEXT_DROP))
        	    {
        	      error0 = NSH_NODE_ERROR_INVALID_OPTIONS;
        	      goto trace0;
        	    }
	          //vnet_buffer(b0)->sw_if_index[VLIB_RX] = map0->sw_if_index;
        	}

              /* Pop NSH header */
	      vlib_buffer_advance(b0, (word)header_len0);
	      goto trace0;
	    }

	  entry0 = hash_get_mem(nm->nsh_entry_by_key, &map0->mapped_nsp_nsi);
	  if (PREDICT_FALSE(entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_ENTRY;
	      goto trace0;
	    }

        trace0: b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              nsh_input_trace_t *tr = vlib_add_trace(vm, node, b0, sizeof(*tr));
              clib_memcpy_fast ( &(tr->trace_data), hdr0, (hdr0->length*4) );
            }

	  /* Process packet 1 */
	  entry1 = hash_get_mem(nm->nsh_mapping_by_key, &nsp_nsi1);
	  if (PREDICT_FALSE(entry1 == 0))
	    {
	      error1 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace1;
	    }

	  /* Entry should point to a mapping ...*/
	  map1 = pool_elt_at_index(nm->nsh_mappings, entry1[0]);
	  if (PREDICT_FALSE(map1 == 0))
	    {
	      error1 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace1;
	    }

	  /* set up things for next node to transmit ie which node to handle it and where */
	  next1 = map1->next_node;
	  //vnet_buffer(b1)->sw_if_index[VLIB_TX] = map1->sw_if_index;

	  if(PREDICT_FALSE(map1->nsh_action == NSH_ACTION_POP))
	    {
	      /* Manipulate MD2 */
              if(PREDICT_FALSE(hdr1->md_type == 2))
        	{
        	  if (PREDICT_FALSE(next1 == NSH_NODE_NEXT_DROP))
        	    {
        	      error1 = NSH_NODE_ERROR_INVALID_OPTIONS;
        	      goto trace1;
        	    }
	          //vnet_buffer(b1)->sw_if_index[VLIB_RX] = map1->sw_if_index;
        	}

              /* Pop NSH header */
	      vlib_buffer_advance(b1, (word)header_len1);
	      goto trace1;
	    }

	  entry1 = hash_get_mem(nm->nsh_entry_by_key, &map1->mapped_nsp_nsi);
	  if (PREDICT_FALSE(entry1 == 0))
	    {
	      error1 = NSH_NODE_ERROR_NO_ENTRY;
	      goto trace1;
	    }


	trace1: b1->error = error1 ? node->errors[error1] : 0;

	  if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      nsh_input_trace_t *tr = vlib_add_trace(vm, node, b1, sizeof(*tr));
	      clib_memcpy_fast ( &(tr->trace_data), hdr1, (hdr1->length*4) );
	    }

	  vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
					  n_left_to_next, bi0, bi1, next0, next1);

	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = 0;
	  vlib_buffer_t * b0 = NULL;
	  u32 next0 = NSH_NODE_NEXT_DROP;
	  uword * entry0;
	  nsh_base_header_t * hdr0 = 0;
	  u32 header_len0 = 0;
	  u32 nsp_nsi0;
	  u32 error0;
	  nsh_map_t * map0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  error0 = 0;

	  b0 = vlib_get_buffer(vm, bi0);
	  hdr0 = vlib_buffer_get_current(b0);

          nsp_nsi0 = hdr0->nsp_nsi;
          header_len0 = hdr0->length * 4;

	  entry0 = hash_get_mem(nm->nsh_mapping_by_key, &nsp_nsi0);

	  if (PREDICT_FALSE(entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace00;
	    }

	  /* Entry should point to a mapping ...*/
	  map0 = pool_elt_at_index(nm->nsh_mappings, entry0[0]);

	  if (PREDICT_FALSE(map0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_MAPPING;
	      goto trace00;
	    }

	  /* set up things for next node to transmit ie which node to handle it and where */
	  next0 = map0->next_node;
	  //vnet_buffer(b0)->sw_if_index[VLIB_TX] = map0->sw_if_index;

	  if(PREDICT_FALSE(map0->nsh_action == NSH_ACTION_POP))
	    {
	      /* Manipulate MD2 */
              if(PREDICT_FALSE(hdr0->md_type == 2))
        	{
        	  if (PREDICT_FALSE(next0 == NSH_NODE_NEXT_DROP))
        	    {
        	      error0 = NSH_NODE_ERROR_INVALID_OPTIONS;
        	      goto trace00;
        	    }
	          //vnet_buffer(b0)->sw_if_index[VLIB_RX] = map0->sw_if_index;
        	}

              /* Pop NSH header */
	      vlib_buffer_advance(b0, (word)header_len0);
	      goto trace00;
	    }

	  entry0 = hash_get_mem(nm->nsh_entry_by_key, &map0->mapped_nsp_nsi);
	  if (PREDICT_FALSE(entry0 == 0))
	    {
	      error0 = NSH_NODE_ERROR_NO_ENTRY;
	      goto trace00;
	    }

	  trace00: b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      nsh_input_trace_t *tr = vlib_add_trace(vm, node, b0, sizeof(*tr));
	      clib_memcpy_fast ( &(tr->trace_data[0]), hdr0, (hdr0->length*4) );
	    }

	  vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
					  n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame(vm, node, next_index, n_left_to_next);

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
VLIB_NODE_FN (nsh_pop_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
  return nsh_pop_inline (vm, node, from_frame);
}

static char * nsh_pop_node_error_strings[] = {
#define _(sym,string) string,
  foreach_nsh_node_error
#undef _
};

/* register nsh-input node */
VLIB_REGISTER_NODE (nsh_pop_node) = {
  .name = "nsh-pop",
  .vector_size = sizeof (u32),
  .format_trace = format_nsh_pop_node_map_trace,
  .format_buffer = format_nsh_pop_header,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nsh_pop_node_error_strings),
  .error_strings = nsh_pop_node_error_strings,

  .n_next_nodes = NSH_NODE_N_NEXT,

  .next_nodes = {
#define _(s,n) [NSH_NODE_NEXT_##s] = n,
    foreach_nsh_node_next
#undef _
  },
};

