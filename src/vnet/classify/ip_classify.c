/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>	/* for ethernet_header_t */
#include <vnet/classify/vnet_classify.h>
#include <vnet/dpo/classify_dpo.h>

typedef struct
{
  u32 next_index;
  u32 table_index;
  u32 entry_index;
} ip_classify_trace_t;

/* packet trace format function */
static u8 *
format_ip_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_classify_trace_t *t = va_arg (*args, ip_classify_trace_t *);

  s = format (s, "IP_CLASSIFY: next_index %d, table %d, entry %d",
	      t->next_index, t->table_index, t->entry_index);
  return s;
}

#define foreach_ip_classify_error               \
_(MISS, "Classify misses")                      \
_(HIT, "Classify hits")                         \
_(CHAIN_HIT, "Classify hits after chain walk")

typedef enum
{
#define _(sym,str) IP_CLASSIFY_ERROR_##sym,
  foreach_ip_classify_error
#undef _
    IP_CLASSIFY_N_ERROR,
} ip_classify_error_t;

static char *ip_classify_error_strings[] = {
#define _(sym,string) string,
  foreach_ip_classify_error
#undef _
};

static inline uword
ip_classify_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame, int is_ip4)
{
  u32 n_left_from, *from, *to_next;
  ip_lookup_next_t next_index;
  vnet_classify_main_t *vcm = &vnet_classify_main;
  f64 now = vlib_time_now (vm);
  u32 hits = 0;
  u32 misses = 0;
  u32 chain_hits = 0;
  u32 n_next;

  if (is_ip4)
    {
      n_next = IP4_LOOKUP_N_NEXT;
    }
  else
    {
      n_next = IP6_LOOKUP_N_NEXT;
    }

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  /* First pass: compute hashes */

  while (n_left_from > 2)
    {
      vlib_buffer_t *b0, *b1;
      u32 bi0, bi1;
      u8 *h0, *h1;
      u32 cd_index0, cd_index1;
      classify_dpo_t *cd0, *cd1;
      u32 table_index0, table_index1;
      vnet_classify_table_t *t0, *t1;

      /* prefetch next iteration */
      {
	vlib_buffer_t *p1, *p2;

	p1 = vlib_get_buffer (vm, from[1]);
	p2 = vlib_get_buffer (vm, from[2]);

	vlib_prefetch_buffer_header (p1, STORE);
	CLIB_PREFETCH (p1->data, CLIB_CACHE_LINE_BYTES, STORE);
	vlib_prefetch_buffer_header (p2, STORE);
	CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
      }

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      h0 = vlib_buffer_get_current (b0) - ethernet_buffer_header_size (b0);

      bi1 = from[1];
      b1 = vlib_get_buffer (vm, bi1);
      h1 = vlib_buffer_get_current (b1) - ethernet_buffer_header_size (b1);

      cd_index0 = vnet_buffer (b0)->ip.adj_index;
      cd0 = classify_dpo_get (cd_index0);
      table_index0 = cd0->cd_table_index;

      cd_index1 = vnet_buffer (b1)->ip.adj_index;
      cd1 = classify_dpo_get (cd_index1);
      table_index1 = cd1->cd_table_index;

      t0 = pool_elt_at_index (vcm->tables, table_index0);

      t1 = pool_elt_at_index (vcm->tables, table_index1);

      vnet_buffer (b0)->l2_classify.hash = vnet_classify_hash_packet (t0, h0);

      vnet_classify_prefetch_bucket (t0, vnet_buffer (b0)->l2_classify.hash);

      vnet_buffer (b1)->l2_classify.hash = vnet_classify_hash_packet (t1, h1);

      vnet_classify_prefetch_bucket (t1, vnet_buffer (b1)->l2_classify.hash);

      vnet_buffer (b0)->l2_classify.table_index = table_index0;

      vnet_buffer (b1)->l2_classify.table_index = table_index1;

      from += 2;
      n_left_from -= 2;
    }

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0;
      u32 bi0;
      u8 *h0;
      u32 cd_index0;
      classify_dpo_t *cd0;
      u32 table_index0;
      vnet_classify_table_t *t0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      h0 = vlib_buffer_get_current (b0) - ethernet_buffer_header_size (b0);

      cd_index0 = vnet_buffer (b0)->ip.adj_index;
      cd0 = classify_dpo_get (cd_index0);
      table_index0 = cd0->cd_table_index;

      t0 = pool_elt_at_index (vcm->tables, table_index0);
      vnet_buffer (b0)->l2_classify.hash = vnet_classify_hash_packet (t0, h0);

      vnet_buffer (b0)->l2_classify.table_index = table_index0;
      vnet_classify_prefetch_bucket (t0, vnet_buffer (b0)->l2_classify.hash);

      from++;
      n_left_from--;
    }

  next_index = node->cached_next_index;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Not enough load/store slots to dual loop... */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = IP_LOOKUP_NEXT_DROP;
	  u32 table_index0;
	  vnet_classify_table_t *t0;
	  vnet_classify_entry_t *e0;
	  u64 hash0;
	  u8 *h0;

	  /* Stride 3 seems to work best */
	  if (PREDICT_TRUE (n_left_from > 3))
	    {
	      vlib_buffer_t *p1 = vlib_get_buffer (vm, from[3]);
	      vnet_classify_table_t *tp1;
	      u32 table_index1;
	      u64 phash1;

	      table_index1 = vnet_buffer (p1)->l2_classify.table_index;

	      if (PREDICT_TRUE (table_index1 != ~0))
		{
		  tp1 = pool_elt_at_index (vcm->tables, table_index1);
		  phash1 = vnet_buffer (p1)->l2_classify.hash;
		  vnet_classify_prefetch_entry (tp1, phash1);
		}
	    }

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  h0 = b0->data;
	  table_index0 = vnet_buffer (b0)->l2_classify.table_index;
	  e0 = 0;
	  t0 = 0;
	  vnet_buffer (b0)->l2_classify.opaque_index = ~0;

	  if (PREDICT_TRUE (table_index0 != ~0))
	    {
	      hash0 = vnet_buffer (b0)->l2_classify.hash;
	      t0 = pool_elt_at_index (vcm->tables, table_index0);

	      e0 = vnet_classify_find_entry (t0, h0, hash0, now);
	      if (e0)
		{
		  vnet_buffer (b0)->l2_classify.opaque_index
		    = e0->opaque_index;
		  vlib_buffer_advance (b0, e0->advance);
		  next0 = (e0->next_index < node->n_next_nodes) ?
		    e0->next_index : next0;
		  hits++;
		}
	      else
		{
		  while (1)
		    {
		      if (t0->next_table_index != ~0)
			t0 = pool_elt_at_index (vcm->tables,
						t0->next_table_index);
		      else
			{
			  next0 = (t0->miss_next_index < n_next) ?
			    t0->miss_next_index : next0;
			  misses++;
			  break;
			}

		      hash0 = vnet_classify_hash_packet (t0, h0);
		      e0 = vnet_classify_find_entry (t0, h0, hash0, now);
		      if (e0)
			{
			  vnet_buffer (b0)->l2_classify.opaque_index
			    = e0->opaque_index;
			  vlib_buffer_advance (b0, e0->advance);
			  next0 = (e0->next_index < node->n_next_nodes) ?
			    e0->next_index : next0;
			  hits++;
			  chain_hits++;
			  break;
			}
		    }
		}
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ip_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	      t->table_index = t0 ? t0 - vcm->tables : ~0;
	      t->entry_index = e0 ? e0 - t0->entries : ~0;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       IP_CLASSIFY_ERROR_MISS, misses);
  vlib_node_increment_counter (vm, node->node_index,
			       IP_CLASSIFY_ERROR_HIT, hits);
  vlib_node_increment_counter (vm, node->node_index,
			       IP_CLASSIFY_ERROR_CHAIN_HIT, chain_hits);
  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_classify_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  return ip_classify_inline (vm, node, frame, 1 /* is_ip4 */ );
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_classify_node) = {
  .name = "ip4-classify",
  .vector_size = sizeof (u32),
  .sibling_of = "ip4-lookup",
  .format_trace = format_ip_classify_trace,
  .n_errors = ARRAY_LEN(ip_classify_error_strings),
  .error_strings = ip_classify_error_strings,

  .n_next_nodes = 0,
};
/* *INDENT-ON* */

VLIB_NODE_FN (ip6_classify_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  return ip_classify_inline (vm, node, frame, 0 /* is_ip4 */ );
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_classify_node) = {
  .name = "ip6-classify",
  .vector_size = sizeof (u32),
  .sibling_of = "ip6-lookup",
  .format_trace = format_ip_classify_trace,
  .n_errors = ARRAY_LEN(ip_classify_error_strings),
  .error_strings = ip_classify_error_strings,

  .n_next_nodes = 0,
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
static clib_error_t *
ip_classify_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip_classify_init);
#endif /* CLIB_MARCH_VARIANT */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
