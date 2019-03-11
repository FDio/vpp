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
#include <vnet/classify/vnet_classify.h>
#include <vnet/classify/in_out_acl.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 table_index;
  u32 offset;
} ip_in_out_acl_trace_t;

/* packet trace format function */
static u8 *
format_ip_in_out_acl_trace (u8 * s, u32 is_output, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_in_out_acl_trace_t *t = va_arg (*args, ip_in_out_acl_trace_t *);

  s = format (s, "%s: sw_if_index %d, next_index %d, table %d, offset %d",
	      is_output ? "OUTACL" : "INACL",
	      t->sw_if_index, t->next_index, t->table_index, t->offset);
  return s;
}

static u8 *
format_ip_inacl_trace (u8 * s, va_list * args)
{
  return format_ip_in_out_acl_trace (s, 0 /* is_output */ , args);
}

static u8 *
format_ip_outacl_trace (u8 * s, va_list * args)
{
  return format_ip_in_out_acl_trace (s, 1 /* is_output */ , args);
}

extern vlib_node_registration_t ip4_inacl_node;
extern vlib_node_registration_t ip4_outacl_node;
extern vlib_node_registration_t ip6_inacl_node;
extern vlib_node_registration_t ip6_outacl_node;

#define foreach_ip_inacl_error                  \
_(MISS, "input ACL misses")                     \
_(HIT, "input ACL hits")                        \
_(CHAIN_HIT, "input ACL hits after chain walk")

#define foreach_ip_outacl_error                  \
_(MISS, "output ACL misses")                     \
_(HIT, "output ACL hits")                        \
_(CHAIN_HIT, "output ACL hits after chain walk")

typedef enum
{
#define _(sym,str) IP_INACL_ERROR_##sym,
  foreach_ip_inacl_error
#undef _
    IP_INACL_N_ERROR,
} ip_inacl_error_t;

static char *ip_inacl_error_strings[] = {
#define _(sym,string) string,
  foreach_ip_inacl_error
#undef _
};

typedef enum
{
#define _(sym,str) IP_OUTACL_ERROR_##sym,
  foreach_ip_outacl_error
#undef _
    IP_OUTACL_N_ERROR,
} ip_outacl_error_t;

static char *ip_outacl_error_strings[] = {
#define _(sym,string) string,
  foreach_ip_outacl_error
#undef _
};

static inline uword
ip_in_out_acl_inline (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame,
		      int is_ip4, int is_output)
{
  u32 n_left_from, *from, *to_next;
  acl_next_index_t next_index;
  in_out_acl_main_t *am = &in_out_acl_main;
  vnet_classify_main_t *vcm = am->vnet_classify_main;
  f64 now = vlib_time_now (vm);
  u32 hits = 0;
  u32 misses = 0;
  u32 chain_hits = 0;
  in_out_acl_table_id_t tid;
  vlib_node_runtime_t *error_node;
  u32 n_next_nodes;

  n_next_nodes = node->n_next_nodes;

  if (is_ip4)
    {
      tid = IN_OUT_ACL_TABLE_IP4;
      error_node = vlib_node_get_runtime (vm, ip4_input_node.index);
    }
  else
    {
      tid = IN_OUT_ACL_TABLE_IP6;
      error_node = vlib_node_get_runtime (vm, ip6_input_node.index);
    }

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  /* First pass: compute hashes */

  while (n_left_from > 2)
    {
      vlib_buffer_t *b0, *b1;
      u32 bi0, bi1;
      u8 *h0, *h1;
      u32 sw_if_index0, sw_if_index1;
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

      bi1 = from[1];
      b1 = vlib_get_buffer (vm, bi1);

      sw_if_index0 =
	vnet_buffer (b0)->sw_if_index[is_output ? VLIB_TX : VLIB_RX];
      table_index0 =
	am->classify_table_index_by_sw_if_index[is_output][tid][sw_if_index0];

      sw_if_index1 =
	vnet_buffer (b1)->sw_if_index[is_output ? VLIB_TX : VLIB_RX];
      table_index1 =
	am->classify_table_index_by_sw_if_index[is_output][tid][sw_if_index1];

      t0 = pool_elt_at_index (vcm->tables, table_index0);

      t1 = pool_elt_at_index (vcm->tables, table_index1);

      if (t0->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
	h0 = (void *) vlib_buffer_get_current (b0) + t0->current_data_offset;
      else
	h0 = b0->data;

      if (is_output)
	{
	  /* Save the rewrite length, since we are using the l2_classify struct */
	  vnet_buffer (b0)->l2_classify.pad.l2_len =
	    vnet_buffer (b0)->ip.save_rewrite_length;
	  /* advance the match pointer so the matching happens on IP header */
	  h0 += vnet_buffer (b0)->l2_classify.pad.l2_len;
	}

      vnet_buffer (b0)->l2_classify.hash =
	vnet_classify_hash_packet (t0, (u8 *) h0);

      vnet_classify_prefetch_bucket (t0, vnet_buffer (b0)->l2_classify.hash);

      if (t1->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
	h1 = (void *) vlib_buffer_get_current (b1) + t1->current_data_offset;
      else
	h1 = b1->data;

      if (is_output)
	{
	  /* Save the rewrite length, since we are using the l2_classify struct */
	  vnet_buffer (b1)->l2_classify.pad.l2_len =
	    vnet_buffer (b1)->ip.save_rewrite_length;
	  /* advance the match pointer so the matching happens on IP header */
	  h1 += vnet_buffer (b1)->l2_classify.pad.l2_len;
	}

      vnet_buffer (b1)->l2_classify.hash =
	vnet_classify_hash_packet (t1, (u8 *) h1);

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
      u32 sw_if_index0;
      u32 table_index0;
      vnet_classify_table_t *t0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);

      sw_if_index0 =
	vnet_buffer (b0)->sw_if_index[is_output ? VLIB_TX : VLIB_RX];
      table_index0 =
	am->classify_table_index_by_sw_if_index[is_output][tid][sw_if_index0];

      t0 = pool_elt_at_index (vcm->tables, table_index0);

      if (t0->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
	h0 = (void *) vlib_buffer_get_current (b0) + t0->current_data_offset;
      else
	h0 = b0->data;

      if (is_output)
	{
	  /* Save the rewrite length, since we are using the l2_classify struct */
	  vnet_buffer (b0)->l2_classify.pad.l2_len =
	    vnet_buffer (b0)->ip.save_rewrite_length;
	  /* advance the match pointer so the matching happens on IP header */
	  h0 += vnet_buffer (b0)->l2_classify.pad.l2_len;
	}

      vnet_buffer (b0)->l2_classify.hash =
	vnet_classify_hash_packet (t0, (u8 *) h0);

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
	  u32 next0 = ACL_NEXT_INDEX_DENY;
	  u32 table_index0;
	  vnet_classify_table_t *t0;
	  vnet_classify_entry_t *e0;
	  u64 hash0;
	  u8 *h0;
	  u8 error0;

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
	  table_index0 = vnet_buffer (b0)->l2_classify.table_index;
	  e0 = 0;
	  t0 = 0;
	  vnet_get_config_data (am->vnet_config_main[is_output][tid],
				&b0->current_config_index, &next0,
				/* # bytes of config data */ 0);

	  vnet_buffer (b0)->l2_classify.opaque_index = ~0;

	  if (PREDICT_TRUE (table_index0 != ~0))
	    {
	      hash0 = vnet_buffer (b0)->l2_classify.hash;
	      t0 = pool_elt_at_index (vcm->tables, table_index0);

	      if (t0->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
		h0 =
		  (void *) vlib_buffer_get_current (b0) +
		  t0->current_data_offset;
	      else
		h0 = b0->data;

	      /* advance the match pointer so the matching happens on IP header */
	      if (is_output)
		h0 += vnet_buffer (b0)->l2_classify.pad.l2_len;

	      e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);
	      if (e0)
		{
		  vnet_buffer (b0)->l2_classify.opaque_index
		    = e0->opaque_index;
		  vlib_buffer_advance (b0, e0->advance);

		  next0 = (e0->next_index < n_next_nodes) ?
		    e0->next_index : next0;

		  hits++;

		  if (is_ip4)
		    error0 = (next0 == ACL_NEXT_INDEX_DENY) ?
		      (is_output ? IP4_ERROR_OUTACL_SESSION_DENY :
		       IP4_ERROR_INACL_SESSION_DENY) : IP4_ERROR_NONE;
		  else
		    error0 = (next0 == ACL_NEXT_INDEX_DENY) ?
		      (is_output ? IP6_ERROR_OUTACL_SESSION_DENY :
		       IP6_ERROR_INACL_SESSION_DENY) : IP6_ERROR_NONE;
		  b0->error = error_node->errors[error0];

		  if (!is_output)
		    {
		      if (e0->action == CLASSIFY_ACTION_SET_IP4_FIB_INDEX ||
			  e0->action == CLASSIFY_ACTION_SET_IP6_FIB_INDEX)
			vnet_buffer (b0)->sw_if_index[VLIB_TX] = e0->metadata;
		      else if (e0->action == CLASSIFY_ACTION_SET_METADATA)
			vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
			  e0->metadata;
		    }
		}
	      else
		{
		  while (1)
		    {
		      if (PREDICT_TRUE (t0->next_table_index != ~0))
			t0 = pool_elt_at_index (vcm->tables,
						t0->next_table_index);
		      else
			{
			  next0 = (t0->miss_next_index < n_next_nodes) ?
			    t0->miss_next_index : next0;

			  misses++;

			  if (is_ip4)
			    error0 = (next0 == ACL_NEXT_INDEX_DENY) ?
			      (is_output ? IP4_ERROR_OUTACL_TABLE_MISS :
			       IP4_ERROR_INACL_TABLE_MISS) : IP4_ERROR_NONE;
			  else
			    error0 = (next0 == ACL_NEXT_INDEX_DENY) ?
			      (is_output ? IP6_ERROR_OUTACL_TABLE_MISS :
			       IP6_ERROR_INACL_TABLE_MISS) : IP6_ERROR_NONE;
			  b0->error = error_node->errors[error0];
			  break;
			}

		      if (t0->current_data_flag ==
			  CLASSIFY_FLAG_USE_CURR_DATA)
			h0 =
			  (void *) vlib_buffer_get_current (b0) +
			  t0->current_data_offset;
		      else
			h0 = b0->data;

		      /* advance the match pointer so the matching happens on IP header */
		      if (is_output)
			h0 += vnet_buffer (b0)->l2_classify.pad.l2_len;

		      hash0 = vnet_classify_hash_packet (t0, (u8 *) h0);
		      e0 = vnet_classify_find_entry
			(t0, (u8 *) h0, hash0, now);
		      if (e0)
			{
			  vnet_buffer (b0)->l2_classify.opaque_index
			    = e0->opaque_index;
			  vlib_buffer_advance (b0, e0->advance);
			  next0 = (e0->next_index < n_next_nodes) ?
			    e0->next_index : next0;
			  hits++;
			  chain_hits++;

			  if (is_ip4)
			    error0 = (next0 == ACL_NEXT_INDEX_DENY) ?
			      (is_output ? IP4_ERROR_OUTACL_SESSION_DENY :
			       IP4_ERROR_INACL_SESSION_DENY) : IP4_ERROR_NONE;
			  else
			    error0 = (next0 == ACL_NEXT_INDEX_DENY) ?
			      (is_output ? IP6_ERROR_OUTACL_SESSION_DENY :
			       IP6_ERROR_INACL_SESSION_DENY) : IP6_ERROR_NONE;
			  b0->error = error_node->errors[error0];

			  if (!is_output)
			    {
			      if (e0->action ==
				  CLASSIFY_ACTION_SET_IP4_FIB_INDEX
				  || e0->action ==
				  CLASSIFY_ACTION_SET_IP6_FIB_INDEX)
				vnet_buffer (b0)->sw_if_index[VLIB_TX] =
				  e0->metadata;
			      else if (e0->action ==
				       CLASSIFY_ACTION_SET_METADATA)
				vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
				  e0->metadata;
			    }
			  break;
			}
		    }
		}
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ip_in_out_acl_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index =
		vnet_buffer (b0)->sw_if_index[is_output ? VLIB_TX : VLIB_RX];
	      t->next_index = next0;
	      t->table_index = t0 ? t0 - vcm->tables : ~0;
	      t->offset = (e0 && t0) ? vnet_classify_get_offset (t0, e0) : ~0;
	    }

	  if ((next0 == ACL_NEXT_INDEX_DENY) && is_output)
	    {
	      /* on output, for the drop node to work properly, go back to ip header */
	      vlib_buffer_advance (b0, vnet_buffer (b0)->l2.l2_len);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       is_output ? IP_OUTACL_ERROR_MISS :
			       IP_INACL_ERROR_MISS, misses);
  vlib_node_increment_counter (vm, node->node_index,
			       is_output ? IP_OUTACL_ERROR_HIT :
			       IP_INACL_ERROR_HIT, hits);
  vlib_node_increment_counter (vm, node->node_index,
			       is_output ? IP_OUTACL_ERROR_CHAIN_HIT :
			       IP_INACL_ERROR_CHAIN_HIT, chain_hits);
  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_inacl_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return ip_in_out_acl_inline (vm, node, frame, 1 /* is_ip4 */ ,
			       0 /* is_output */ );
}

VLIB_NODE_FN (ip4_outacl_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return ip_in_out_acl_inline (vm, node, frame, 1 /* is_ip4 */ ,
			       1 /* is_output */ );
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_inacl_node) = {
  .name = "ip4-inacl",
  .vector_size = sizeof (u32),
  .format_trace = format_ip_inacl_trace,
  .n_errors = ARRAY_LEN(ip_inacl_error_strings),
  .error_strings = ip_inacl_error_strings,

  .n_next_nodes = ACL_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [ACL_NEXT_INDEX_DENY] = "ip4-drop",
  },
};

VLIB_REGISTER_NODE (ip4_outacl_node) = {
  .name = "ip4-outacl",
  .vector_size = sizeof (u32),
  .format_trace = format_ip_outacl_trace,
  .n_errors = ARRAY_LEN(ip_outacl_error_strings),
  .error_strings = ip_outacl_error_strings,

  .n_next_nodes = ACL_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [ACL_NEXT_INDEX_DENY] = "ip4-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (ip6_inacl_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return ip_in_out_acl_inline (vm, node, frame, 0 /* is_ip4 */ ,
			       0 /* is_output */ );
}

VLIB_NODE_FN (ip6_outacl_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return ip_in_out_acl_inline (vm, node, frame, 0 /* is_ip4 */ ,
			       1 /* is_output */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_inacl_node) = {
  .name = "ip6-inacl",
  .vector_size = sizeof (u32),
  .format_trace = format_ip_inacl_trace,
  .n_errors = ARRAY_LEN(ip_inacl_error_strings),
  .error_strings = ip_inacl_error_strings,

  .n_next_nodes = ACL_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [ACL_NEXT_INDEX_DENY] = "ip6-drop",
  },
};

VLIB_REGISTER_NODE (ip6_outacl_node) = {
  .name = "ip6-outacl",
  .vector_size = sizeof (u32),
  .format_trace = format_ip_outacl_trace,
  .n_errors = ARRAY_LEN(ip_outacl_error_strings),
  .error_strings = ip_outacl_error_strings,

  .n_next_nodes = ACL_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [ACL_NEXT_INDEX_DENY] = "ip6-drop",
  },
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
static clib_error_t *
ip_in_out_acl_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip_in_out_acl_init);
#endif /* CLIB_MARCH_VARIANT */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
