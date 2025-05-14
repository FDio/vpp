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
}
ip_in_out_acl_trace_t;

/* packet trace format function */
static u8 *
format_ip_in_out_acl_trace (u8 * s, u32 is_output, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_in_out_acl_trace_t *t = va_arg (*args, ip_in_out_acl_trace_t *);
  const vnet_classify_main_t *vcm = &vnet_classify_main;
  const u32 indent = format_get_indent (s);
  vnet_classify_table_t *table;
  vnet_classify_entry_t *e;

  s =
    format (s, "%s: sw_if_index %d, next_index %d, table_index %d, offset %d",
	    is_output ? "OUTACL" : "INACL", t->sw_if_index, t->next_index,
	    t->table_index, t->offset);

  if (pool_is_free_index (vcm->tables, t->table_index))
    return format (s, "\n%Uno table", format_white_space, indent + 4);

  if (~0 == t->offset)
    return format (s, "\n%Uno match", format_white_space, indent + 4);

  table = vnet_classify_table_get (t->table_index);
  e = vnet_classify_get_entry (table, t->offset);
  return format (s, "\n%U%U", format_white_space, indent + 4,
		 format_classify_entry, table, e);
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
}
ip_inacl_error_t;

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
}
ip_outacl_error_t;

static char *ip_outacl_error_strings[] = {
#define _(sym,string) string,
  foreach_ip_outacl_error
#undef _
};

static_always_inline void
ip_in_out_acl_inline_trace (
  vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
  vlib_buffer_t **b, u16 *next, u32 n_left, u32 *hits__, u32 *misses__,
  u32 *chain_hits__, const vlib_error_t error_none,
  const vlib_error_t error_deny, const vlib_error_t error_miss,
  vnet_classify_table_t *tables, const u32 *table_index_by_sw_if_index,
  u32 *fib_index_by_sw_if_index, vnet_config_main_t *cm,
  const vlib_rx_or_tx_t way, const int is_output, const int do_trace)
{
  f64 now = vlib_time_now (vm);
  u32 hits = 0;
  u32 misses = 0;
  u32 chain_hits = 0;
  u32 n_next_nodes = node->n_next_nodes;
  u8 *h[4];
  u32 sw_if_index[4];
  u32 table_index[4];
  vnet_classify_table_t *t[4] = { 0, 0 };
  u32 hash[4];

  /* calculate hashes for b[0] & b[1] */
  if (n_left >= 2)
    {
      /* ~0 is used as a wildcard to say 'always use sw_if_index 0'
       * aka local0. It is used when we do not care about the sw_if_index, as
       * when punting */
      sw_if_index[2] = ~0 == way ? 0 : vnet_buffer (b[0])->sw_if_index[way];
      sw_if_index[3] = ~0 == way ? 0 : vnet_buffer (b[1])->sw_if_index[way];

      table_index[2] = table_index_by_sw_if_index[sw_if_index[2]];
      table_index[3] = table_index_by_sw_if_index[sw_if_index[3]];

      t[2] = pool_elt_at_index (tables, table_index[2]);
      t[3] = pool_elt_at_index (tables, table_index[3]);

      if (t[2]->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
	h[2] =
	  (void *) vlib_buffer_get_current (b[0]) + t[2]->current_data_offset;
      else
	h[2] = b[0]->data;

      if (t[3]->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
	h[3] =
	  (void *) vlib_buffer_get_current (b[1]) + t[3]->current_data_offset;
      else
	h[3] = b[1]->data;

      if (is_output)
	{
	  /* Save the rewrite length, since we are using the l2_classify struct */
	  vnet_buffer (b[0])->l2.l2_len =
	    vnet_buffer (b[0])->ip.save_rewrite_length;
	  /* advance the match pointer so the matching happens on IP header */
	  h[2] += vnet_buffer (b[0])->l2.l2_len;

	  /* Save the rewrite length, since we are using the l2_classify struct */
	  vnet_buffer (b[1])->l2.l2_len =
	    vnet_buffer (b[1])->ip.save_rewrite_length;
	  /* advance the match pointer so the matching happens on IP header */
	  h[3] += vnet_buffer (b[1])->l2.l2_len;
	}

      hash[2] = vnet_classify_hash_packet_inline (t[2], (u8 *) h[2]);
      hash[3] = vnet_classify_hash_packet_inline (t[3], (u8 *) h[3]);

      vnet_buffer (b[0])->l2_classify.hash = hash[2];
      vnet_buffer (b[1])->l2_classify.hash = hash[3];

      vnet_buffer (b[0])->l2_classify.table_index = table_index[2];
      vnet_buffer (b[1])->l2_classify.table_index = table_index[3];

      vnet_buffer (b[0])->l2_classify.opaque_index = ~0;
      vnet_buffer (b[1])->l2_classify.opaque_index = ~0;

      vnet_classify_prefetch_bucket (t[2],
				     vnet_buffer (b[0])->l2_classify.hash);
      vnet_classify_prefetch_bucket (t[3],
				     vnet_buffer (b[1])->l2_classify.hash);
    }

  while (n_left >= 2)
    {
      vnet_classify_entry_t *e[2] = { 0, 0 };
      u32 _next[2] = { ACL_NEXT_INDEX_DENY, ACL_NEXT_INDEX_DENY };

      h[0] = h[2];
      h[1] = h[3];
      t[0] = t[2];
      t[1] = t[3];

      sw_if_index[0] = sw_if_index[2];
      sw_if_index[1] = sw_if_index[3];

      table_index[0] = table_index[2];
      table_index[1] = table_index[3];

      hash[0] = hash[2];
      hash[1] = hash[3];

      /* prefetch next iteration */
      if (n_left >= 6)
	{
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);

	  clib_prefetch_load (b[4]->data);
	  clib_prefetch_load (b[5]->data);
	}

      /* calculate hashes for b[2] & b[3] */
      if (n_left >= 4)
	{
	  sw_if_index[2] =
	    ~0 == way ? 0 : vnet_buffer (b[2])->sw_if_index[way];
	  sw_if_index[3] =
	    ~0 == way ? 0 : vnet_buffer (b[3])->sw_if_index[way];

	  table_index[2] = table_index_by_sw_if_index[sw_if_index[2]];
	  table_index[3] = table_index_by_sw_if_index[sw_if_index[3]];

	  t[2] = pool_elt_at_index (tables, table_index[2]);
	  t[3] = pool_elt_at_index (tables, table_index[3]);

	  if (t[2]->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
	    h[2] =
	      (void *) vlib_buffer_get_current (b[2]) +
	      t[2]->current_data_offset;
	  else
	    h[2] = b[2]->data;

	  if (t[3]->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
	    h[3] =
	      (void *) vlib_buffer_get_current (b[3]) +
	      t[3]->current_data_offset;
	  else
	    h[3] = b[3]->data;

	  if (is_output)
	    {
	      /* Save the rewrite length, since we are using the l2_classify struct */
	      vnet_buffer (b[2])->l2.l2_len =
		vnet_buffer (b[2])->ip.save_rewrite_length;
	      /* advance the match pointer so the matching happens on IP header */
	      h[2] += vnet_buffer (b[2])->l2.l2_len;

	      /* Save the rewrite length, since we are using the l2_classify struct */
	      vnet_buffer (b[3])->l2.l2_len =
		vnet_buffer (b[3])->ip.save_rewrite_length;
	      /* advance the match pointer so the matching happens on IP header */
	      h[3] += vnet_buffer (b[3])->l2.l2_len;
	    }

	  hash[2] = vnet_classify_hash_packet_inline (t[2], (u8 *) h[2]);
	  hash[3] = vnet_classify_hash_packet_inline (t[3], (u8 *) h[3]);

	  vnet_buffer (b[2])->l2_classify.hash = hash[2];
	  vnet_buffer (b[3])->l2_classify.hash = hash[3];

	  vnet_buffer (b[2])->l2_classify.table_index = table_index[2];
	  vnet_buffer (b[3])->l2_classify.table_index = table_index[3];

	  vnet_buffer (b[2])->l2_classify.opaque_index = ~0;
	  vnet_buffer (b[3])->l2_classify.opaque_index = ~0;

	  vnet_classify_prefetch_bucket (t[2],
					 vnet_buffer (b[2])->
					 l2_classify.hash);
	  vnet_classify_prefetch_bucket (t[3],
					 vnet_buffer (b[3])->
					 l2_classify.hash);
	}

      /* find entry for b[0] & b[1] */
      vnet_get_config_data (cm, &b[0]->current_config_index, &_next[0],
			    /* # bytes of config data */ 0);
      vnet_get_config_data (cm, &b[1]->current_config_index, &_next[1],
			    /* # bytes of config data */ 0);

      if (PREDICT_TRUE (table_index[0] != ~0))
	{
	  e[0] =
	    vnet_classify_find_entry_inline (t[0], (u8 *) h[0], hash[0], now);
	  if (e[0])
	    {
	      vnet_buffer (b[0])->l2_classify.opaque_index
		= e[0]->opaque_index;
	      vlib_buffer_advance (b[0], e[0]->advance);

	      _next[0] = (e[0]->next_index < n_next_nodes) ?
		e[0]->next_index : _next[0];

	      hits++;

	      b[0]->error =
		(_next[0] == ACL_NEXT_INDEX_DENY) ? error_deny : error_none;

	      if (!is_output)
		{
		  if (e[0]->action == CLASSIFY_ACTION_SET_IP4_FIB_INDEX ||
		      e[0]->action == CLASSIFY_ACTION_SET_IP6_FIB_INDEX)
		    vnet_buffer (b[0])->sw_if_index[VLIB_TX] = e[0]->metadata;
		  else if (e[0]->action == CLASSIFY_ACTION_SET_METADATA)
		    {
		      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] =
			e[0]->metadata;
		      /* For source check in case we skip the lookup node */
		      ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index,
						      b[0]);
		    }
		}
	      else
		{
		  if (e[0]->action == CLASSIFY_ACTION_MARK_FLOW)
		    {
		      b[0]->flow_id = e[0]->metadata;
		      b[0]->flags |= VNET_BUFFER_F_TM_QUEUE_VALID;
		    }
		}
	    }
	  else
	    {
	      while (1)
		{
		  table_index[0] = t[0]->next_table_index;
		  if (PREDICT_TRUE (table_index[0] != ~0))
		    t[0] = pool_elt_at_index (tables, table_index[0]);
		  else
		    {
		      _next[0] = (t[0]->miss_next_index < n_next_nodes) ?
			t[0]->miss_next_index : _next[0];

		      misses++;

		      b[0]->error = (_next[0] == ACL_NEXT_INDEX_DENY) ?
				      error_miss :
				      error_none;
		      break;
		    }

		  if (t[0]->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
		    h[0] =
		      (void *) vlib_buffer_get_current (b[0]) +
		      t[0]->current_data_offset;
		  else
		    h[0] = b[0]->data;

		  /* advance the match pointer so the matching happens on IP header */
		  if (is_output)
		    h[0] += vnet_buffer (b[0])->l2.l2_len;

		  hash[0] =
		    vnet_classify_hash_packet_inline (t[0], (u8 *) h[0]);
		  e[0] =
		    vnet_classify_find_entry_inline (t[0], (u8 *) h[0],
						     hash[0], now);
		  if (e[0])
		    {
		      vnet_buffer (b[0])->l2_classify.opaque_index
			= e[0]->opaque_index;
		      vlib_buffer_advance (b[0], e[0]->advance);
		      _next[0] = (e[0]->next_index < n_next_nodes) ?
			e[0]->next_index : _next[0];
		      hits++;
		      chain_hits++;

		      b[0]->error = (_next[0] == ACL_NEXT_INDEX_DENY) ?
				      error_deny :
				      error_none;

		      if (!is_output)
			{
			  if (e[0]->action ==
			      CLASSIFY_ACTION_SET_IP4_FIB_INDEX
			      || e[0]->action ==
			      CLASSIFY_ACTION_SET_IP6_FIB_INDEX)
			    vnet_buffer (b[0])->sw_if_index[VLIB_TX] =
			      e[0]->metadata;
			  else if (e[0]->action ==
				   CLASSIFY_ACTION_SET_METADATA)
			    {
			      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] =
				e[0]->metadata;
			      /* For source check in case we skip the lookup
			       * node */
			      ip_lookup_set_buffer_fib_index (
				fib_index_by_sw_if_index, b[0]);
			    }
			}
		      else
			{
			  if (e[0]->action == CLASSIFY_ACTION_MARK_FLOW)
			    {
			      b[0]->flow_id = e[0]->metadata;
			      b[0]->flags |= VNET_BUFFER_F_TM_QUEUE_VALID;
			    }
			}
		      break;
		    }
		}
	    }
	}

      if (PREDICT_TRUE (table_index[1] != ~0))
	{
	  e[1] =
	    vnet_classify_find_entry_inline (t[1], (u8 *) h[1], hash[1], now);
	  if (e[1])
	    {
	      vnet_buffer (b[1])->l2_classify.opaque_index
		= e[1]->opaque_index;
	      vlib_buffer_advance (b[1], e[1]->advance);

	      _next[1] = (e[1]->next_index < n_next_nodes) ?
		e[1]->next_index : _next[1];

	      hits++;

	      b[1]->error =
		(_next[1] == ACL_NEXT_INDEX_DENY) ? error_deny : error_none;

	      if (!is_output)
		{
		  if (e[1]->action == CLASSIFY_ACTION_SET_IP4_FIB_INDEX ||
		      e[1]->action == CLASSIFY_ACTION_SET_IP6_FIB_INDEX)
		    vnet_buffer (b[1])->sw_if_index[VLIB_TX] = e[1]->metadata;
		  else if (e[1]->action == CLASSIFY_ACTION_SET_METADATA)
		    {
		      vnet_buffer (b[1])->ip.adj_index[VLIB_TX] =
			e[1]->metadata;
		      /* For source check in case we skip the lookup node */
		      ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index,
						      b[1]);
		    }
		}
	      else
		{
		  if (e[1]->action == CLASSIFY_ACTION_MARK_FLOW)
		    {
		      b[1]->flow_id = e[1]->metadata;
		      b[1]->flags |= VNET_BUFFER_F_TM_QUEUE_VALID;
		    }
		}
	    }
	  else
	    {
	      while (1)
		{
		  table_index[1] = t[1]->next_table_index;
		  if (PREDICT_TRUE (table_index[1] != ~0))
		    t[1] = pool_elt_at_index (tables, table_index[1]);
		  else
		    {
		      _next[1] = (t[1]->miss_next_index < n_next_nodes) ?
			t[1]->miss_next_index : _next[1];

		      misses++;

		      b[1]->error = (_next[1] == ACL_NEXT_INDEX_DENY) ?
				      error_miss :
				      error_none;
		      break;
		    }

		  if (t[1]->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
		    h[1] =
		      (void *) vlib_buffer_get_current (b[1]) +
		      t[1]->current_data_offset;
		  else
		    h[1] = b[1]->data;

		  /* advance the match pointer so the matching happens on IP header */
		  if (is_output)
		    h[1] += vnet_buffer (b[1])->l2.l2_len;

		  hash[1] =
		    vnet_classify_hash_packet_inline (t[1], (u8 *) h[1]);
		  e[1] =
		    vnet_classify_find_entry_inline (t[1], (u8 *) h[1],
						     hash[1], now);
		  if (e[1])
		    {
		      vnet_buffer (b[1])->l2_classify.opaque_index
			= e[1]->opaque_index;
		      vlib_buffer_advance (b[1], e[1]->advance);
		      _next[1] = (e[1]->next_index < n_next_nodes) ?
			e[1]->next_index : _next[1];
		      hits++;
		      chain_hits++;

		      b[1]->error = (_next[1] == ACL_NEXT_INDEX_DENY) ?
				      error_deny :
				      error_none;

		      if (!is_output)
			{
			  if (e[1]->action ==
			      CLASSIFY_ACTION_SET_IP4_FIB_INDEX
			      || e[1]->action ==
			      CLASSIFY_ACTION_SET_IP6_FIB_INDEX)
			    vnet_buffer (b[1])->sw_if_index[VLIB_TX] =
			      e[1]->metadata;
			  else if (e[1]->action ==
				   CLASSIFY_ACTION_SET_METADATA)
			    {
			      vnet_buffer (b[1])->ip.adj_index[VLIB_TX] =
				e[1]->metadata;
			      /* For source check in case we skip the lookup
			       * node */
			      ip_lookup_set_buffer_fib_index (
				fib_index_by_sw_if_index, b[1]);
			    }
			}
		      else
			{
			  if (e[1]->action == CLASSIFY_ACTION_MARK_FLOW)
			    {
			      b[1]->flow_id = e[1]->metadata;
			      b[1]->flags |= VNET_BUFFER_F_TM_QUEUE_VALID;
			    }
			}
		      break;
		    }
		}
	    }
	}

      if (do_trace && b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  ip_in_out_acl_trace_t *_t =
	    vlib_add_trace (vm, node, b[0], sizeof (*_t));
	  _t->sw_if_index =
	    ~0 == way ? 0 : vnet_buffer (b[0])->sw_if_index[way];
	  _t->next_index = _next[0];
	  _t->table_index = table_index[0];
	  _t->offset = (e[0]
			&& t[0]) ? vnet_classify_get_offset (t[0], e[0]) : ~0;
	}

      if (do_trace && b[1]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  ip_in_out_acl_trace_t *_t =
	    vlib_add_trace (vm, node, b[1], sizeof (*_t));
	  _t->sw_if_index =
	    ~0 == way ? 0 : vnet_buffer (b[1])->sw_if_index[way];
	  _t->next_index = _next[1];
	  _t->table_index = table_index[1];
	  _t->offset = (e[1]
			&& t[1]) ? vnet_classify_get_offset (t[1], e[1]) : ~0;
	}

      if ((_next[0] == ACL_NEXT_INDEX_DENY) && is_output)
	{
	  /* on output, for the drop node to work properly, go back to ip header */
	  vlib_buffer_advance (b[0], vnet_buffer (b[0])->l2.l2_len);
	}

      if ((_next[1] == ACL_NEXT_INDEX_DENY) && is_output)
	{
	  /* on output, for the drop node to work properly, go back to ip header */
	  vlib_buffer_advance (b[1], vnet_buffer (b[1])->l2.l2_len);
	}

      next[0] = _next[0];
      next[1] = _next[1];

      /* _next */
      next += 2;
      b += 2;
      n_left -= 2;
    }

  while (n_left > 0)
    {
      u8 *h0;
      u32 sw_if_index0;
      u32 table_index0;
      vnet_classify_table_t *t0 = 0;
      vnet_classify_entry_t *e0 = 0;
      u32 next0 = ACL_NEXT_INDEX_DENY;
      u32 hash0;

      sw_if_index0 = ~0 == way ? 0 : vnet_buffer (b[0])->sw_if_index[way];
      table_index0 = table_index_by_sw_if_index[sw_if_index0];

      t0 = pool_elt_at_index (tables, table_index0);

      if (t0->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
	h0 =
	  (void *) vlib_buffer_get_current (b[0]) + t0->current_data_offset;
      else
	h0 = b[0]->data;

      if (is_output)
	{
	  /* Save the rewrite length, since we are using the l2_classify struct */
	  vnet_buffer (b[0])->l2.l2_len =
	    vnet_buffer (b[0])->ip.save_rewrite_length;
	  /* advance the match pointer so the matching happens on IP header */
	  h0 += vnet_buffer (b[0])->l2.l2_len;
	}

      vnet_buffer (b[0])->l2_classify.hash =
	vnet_classify_hash_packet (t0, (u8 *) h0);

      vnet_buffer (b[0])->l2_classify.table_index = table_index0;
      vnet_buffer (b[0])->l2_classify.opaque_index = ~0;

      vnet_get_config_data (cm, &b[0]->current_config_index, &next0,
			    /* # bytes of config data */ 0);

      if (PREDICT_TRUE (table_index0 != ~0))
	{
	  hash0 = vnet_buffer (b[0])->l2_classify.hash;
	  t0 = pool_elt_at_index (tables, table_index0);

	  if (t0->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
	    h0 =
	      (void *) vlib_buffer_get_current (b[0]) +
	      t0->current_data_offset;
	  else
	    h0 = b[0]->data;

	  /* advance the match pointer so the matching happens on IP header */
	  if (is_output)
	    h0 += vnet_buffer (b[0])->l2.l2_len;

	  e0 = vnet_classify_find_entry_inline (t0, (u8 *) h0, hash0, now);
	  if (e0)
	    {
	      vnet_buffer (b[0])->l2_classify.opaque_index = e0->opaque_index;
	      vlib_buffer_advance (b[0], e0->advance);

	      next0 = (e0->next_index < n_next_nodes) ?
		e0->next_index : next0;

	      hits++;

	      b[0]->error =
		(next0 == ACL_NEXT_INDEX_DENY) ? error_deny : error_none;

	      if (!is_output)
		{
		  if (e0->action == CLASSIFY_ACTION_SET_IP4_FIB_INDEX ||
		      e0->action == CLASSIFY_ACTION_SET_IP6_FIB_INDEX)
		    vnet_buffer (b[0])->sw_if_index[VLIB_TX] = e0->metadata;
		  else if (e0->action == CLASSIFY_ACTION_SET_METADATA)
		    {
		      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = e0->metadata;
		      /* For source check in case we skip the lookup node */
		      ip_lookup_set_buffer_fib_index (fib_index_by_sw_if_index,
						      b[0]);
		    }
		}
	      else
		{
		  if (e0->action == CLASSIFY_ACTION_MARK_FLOW)
		    {
		      b[0]->flow_id = e0->metadata;
		      b[0]->flags |= VNET_BUFFER_F_TM_QUEUE_VALID;
		    }
		}
	    }
	  else
	    {
	      while (1)
		{
		  table_index0 = t0->next_table_index;
		  if (PREDICT_TRUE (table_index0 != ~0))
		    t0 = pool_elt_at_index (tables, table_index0);
		  else
		    {
		      next0 = (t0->miss_next_index < n_next_nodes) ?
			t0->miss_next_index : next0;

		      misses++;

		      b[0]->error = (next0 == ACL_NEXT_INDEX_DENY) ?
				      error_miss :
				      error_none;
		      break;
		    }

		  if (t0->current_data_flag == CLASSIFY_FLAG_USE_CURR_DATA)
		    h0 =
		      (void *) vlib_buffer_get_current (b[0]) +
		      t0->current_data_offset;
		  else
		    h0 = b[0]->data;

		  /* advance the match pointer so the matching happens on IP header */
		  if (is_output)
		    h0 += vnet_buffer (b[0])->l2.l2_len;

		  hash0 = vnet_classify_hash_packet_inline (t0, (u8 *) h0);
		  e0 = vnet_classify_find_entry_inline
		    (t0, (u8 *) h0, hash0, now);
		  if (e0)
		    {
		      vnet_buffer (b[0])->l2_classify.opaque_index
			= e0->opaque_index;
		      vlib_buffer_advance (b[0], e0->advance);
		      next0 = (e0->next_index < n_next_nodes) ?
			e0->next_index : next0;
		      hits++;

		      b[0]->error = (next0 == ACL_NEXT_INDEX_DENY) ?
				      error_deny :
				      error_none;

		      if (!is_output)
			{
			  if (e0->action ==
			      CLASSIFY_ACTION_SET_IP4_FIB_INDEX
			      || e0->action ==
			      CLASSIFY_ACTION_SET_IP6_FIB_INDEX)
			    vnet_buffer (b[0])->sw_if_index[VLIB_TX] =
			      e0->metadata;
			  else if (e0->action == CLASSIFY_ACTION_SET_METADATA)
			    {
			      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] =
				e0->metadata;
			      /* For source check in case we skip the lookup
			       * node */
			      ip_lookup_set_buffer_fib_index (
				fib_index_by_sw_if_index, b[0]);
			    }
			}
		      else
			{
			  if (e0->action == CLASSIFY_ACTION_MARK_FLOW)
			    {
			      b[0]->flow_id = e0->metadata;
			      b[0]->flags |= VNET_BUFFER_F_TM_QUEUE_VALID;
			    }
			}
		      break;
		    }
		}
	    }
	}

      if (do_trace && b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  ip_in_out_acl_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index =
	    ~0 == way ? 0 : vnet_buffer (b[0])->sw_if_index[way];
	  t->next_index = next0;
	  t->table_index = table_index0;
	  t->offset = (e0 && t0) ? vnet_classify_get_offset (t0, e0) : ~0;
	}

      if ((next0 == ACL_NEXT_INDEX_DENY) && is_output)
	{
	  /* on output, for the drop node to work properly, go back to ip header */
	  vlib_buffer_advance (b[0], vnet_buffer (b[0])->l2.l2_len);
	}

      next[0] = next0;

      /* next */
      next++;
      b++;
      n_left--;
    }

  *hits__ = hits;
  *misses__ = misses;
  *chain_hits__ = chain_hits;
}

static_always_inline uword
ip_in_out_acl_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, const in_out_acl_table_id_t tid,
		      u32 *fib_index_by_sw_if_index,
		      const vlib_node_registration_t *parent_error_node,
		      const u32 error_none_index, const u32 error_deny_index,
		      const u32 error_miss_index, const vlib_rx_or_tx_t way,
		      const int is_output)
{
  const in_out_acl_main_t *am = &in_out_acl_main;
  vnet_classify_table_t *tables = am->vnet_classify_main->tables;
  u32 *from = vlib_frame_vector_args (frame);
  const u32 *table_index_by_sw_if_index =
    am->classify_table_index_by_sw_if_index[is_output][tid];
  vnet_config_main_t *cm = am->vnet_config_main[is_output][tid];
  const vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, parent_error_node->index);
  const vlib_error_t error_none = error_node->errors[error_none_index];
  const vlib_error_t error_deny = error_node->errors[error_deny_index];
  const vlib_error_t error_miss = error_node->errors[error_miss_index];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  u32 hits, misses, chain_hits;

  vlib_get_buffers (vm, from, bufs, frame->n_vectors);

#define ip_in_out_acl_inline_trace__(do_trace)                                \
  ip_in_out_acl_inline_trace (                                                \
    vm, node, frame, bufs, nexts, frame->n_vectors, &hits, &misses,           \
    &chain_hits, error_deny, error_miss, error_none, tables,                  \
    table_index_by_sw_if_index, fib_index_by_sw_if_index, cm, way, is_output, \
    do_trace)

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    ip_in_out_acl_inline_trace__ (1 /* do_trace */);
  else
    ip_in_out_acl_inline_trace__ (0 /* do_trace */);

  vlib_node_increment_counter (
    vm, node->node_index,
    is_output ? IP_OUTACL_ERROR_MISS : IP_INACL_ERROR_MISS, misses);
  vlib_node_increment_counter (
    vm, node->node_index, is_output ? IP_OUTACL_ERROR_HIT : IP_INACL_ERROR_HIT,
    hits);
  vlib_node_increment_counter (vm, node->node_index,
			       is_output ? IP_OUTACL_ERROR_CHAIN_HIT :
					   IP_INACL_ERROR_CHAIN_HIT,
			       chain_hits);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_inacl_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip_in_out_acl_inline (
    vm, node, frame, IN_OUT_ACL_TABLE_IP4, ip4_main.fib_index_by_sw_if_index,
    &ip4_input_node, IP4_ERROR_NONE, IP4_ERROR_INACL_SESSION_DENY,
    IP4_ERROR_INACL_TABLE_MISS, VLIB_RX, 0 /* is_output */);
}

VLIB_NODE_FN (ip4_punt_acl_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip_in_out_acl_inline (
    vm, node, frame, IN_OUT_ACL_TABLE_IP4_PUNT,
    ip4_main.fib_index_by_sw_if_index, &ip4_input_node, IP4_ERROR_NONE,
    IP4_ERROR_INACL_SESSION_DENY, IP4_ERROR_INACL_TABLE_MISS, ~0 /* way */,
    0 /* is_output */);
}

VLIB_NODE_FN (ip4_outacl_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip_in_out_acl_inline (
    vm, node, frame, IN_OUT_ACL_TABLE_IP4, NULL, &ip4_input_node,
    IP4_ERROR_NONE, IP4_ERROR_INACL_SESSION_DENY, IP4_ERROR_INACL_TABLE_MISS,
    VLIB_TX, 1 /* is_output */);
}

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

VLIB_REGISTER_NODE (ip4_punt_acl_node) = {
  .name = "ip4-punt-acl",
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

VNET_FEATURE_INIT (ip4_punt_acl_feature) = {
  .arc_name = "ip4-punt",
  .node_name = "ip4-punt-acl",
  .runs_after = VNET_FEATURES ("ip4-punt-policer"),
};

VLIB_NODE_FN (ip6_inacl_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return ip_in_out_acl_inline (
    vm, node, frame, IN_OUT_ACL_TABLE_IP6, ip6_main.fib_index_by_sw_if_index,
    &ip6_input_node, IP6_ERROR_NONE, IP6_ERROR_INACL_SESSION_DENY,
    IP6_ERROR_INACL_TABLE_MISS, VLIB_RX, 0 /* is_output */);
}

VLIB_NODE_FN (ip6_punt_acl_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip_in_out_acl_inline (
    vm, node, frame, IN_OUT_ACL_TABLE_IP6_PUNT,
    ip4_main.fib_index_by_sw_if_index, &ip6_input_node, IP6_ERROR_NONE,
    IP6_ERROR_INACL_SESSION_DENY, IP6_ERROR_INACL_TABLE_MISS, ~0 /* way */,
    0 /* is_output */);
}

VLIB_NODE_FN (ip6_outacl_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return ip_in_out_acl_inline (
    vm, node, frame, IN_OUT_ACL_TABLE_IP6, NULL, &ip6_input_node,
    IP6_ERROR_NONE, IP6_ERROR_INACL_SESSION_DENY, IP6_ERROR_INACL_TABLE_MISS,
    VLIB_TX, 1 /* is_output */);
}

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

VLIB_REGISTER_NODE (ip6_punt_acl_node) = {
  .name = "ip6-punt-acl",
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

VNET_FEATURE_INIT (ip6_punt_acl_feature) = {
  .arc_name = "ip6-punt",
  .node_name = "ip6-punt-acl",
  .runs_after = VNET_FEATURES ("ip6-punt-policer"),
};

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
