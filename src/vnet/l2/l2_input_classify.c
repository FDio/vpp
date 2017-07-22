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
/*
 * l2_classify.c
 */

#include <vnet/l2/l2_classify.h>
#include <vnet/api_errno.h>

/**
 * @file
 * @brief L2 input classifier.
 *
 * @sa @ref vnet/vnet/classify/vnet_classify.c
 * @sa @ref vnet/vnet/classify/vnet_classify.h
 */

/**
 * @brief l2_input_classifier packet trace record.
 */
typedef struct
{
  /** interface handle for the ith packet */
  u32 sw_if_index;
  /** graph arc index selected for this packet */
  u32 next_index;
  /** classifier table which provided the final result */
  u32 table_index;
  /** offset in classifier heap of the corresponding session */
  u32 session_offset;
} l2_input_classify_trace_t;

/**
 * @brief vlib node runtime.
 */
typedef struct
{
  /** use-case independent main object pointer */
  vnet_classify_main_t *vcm;
  /** l2 input classifier main object pointer */
  l2_input_classify_main_t *l2cm;
} l2_input_classify_runtime_t;

/** Packet trace format function. */
static u8 *
format_l2_input_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_input_classify_trace_t *t = va_arg (*args, l2_input_classify_trace_t *);

  s = format (s, "l2-classify: sw_if_index %d, table %d, offset %x, next %d",
	      t->sw_if_index, t->table_index, t->session_offset,
	      t->next_index);
  return s;
}

/** l2 input classifier main data structure. */
l2_input_classify_main_t l2_input_classify_main;

vlib_node_registration_t l2_input_classify_node;

#define foreach_l2_input_classify_error               \
_(MISS, "Classify misses")                      \
_(HIT, "Classify hits")                         \
_(CHAIN_HIT, "Classify hits after chain walk")  \
_(DROP, "L2 Classify Drops")

typedef enum
{
#define _(sym,str) L2_INPUT_CLASSIFY_ERROR_##sym,
  foreach_l2_input_classify_error
#undef _
    L2_INPUT_CLASSIFY_N_ERROR,
} l2_input_classify_error_t;

static char *l2_input_classify_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_input_classify_error
#undef _
};

/**
 * @brief l2 input classifier node.
 * @node l2-input-classify
 *
 * This is the l2 input classifier dispatch node
 *
 * @param vm    vlib_main_t corresponding to the current thread.
 * @param node  vlib_node_runtime_t data for this node.
 * @param frame vlib_frame_t whose contents should be dispatched.
 *
 * @par Graph mechanics: buffer metadata, next index usage
 *
 * @em Uses:
 * - <code>(l2_input_classify_runtime_t *)
 *         rt->classify_table_index_by_sw_if_index</code>
 *	- Head of the per-interface, per-protocol classifier table chain
 * 	  for a specific interface.
 *      - @c ~0 => send pkts to the next feature in the L2 feature chain.
 * - <code>vnet_buffer(b)->sw_if_index[VLIB_RX]</code>
 * 	- Indicates the @c sw_if_index value of the interface that the
 * 	  packet was received on.
 * - <code>vnet_buffer(b0)->l2.feature_bitmap</code>
 * 	- Used to steer packets across l2 features enabled on the interface
 * - <code>(vnet_classify_entry_t) e0->next_index</code>
 *	- Used to steer traffic when the classifier hits on a session
 * - <code>(vnet_classify_entry_t) e0->advance</code>
 *	- Signed quantity applied via <code>vlib_buffer_advance</code>
 * 	  when the classifier hits on a session
 * - <code>(vnet_classify_table_t) t0->miss_next_index</code>
 *	- Used to steer traffic when the classifier misses
 *
 * @em Sets:
 * - <code>vnet_buffer (b0)->l2_classify.table_index</code>
 * 	- Classifier table index of the first classifier table in
 *	the classifier table chain
 * - <code>vnet_buffer (b0)->l2_classify.hash</code>
 * 	- Bounded-index extensible hash corresponding to the
 *	masked fields in the current packet
 * - <code>vnet_buffer (b0)->l2.feature_bitmap</code>
 * 	- Used to steer packets across l2 features enabled on the interface
 * - <code>vnet_buffer (b0)->l2_classify.opaque_index</code>
 * 	- Copied from the classifier session object upon classifier hit
 *
 * @em Counters:
 * - <code>L2_INPUT_CLASSIFY_ERROR_MISS</code> Classifier misses
 * - <code>L2_INPUT_CLASSIFY_ERROR_HIT</code> Classifier hits
 * - <code>L2_INPUT_CLASSIFY_ERROR_CHAIN_HIT</code>
 *   Classifier hits in other than the first table
 */

static uword
l2_input_classify_node_fn (vlib_main_t * vm,
			   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l2_input_classify_next_t next_index;
  l2_input_classify_main_t *cm = &l2_input_classify_main;
  vnet_classify_main_t *vcm = cm->vnet_classify_main;
  l2_input_classify_runtime_t *rt =
    (l2_input_classify_runtime_t *) node->runtime_data;
  u32 hits = 0;
  u32 misses = 0;
  u32 chain_hits = 0;
  f64 now;
  u32 n_next_nodes;

  n_next_nodes = node->n_next_nodes;

  now = vlib_time_now (vm);

  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  /* First pass: compute hash */

  while (n_left_from > 2)
    {
      vlib_buffer_t *b0, *b1;
      u32 bi0, bi1;
      ethernet_header_t *h0, *h1;
      u32 sw_if_index0, sw_if_index1;
      u16 type0, type1;
      int type_index0, type_index1;
      vnet_classify_table_t *t0, *t1;
      u32 table_index0, table_index1;
      u64 hash0, hash1;


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
      h0 = vlib_buffer_get_current (b0);

      bi1 = from[1];
      b1 = vlib_get_buffer (vm, bi1);
      h1 = vlib_buffer_get_current (b1);

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      vnet_buffer (b0)->l2_classify.table_index = ~0;

      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
      vnet_buffer (b1)->l2_classify.table_index = ~0;

      /* Select classifier table based on ethertype */
      type0 = clib_net_to_host_u16 (h0->type);
      type1 = clib_net_to_host_u16 (h1->type);

      type_index0 = (type0 == ETHERNET_TYPE_IP4)
	? L2_INPUT_CLASSIFY_TABLE_IP4 : L2_INPUT_CLASSIFY_TABLE_OTHER;
      type_index0 = (type0 == ETHERNET_TYPE_IP6)
	? L2_INPUT_CLASSIFY_TABLE_IP6 : type_index0;

      type_index1 = (type1 == ETHERNET_TYPE_IP4)
	? L2_INPUT_CLASSIFY_TABLE_IP4 : L2_INPUT_CLASSIFY_TABLE_OTHER;
      type_index1 = (type1 == ETHERNET_TYPE_IP6)
	? L2_INPUT_CLASSIFY_TABLE_IP6 : type_index1;

      vnet_buffer (b0)->l2_classify.table_index =
	table_index0 =
	rt->l2cm->classify_table_index_by_sw_if_index
	[type_index0][sw_if_index0];

      if (table_index0 != ~0)
	{
	  t0 = pool_elt_at_index (vcm->tables, table_index0);

	  vnet_buffer (b0)->l2_classify.hash = hash0 =
	    vnet_classify_hash_packet (t0, (u8 *) h0);
	  vnet_classify_prefetch_bucket (t0, hash0);
	}

      vnet_buffer (b1)->l2_classify.table_index =
	table_index1 =
	rt->l2cm->classify_table_index_by_sw_if_index
	[type_index1][sw_if_index1];

      if (table_index1 != ~0)
	{
	  t1 = pool_elt_at_index (vcm->tables, table_index1);

	  vnet_buffer (b1)->l2_classify.hash = hash1 =
	    vnet_classify_hash_packet (t1, (u8 *) h1);
	  vnet_classify_prefetch_bucket (t1, hash1);
	}

      from += 2;
      n_left_from -= 2;
    }

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0;
      u32 bi0;
      ethernet_header_t *h0;
      u32 sw_if_index0;
      u16 type0;
      u32 type_index0;
      vnet_classify_table_t *t0;
      u32 table_index0;
      u64 hash0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      h0 = vlib_buffer_get_current (b0);

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      vnet_buffer (b0)->l2_classify.table_index = ~0;

      /* Select classifier table based on ethertype */
      type0 = clib_net_to_host_u16 (h0->type);

      type_index0 = (type0 == ETHERNET_TYPE_IP4)
	? L2_INPUT_CLASSIFY_TABLE_IP4 : L2_INPUT_CLASSIFY_TABLE_OTHER;
      type_index0 = (type0 == ETHERNET_TYPE_IP6)
	? L2_INPUT_CLASSIFY_TABLE_IP6 : type_index0;

      vnet_buffer (b0)->l2_classify.table_index =
	table_index0 = rt->l2cm->classify_table_index_by_sw_if_index
	[type_index0][sw_if_index0];

      if (table_index0 != ~0)
	{
	  t0 = pool_elt_at_index (vcm->tables, table_index0);

	  vnet_buffer (b0)->l2_classify.hash = hash0 =
	    vnet_classify_hash_packet (t0, (u8 *) h0);
	  vnet_classify_prefetch_bucket (t0, hash0);
	}
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
	  u32 next0 = ~0;	/* next l2 input feature, please... */
	  ethernet_header_t *h0;
	  u32 table_index0;
	  u64 hash0;
	  vnet_classify_table_t *t0;
	  vnet_classify_entry_t *e0;

	  if (PREDICT_TRUE (n_left_from > 2))
	    {
	      vlib_buffer_t *p2 = vlib_get_buffer (vm, from[2]);
	      u64 phash2;
	      u32 table_index2;
	      vnet_classify_table_t *tp2;

	      /*
	       * Prefetch table entry two ahead. Buffer / data
	       * were prefetched above...
	       */
	      table_index2 = vnet_buffer (p2)->l2_classify.table_index;

	      if (PREDICT_TRUE (table_index2 != ~0))
		{
		  tp2 = pool_elt_at_index (vcm->tables, table_index2);
		  phash2 = vnet_buffer (p2)->l2_classify.hash;
		  vnet_classify_prefetch_entry (tp2, phash2);
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
	  h0 = vlib_buffer_get_current (b0);
	  table_index0 = vnet_buffer (b0)->l2_classify.table_index;
	  e0 = 0;
	  vnet_buffer (b0)->l2_classify.opaque_index = ~0;

	  if (PREDICT_TRUE (table_index0 != ~0))
	    {
	      hash0 = vnet_buffer (b0)->l2_classify.hash;
	      t0 = pool_elt_at_index (vcm->tables, table_index0);

	      e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);
	      if (e0)
		{
		  vnet_buffer (b0)->l2_classify.opaque_index
		    = e0->opaque_index;
		  vlib_buffer_advance (b0, e0->advance);
		  next0 = (e0->next_index < n_next_nodes) ?
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
			  next0 = (t0->miss_next_index < n_next_nodes) ?
			    t0->miss_next_index : next0;
			  misses++;
			  break;
			}

		      hash0 = vnet_classify_hash_packet (t0, (u8 *) h0);
		      e0 =
			vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);
		      if (e0)
			{
			  vnet_buffer (b0)->l2_classify.opaque_index
			    = e0->opaque_index;
			  vlib_buffer_advance (b0, e0->advance);
			  next0 = (e0->next_index < n_next_nodes) ?
			    e0->next_index : next0;
			  hits++;
			  chain_hits++;
			  break;
			}
		    }
		}
	    }

	  if (PREDICT_FALSE (next0 == 0))
	    b0->error = node->errors[L2_INPUT_CLASSIFY_ERROR_DROP];

	  /* Determine the next node and remove ourself from bitmap */
	  if (PREDICT_TRUE (next0 == ~0))
	    next0 = vnet_l2_feature_next (b0, cm->l2_inp_feat_next,
					  L2INPUT_FEAT_INPUT_CLASSIFY);
	  else
	    vnet_buffer (b0)->l2.feature_bitmap &=
	      ~L2INPUT_FEAT_INPUT_CLASSIFY;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_input_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->table_index = table_index0;
	      t->next_index = next0;
	      t->session_offset = e0 ? vnet_classify_get_offset (t0, e0) : 0;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       L2_INPUT_CLASSIFY_ERROR_MISS, misses);
  vlib_node_increment_counter (vm, node->node_index,
			       L2_INPUT_CLASSIFY_ERROR_HIT, hits);
  vlib_node_increment_counter (vm, node->node_index,
			       L2_INPUT_CLASSIFY_ERROR_CHAIN_HIT, chain_hits);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2_input_classify_node) = {
  .function = l2_input_classify_node_fn,
  .name = "l2-input-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_input_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_input_classify_error_strings),
  .error_strings = l2_input_classify_error_strings,

  .runtime_data_bytes = sizeof (l2_input_classify_runtime_t),

  .n_next_nodes = L2_INPUT_CLASSIFY_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [L2_INPUT_CLASSIFY_NEXT_DROP]  = "error-drop",
    [L2_INPUT_CLASSIFY_NEXT_ETHERNET_INPUT] = "ethernet-input-not-l2",
    [L2_INPUT_CLASSIFY_NEXT_IP4_INPUT] = "ip4-input",
    [L2_INPUT_CLASSIFY_NEXT_IP6_INPUT] = "ip6-input",
    [L2_INPUT_CLASSIFY_NEXT_LI] = "li-hit",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (l2_input_classify_node,
			      l2_input_classify_node_fn);

/** l2 input classsifier feature initialization. */
clib_error_t *
l2_input_classify_init (vlib_main_t * vm)
{
  l2_input_classify_main_t *cm = &l2_input_classify_main;
  l2_input_classify_runtime_t *rt;

  rt = vlib_node_get_runtime_data (vm, l2_input_classify_node.index);

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();
  cm->vnet_classify_main = &vnet_classify_main;

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2_input_classify_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       cm->l2_inp_feat_next);
  rt->l2cm = cm;
  rt->vcm = cm->vnet_classify_main;

  return 0;
}

VLIB_INIT_FUNCTION (l2_input_classify_init);

clib_error_t *
l2_input_classify_worker_init (vlib_main_t * vm)
{
  l2_input_classify_main_t *cm = &l2_input_classify_main;
  l2_input_classify_runtime_t *rt;

  rt = vlib_node_get_runtime_data (vm, l2_input_classify_node.index);

  rt->l2cm = cm;
  rt->vcm = cm->vnet_classify_main;

  return 0;
}

VLIB_WORKER_INIT_FUNCTION (l2_input_classify_worker_init);

/** Enable/disable l2 input classification on a specific interface. */
void
vnet_l2_input_classify_enable_disable (u32 sw_if_index, int enable_disable)
{
  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_INPUT_CLASSIFY,
			      (u32) enable_disable);
}

/** @brief Set l2 per-protocol, per-interface input classification tables.
 *
 *  @param sw_if_index  interface handle
 *  @param ip4_table_index  ip4 classification table index, or ~0
 *  @param ip6_table_index  ip6 classification table index, or ~0
 *  @param other_table_index  non-ip4, non-ip6 classification table index,
 *         or ~0
 *  @returns 0 on success, VNET_API_ERROR_NO_SUCH_TABLE, TABLE2, TABLE3
 *  if the indicated (non-~0) table does not exist.
 */

int
vnet_l2_input_classify_set_tables (u32 sw_if_index,
				   u32 ip4_table_index,
				   u32 ip6_table_index, u32 other_table_index)
{
  l2_input_classify_main_t *cm = &l2_input_classify_main;
  vnet_classify_main_t *vcm = cm->vnet_classify_main;

  /* Assume that we've validated sw_if_index in the API layer */

  if (ip4_table_index != ~0 &&
      pool_is_free_index (vcm->tables, ip4_table_index))
    return VNET_API_ERROR_NO_SUCH_TABLE;

  if (ip6_table_index != ~0 &&
      pool_is_free_index (vcm->tables, ip6_table_index))
    return VNET_API_ERROR_NO_SUCH_TABLE2;

  if (other_table_index != ~0 &&
      pool_is_free_index (vcm->tables, other_table_index))
    return VNET_API_ERROR_NO_SUCH_TABLE3;

  vec_validate
    (cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP4],
     sw_if_index);

  vec_validate
    (cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP6],
     sw_if_index);

  vec_validate
    (cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_OTHER],
     sw_if_index);

  cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP4]
    [sw_if_index] = ip4_table_index;

  cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP6]
    [sw_if_index] = ip6_table_index;

  cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_OTHER]
    [sw_if_index] = other_table_index;

  return 0;
}

static clib_error_t *
int_l2_input_classify_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 other_table_index = ~0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "intfc %U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "ip4-table %d", &ip4_table_index))
	;
      else if (unformat (input, "ip6-table %d", &ip6_table_index))
	;
      else if (unformat (input, "other-table %d", &other_table_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface must be specified");


  if (ip4_table_index == ~0 && ip6_table_index == ~0
      && other_table_index == ~0)
    {
      vlib_cli_output (vm, "L2 classification disabled");
      vnet_l2_input_classify_enable_disable (sw_if_index, 0 /* enable */ );
      return 0;
    }

  rv = vnet_l2_input_classify_set_tables (sw_if_index, ip4_table_index,
					  ip6_table_index, other_table_index);
  switch (rv)
    {
    case 0:
      vnet_l2_input_classify_enable_disable (sw_if_index, 1 /* enable */ );
      break;

    default:
      return clib_error_return (0, "vnet_l2_input_classify_set_tables: %d",
				rv);
      break;
    }

  return 0;
}

/*?
 * Configure l2 input classification.
 *
 * @cliexpar
 * @cliexstart{set interface l2 input classify intfc <interface-name> [ip4-table <index>] [ip6-table <index>] [other-table <index>]}
 * @cliexend
 * @todo This is incomplete. This needs a detailed description and a
 * practical example.
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (int_l2_input_classify_cli, static) = {
  .path = "set interface l2 input classify",
  .short_help =
  "set interface l2 input classify intfc <interface-name> [ip4-table <n>]\n"
  "  [ip6-table <n>] [other-table <n>]",
  .function = int_l2_input_classify_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
