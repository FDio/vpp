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

#include <stdint.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/policer/policer.h>
#include <vnet/ip/ip.h>
#include <vnet/classify/policer_classify.h>
#include <vnet/classify/vnet_classify.h>

#define IP4_NON_DSCP_BITS 0x03
#define IP4_DSCP_SHIFT    2
#define IP6_NON_DSCP_BITS 0xf03fffff
#define IP6_DSCP_SHIFT    22

/* Dispatch functions meant to be instantiated elsewhere */

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 policer_index;
} vnet_policer_trace_t;

/* packet trace format function */
static u8 *
format_policer_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vnet_policer_trace_t *t = va_arg (*args, vnet_policer_trace_t *);

  s = format (s, "VNET_POLICER: sw_if_index %d policer_index %d next %d",
	      t->sw_if_index, t->policer_index, t->next_index);
  return s;
}

#define foreach_vnet_policer_error              \
_(TRANSMIT, "Packets Transmitted")              \
_(DROP, "Packets Dropped")

typedef enum
{
#define _(sym,str) VNET_POLICER_ERROR_##sym,
  foreach_vnet_policer_error
#undef _
    VNET_POLICER_N_ERROR,
} vnet_policer_error_t;

static char *vnet_policer_error_strings[] = {
#define _(sym,string) string,
  foreach_vnet_policer_error
#undef _
};

static_always_inline void
vnet_policer_mark (vlib_buffer_t * b, u8 dscp)
{
  ethernet_header_t *eh;
  ip4_header_t *ip4h;
  ip6_header_t *ip6h;
  u16 type;

  eh = (ethernet_header_t *) b->data;
  type = clib_net_to_host_u16 (eh->type);

  if (PREDICT_TRUE (type == ETHERNET_TYPE_IP4))
    {
      ip4h = (ip4_header_t *) & (b->data[sizeof (ethernet_header_t)]);;
      ip4h->tos &= IP4_NON_DSCP_BITS;
      ip4h->tos |= dscp << IP4_DSCP_SHIFT;
      ip4h->checksum = ip4_header_checksum (ip4h);
    }
  else
    {
      if (PREDICT_TRUE (type == ETHERNET_TYPE_IP6))
	{
	  ip6h = (ip6_header_t *) & (b->data[sizeof (ethernet_header_t)]);
	  ip6h->ip_version_traffic_class_and_flow_label &=
	    clib_host_to_net_u32 (IP6_NON_DSCP_BITS);
	  ip6h->ip_version_traffic_class_and_flow_label |=
	    clib_host_to_net_u32 (dscp << IP6_DSCP_SHIFT);
	}
    }
}

static_always_inline
  u8 vnet_policer_police (vlib_main_t * vm,
			  vlib_buffer_t * b,
			  u32 policer_index,
			  u64 time_in_policer_periods,
			  policer_result_e packet_color)
{
  u8 act;
  u32 len;
  u32 col;
  policer_read_response_type_st *pol;
  vnet_policer_main_t *pm = &vnet_policer_main;

  len = vlib_buffer_length_in_chain (vm, b);
  pol = &pm->policers[policer_index];
  col = vnet_police_packet (pol, len, packet_color, time_in_policer_periods);
  act = pol->action[col];
  if (PREDICT_TRUE (act == SSE2_QOS_ACTION_MARK_AND_TRANSMIT))
    vnet_policer_mark (b, pol->mark_dscp[col]);

  return act;
}

static inline uword
vnet_policer_inline (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * frame, vnet_policer_index_t which)
{
  u32 n_left_from, *from, *to_next;
  vnet_policer_next_t next_index;
  vnet_policer_main_t *pm = &vnet_policer_main;
  u64 time_in_policer_periods;
  u32 transmitted = 0;

  time_in_policer_periods =
    clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 sw_if_index0, sw_if_index1;
	  u32 pi0 = 0, pi1 = 0;
	  u8 act0, act1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *b2, *b3;

	    b2 = vlib_get_buffer (vm, from[2]);
	    b3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (b2, LOAD);
	    vlib_prefetch_buffer_header (b3, LOAD);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  next0 = VNET_POLICER_NEXT_TRANSMIT;

	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	  next1 = VNET_POLICER_NEXT_TRANSMIT;


	  if (which == VNET_POLICER_INDEX_BY_SW_IF_INDEX)
	    {
	      pi0 = pm->policer_index_by_sw_if_index[sw_if_index0];
	      pi1 = pm->policer_index_by_sw_if_index[sw_if_index1];
	    }

	  if (which == VNET_POLICER_INDEX_BY_OPAQUE)
	    {
	      pi0 = vnet_buffer (b0)->policer.index;
	      pi1 = vnet_buffer (b1)->policer.index;
	    }

	  if (which == VNET_POLICER_INDEX_BY_EITHER)
	    {
	      pi0 = vnet_buffer (b0)->policer.index;
	      pi0 = (pi0 != ~0) ? pi0 :
		pm->policer_index_by_sw_if_index[sw_if_index0];
	      pi1 = vnet_buffer (b1)->policer.index;
	      pi1 = (pi1 != ~0) ? pi1 :
		pm->policer_index_by_sw_if_index[sw_if_index1];
	    }

	  act0 = vnet_policer_police (vm, b0, pi0, time_in_policer_periods,
				      POLICE_CONFORM /* no chaining */ );

	  act1 = vnet_policer_police (vm, b1, pi1, time_in_policer_periods,
				      POLICE_CONFORM /* no chaining */ );

	  if (PREDICT_FALSE (act0 == SSE2_QOS_ACTION_DROP))	/* drop action */
	    {
	      next0 = VNET_POLICER_NEXT_DROP;
	      b0->error = node->errors[VNET_POLICER_ERROR_DROP];
	    }
	  else			/* transmit or mark-and-transmit action */
	    {
	      transmitted++;
	    }

	  if (PREDICT_FALSE (act1 == SSE2_QOS_ACTION_DROP))	/* drop action */
	    {
	      next1 = VNET_POLICER_NEXT_DROP;
	      b1->error = node->errors[VNET_POLICER_ERROR_DROP];
	    }
	  else			/* transmit or mark-and-transmit action */
	    {
	      transmitted++;
	    }


	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  vnet_policer_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  t->next_index = next0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  vnet_policer_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  t->next_index = next1;
		}
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 sw_if_index0;
	  u32 pi0 = 0;
	  u8 act0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  next0 = VNET_POLICER_NEXT_TRANSMIT;

	  if (which == VNET_POLICER_INDEX_BY_SW_IF_INDEX)
	    pi0 = pm->policer_index_by_sw_if_index[sw_if_index0];

	  if (which == VNET_POLICER_INDEX_BY_OPAQUE)
	    pi0 = vnet_buffer (b0)->policer.index;

	  if (which == VNET_POLICER_INDEX_BY_EITHER)
	    {
	      pi0 = vnet_buffer (b0)->policer.index;
	      pi0 = (pi0 != ~0) ? pi0 :
		pm->policer_index_by_sw_if_index[sw_if_index0];
	    }

	  act0 = vnet_policer_police (vm, b0, pi0, time_in_policer_periods,
				      POLICE_CONFORM /* no chaining */ );

	  if (PREDICT_FALSE (act0 == SSE2_QOS_ACTION_DROP))	/* drop action */
	    {
	      next0 = VNET_POLICER_NEXT_DROP;
	      b0->error = node->errors[VNET_POLICER_ERROR_DROP];
	    }
	  else			/* transmit or mark-and-transmit action */
	    {
	      transmitted++;
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      vnet_policer_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->policer_index = pi0;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       VNET_POLICER_ERROR_TRANSMIT, transmitted);
  return frame->n_vectors;
}

uword
vnet_policer_by_sw_if_index (vlib_main_t * vm,
			     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return vnet_policer_inline (vm, node, frame,
			      VNET_POLICER_INDEX_BY_SW_IF_INDEX);
}

uword
vnet_policer_by_opaque (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return vnet_policer_inline (vm, node, frame, VNET_POLICER_INDEX_BY_OPAQUE);
}

uword
vnet_policer_by_either (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return vnet_policer_inline (vm, node, frame, VNET_POLICER_INDEX_BY_EITHER);
}

void
vnet_policer_node_funcs_reference (void)
{
}


#define TEST_CODE 1

#ifdef TEST_CODE

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (policer_by_sw_if_index_node, static) = {
  .function = vnet_policer_by_sw_if_index,
  .name = "policer-by-sw-if-index",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vnet_policer_error_strings),
  .error_strings = vnet_policer_error_strings,

  .n_next_nodes = VNET_POLICER_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [VNET_POLICER_NEXT_TRANSMIT] = "ethernet-input",
    [VNET_POLICER_NEXT_DROP] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (policer_by_sw_if_index_node,
			      vnet_policer_by_sw_if_index);
/* *INDENT-ON* */


int
test_policer_add_del (u32 rx_sw_if_index, u8 * config_name, int is_add)
{
  vnet_policer_main_t *pm = &vnet_policer_main;
  policer_read_response_type_st *template;
  policer_read_response_type_st *policer;
  vnet_hw_interface_t *rxhi;
  uword *p;

  rxhi = vnet_get_sup_hw_interface (pm->vnet_main, rx_sw_if_index);

  /* Make sure caller didn't pass a vlan subif, etc. */
  if (rxhi->sw_if_index != rx_sw_if_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (is_add)
    {

      p = hash_get_mem (pm->policer_config_by_name, config_name);

      if (p == 0)
	return -2;

      template = pool_elt_at_index (pm->policer_templates, p[0]);

      vnet_hw_interface_rx_redirect_to_node
	(pm->vnet_main, rxhi->hw_if_index, policer_by_sw_if_index_node.index);

      pool_get_aligned (pm->policers, policer, CLIB_CACHE_LINE_BYTES);

      policer[0] = template[0];

      vec_validate (pm->policer_index_by_sw_if_index, rx_sw_if_index);
      pm->policer_index_by_sw_if_index[rx_sw_if_index]
	= policer - pm->policers;
    }
  else
    {
      u32 pi;
      vnet_hw_interface_rx_redirect_to_node (pm->vnet_main,
					     rxhi->hw_if_index,
					     ~0 /* disable */ );

      pi = pm->policer_index_by_sw_if_index[rx_sw_if_index];
      pm->policer_index_by_sw_if_index[rx_sw_if_index] = ~0;
      pool_put_index (pm->policers, pi);
    }

  return 0;
}

static clib_error_t *
test_policer_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_policer_main_t *pm = &vnet_policer_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 rx_sw_if_index;
  int rv;
  u8 *config_name = 0;
  int rx_set = 0;
  int is_add = 1;
  int is_show = 0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "intfc %U", unformat_vnet_sw_interface,
		    pm->vnet_main, &rx_sw_if_index))
	rx_set = 1;
      else if (unformat (line_input, "show"))
	is_show = 1;
      else if (unformat (line_input, "policer %s", &config_name))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	break;
    }

  if (rx_set == 0)
    {
      error = clib_error_return (0, "interface not set");
      goto done;
    }

  if (is_show)
    {
      u32 pi = pm->policer_index_by_sw_if_index[rx_sw_if_index];
      policer_read_response_type_st *policer;
      policer = pool_elt_at_index (pm->policers, pi);

      vlib_cli_output (vm, "%U", format_policer_instance, policer);
      goto done;
    }

  if (is_add && config_name == 0)
    {
      error = clib_error_return (0, "policer config name required");
      goto done;
    }

  rv = test_policer_add_del (rx_sw_if_index, config_name, is_add);

  switch (rv)
    {
    case 0:
      break;

    default:
      error = clib_error_return
	(0, "WARNING: vnet_vnet_policer_add_del returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_patch_command, static) = {
    .path = "test policer",
    .short_help =
    "intfc <intfc> policer <policer-config-name> [del]",
    .function = test_policer_command_fn,
};
/* *INDENT-ON* */

#endif /* TEST_CODE */


typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 table_index;
  u32 offset;
  u32 policer_index;
} policer_classify_trace_t;

static u8 *
format_policer_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  policer_classify_trace_t *t = va_arg (*args, policer_classify_trace_t *);

  s = format (s, "POLICER_CLASSIFY: sw_if_index %d next %d table %d offset %d"
	      " policer_index %d",
	      t->sw_if_index, t->next_index, t->table_index, t->offset,
	      t->policer_index);
  return s;
}

#define foreach_policer_classify_error                 \
_(MISS, "Policer classify misses")                     \
_(HIT, "Policer classify hits")                        \
_(CHAIN_HIT, "Polcier classify hits after chain walk") \
_(DROP, "Policer classify action drop")

typedef enum
{
#define _(sym,str) POLICER_CLASSIFY_ERROR_##sym,
  foreach_policer_classify_error
#undef _
    POLICER_CLASSIFY_N_ERROR,
} policer_classify_error_t;

static char *policer_classify_error_strings[] = {
#define _(sym,string) string,
  foreach_policer_classify_error
#undef _
};

static inline uword
policer_classify_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * frame,
			 policer_classify_table_id_t tid)
{
  u32 n_left_from, *from, *to_next;
  policer_classify_next_index_t next_index;
  policer_classify_main_t *pcm = &policer_classify_main;
  vnet_classify_main_t *vcm = pcm->vnet_classify_main;
  f64 now = vlib_time_now (vm);
  u32 hits = 0;
  u32 misses = 0;
  u32 chain_hits = 0;
  u32 drop = 0;
  u32 n_next_nodes;
  u64 time_in_policer_periods;

  time_in_policer_periods =
    clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

  n_next_nodes = node->n_next_nodes;

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

      /* Prefetch next iteration */
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
      h0 = b0->data;

      bi1 = from[1];
      b1 = vlib_get_buffer (vm, bi1);
      h1 = b1->data;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      table_index0 =
	pcm->classify_table_index_by_sw_if_index[tid][sw_if_index0];

      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
      table_index1 =
	pcm->classify_table_index_by_sw_if_index[tid][sw_if_index1];

      t0 = pool_elt_at_index (vcm->tables, table_index0);

      t1 = pool_elt_at_index (vcm->tables, table_index1);

      vnet_buffer (b0)->l2_classify.hash =
	vnet_classify_hash_packet (t0, (u8 *) h0);

      vnet_classify_prefetch_bucket (t0, vnet_buffer (b0)->l2_classify.hash);

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
      h0 = b0->data;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      table_index0 =
	pcm->classify_table_index_by_sw_if_index[tid][sw_if_index0];

      t0 = pool_elt_at_index (vcm->tables, table_index0);
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
	  u32 next0 = POLICER_CLASSIFY_NEXT_INDEX_DROP;
	  u32 table_index0;
	  vnet_classify_table_t *t0;
	  vnet_classify_entry_t *e0;
	  u64 hash0;
	  u8 *h0;
	  u8 act0;

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

	  /* Speculatively enqueue b0 to the current next frame */
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

	  if (tid == POLICER_CLASSIFY_TABLE_L2)
	    {
	      /* Feature bitmap update and determine the next node */
	      next0 = vnet_l2_feature_next (b0, pcm->feat_next_node_index,
					    L2INPUT_FEAT_POLICER_CLAS);
	    }
	  else
	    vnet_get_config_data (pcm->vnet_config_main[tid],
				  &b0->current_config_index, &next0,
				  /* # bytes of config data */ 0);

	  vnet_buffer (b0)->l2_classify.opaque_index = ~0;

	  if (PREDICT_TRUE (table_index0 != ~0))
	    {
	      hash0 = vnet_buffer (b0)->l2_classify.hash;
	      t0 = pool_elt_at_index (vcm->tables, table_index0);
	      e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);

	      if (e0)
		{
		  act0 = vnet_policer_police (vm,
					      b0,
					      e0->next_index,
					      time_in_policer_periods,
					      e0->opaque_index);
		  if (PREDICT_FALSE (act0 == SSE2_QOS_ACTION_DROP))
		    {
		      next0 = POLICER_CLASSIFY_NEXT_INDEX_DROP;
		      b0->error = node->errors[POLICER_CLASSIFY_ERROR_DROP];
		      drop++;
		    }
		  hits++;
		}
	      else
		{
		  while (1)
		    {
		      if (PREDICT_TRUE (t0->next_table_index != ~0))
			{
			  t0 = pool_elt_at_index (vcm->tables,
						  t0->next_table_index);
			}
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
			  act0 = vnet_policer_police (vm,
						      b0,
						      e0->next_index,
						      time_in_policer_periods,
						      e0->opaque_index);
			  if (PREDICT_FALSE (act0 == SSE2_QOS_ACTION_DROP))
			    {
			      next0 = POLICER_CLASSIFY_NEXT_INDEX_DROP;
			      b0->error =
				node->errors[POLICER_CLASSIFY_ERROR_DROP];
			      drop++;
			    }
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
	      policer_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      t->table_index = t0 ? t0 - vcm->tables : ~0;
	      t->offset = (e0 && t0) ? vnet_classify_get_offset (t0, e0) : ~0;
	      t->policer_index = e0 ? e0->next_index : ~0;
	    }

	  /* Verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       POLICER_CLASSIFY_ERROR_MISS, misses);
  vlib_node_increment_counter (vm, node->node_index,
			       POLICER_CLASSIFY_ERROR_HIT, hits);
  vlib_node_increment_counter (vm, node->node_index,
			       POLICER_CLASSIFY_ERROR_CHAIN_HIT, chain_hits);
  vlib_node_increment_counter (vm, node->node_index,
			       POLICER_CLASSIFY_ERROR_DROP, drop);

  return frame->n_vectors;
}

static uword
ip4_policer_classify (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return policer_classify_inline (vm, node, frame,
				  POLICER_CLASSIFY_TABLE_IP4);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_policer_classify_node) = {
  .function = ip4_policer_classify,
  .name = "ip4-policer-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_classify_trace,
  .n_errors = ARRAY_LEN(policer_classify_error_strings),
  .error_strings = policer_classify_error_strings,
  .n_next_nodes = POLICER_CLASSIFY_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [POLICER_CLASSIFY_NEXT_INDEX_DROP] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_policer_classify_node, ip4_policer_classify);
/* *INDENT-ON* */

static uword
ip6_policer_classify (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return policer_classify_inline (vm, node, frame,
				  POLICER_CLASSIFY_TABLE_IP6);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_policer_classify_node) = {
  .function = ip6_policer_classify,
  .name = "ip6-policer-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_classify_trace,
  .n_errors = ARRAY_LEN(policer_classify_error_strings),
  .error_strings = policer_classify_error_strings,
  .n_next_nodes = POLICER_CLASSIFY_NEXT_INDEX_N_NEXT,
  .next_nodes = {
    [POLICER_CLASSIFY_NEXT_INDEX_DROP] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_policer_classify_node, ip6_policer_classify);
/* *INDENT-ON* */

static uword
l2_policer_classify (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return policer_classify_inline (vm, node, frame, POLICER_CLASSIFY_TABLE_L2);
}

VLIB_REGISTER_NODE (l2_policer_classify_node) =
{
  .function = l2_policer_classify,.name = "l2-policer-classify",.vector_size =
    sizeof (u32),.format_trace = format_policer_classify_trace,.n_errors =
    ARRAY_LEN (policer_classify_error_strings),.error_strings =
    policer_classify_error_strings,.n_next_nodes =
    POLICER_CLASSIFY_NEXT_INDEX_N_NEXT,.next_nodes =
  {
  [POLICER_CLASSIFY_NEXT_INDEX_DROP] = "error-drop",}
,};

VLIB_NODE_FUNCTION_MULTIARCH (l2_policer_classify_node, l2_policer_classify);


static clib_error_t *
policer_classify_init (vlib_main_t * vm)
{
  policer_classify_main_t *pcm = &policer_classify_main;

  pcm->vlib_main = vm;
  pcm->vnet_main = vnet_get_main ();
  pcm->vnet_classify_main = &vnet_classify_main;

  /* Initialize L2 feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2_policer_classify_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       pcm->feat_next_node_index);

  return 0;
}

VLIB_INIT_FUNCTION (policer_classify_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
