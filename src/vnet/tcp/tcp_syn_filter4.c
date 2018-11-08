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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip.h>
#include <vppinfra/xxhash.h>

typedef struct
{
  f64 next_reset;
  f64 reset_interval;
  u8 *syn_counts;
} syn_filter4_runtime_t;

typedef struct
{
  u32 next_index;
  int not_a_syn;
  u8 filter_value;
} syn_filter4_trace_t;

/* packet trace format function */
static u8 *
format_syn_filter4_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  syn_filter4_trace_t *t = va_arg (*args, syn_filter4_trace_t *);

  s = format (s, "SYN_FILTER4: next index %d, %s",
	      t->next_index, t->not_a_syn ? "not a syn" : "syn");
  if (t->not_a_syn == 0)
    s = format (s, ", filter value %d\n", t->filter_value);
  else
    s = format (s, "\n");
  return s;
}

static vlib_node_registration_t syn_filter4_node;

#define foreach_syn_filter_error                \
_(THROTTLED, "TCP SYN packet throttle drops")   \
_(OK, "TCP SYN packets passed")

typedef enum
{
#define _(sym,str) SYN_FILTER_ERROR_##sym,
  foreach_syn_filter_error
#undef _
    SYN_FILTER_N_ERROR,
} syn_filter_error_t;

static char *syn_filter4_error_strings[] = {
#define _(sym,string) string,
  foreach_syn_filter_error
#undef _
};

typedef enum
{
  SYN_FILTER_NEXT_DROP,
  SYN_FILTER_N_NEXT,
} syn_filter_next_t;

extern vnet_feature_arc_registration_t vnet_feat_arc_ip4_local;

static uword
syn_filter4_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  syn_filter_next_t next_index;
  u32 ok_syn_packets = 0;
  vnet_feature_main_t *fm = &feature_main;
  u8 arc_index = vnet_feat_arc_ip4_local.feature_arc_index;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc_index];
  syn_filter4_runtime_t *rt = (syn_filter4_runtime_t *) node->runtime_data;
  f64 now = vlib_time_now (vm);
  /* Shut up spurious gcc warnings. */
  u8 *c0 = 0, *c1 = 0, *c2 = 0, *c3 = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (now > rt->next_reset)
    {
      memset (rt->syn_counts, 0, vec_len (rt->syn_counts));
      rt->next_reset = now + rt->reset_interval;
    }

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 next0, next1, next2, next3;
	  ip4_header_t *ip0, *ip1, *ip2, *ip3;
	  tcp_header_t *tcp0, *tcp1, *tcp2, *tcp3;
	  u32 not_a_syn0 = 1, not_a_syn1 = 1, not_a_syn2 = 1, not_a_syn3 = 1;
	  u64 hash0, hash1, hash2, hash3;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p4, *p5, *p6, *p7;

	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
	    p6 = vlib_get_buffer (vm, from[6]);
	    p7 = vlib_get_buffer (vm, from[7]);

	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_header (p6, LOAD);
	    vlib_prefetch_buffer_header (p7, LOAD);

	    CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next[2] = bi2 = from[2];
	  to_next[3] = bi3 = from[3];
	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  vnet_get_config_data
	    (&cm->config_main, &b0->current_config_index,
	     &next0, 0 /* sizeof (c0[0]) */ );
	  vnet_get_config_data
	    (&cm->config_main, &b1->current_config_index,
	     &next1, 0 /* sizeof (c0[0]) */ );
	  vnet_get_config_data
	    (&cm->config_main, &b2->current_config_index,
	     &next2, 0 /* sizeof (c0[0]) */ );
	  vnet_get_config_data
	    (&cm->config_main, &b3->current_config_index,
	     &next3, 0 /* sizeof (c0[0]) */ );

	  /* Not TCP? */
	  ip0 = vlib_buffer_get_current (b0);
	  if (ip0->protocol != IP_PROTOCOL_TCP)
	    goto trace00;

	  tcp0 = ip4_next_header (ip0);
	  /*
	   * Not a SYN?
	   * $$$$ hack: the TCP bitfield flags seem not to compile
	   * correct code.
	   */
	  if (PREDICT_TRUE (!(tcp0->flags & 0x2)))
	    goto trace00;

	  not_a_syn0 = 0;
	  hash0 = clib_xxhash ((u64) ip0->src_address.as_u32);
	  c0 = &rt->syn_counts[hash0 & (_vec_len (rt->syn_counts) - 1)];
	  if (PREDICT_FALSE (*c0 >= 0x80))
	    {
	      next0 = SYN_FILTER_NEXT_DROP;
	      b0->error = node->errors[SYN_FILTER_ERROR_THROTTLED];
	      goto trace00;
	    }
	  *c0 += 1;
	  ok_syn_packets++;

	trace00:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      syn_filter4_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->not_a_syn = not_a_syn0;
	      t->next_index = next0;
	      t->filter_value = not_a_syn0 ? 0 : *c0;
	    }

	  /* Not TCP? */
	  ip1 = vlib_buffer_get_current (b1);
	  if (ip1->protocol != IP_PROTOCOL_TCP)
	    goto trace01;

	  tcp1 = ip4_next_header (ip1);
	  /*
	   * Not a SYN?
	   * $$$$ hack: the TCP bitfield flags seem not to compile
	   * correct code.
	   */
	  if (PREDICT_TRUE (!(tcp1->flags & 0x2)))
	    goto trace01;

	  not_a_syn1 = 0;
	  hash1 = clib_xxhash ((u64) ip1->src_address.as_u32);
	  c1 = &rt->syn_counts[hash1 & (_vec_len (rt->syn_counts) - 1)];
	  if (PREDICT_FALSE (*c1 >= 0x80))
	    {
	      next1 = SYN_FILTER_NEXT_DROP;
	      b1->error = node->errors[SYN_FILTER_ERROR_THROTTLED];
	      goto trace01;
	    }
	  *c1 += 1;
	  ok_syn_packets++;

	trace01:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      syn_filter4_trace_t *t =
		vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->not_a_syn = not_a_syn1;
	      t->next_index = next1;
	      t->filter_value = not_a_syn1 ? 0 : *c1;
	    }

	  /* Not TCP? */
	  ip2 = vlib_buffer_get_current (b2);
	  if (ip2->protocol != IP_PROTOCOL_TCP)
	    goto trace02;

	  tcp2 = ip4_next_header (ip2);
	  /*
	   * Not a SYN?
	   * $$$$ hack: the TCP bitfield flags seem not to compile
	   * correct code.
	   */
	  if (PREDICT_TRUE (!(tcp2->flags & 0x2)))
	    goto trace02;

	  not_a_syn2 = 0;
	  hash2 = clib_xxhash ((u64) ip2->src_address.as_u32);
	  c2 = &rt->syn_counts[hash2 & (_vec_len (rt->syn_counts) - 1)];
	  if (PREDICT_FALSE (*c2 >= 0x80))
	    {
	      next2 = SYN_FILTER_NEXT_DROP;
	      b2->error = node->errors[SYN_FILTER_ERROR_THROTTLED];
	      goto trace02;
	    }
	  *c2 += 1;
	  ok_syn_packets++;

	trace02:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b2->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      syn_filter4_trace_t *t =
		vlib_add_trace (vm, node, b2, sizeof (*t));
	      t->not_a_syn = not_a_syn2;
	      t->next_index = next2;
	      t->filter_value = not_a_syn2 ? 0 : *c2;
	    }

	  /* Not TCP? */
	  ip3 = vlib_buffer_get_current (b3);
	  if (ip3->protocol != IP_PROTOCOL_TCP)
	    goto trace03;

	  tcp3 = ip4_next_header (ip3);
	  /*
	   * Not a SYN?
	   * $$$$ hack: the TCP bitfield flags seem not to compile
	   * correct code.
	   */
	  if (PREDICT_TRUE (!(tcp3->flags & 0x2)))
	    goto trace03;

	  not_a_syn3 = 0;
	  hash3 = clib_xxhash ((u64) ip3->src_address.as_u32);
	  c3 = &rt->syn_counts[hash3 & (_vec_len (rt->syn_counts) - 1)];
	  if (PREDICT_FALSE (*c3 >= 0x80))
	    {
	      next3 = SYN_FILTER_NEXT_DROP;
	      b3->error = node->errors[SYN_FILTER_ERROR_THROTTLED];
	      goto trace03;
	    }
	  *c3 += 1;
	  ok_syn_packets++;

	trace03:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b3->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      syn_filter4_trace_t *t =
		vlib_add_trace (vm, node, b3, sizeof (*t));
	      t->not_a_syn = not_a_syn3;
	      t->next_index = next3;
	      t->filter_value = not_a_syn3 ? 0 : *c3;
	    }
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  ip4_header_t *ip0;
	  tcp_header_t *tcp0;
	  u32 not_a_syn0 = 1;
	  u32 hash0;
	  u8 *c0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  vnet_get_config_data
	    (&cm->config_main, &b0->current_config_index,
	     &next0, 0 /* sizeof (c0[0]) */ );

	  /* Not TCP? */
	  ip0 = vlib_buffer_get_current (b0);
	  if (ip0->protocol != IP_PROTOCOL_TCP)
	    goto trace0;

	  tcp0 = ip4_next_header (ip0);
	  /*
	   * Not a SYN?
	   * $$$$ hack: the TCP bitfield flags seem not to compile
	   * correct code.
	   */
	  if (PREDICT_TRUE (!(tcp0->flags & 0x2)))
	    goto trace0;

	  not_a_syn0 = 0;
	  hash0 = clib_xxhash ((u64) ip0->src_address.as_u32);
	  c0 = &rt->syn_counts[hash0 & (_vec_len (rt->syn_counts) - 1)];
	  if (PREDICT_FALSE (*c0 >= 0x80))
	    {
	      next0 = SYN_FILTER_NEXT_DROP;
	      b0->error = node->errors[SYN_FILTER_ERROR_THROTTLED];
	      goto trace0;
	    }
	  *c0 += 1;
	  ok_syn_packets++;

	trace0:

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      syn_filter4_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->not_a_syn = not_a_syn0;
	      t->next_index = next0;
	      t->filter_value = not_a_syn0 ? 0 : *c0;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, syn_filter4_node.index,
			       SYN_FILTER_ERROR_OK, ok_syn_packets);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (syn_filter4_node, static) =
{
  .function = syn_filter4_node_fn,
  .name = "syn-filter-4",
  .vector_size = sizeof (u32),
  .format_trace = format_syn_filter4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .runtime_data_bytes = sizeof (syn_filter4_runtime_t),
  .n_errors = ARRAY_LEN(syn_filter4_error_strings),
  .error_strings = syn_filter4_error_strings,

  .n_next_nodes = SYN_FILTER_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SYN_FILTER_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (syn_filter4_node, syn_filter4_node_fn);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (syn_filter_4, static) =
{
  .arc_name = "ip4-local",
  .node_name = "syn-filter-4",
  .runs_before = VNET_FEATURES("ip4-local-end-of-arc"),
};
/* *INDENT-ON* */

int
syn_filter_enable_disable (u32 sw_if_index, int enable_disable)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (vnm, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (enable_disable)
    {
      syn_filter4_runtime_t *rt;

      /* *INDENT-OFF* */
      foreach_vlib_main ({
	rt = vlib_node_get_runtime_data (this_vlib_main, syn_filter4_node.index);
	vec_validate (rt->syn_counts, 1023);
	/*
	 * Given perfect disperson / optimal hashing results:
	 * Allow 128k (successful) syns/sec. 1024, buckets each of which
	 * absorb 128 syns before filtering. Reset table once a second.
	 * Reality bites, lets try resetting once every 100ms.
	 */
	rt->reset_interval = 0.1;	/* reset interval in seconds */
      });
      /* *INDENT-ON* */
    }

  rv = vnet_feature_enable_disable ("ip4-local", "syn-filter-4",
				    sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
syn_filter_enable_disable_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int enable_disable = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = syn_filter_enable_disable (sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "feature arc not found");

    case VNET_API_ERROR_INVALID_VALUE_2:
      return clib_error_return (0, "feature node not found");

    default:
      return clib_error_return (0, "syn_filter_enable_disable returned %d",
				rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (sr_content_command, static) =
{
  .path = "ip syn filter",
  .short_help = "ip syn filter <interface-name> [disable]",
  .function = syn_filter_enable_disable_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
