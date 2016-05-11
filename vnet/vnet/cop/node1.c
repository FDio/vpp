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

#include <vnet/cop/cop.h>

typedef struct {
  u32 next_index;
  u32 sw_if_index;
} cop_input_trace_t;

/* packet trace format function */
static u8 * format_cop_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cop_input_trace_t * t = va_arg (*args, cop_input_trace_t *);
  
  s = format (s, "COP_INPUT: sw_if_index %d, next index %d",
              t->sw_if_index, t->next_index);
  return s;
}

vlib_node_registration_t cop_input_node;

#define foreach_cop_input_error \
_(PROCESSED, "COP input packets processed")

typedef enum {
#define _(sym,str) COP_INPUT_ERROR_##sym,
  foreach_cop_input_error
#undef _
  COP_INPUT_N_ERROR,
} cop_input_error_t;

static char * cop_input_error_strings[] = {
#define _(sym,string) string,
  foreach_cop_input_error
#undef _
};

static uword
cop_input_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  cop_feature_type_t next_index;
  cop_main_t *cm = &cop_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;
          ethernet_header_t * en0, * en1;
          cop_config_main_t * ccm0, * ccm1;
          u32 advance0, advance1;
          int proto0, proto1;
          
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;
            
	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
            
	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
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

          en0 = vlib_buffer_get_current (b0);
          en1 = vlib_buffer_get_current (b1);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

          proto0 = VNET_COP_DEFAULT;
          proto1 = VNET_COP_DEFAULT;
          advance0 = 0;
          advance1 = 0;

          if (en0->type == clib_host_to_net_u16(ETHERNET_TYPE_IP4))
            {
              proto0 = VNET_COP_IP4;
              advance0 = sizeof(ethernet_header_t);
            }
          else if (en0->type == clib_host_to_net_u16(ETHERNET_TYPE_IP6))
            {
              proto0 = VNET_COP_IP6;
              advance0 = sizeof(ethernet_header_t);
            }

          if (en1->type == clib_host_to_net_u16(ETHERNET_TYPE_IP4))
            {
              proto1 = VNET_COP_IP4;
              advance1 = sizeof(ethernet_header_t);
            }
          else if (en1->type == clib_host_to_net_u16(ETHERNET_TYPE_IP6))
            {
              proto1 = VNET_COP_IP6;
              advance1 = sizeof(ethernet_header_t);
            }

	  ccm0 = cm->cop_config_mains + proto0;
	  ccm1 = cm->cop_config_mains + proto1;
          vnet_buffer(b0)->cop.current_config_index = 
            ccm0->config_index_by_sw_if_index [sw_if_index0];

          vnet_buffer(b1)->cop.current_config_index = 
            ccm1->config_index_by_sw_if_index [sw_if_index1];

          vlib_buffer_advance (b0, advance0);
          vlib_buffer_advance (b1, advance1);

          vnet_get_config_data (&ccm0->config_main,
                                &vnet_buffer(b0)->cop.current_config_index,
                                &next0, 0 /* bytes of config data */);

          vnet_get_config_data (&ccm1->config_main,
                                &vnet_buffer(b1)->cop.current_config_index,
                                &next1, 0 /* bytes of config data */);

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              cop_input_trace_t *t = 
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
            }

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b1->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              cop_input_trace_t *t = 
                 vlib_add_trace (vm, node, b1, sizeof (*t));
              t->sw_if_index = sw_if_index1;
              t->next_index = next1;
            }
          /* verify speculative enqueues, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0;
          u32 sw_if_index0;
          ethernet_header_t *en0;
          cop_config_main_t *ccm0;
          u32 advance0;
          int proto0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          /* 
           * Direct from the driver, we should be at offset 0
           * aka at &b0->data[0]
           */
          ASSERT (b0->current_data == 0);

          en0 = vlib_buffer_get_current (b0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          proto0 = VNET_COP_DEFAULT;
          advance0 = 0;

          if (en0->type == clib_host_to_net_u16(ETHERNET_TYPE_IP4))
            {
              proto0 = VNET_COP_IP4;
              advance0 = sizeof(ethernet_header_t);
            }
          else if (en0->type == clib_host_to_net_u16(ETHERNET_TYPE_IP6))
            {
              proto0 = VNET_COP_IP6;
              advance0 = sizeof(ethernet_header_t);
            }

	  ccm0 = cm->cop_config_mains + proto0;
          vnet_buffer(b0)->cop.current_config_index = 
            ccm0->config_index_by_sw_if_index [sw_if_index0];

          vlib_buffer_advance (b0, advance0);

          vnet_get_config_data (&ccm0->config_main,
                                &vnet_buffer(b0)->cop.current_config_index,
                                &next0, 0 /* bytes of config data */);

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) 
            {
              cop_input_trace_t *t = 
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
            }
            
          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, cop_input_node.index, 
                               COP_INPUT_ERROR_PROCESSED, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cop_input_node) = {
  .function = cop_input_node_fn,
  .name = "cop-input",
  .vector_size = sizeof (u32),
  .format_trace = format_cop_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(cop_input_error_strings),
  .error_strings = cop_input_error_strings,

  .n_next_nodes = COP_RX_N_FEATURES,

  /* edit / add dispositions here */
  .next_nodes = {
    [IP4_RX_COP_WHITELIST] = "ip4-cop-whitelist",
    [IP6_RX_COP_WHITELIST] = "ip6-cop-whitelist",
    [DEFAULT_RX_COP_WHITELIST] = "default-cop-whitelist",
    [IP4_RX_COP_INPUT] = "ip4-input",
    [IP6_RX_COP_INPUT] = "ip6-input",
    [DEFAULT_RX_COP_INPUT] = "ethernet-input",
    [RX_COP_DROP] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (cop_input_node, cop_input_node_fn)

#define foreach_cop_stub                        \
_(default-cop-whitelist, default_cop_whitelist)

#define _(n,f)                                  \
                                                \
static uword                                    \
f##_node_fn (vlib_main_t * vm,                  \
             vlib_node_runtime_t * node,        \
             vlib_frame_t * frame)              \
{                                               \
  clib_warning ("BUG: stub function called");   \
  return 0;                                     \
}                                               \
                                                \
VLIB_REGISTER_NODE (f##_input_node) = {         \
  .function = f##_node_fn,                      \
  .name = #n,                                   \
  .vector_size = sizeof (u32),                  \
  .type = VLIB_NODE_TYPE_INTERNAL,              \
                                                \
  .n_errors = 0,                                \
  .error_strings = 0,                           \
                                                \
  .n_next_nodes = 0,                            \
};

foreach_cop_stub;






