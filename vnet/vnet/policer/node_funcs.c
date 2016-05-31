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

#define IP4_NON_DSCP_BITS 0x03
#define IP4_DSCP_SHIFT    2
#define IP6_NON_DSCP_BITS 0xf03fffff
#define IP6_DSCP_SHIFT    22

/* Dispatch functions meant to be instantiated elsewhere */

typedef struct {
  u32 next_index;
  u32 sw_if_index;
  u32 policer_index;
} vnet_policer_trace_t;

/* packet trace format function */
static u8 * format_policer_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vnet_policer_trace_t * t = va_arg (*args, vnet_policer_trace_t *);
  
  s = format (s, "VNET_POLICER: sw_if_index %d policer_index %d next %d",
              t->sw_if_index, t->policer_index, t->next_index);
  return s;
}

#define foreach_vnet_policer_error              \
_(TRANSMIT, "Packets Transmitted")              \
_(DROP, "Packets Dropped")

typedef enum {
#define _(sym,str) VNET_POLICER_ERROR_##sym,
  foreach_vnet_policer_error
#undef _
  VNET_POLICER_N_ERROR,
} vnet_policer_error_t;

static char * vnet_policer_error_strings[] = {
#define _(sym,string) string,
  foreach_vnet_policer_error
#undef _
};

static_always_inline
void vnet_policer_mark (vlib_buffer_t * b, u8 dscp)
{
  ethernet_header_t * eh;
  ip4_header_t * ip4h;
  ip6_header_t * ip6h;
  u16 type;

  eh = (ethernet_header_t *) b->data;
  type = clib_net_to_host_u16 (eh->type);

  if (PREDICT_TRUE(type == ETHERNET_TYPE_IP4))
    {
      ip4h = (ip4_header_t *) &(b->data[sizeof(ethernet_header_t)]);;
      ip4h->tos &= IP4_NON_DSCP_BITS;
      ip4h->tos |= dscp << IP4_DSCP_SHIFT;
      ip4h->checksum = ip4_header_checksum (ip4h);
    }
  else
    {
      if (PREDICT_TRUE(type == ETHERNET_TYPE_IP6))
        {
          ip6h = (ip6_header_t *) &(b->data[sizeof(ethernet_header_t)]);
          ip6h->ip_version_traffic_class_and_flow_label &=
            clib_host_to_net_u32(IP6_NON_DSCP_BITS);
          ip6h->ip_version_traffic_class_and_flow_label |=
            clib_host_to_net_u32(dscp << IP6_DSCP_SHIFT);
        }
    }
}

static inline
uword vnet_policer_inline (vlib_main_t * vm,
                           vlib_node_runtime_t * node,
                           vlib_frame_t * frame,
                           vnet_policer_index_t which)
{
  u32 n_left_from, * from, * to_next;
  vnet_policer_next_t next_index;
  vnet_policer_main_t * pm = &vnet_policer_main;
  u64 time_in_policer_periods;
  u32 transmitted = 0;

  time_in_policer_periods = 
    clib_cpu_time_now() >> POLICER_TICKS_PER_PERIOD_SHIFT;

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
          u32 pi0 = 0, pi1 = 0;
          u32 len0, len1;
          u32 col0, col1;
          policer_read_response_type_st * pol0, * pol1;
          u8 act0, act1;
          
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * b2, * b3;
            
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

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          next0 = VNET_POLICER_NEXT_TRANSMIT;

          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
          next1 = VNET_POLICER_NEXT_TRANSMIT;


          if (which == VNET_POLICER_INDEX_BY_SW_IF_INDEX)
            {
              pi0 = pm->policer_index_by_sw_if_index[sw_if_index0];
              pi1 = pm->policer_index_by_sw_if_index[sw_if_index1];
            }

          if (which == VNET_POLICER_INDEX_BY_OPAQUE)
            {
              pi0 = vnet_buffer(b0)->policer.index;
              pi1 = vnet_buffer(b1)->policer.index;
            }

          if (which == VNET_POLICER_INDEX_BY_EITHER)
            {
              pi0 = vnet_buffer(b0)->policer.index;
              pi0 = (pi0 != ~0) ? pi0 : 
                pm->policer_index_by_sw_if_index [sw_if_index0];
              pi1 = vnet_buffer(b1)->policer.index;
              pi1 = (pi1 != ~0) ? pi1 : 
                pm->policer_index_by_sw_if_index [sw_if_index1];
            }

          len0 = vlib_buffer_length_in_chain (vm, b0);
          pol0 = &pm->policers [pi0];
          col0 = vnet_police_packet (pol0, len0, 
                                     POLICE_CONFORM /* no chaining */,
                                     time_in_policer_periods);
          act0 = pol0->action[col0];

          len1 = vlib_buffer_length_in_chain (vm, b1);
          pol1 = &pm->policers [pi1];
          col1 = vnet_police_packet (pol1, len1, 
                                     POLICE_CONFORM /* no chaining */,
                                     time_in_policer_periods);
          act1 = pol1->action[col1];

          if (PREDICT_FALSE(act0 == SSE2_QOS_ACTION_DROP)) /* drop action */
            {
              next0 = VNET_POLICER_NEXT_DROP;
              b0->error = node->errors[VNET_POLICER_ERROR_DROP];
            }
          else /* transmit or mark-and-transmit action */
            {
              if (PREDICT_TRUE(act0 == SSE2_QOS_ACTION_MARK_AND_TRANSMIT))
                vnet_policer_mark(b0, pol0->mark_dscp[col0]);
              transmitted++;
            }

          if (PREDICT_FALSE(act1 == SSE2_QOS_ACTION_DROP)) /* drop action */
            {
              next1 = VNET_POLICER_NEXT_DROP;
              b1->error = node->errors[VNET_POLICER_ERROR_DROP];
            }
          else /* transmit or mark-and-transmit action */
            {
              if (PREDICT_TRUE(act1 == SSE2_QOS_ACTION_MARK_AND_TRANSMIT))
                vnet_policer_mark(b1, pol1->mark_dscp[col1]);
              transmitted++;
            }


          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
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
	  vlib_buffer_t * b0;
          u32 next0;
          u32 sw_if_index0;
          u32 pi0 = 0;
          u32 len0;
          u32 col0;
          policer_read_response_type_st * pol0;
          u8 act0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          next0 = VNET_POLICER_NEXT_TRANSMIT;

          if (which == VNET_POLICER_INDEX_BY_SW_IF_INDEX)
            pi0 = pm->policer_index_by_sw_if_index[sw_if_index0];

          if (which == VNET_POLICER_INDEX_BY_OPAQUE)
            pi0 = vnet_buffer(b0)->policer.index;

          if (which == VNET_POLICER_INDEX_BY_EITHER)
            {
              pi0 = vnet_buffer(b0)->policer.index;
              pi0 = (pi0 != ~0) ? pi0 : 
                pm->policer_index_by_sw_if_index [sw_if_index0];
            }

          len0 = vlib_buffer_length_in_chain (vm, b0);
          pol0 = &pm->policers [pi0];
          col0 = vnet_police_packet (pol0, len0, 
                                     POLICE_CONFORM /* no chaining */,
                                     time_in_policer_periods);
          act0 = pol0->action[col0];
          
          if (PREDICT_FALSE(act0 == SSE2_QOS_ACTION_DROP)) /* drop action */
            {
              next0 = VNET_POLICER_NEXT_DROP;
              b0->error = node->errors[VNET_POLICER_ERROR_DROP];
            }
          else /* transmit or mark-and-transmit action */
            {
              if (PREDICT_TRUE(act0 == SSE2_QOS_ACTION_MARK_AND_TRANSMIT))
                vnet_policer_mark(b0, pol0->mark_dscp[col0]);
              transmitted++;
            }
          
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
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
                               VNET_POLICER_ERROR_TRANSMIT, 
                               transmitted);
  return frame->n_vectors;
}

uword vnet_policer_by_sw_if_index (vlib_main_t * vm,
                                   vlib_node_runtime_t * node,
                                   vlib_frame_t * frame)
{
  return vnet_policer_inline (vm, node, frame, 
                              VNET_POLICER_INDEX_BY_SW_IF_INDEX);
}

uword vnet_policer_by_opaque (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
  return vnet_policer_inline (vm, node, frame, 
                              VNET_POLICER_INDEX_BY_OPAQUE);
}

uword vnet_policer_by_either (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
  return vnet_policer_inline (vm, node, frame, 
                              VNET_POLICER_INDEX_BY_EITHER);
}

void vnet_policer_node_funcs_reference (void) { }


#define TEST_CODE 1

#ifdef TEST_CODE

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


int test_policer_add_del (u32 rx_sw_if_index, u8 *config_name,
                          int is_add)
{
  vnet_policer_main_t * pm = &vnet_policer_main;  
  policer_read_response_type_st * template;
  policer_read_response_type_st * policer;
  vnet_hw_interface_t * rxhi;
  uword * p;

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
        (pm->vnet_main, 
         rxhi->hw_if_index,
         policer_by_sw_if_index_node.index);

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
                                             ~0 /* disable */);

      pi = pm->policer_index_by_sw_if_index[rx_sw_if_index];
      pm->policer_index_by_sw_if_index[rx_sw_if_index] = ~0;
      pool_put_index (pm->policers, pi);
    }
  
  return 0;
}

static clib_error_t *
test_policer_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  vnet_policer_main_t * pm = &vnet_policer_main;  
  unformat_input_t _line_input, * line_input = &_line_input;
  u32 rx_sw_if_index;
  int rv;
  u8 * config_name = 0;
  int rx_set = 0;
  int is_add = 1;
  int is_show = 0;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "intfc %U", unformat_vnet_sw_interface,
                    pm->vnet_main, &rx_sw_if_index))
        rx_set = 1;
      else if (unformat (line_input, "show"))
        is_show=1;
      else if (unformat (line_input, "policer %s", &config_name))
        ;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else break;
    }

  if (rx_set == 0)
    return clib_error_return (0, "interface not set");

  if (is_show)
    {
      u32 pi = pm->policer_index_by_sw_if_index[rx_sw_if_index];
      policer_read_response_type_st * policer;
      policer = pool_elt_at_index (pm->policers, pi);
      
      vlib_cli_output (vm, "%U", format_policer_instance, policer);
      return 0;
    }

  if (is_add && config_name == 0)
    {
      return clib_error_return (0, "policer config name required");
    }

  rv = test_policer_add_del (rx_sw_if_index, config_name, is_add);

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return 
        (0, "WARNING: vnet_vnet_policer_add_del returned %d", rv);
    }
  
  return 0;
}

VLIB_CLI_COMMAND (test_patch_command, static) = {
    .path = "test policer",
    .short_help = 
    "intfc <intfc> policer <policer-config-name> [del]",
    .function = test_policer_command_fn,
};


#endif /* TEST_CODE */
