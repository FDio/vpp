/*
 * Copyright (c) 2016,2020 Cisco and/or its affiliates.
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
#include <plugins/adl/adl.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/load_balance.h>

typedef struct {
  u32 next_index;
  u32 sw_if_index;
} ip6_adl_allowlist_trace_t;

/* packet trace format function */
static u8 * format_ip6_adl_allowlist_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_adl_allowlist_trace_t * t = va_arg (*args, ip6_adl_allowlist_trace_t *);

  s = format (s, "IP6_ADL_ALLOWLIST: sw_if_index %d, next index %d",
              t->sw_if_index, t->next_index);
  return s;
}

#define foreach_ip6_adl_allowlist_error         \
_(ALLOWED, "ip6 allowlist allowed")             \
_(DROPPED, "ip6 allowlist dropped")

typedef enum {
#define _(sym,str) IP6_ADL_ALLOWLIST_ERROR_##sym,
  foreach_ip6_adl_allowlist_error
#undef _
  IP6_ADL_ALLOWLIST_N_ERROR,
} ip6_adl_allowlist_error_t;

static char * ip6_adl_allowlist_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_adl_allowlist_error
#undef _
};

VLIB_NODE_FN (ip6_adl_allowlist_node) (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  adl_feature_type_t next_index;
  adl_main_t *cm = &adl_main;
  vlib_combined_counter_main_t * vcm = &load_balance_main.lbm_via_counters;
  clib_thread_index_t thread_index = vm->thread_index;
  u32 allowed_packets;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  allowed_packets = n_left_from;
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
          ip6_header_t * ip0, * ip1;
          adl_config_main_t * ccm0, * ccm1;
          adl_config_data_t * c0, * c1;
          u32 lb_index0, lb_index1;
          const load_balance_t * lb0, *lb1;
          const dpo_id_t *dpo0, *dpo1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    clib_prefetch_store (p2->data);
	    clib_prefetch_store (p3->data);
	  }

          /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

	  ip0 = vlib_buffer_get_current (b0);

	  ccm0 = cm->adl_config_mains + VNET_ADL_IP6;

	  c0 = vnet_get_config_data
              (&ccm0->config_main,
               &adl_buffer (b0)->adl.current_config_index,
               &next0,
               sizeof (c0[0]));

          lb_index0 = ip6_fib_table_fwding_lookup (c0->fib_index,
						    &ip0->src_address);
	  lb0 = load_balance_get (lb_index0);
          dpo0 = load_balance_get_bucket_i(lb0, 0);

          if (PREDICT_FALSE(dpo0->dpoi_type != DPO_RECEIVE))
            {
              b0->error = node->errors[IP6_ADL_ALLOWLIST_ERROR_DROPPED];
              allowed_packets--;
              next0 = RX_ADL_DROP;
            }

	  b1 = vlib_get_buffer (vm, bi1);
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

	  ip1 = vlib_buffer_get_current (b1);

	  ccm1 = cm->adl_config_mains + VNET_ADL_IP6;

	  c1 = vnet_get_config_data
              (&ccm1->config_main,
               &adl_buffer (b1)->adl.current_config_index,
               &next1,
               sizeof (c1[0]));

          lb_index1 = ip6_fib_table_fwding_lookup (c1->fib_index,
						    &ip1->src_address);

	  lb1 = load_balance_get (lb_index1);
          dpo1 = load_balance_get_bucket_i(lb1, 0);

          vlib_increment_combined_counter
              (vcm, thread_index, lb_index0, 1,
               vlib_buffer_length_in_chain (vm, b0)
               + sizeof(ethernet_header_t));

          vlib_increment_combined_counter
              (vcm, thread_index, lb_index1, 1,
               vlib_buffer_length_in_chain (vm, b1)
               + sizeof(ethernet_header_t));

          if (PREDICT_FALSE(dpo1->dpoi_type != DPO_RECEIVE))
            {
              b1->error = node->errors[IP6_ADL_ALLOWLIST_ERROR_DROPPED];
              allowed_packets--;
              next1 = RX_ADL_DROP;
            }

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              ip6_adl_allowlist_trace_t *t =
                 vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->next_index = next0;
            }

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b1->flags & VLIB_BUFFER_IS_TRACED)))
            {
              ip6_adl_allowlist_trace_t *t =
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
          ip6_header_t * ip0;
          adl_config_main_t *ccm0;
          adl_config_data_t *c0;
          u32 lb_index0;
          const load_balance_t * lb0;
          const dpo_id_t *dpo0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          sw_if_index0 = adl_buffer(b0)->sw_if_index[VLIB_RX];

	  ip0 = vlib_buffer_get_current (b0);

	  ccm0 = cm->adl_config_mains + VNET_ADL_IP6;

	  c0 = vnet_get_config_data
              (&ccm0->config_main,
               &adl_buffer (b0)->adl.current_config_index,
               &next0,
               sizeof (c0[0]));

          lb_index0 = ip6_fib_table_fwding_lookup (c0->fib_index,
						    &ip0->src_address);

	  lb0 = load_balance_get (lb_index0);
          dpo0 = load_balance_get_bucket_i(lb0, 0);

          vlib_increment_combined_counter
              (vcm, thread_index, lb_index0, 1,
               vlib_buffer_length_in_chain (vm, b0)
               + sizeof(ethernet_header_t));

          if (PREDICT_FALSE(dpo0->dpoi_type != DPO_RECEIVE))
            {
              b0->error = node->errors[IP6_ADL_ALLOWLIST_ERROR_DROPPED];
              allowed_packets--;
              next0 = RX_ADL_DROP;
            }

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              ip6_adl_allowlist_trace_t *t =
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
  vlib_node_increment_counter (vm, node->node_index,
			       IP6_ADL_ALLOWLIST_ERROR_ALLOWED,
                               allowed_packets);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_adl_allowlist_node) = {
  .name = "ip6-adl-allowlist",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_adl_allowlist_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ip6_adl_allowlist_error_strings),
  .error_strings = ip6_adl_allowlist_error_strings,

  .n_next_nodes = ADL_RX_N_FEATURES,

  /* edit / add dispositions here */
  .next_nodes = {
    [IP4_RX_ADL_ALLOWLIST] = "ip4-adl-allowlist",
    [IP6_RX_ADL_ALLOWLIST] = "ip6-adl-allowlist",
    [DEFAULT_RX_ADL_ALLOWLIST] = "default-adl-allowlist",
    [IP4_RX_ADL_INPUT] = "ip4-input",
    [IP6_RX_ADL_INPUT] = "ip6-input",
    [DEFAULT_RX_ADL_INPUT] = "ethernet-input",
    [RX_ADL_DROP] = "error-drop",
  },
};

static clib_error_t *
ip6_allowlist_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip6_allowlist_init);
