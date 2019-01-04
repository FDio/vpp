/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vppinfra/error.h>

#include <vnet/feature/feature.h>
#include <vnet/ethernet/ethernet.h>

int
vnet_sw_interface_stats_dump (u32 sw_if_index)
{
  ethernet_interface_t *eif;
  vnet_sw_interface_t *si;
  ethernet_main_t *em;
  vnet_main_t *vnm;

  vnm = vnet_get_main ();
  em = &ethernet_main;
  si = vnet_get_sw_interface (vnm, sw_if_index);

  /*
   * only ethernet HW interfaces are supported at this time
   */
   si.
  /*if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    {
      return (VNET_API_ERROR_INVALID_VALUE);
    }

  eif = ethernet_get_interface (em, si->hw_if_index);

  if (!eif)
    {
      return (VNET_API_ERROR_FEATURE_DISABLED);
    }

  vnet_feature_enable_disable ("device-input", "stats-collect-rx",
			       sw_if_index, enable, 0, 0);
  vnet_feature_enable_disable ("interface-output", "stats-collect-tx",
			       sw_if_index, enable, 0, 0);*/

  return (0);
}

int
vnet_sw_interface_stats_collect_enable_disable (u32 sw_if_index, u8 enable)
{
  ethernet_interface_t *eif;
  vnet_sw_interface_t *si;
  ethernet_main_t *em;
  vnet_main_t *vnm;

  vnm = vnet_get_main ();
  em = &ethernet_main;
  si = vnet_get_sw_interface (vnm, sw_if_index);

  /*
   * only ethernet HW interfaces are supported at this time
   */
  if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    {
      return (VNET_API_ERROR_INVALID_VALUE);
    }

  eif = ethernet_get_interface (em, si->hw_if_index);

  if (!eif)
    {
      return (VNET_API_ERROR_FEATURE_DISABLED);
    }

  vnet_feature_enable_disable ("device-input", "stats-collect-rx",
			       sw_if_index, enable, 0, 0);
  vnet_feature_enable_disable ("interface-output", "stats-collect-tx",
			       sw_if_index, enable, 0, 0);

  return (0);
}

static u8 *
format_stats_collect_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  return s;
}

#define inc_counter(ctype, rx_tx)                               \
{                                                               \
}

static_always_inline uword
stats_collect_inline (vlib_main_t * vm,
		      vlib_node_runtime_t * node,
		      vlib_frame_t * frame, vlib_rx_or_tx_t rxtx)
{
  vnet_interface_counter_type_t ct;
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 sw_if_index = 0;
  u32 stats_n_packets[VNET_N_COMBINED_INTERFACE_COUNTER] = { 0 };
  u64 stats_n_bytes[VNET_N_COMBINED_INTERFACE_COUNTER] = { 0 };

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = 0;
	  int b0_ctype;

	  /* speculatively enqueue b0 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next += 1;
	  n_left_to_next -= 1;
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index = vnet_buffer (b0)->sw_if_index[rxtx];

	  if (VLIB_RX == rxtx)
	    {
	      b0_ctype =
		eh_dst_addr_to_rx_ctype (vlib_buffer_get_current (b0));
	    }
	  else
	    {
	      b0_ctype =
		eh_dst_addr_to_tx_ctype (vlib_buffer_get_current (b0));
	    }

	  stats_n_bytes[b0_ctype] += vlib_buffer_length_in_chain (vm, b0);
	  stats_n_packets[b0_ctype] += 1;

	  vnet_feature_next (&next0, b0);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      if (VLIB_RX == rxtx)
	{
	  foreach_rx_combined_interface_counter (ct)
	  {
	    vlib_increment_combined_counter
	      (vnet_main.interface_main.combined_sw_if_counters + ct,
	       vlib_get_thread_index (),
	       sw_if_index, stats_n_packets[ct], stats_n_bytes[ct]);
	  }
	}
      else
	{
	  foreach_tx_combined_interface_counter (ct)
	  {
	    vlib_increment_combined_counter
	      (vnet_main.interface_main.combined_sw_if_counters + ct,
	       vlib_get_thread_index (),
	       sw_if_index, stats_n_packets[ct], stats_n_bytes[ct]);
	  }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
stats_collect_rx (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return stats_collect_inline (vm, node, frame, VLIB_RX);
}

static uword
stats_collect_tx (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return stats_collect_inline (vm, node, frame, VLIB_TX);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (stats_collect_rx_node) = {
  .vector_size = sizeof (u32),
  .format_trace = format_stats_collect_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 0,
  .function = stats_collect_rx,
  .name = "stats-collect-rx",
};

VLIB_REGISTER_NODE (stats_collect_tx_node) = {
  .vector_size = sizeof (u32),
  .format_trace = format_stats_collect_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 0,
  .function = stats_collect_tx,
  .name = "stats-collect-tx",
};

VLIB_NODE_FUNCTION_MULTIARCH (stats_collect_rx_node, stats_collect_rx);
VLIB_NODE_FUNCTION_MULTIARCH (stats_collect_tx_node, stats_collect_tx);

VNET_FEATURE_INIT (stats_collect_rx_node, static) = {
  .arc_name = "device-input",
  .node_name = "stats-collect-rx",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (stats_collect_tx_node, static) = {
  .arc_name = "interface-output",
  .node_name = "stats-collect-tx",
  .runs_before = VNET_FEATURES ("interface-tx"),
};

/* *INDENT-ON* */

static clib_error_t *
stats_collect_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (stats_collect_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
