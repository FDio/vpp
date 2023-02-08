/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>

#include <ena/ena.h>
#include <ena/ena_inlines.h>

#define foreach_ena_input_error _ (BUFFER_ALLOC, "buffer alloc error")

typedef enum
{
#define _(f, s) ENA_INPUT_ERROR_##f,
  foreach_ena_input_error
#undef _
    ENA_INPUT_N_ERROR,
} ena_input_error_t;

static __clib_unused char *ena_input_error_strings[] = {
#define _(n, s) s,
  foreach_ena_input_error
#undef _
};

static_always_inline uword
ena_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, ena_device_t *ad, u16 qid,
			 int with_flows)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword n_rx_packets = 0;
  uword n_rx_bytes = 0;
  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, ad->hw_if_index, n_rx_packets, n_rx_bytes);

  return n_rx_packets;
}

VLIB_NODE_FN (ena_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  vnet_hw_if_rxq_poll_vector_t *pv;

  pv = vnet_hw_if_get_rxq_poll_vector (vm, node);

  for (int i = 0; i < vec_len (pv); i++)
    {
      ena_device_t *ad = ena_get_device (pv[i].dev_instance);
      if ((ad->admin_up) == 0)
	continue;
      n_rx += ena_device_input_inline (vm, node, frame, ad, pv[i].queue_id, 0);
    }

  return n_rx;
}

VLIB_REGISTER_NODE (ena_input_node) = {
  .name = "ena-input",
  .sibling_of = "device-input",
  .format_trace = format_ena_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = ENA_INPUT_N_ERROR,
  .error_strings = ena_input_error_strings,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
};
