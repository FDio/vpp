/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>

#include <igb/igb.h>

#define foreach_igb_input_error \
  _(BUFFER_ALLOC, "buffer alloc error")

typedef enum
{
#define _(f,s) IGB_INPUT_ERROR_##f,
  foreach_igb_input_error
#undef _
    IGB_INPUT_N_ERROR,
} igb_input_error_t;

static __clib_unused char *igb_input_error_strings[] = {
#define _(n,s) s,
  foreach_igb_input_error
#undef _
};

#define IGB_INPUT_REFILL_TRESHOLD 32

static_always_inline uword
igb_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame, igb_device_t * ad, u16 qid)
{
  u32 n_rx_packets = 0;
  return n_rx_packets;
}

VLIB_NODE_FN (igb_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  u32 n_rx = 0;
  igb_main_t *am = &igb_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    igb_device_t *ad;
    ad = vec_elt_at_index (am->devices, dq->dev_instance);
    if ((ad->flags & IGB_DEVICE_F_ADMIN_UP) == 0)
      continue;
    n_rx += igb_device_input_inline (vm, node, frame, ad, dq->queue_id);
  }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (igb_input_node) = {
  .name = "igb-input",
  .sibling_of = "device-input",
  .format_trace = format_igb_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = IGB_INPUT_N_ERROR,
  .error_strings = igb_input_error_strings,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
