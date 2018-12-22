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

#include <af_xdp/af_xdp.h>

#define foreach_af_xdp_input_error \
  _(BUFFER_ALLOC, "buffer alloc error")

typedef enum
{
#define _(f,s) AF_XDP_INPUT_ERROR_##f,
  foreach_af_xdp_input_error
#undef _
    AF_XDP_INPUT_N_ERROR,
} af_xdp_input_error_t;

static __clib_unused char *af_xdp_input_error_strings[] = {
#define _(n,s) s,
  foreach_af_xdp_input_error
#undef _
};


static_always_inline uword
af_xdp_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame, af_xdp_device_t * ad,
			    u16 qid)
{
  uword n_rx_packets = 0;
  return n_rx_packets;
}

VLIB_NODE_FN (af_xdp_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_rx = 0;
  af_xdp_main_t *am = &af_xdp_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    af_xdp_device_t *ad;
    ad = vec_elt_at_index (am->devices, dq->dev_instance);
    if ((ad->flags & AF_XDP_DEVICE_F_ADMIN_UP) == 0)
      continue;
    n_rx += af_xdp_device_input_inline (vm, node, frame, ad, dq->queue_id);
  }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (af_xdp_input_node) = {
  .name = "af_xdp-input",
  .sibling_of = "device-input",
  .format_trace = format_af_xdp_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = AF_XDP_INPUT_N_ERROR,
  .error_strings = af_xdp_input_error_strings,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
