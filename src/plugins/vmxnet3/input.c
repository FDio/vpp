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

#include <vmxnet3/vmxnet3.h>

#define foreach_vmxnet3_input_error \
  _(BUFFER_ALLOC, "buffer alloc error") \
  _(RX_PACKET_ERROR, "Rx packet errors")

typedef enum
{
#define _(f,s) VMXNET3_INPUT_ERROR_##f,
  foreach_vmxnet3_input_error
#undef _
    VMXNET3_INPUT_N_ERROR,
} vmxnet3_input_error_t;

static __clib_unused char *vmxnet3_input_error_strings[] = {
#define _(n,s) s,
  foreach_vmxnet3_input_error
#undef _
};

VLIB_NODE_FN (vmxnet3_input_node) (vlib_main_t * vm,
                                   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  u32 n_rx = 0;

  return n_rx;
}

#ifndef CLIB_MARCH_VARIANT
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vmxnet3_input_node) = {
  .name = "vmxnet3-input",
  .sibling_of = "device-input",
  .format_trace = format_vmxnet3_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = VMXNET3_INPUT_N_ERROR,
  .error_strings = vmxnet3_input_error_strings,
};
#endif

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
