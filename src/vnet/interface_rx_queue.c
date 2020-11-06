/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vlib/unix/unix.h>

/* *INDENT-OFF* */
VLIB_REGISTER_LOG_CLASS (if_rxq_log, static) = {
  .class_name = "interface",
  .subclass_name = "rx-queue",
};
/* *INDENT-ON* */

#define log_debug(fmt,...) vlib_log_debug(if_rxq_log.class, fmt, __VA_ARGS__)

void
vnet_hw_if_set_input_node (vnet_main_t * vnm, u32 hw_if_index, u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  hi->input_node_index = node_index;
  log_debug ("set_input_node: node %U for interface %s",
	     format_vlib_node_name, vm, node_index, hi->name);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
