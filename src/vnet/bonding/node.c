/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#define _GNU_SOURCE
#include <stdint.h>
#include <vnet/bonding/node.h>

bond_main_t bond_main;

#define foreach_bond_input_func_error      \
  _(NO_ERROR, "no error")

typedef enum
{
#define _(f,s) BOND_INPUT_FUNC_ERROR_##f,
  foreach_bond_input_func_error
#undef _
    BOND_INPUT_FUNC_N_ERROR,
} bond_input_func_error_t;

static char *bond_input_func_error_strings[] = {
#define _(n,s) s,
  foreach_bond_input_func_error
#undef _
};

static u8 *
format_bond_input_trace (u8 * s, va_list * va)
{
  return s;
}

static uword
bond_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  uword n_rx_packets = 0;

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (bond_input_node,static) = {
  .function = bond_input_fn,
  .name = "bond-input",
  .sibling_of = "device-input",
  .format_trace = format_bond_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = BOND_INPUT_FUNC_N_ERROR,
  .error_strings = bond_input_func_error_strings,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
