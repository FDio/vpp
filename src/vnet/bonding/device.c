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
#include <vnet/bonding/lacp/node.h>

#define foreach_bond_tx_func_error      \
  _(NO_ERROR, "no error")

typedef enum
{
#define _(f,s) BOND_TX_FUNC_ERROR_##f,
  foreach_bond_tx_func_error
#undef _
    BOND_TX_FUNC_N_ERROR,
} bond_tx_func_error_t;

static char *bond_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_bond_tx_func_error
#undef _
};

static u8 *
format_bond_trace (u8 * s, va_list * args)
{
  return s;
}

u8 *
format_bond_interface_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  bond_main_t *bm = &bond_main;
  bond_if_t *bif = pool_elt_at_index (bm->interfaces, dev_instance);

  s = format (s, "bundle%lu/%lu", bif->group, bif->dev_instance);

  return s;
}

static clib_error_t *
bond_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  return 0;
}

static uword
bond_tx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (bond_dev_class) = {
  .name = "bond",
  .tx_function = bond_tx,
  .tx_function_n_errors = BOND_TX_FUNC_N_ERROR,
  .tx_function_error_strings = bond_tx_func_error_strings,
  .format_device_name = format_bond_interface_name,
  .admin_up_down_function = bond_interface_admin_up_down,
  .format_tx_trace = format_bond_trace,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (bond_dev_class, bond_tx)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
