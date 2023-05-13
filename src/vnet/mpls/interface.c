/*
 * interface.c: mpls interfaces
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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
#include <vnet/mpls/mpls.h>
#include <vnet/fib/mpls_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/dpo/classify_dpo.h>

typedef struct
{
  mpls_interface_state_change_function_t *function;
  uword function_opaque;
} mpls_interface_state_change_callback_t;

/** Functions to call when interface becomes MPLS enabled/disabled. */
static mpls_interface_state_change_callback_t *state_change_callbacks;

u8
mpls_sw_interface_is_enabled (u32 sw_if_index)
{
    mpls_main_t * mm = &mpls_main;

    if (vec_len(mm->mpls_enabled_by_sw_if_index) <= sw_if_index)
        return (0);

    return (mm->mpls_enabled_by_sw_if_index[sw_if_index]);
}

void
mpls_interface_state_change_add_callback (
  mpls_interface_state_change_function_t *function, uword opaque)
{
  mpls_interface_state_change_callback_t cb = {
    .function = function,
    .function_opaque = opaque,
  };
  vec_add1 (state_change_callbacks, cb);
}

int
mpls_sw_interface_enable_disable (mpls_main_t *mm, u32 sw_if_index,
				  u8 is_enable)
{
  fib_node_index_t lfib_index;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);

  vec_validate_init_empty (mm->mpls_enabled_by_sw_if_index, sw_if_index, 0);

  lfib_index = fib_table_find(FIB_PROTOCOL_MPLS,
                              MPLS_FIB_DEFAULT_TABLE_ID);

  if (~0 == lfib_index)
       return VNET_API_ERROR_NO_SUCH_FIB;

  /*
   * enable/disable only on the 1<->0 transition
   */
  if (is_enable)
    {
      if (1 != ++mm->mpls_enabled_by_sw_if_index[sw_if_index])
          return (0);

      fib_table_lock (lfib_index, FIB_PROTOCOL_MPLS, FIB_SOURCE_INTERFACE);

      vec_validate(mm->fib_index_by_sw_if_index, sw_if_index);
      mm->fib_index_by_sw_if_index[sw_if_index] = lfib_index;
    }
  else
    {
      ASSERT(mm->mpls_enabled_by_sw_if_index[sw_if_index] > 0);
      if (0 != --mm->mpls_enabled_by_sw_if_index[sw_if_index])
          return (0);

      fib_table_unlock (mm->fib_index_by_sw_if_index[sw_if_index],
			FIB_PROTOCOL_MPLS, FIB_SOURCE_INTERFACE);
    }

  vnet_feature_enable_disable ("mpls-input", "mpls-not-enabled",
                               sw_if_index, !is_enable, 0, 0);

  if (is_enable)
    hi->l3_if_count++;
  else if (hi->l3_if_count)
    hi->l3_if_count--;

  {
    mpls_interface_state_change_callback_t *cb;
    vec_foreach (cb, state_change_callbacks)
      cb->function (mm, cb->function_opaque, sw_if_index, is_enable);
  }

  return (0);
}

static clib_error_t *
mpls_interface_enable_disable (vlib_main_t * vm,
                               unformat_input_t * input,
                               vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 sw_if_index, enable;
  int rv;

  sw_if_index = ~0;

  if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (unformat (input, "enable"))
      enable = 1;
  else if (unformat (input, "disable"))
      enable = 0;
  else
    {
      error = clib_error_return (0, "expected 'enable' or 'disable'",
				 format_unformat_error, input);
      goto done;
    }

  rv = mpls_sw_interface_enable_disable (&mpls_main, sw_if_index, enable);

  if (VNET_API_ERROR_NO_SUCH_FIB == rv)
      error = clib_error_return (0, "default MPLS table must be created first");

 done:
  return error;
}

/*?
 * This command enables an interface to accept MPLS packets
 *
 * @cliexpar
 * @cliexstart{set interface mpls}
 *  set interface mpls GigEthernet0/8/0 enable
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (set_interface_ip_table_command, static) = {
  .path = "set interface mpls",
  .function = mpls_interface_enable_disable,
  .short_help = "Enable/Disable an interface for MPLS forwarding",
};

static void
show_mpls_one_interface (vnet_main_t *vnm, vlib_main_t *vm, u32 sw_if_index,
			 bool verbose)
{
  mpls_main_t *mm = &mpls_main;
  u8 enabled;

  enabled = mm->mpls_enabled_by_sw_if_index[sw_if_index];

  if (enabled)
    {
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnm,
		       sw_if_index);
      vlib_cli_output (vm, "  MPLS enabled");
    }
  else if (verbose)
    {
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnm,
		       sw_if_index);
      vlib_cli_output (vm, "  MPLS disabled");
    }
}

static walk_rc_t
show_mpls_interface_walk (vnet_main_t *vnm, vnet_sw_interface_t *si, void *ctx)
{
  show_mpls_one_interface (vnm, ctx, si->sw_if_index, false);

  return (WALK_CONTINUE);
}

static clib_error_t *
show_mpls_interface (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;

  sw_if_index = ~0;

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    ;

  if (~0 == sw_if_index)
    {
      vnet_sw_interface_walk (vnm, show_mpls_interface_walk, vm);
    }
  else
    {
      show_mpls_one_interface (vnm, vm, sw_if_index, true);
    }

  return NULL;
}

/*?
 * This command displays the MPLS forwarding state of an interface
 *
 * @cliexpar
 * @cliexstart{show mpls interface}
 *  set mpls interface GigEthernet0/8/0
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (show_mpls_interface_command, static) = {
  .path = "show mpls interface",
  .function = show_mpls_interface,
  .short_help = "Show MPLS interface forwarding",
};
