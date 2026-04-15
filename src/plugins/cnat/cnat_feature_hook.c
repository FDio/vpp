/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */
#include <vlib/vlib.h>
#include <vppinfra/vec.h>
#include <cnat/cnat_feature_hook.h>

static int
cnat_feature_hook_add_del_fn (int is_add, cnat_slow_path_fn_t func, cnat_hook_order_t order,
			      cnat_slow_path_fn_t **chain)
{
  if (is_add)
    {
      cnat_slow_path_fn_t *f;
      vec_foreach (f, *chain)
	if (*f == func)
	  return -2; /* duplicate */
      if (order == CNAT_HOOK_PREPEND)
	vec_insert_elts (*chain, &func, 1, 0);
      else
	vec_add1 (*chain, func);
      return 0;
    }
  cnat_slow_path_fn_t *f;
  vec_foreach (f, *chain)
    {
      if (*f == func)
	{
	  vec_delete (*chain, 1, f - *chain);
	  return 0;
	}
    }
  return -1;
}

__clib_export int
cnat_feature_hook_input_add_del (int is_add, cnat_slow_path_fn_t func, cnat_hook_order_t order)
{
  cnat_main_t *cm = &cnat_main;
  return cnat_feature_hook_add_del_fn (is_add, func, order, &cm->slow_path_input_func);
}

__clib_export int
cnat_feature_hook_output_add_del (int is_add, cnat_slow_path_fn_t func, cnat_hook_order_t order)
{
  cnat_main_t *cm = &cnat_main;
  return cnat_feature_hook_add_del_fn (is_add, func, order, &cm->slow_path_output_func);
}

/* Ensure the default DNAT/SNAT hooks are in the vec before any external plugin
 * registers its own hooks.  Idempotent — safe to call multiple times.
 * Called by cnat_sw_interface_enable_disable and by external plugins before
 * they register their own hooks.
 * Must be called before workers start; no runtime registration is safe
 * without a worker barrier. */
__clib_export void
cnat_feature_hooks_ensure_init (void)
{
  cnat_main_t *cm = &cnat_main;
  if (cm->feature_hook_init_done)
    return;
  cnat_feature_hook_input_add_del (1, cnat_dnat_input_slow_path, CNAT_HOOK_APPEND);
  cnat_feature_hook_output_add_del (1, cnat_snat_output_slow_path, CNAT_HOOK_APPEND);
  cm->feature_hook_init_done = 1;
}

static clib_error_t *
cnat_show_feature_hooks_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  cnat_main_t *cm = &cnat_main;
  cnat_slow_path_fn_t *fi;
  cnat_slow_path_fn_t *fo;

  vlib_cli_output (vm, "Cnat Feature hooks:");
  vlib_cli_output (vm, " input (%u):", vec_len (cm->slow_path_input_func));
  vec_foreach (fi, cm->slow_path_input_func)
    vlib_cli_output (vm, "  %p", *fi);
  vlib_cli_output (vm, " output (%u):", vec_len (cm->slow_path_output_func));
  vec_foreach (fo, cm->slow_path_output_func)
    vlib_cli_output (vm, "  %p", *fo);

  return NULL;
}

VLIB_CLI_COMMAND (cnat_show_cnat_feature_hooks, static) = {
  .path = "show cnat feature-hooks",
  .short_help = "show cnat feature-hooks",
  .function = cnat_show_feature_hooks_fn,
};
