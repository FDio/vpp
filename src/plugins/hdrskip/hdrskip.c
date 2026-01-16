/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <hdrskip/hdrskip.h>

#include <vpp/app/version.h>

hdrskip_main_t hdrskip_main;

static int
hdrskip_validate_sw_if_index (hdrskip_main_t *hsm, u32 sw_if_index)
{
  if (pool_is_free_index (hsm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  return 0;
}

int
hdrskip_input_enable_disable (hdrskip_main_t *hsm, u32 sw_if_index,
			      int enable_disable, u32 skip_bytes,
			      int set_bytes)
{
  vnet_sw_interface_t *sw;
  int rv;

  rv = hdrskip_validate_sw_if_index (hsm, sw_if_index);
  if (rv)
    return rv;

  sw = vnet_get_sw_interface (hsm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (set_bytes)
    {
      if (skip_bytes > HDRSKIP_MAX_ADJUST)
	return VNET_API_ERROR_INVALID_VALUE;

      vec_validate_init_empty (hsm->input_skip_by_sw_if_index, sw_if_index, 0);
      hsm->input_skip_by_sw_if_index[sw_if_index] = skip_bytes;
    }

  vnet_feature_enable_disable ("device-input", "hdrskip-input", sw_if_index,
			       enable_disable, 0, 0);

  return 0;
}

int
hdrskip_output_enable_disable (hdrskip_main_t *hsm, u32 sw_if_index,
			       int enable_disable, u32 restore_bytes,
			       int set_bytes)
{
  int rv;

  rv = hdrskip_validate_sw_if_index (hsm, sw_if_index);
  if (rv)
    return rv;

  if (set_bytes)
    {
      if (restore_bytes > HDRSKIP_MAX_ADJUST)
	return VNET_API_ERROR_INVALID_VALUE;

      vec_validate_init_empty (hsm->output_restore_by_sw_if_index, sw_if_index,
			       0);
      hsm->output_restore_by_sw_if_index[sw_if_index] = restore_bytes;
    }

  vnet_feature_enable_disable ("interface-output", "hdrskip-output",
			       sw_if_index, enable_disable, 0, 0);

  return 0;
}

static clib_error_t *
hdrskip_init (vlib_main_t *vm)
{
  hdrskip_main_t *hsm = &hdrskip_main;

  hsm->vlib_main = vm;
  hsm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (hdrskip_init);

VNET_FEATURE_INIT (hdrskip_input, static) = {
  .arc_name = "device-input",
  .node_name = "hdrskip-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (hdrskip_output, static) = {
  .arc_name = "interface-output",
  .node_name = "hdrskip-output",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Header skip/restore feature",
  .default_disabled = 1,
};
