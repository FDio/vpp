/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/lua.h>

static clib_error_t *
ethernet_config_handler (vnet_main_t *vnm, u32 sw_if_index,
			 const vlua_val_t *config)
{
  const vlua_val_t *val;
  vnet_sw_interface_t *sw;
  clib_error_t *err;

  if (!vlua_val_type_is_table (config))
    return clib_error_return (0, "ethernet config must be a table");

  sw = vnet_get_sw_interface_or_null (vnm, sw_if_index);
  if (!sw || sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return clib_error_return (0, "not a hardware interface");

  val = vlua_val_table_get_entry (config, "max_frame_size");
  if (val)
    {
      u32 mfs;
      if (vlua_val_type_is_integer (val))
	mfs = (u32) vlua_val_get_integer (val);
      else if (vlua_val_type_is_number (val))
	mfs = (u32) vlua_val_get_number (val);
      else
	return clib_error_return (0, "max_frame_size must be number");

      err = vnet_hw_interface_set_max_frame_size (vnm, sw->hw_if_index, mfs);
      if (err)
	return err;
    }

  return 0;
}

static clib_error_t *
vpp_lua_ethernet_init (vlib_main_t *vm)
{
  vlua_register_interface_config_handler ("ethernet", ethernet_config_handler);
  return 0;
}

VLIB_INIT_FUNCTION (vpp_lua_ethernet_init);
