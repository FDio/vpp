/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include "lua.h"

#include <vlua/vlua.h>

#include <vlib/vlib.h>

u8 *vlua_config_stub_path;
u8 **vlua_config_scripts;

static clib_error_t *
lua_config (vlib_main_t *vm, unformat_input_t *input)
{

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      u8 *path = 0;
      if (unformat (input, "script %s", &path))
	{
	  vec_add1 (vlua_config_scripts, path);
	  continue;
	}
      if (unformat (input, "create-stub %s", &path))
	{
	  vec_free (vlua_config_stub_path);
	  vlua_config_stub_path = path;
	  continue;
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (lua_config, "lua");
