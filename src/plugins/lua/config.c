/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/vlua.h>

#include <vlib/vlib.h>

#include <stdlib.h>

static clib_error_t *
lua_config (vlib_main_t *vm, unformat_input_t *input)
{
  vlua_handle_t h = 0;
  u8 **scripts = 0;
  u8 *stub_path = 0;
  clib_error_t *err = 0;
  u8 **script_it = 0;

  if (!unformat (input, "{"))
    return clib_error_return (0, "expected '{' after lua");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      u8 *path = 0;
      if (unformat (input, "script %s", &path))
	{
	  vec_add1 (scripts, path);
	  continue;
	}
      if (unformat (input, "create-stub %s", &path))
	{
	  vec_free (stub_path);
	  stub_path = path;
	  continue;
	}
      if (unformat (input, "}"))
	break;
      err =
	clib_error_return (0, "unknown input '%U'", format_unformat_error,
			   input);
      goto done;
    }

  if (stub_path)
    setenv ("VLUA_EMMY_STUB", (const char *) stub_path, 1);

  if (vec_len (scripts))
    {
      h = vlua_create ();
      vec_foreach (script_it, scripts)
	{
	  err = vlua_run_file (h, "%s", (char *) *script_it);
	  if (err)
	    goto done;
	}
    }

done:
  if (h)
    vlua_destroy (h);
  vec_foreach (script_it, scripts)
    vec_free (*script_it);
  vec_free (scripts);
  vec_free (stub_path);
  return err;
}

VLIB_CONFIG_FUNCTION (lua_config, "lua");
