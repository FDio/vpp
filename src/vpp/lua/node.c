/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/vlua.h>
#include <vnet/vnet.h>
#include <math.h>

static vlua_handle_t lua_main_handle;

vlua_handle_t
vpp_lua_get_main_handle (void)
{
  return lua_main_handle;
}

static void
lua_coop_hook (vlua_handle_t handle __clib_unused)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_process_yield (vm);
}

VLIB_REGISTER_LOG_CLASS (lua_main_log) = {
  .class_name = "lua",
};

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (lua_main_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (lua_main_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
#define log_err(fmt, ...)                                                     \
  vlib_log_err (lua_main_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)

static u8 *vlua_config_stub_path;
static u8 **vlua_config_scripts;

static void
lua_log_vlib (vlua_handle_t handle, vlua_log_level_t level, const char *fmt,
	      va_list *va)
{
  vlib_log_class_t class = lua_main_log.class;
  vlib_log_level_t vlevel;

  switch (level)
    {
    case VLUA_LOG_LEVEL_DEBUG:
      vlevel = VLIB_LOG_LEVEL_DEBUG;
      break;
    case VLUA_LOG_LEVEL_INFO:
      vlevel = VLIB_LOG_LEVEL_INFO;
      break;
    case VLUA_LOG_LEVEL_WARN:
      vlevel = VLIB_LOG_LEVEL_WARNING;
      break;
    case VLUA_LOG_LEVEL_ERR:
    default:
      vlevel = VLIB_LOG_LEVEL_ERR;
      break;
    }

  vlib_log_va (vlevel, class, (char *) fmt, va);
}

static uword
lua_process (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlua_handle_t h;
  clib_error_t *init_err;

  h = vlua_create (&(vlua_create_args_t){
    .log_cb = lua_log_vlib,
    .path_prefix = "vpp",
    .hook_fn = lua_coop_hook,
    .hook_inst_count = 10000,
  });
  lua_main_handle = h;

  init_err = vlua_run_init_functions (h);
  if (init_err)
    {
      log_err ("%U", format_clib_error, init_err);
      clib_error_free (init_err);
      goto done;
    }

  if (vlua_config_stub_path)
    {
      vlua_stub_dump (h, (const char *) vlua_config_stub_path);
      vec_free (vlua_config_stub_path);
    }

  if (vlua_config_scripts)
    {
      clib_error_t *err = 0;
      vec_foreach_pointer (s, vlua_config_scripts)
	{
	  if (err == 0)
	    err = vlua_run_file (h, "%s", s);
	  vec_free (s);
	}
      vec_free (vlua_config_scripts);
      if (err)
	{
	  log_err ("%U", format_clib_error, err);
	  clib_error_free (err);
	}
    }

  while (1)
    {
      f64 wait = vlua_scheduler_run_cycle (h);

      if (isnan (wait))
	{
	  vlib_process_wait_for_event (vm);
	  vlib_process_get_events (vm, 0);
	}
      else
	vlib_process_suspend (vm, wait > 0 ? wait : 0);
    }

done:
  lua_main_handle = 0;
  vlua_destroy (h);
  return 0;
}

VLIB_REGISTER_NODE (lua_process_node) = {
  .function = lua_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "lua",
};

void
vpp_lua_process_wakeup (vlib_main_t *vm)
{
  vlib_process_signal_event (vm, lua_process_node.index, 0, 0);
}

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
