/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <arpa/inet.h>
#include <vnet/session/session.h>
#include <vnet/session/session_rules_table.h>
#include <vnet/tcp/tcp_sdl.h>
#include <plugins/auto_sdl/auto_sdl.h>

#define AUTO_SDL_TEST_I(_cond, _comment, _args...)                            \
  ({                                                                          \
    int _evald = (_cond);                                                     \
    if (!(_evald))                                                            \
      {                                                                       \
	fformat (stderr, "FAIL:%d: " _comment "\n", __LINE__, ##_args);       \
      }                                                                       \
    else                                                                      \
      {                                                                       \
	fformat (stderr, "PASS:%d: " _comment "\n", __LINE__, ##_args);       \
      }                                                                       \
    _evald;                                                                   \
  })

#define AUTO_SDL_TEST(_cond, _comment, _args...)                              \
  {                                                                           \
    if (!AUTO_SDL_TEST_I (_cond, _comment, ##_args))                          \
      {                                                                       \
	return 1;                                                             \
      }                                                                       \
  }

static void
auto_sdl_test_disable_rt_backend_engine (vlib_main_t *vm)
{
  session_enable_disable_args_t args = { .is_en = 0,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_DISABLE };
  vnet_session_enable_disable (vm, &args);
}

static void
auto_sdl_test_enable_sdl_engine (vlib_main_t *vm)
{
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_SDL };
  vnet_session_enable_disable (vm, &args);
}

static int
auto_sdl_test_auto_sdl (vlib_main_t *vm, unformat_input_t *input)
{
  u32 rmt_plen = 0;
  ip46_address_t rmt_ip = {};
  int fib_proto = ~0;
  u8 *ns_id = 0;
  auto_sdl_track_prefix_args_t args;
  app_namespace_t *app_ns;
  u8 *tag = 0;
  u32 action = 0;
  int error = 0;
  auto_sdl_config_args_t asdl_args = {
    .enable = 1,
    .remove_timeout = 300,
    .threshold = 1,
  };
  auto_sdl_plugin_methods_t auto_sdl_plugin;
  clib_error_t *init_res;

  auto_sdl_test_disable_rt_backend_engine (vm);
  auto_sdl_test_enable_sdl_engine (vm);
  if (session_sdl_is_enabled () == 0)
    {
      vlib_cli_output (vm, "session sdl engine is not enabled");
      return -1;
    }
  init_res = auto_sdl_plugin_exports_init (&auto_sdl_plugin);
  if (init_res)
    {
      vlib_cli_output (vm, "Error in auto sdl plugin init");
      return -1;
    }
  auto_sdl_plugin.config (&asdl_args);

  if (unformat_check_input (input) == UNFORMAT_END_OF_INPUT)
    {
      const char ip_str[] = "10.1.0.0";
      const char ip6_str[] = "2501:0db8:85a3:0000:0000:8a2e:0371:0";
      u32 address;
      ip6_address_t address6;
      memset (&args, 0, sizeof (args));
      rmt_plen = 32;
      fib_proto = FIB_PROTOCOL_IP4;
      app_ns = app_namespace_get_default ();
      inet_pton (AF_INET, ip_str, &address);
      address = htonl (address);
      for (int j = 1; j <= 10; j++)
	{
	  address += (j << 8);
	  for (int i = 1; i < 255; i++)
	    {
	      address++;
	      rmt_ip.ip4.as_u32 = ntohl (address);
	      args.prefix.fp_addr = rmt_ip;
	      args.prefix.fp_proto = fib_proto;
	      args.prefix.fp_len = rmt_plen;
	      args.action_index = action;
	      args.tag = tag;
	      args.fib_index = app_namespace_get_fib_index (app_ns, fib_proto);

	      if (auto_sdl_plugin.track_prefix (&args) != 0)
		{
		  vlib_cli_output (vm, "error adding track prefix");
		  error = -1;
		  goto done;
		}
	    }
	}
      /* Add ip6 */
      inet_pton (AF_INET6, ip6_str, &address6);
      fib_proto = FIB_PROTOCOL_IP6;
      rmt_plen = 128;
      for (int i = 1; i < 255; i++)
	{
	  address = htonl (address6.as_u32[3]);
	  address++;
	  address6.as_u32[3] = ntohl (address);
	  memcpy (&rmt_ip.ip6, &address6, sizeof (address6));
	  args.prefix.fp_addr = rmt_ip;
	  args.prefix.fp_proto = fib_proto;
	  args.prefix.fp_len = rmt_plen;
	  args.action_index = action;
	  args.tag = tag;
	  args.fib_index = app_namespace_get_fib_index (app_ns, fib_proto);

	  if (auto_sdl_plugin.track_prefix (&args) != 0)
	    {
	      vlib_cli_output (vm, "error adding track prefix");
	      error = -1;
	      goto done;
	    }
	}

      uword expected = 254 * 10 + 254;
      uword total = auto_sdl_plugin.pool_size ();
      AUTO_SDL_TEST ((total == expected),
		     "total auto sdl entries is %u, expected %u", total,
		     expected);
      auto_sdl_test_disable_rt_backend_engine (vm);
      total = auto_sdl_plugin.pool_size ();
      expected = 0;
      AUTO_SDL_TEST ((total == expected),
		     "total auto sdl entries is %u, expected %u", total,
		     expected);
      goto done;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U/%d", unformat_ip4_address, &rmt_ip.ip4,
		    &rmt_plen))
	fib_proto = FIB_PROTOCOL_IP4;
      else if (unformat (input, "%U/%d", unformat_ip6_address, &rmt_ip.ip6,
			 &rmt_plen))
	fib_proto = FIB_PROTOCOL_IP6;
      else if (unformat (input, "action %d", &action))
	;
      else if (unformat (input, "tag %_%v%_", &tag))
	;
      else if (unformat (input, "appns %_%v%_", &ns_id))
	;
      else
	{
	  vlib_cli_output (vm, "unknown input `%U'", format_unformat_error,
			   input);
	  error = -1;
	  goto done;
	}
    }

  if (fib_proto == ~0)
    {
      vlib_cli_output (vm, "tracked prefix must be entered");
      error = -1;
      goto done;
    }

  if (vec_len (tag) > SESSION_RULE_TAG_MAX_LEN)
    {
      vlib_cli_output (vm, "tag too long (max u64)");
      error = -1;
      goto done;
    }

  if (ns_id)
    {
      app_ns = app_namespace_get_from_id (ns_id);
      if (!app_ns)
	{
	  vlib_cli_output (vm, "namespace %v does not exist", ns_id);
	  error = -1;
	  goto done;
	}
    }
  else
    app_ns = app_namespace_get_default ();

  memset (&args, 0, sizeof (args));
  args.prefix.fp_addr = rmt_ip;
  args.prefix.fp_proto = fib_proto;
  args.prefix.fp_len = rmt_plen;
  args.action_index = action;
  args.tag = tag;
  args.fib_index = app_namespace_get_fib_index (app_ns, fib_proto);

  if (auto_sdl_plugin.track_prefix (&args) != 0)
    {
      vlib_cli_output (vm, "error adding track prefix");
      error = -1;
    }
done:
  vec_free (ns_id);
  vec_free (tag);
  return error;

  return 0;
}

static clib_error_t *
auto_sdl_test_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd_arg)
{
  int res = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "all"))
	;
      res = auto_sdl_test_auto_sdl (vm, input);
      goto done;
    }

done:
  if (res)
    return clib_error_return (0, "Auto SDL unit test failed");
  return 0;
}

VLIB_CLI_COMMAND (auto_sdl_test_command, static) = {
  .path = "test auto-sdl",
  .short_help = "auto-sdl unit tests",
  .function = auto_sdl_test_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Auto SDL - Unit Test",
  .default_disabled = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
