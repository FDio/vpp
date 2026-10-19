/* SPDX-License-Identifier: Apache-2.0 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <ikev2/ikev2_priv.h>

static clib_error_t *
test_ikev2_sa_format (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  ikev2_main_t *km = vlib_get_plugin_symbol ("ikev2_plugin.so", "ikev2_main");
  format_function_t *formatter = vlib_get_plugin_symbol ("ikev2_plugin.so", "format_ikev2_sa");
  if (!km || !formatter)
    return clib_error_return (0, "IKEv2 formatter symbols unavailable");
  if (vlib_num_workers () || pool_elts (km->profiles) || pool_elts (km->sas) ||
      pool_elts (km->sais))
    return clib_error_return (0, "IKEv2 formatter test requires no workers, profiles or SAs");
  ikev2_profile_t *saved_profiles = km->profiles, *p = 0;
  ikev2_sa_t sa = { .profile_index = ~0 };
  clib_error_t *error = 0;
  u8 *s = 0;

  /* Use an isolated pool and empty keys; never print the formatted SA. */
  km->profiles = 0;
  for (int scenario = 0; scenario < 4; scenario++)
    {
      if (scenario == 1)
	{
	  pool_get_zero (km->profiles, p);
	  p->name = format (0, "formatter-test");
	}
      if (scenario == 2)
	sa.profile_index = p - km->profiles;
      if (scenario == 3)
	{
	  vec_free (p->name);
	  pool_put (km->profiles, p);
	}

      for (int details = 0; details <= 1; details++)
	{
	  s = format (0, "%U%c", formatter, &sa, details, 0);
	  if (!strstr ((char *) s, "iip ") ||
	      (details && !strstr ((char *) s, scenario == 2 ? "\n profile: formatter-test" :
							       "\n profile: none")))
	    {
	      error = clib_error_return (0, "scenario %d details %d failed", scenario, details);
	      goto done;
	    }
	  vec_free (s);
	}
    }

  vlib_cli_output (vm, "PASS: 4 profile states, summary and details");
done:
  vec_free (s);
  pool_foreach (p, km->profiles)
    vec_free (p->name);
  pool_free (km->profiles);
  km->profiles = saved_profiles;
  return error;
}

VLIB_CLI_COMMAND (test_ikev2_sa_format_command, static) = {
  .path = "test ikev2 sa-format",
  .short_help = "test ikev2 sa-format",
  .function = test_ikev2_sa_format,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "IKEv2 formatter unit test",
  .default_disabled = 1,
};
