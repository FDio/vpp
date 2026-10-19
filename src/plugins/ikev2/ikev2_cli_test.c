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

static u32
ikev2_test_available_buffers (vlib_main_t *vm)
{
  vlib_buffer_pool_t *bp;
  vlib_buffer_pool_thread_t *bpt;
  u32 available = 0;
  vec_foreach (bp, vm->buffer_main->buffer_pools)
    {
      available += bp->n_avail;
      vec_foreach (bpt, bp->threads)
	available += bpt->n_cached;
    }
  return available;
}

static clib_error_t *
test_ikev2_delete_failure (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  ikev2_main_t *km = vlib_get_plugin_symbol ("ikev2_plugin.so", "ikev2_main");
  if (!km || vlib_num_workers () || pool_elts (km->profiles) || pool_elts (km->sas) ||
      pool_elts (km->sais))
    return clib_error_return (0, "IKEv2 delete test requires no workers, profiles or SAs");
  /* Initialize crypto through the public CLI before installing isolated SAs. */
  const char *setup[] = { "ikev2 profile add delete-failure-test",
			  "ikev2 profile del delete-failure-test" };
  for (int i = 0; i < ARRAY_LEN (setup); i++)
    {
      unformat_input_t cli_input;
      unformat_init_cstring (&cli_input, setup[i]);
      int rc = vlib_cli_input (vm, &cli_input, 0, 0);
      unformat_free (&cli_input);
      if (rc)
	return clib_error_return (0, "test profile setup failed: %s", setup[i]);
    }
  ikev2_sa_t *saved_sas = km->sas, *sa;
  uword *saved_hash = km->sa_by_rspi;
  clib_error_t *error = 0;
  u32 bi, previous_index = ~0;
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return clib_error_return (0, "test buffer allocation failed");
  vlib_buffer_free (vm, &bi, 1);
  u32 available = ikev2_test_available_buffers (vm);
  km->sas = 0;
  km->sa_by_rspi = 0;
  pool_get_zero (km->sas, sa);
  sa->ispi = 0x1234;
  sa->rspi = 0x5678;
  hash_set (km->sa_by_rspi, sa->rspi, sa - km->sas);

  for (int initiator = 0; initiator <= 1; initiator++)
    {
      pool_get_zero (km->sas, sa);
      u32 index = sa - km->sas;
      sa->ispi = 0x11223344;
      sa->rspi = 0x55667788;
      sa->profile_index = ~0;
      sa->state = IKEV2_STATE_AUTHENTICATED;
      sa->is_initiator = initiator;
      ikev2_sa_proposal_t *proposal;
      ikev2_sa_transform_t *transform;
      vec_add2 (sa->r_proposals, proposal, 1);
      clib_memset (proposal, 0, sizeof (*proposal));
      proposal->protocol_id = IKEV2_PROTOCOL_IKE;
      vec_add2 (proposal->transforms, transform, 1);
      clib_memset (transform, 0, sizeof (*transform));
      transform->type = IKEV2_TRANSFORM_TYPE_ENCR;
      transform->encr_type = IKEV2_TRANSFORM_ENCR_TYPE_AES_GCM_16;
      u8 attrs[] = { 0x80, 14, 1, 0 };
      vec_add (transform->attrs, attrs, sizeof (attrs));
      hash_set (km->sa_by_rspi, sa->rspi, index);
      /* Missing encryption keys force the real message generator to fail. */
      unformat_input_t cli_input;
      unformat_init_cstring (&cli_input, "ikev2 initiate del-sa 11223344");
      int rc = vlib_cli_input (vm, &cli_input, 0, 0);
      unformat_free (&cli_input);
      uword *neighbor = hash_get (km->sa_by_rspi, 0x5678);
      if (rc || !pool_is_free_index (km->sas, index) || hash_get (km->sa_by_rspi, 0x55667788) ||
	  pool_elts (km->sas) != 1 || hash_elts (km->sa_by_rspi) != 1 || !neighbor ||
	  neighbor[0] != 0 || pool_is_free_index (km->sas, 0) || km->sas[0].ispi != 0x1234 ||
	  km->sas[0].rspi != 0x5678 || (initiator && index != previous_index) ||
	  ikev2_test_available_buffers (vm) != available)
	{
	  error =
	    clib_error_return (0, "role %d: rc %d, SAs %u, available buffers %u/%u", initiator, rc,
			       pool_elts (km->sas), ikev2_test_available_buffers (vm), available);
	  goto done;
	}
      previous_index = index;
    }
  vlib_cli_output (vm, "PASS: 2 Delete failures, buffer ownership and SA index reuse");
done:
  pool_foreach (sa, km->sas)
    {
      ikev2_sa_proposal_t *proposal;
      vec_foreach (proposal, sa->r_proposals)
	{
	  ikev2_sa_transform_t *transform;
	  vec_foreach (transform, proposal->transforms)
	    vec_free (transform->attrs);
	  vec_free (proposal->transforms);
	}
      vec_free (sa->r_proposals);
      vec_free (sa->del);
    }
  pool_free (km->sas);
  hash_free (km->sa_by_rspi);
  km->sas = saved_sas;
  km->sa_by_rspi = saved_hash;
  return error;
}

VLIB_CLI_COMMAND (test_ikev2_delete_failure_command, static) = {
  .path = "test ikev2 delete-failure",
  .short_help = "test ikev2 delete-failure",
  .function = test_ikev2_delete_failure,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "IKEv2 unit tests",
  .default_disabled = 1,
};
