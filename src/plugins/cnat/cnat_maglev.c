/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <cnat/cnat_maglev.h>

static int
cnat_maglev_perm_compare (void *_a, void *_b)
{
  return *(u64 *) _b - *(u64 *) _a;
  cnat_ep_trk_t *a = ((cnat_maglev_perm_t *) _a)->trk;
  cnat_ep_trk_t *b = ((cnat_maglev_perm_t *) _b)->trk;
  int rv = 0;
  if ((rv =
	 ip_address_cmp (&a->ct_ep[VLIB_TX].ce_ip, &b->ct_ep[VLIB_TX].ce_ip)))
    return rv;
  if ((rv = a->ct_ep[VLIB_TX].ce_port - a->ct_ep[VLIB_TX].ce_port))
    return rv;
  return 0;
}

/**
 * Maglev algorithm implementation. This takes permutation as input,
 * with the values of offset & skip for the backends.
 * It fills buckets matching the permuntations, provided buckets is
 * already of length at least M
 */
static void
cnat_maglev_shuffle (cnat_maglev_perm_t *permutation, u32 *buckets)
{
  u32 N, M, i, done = 0;
  u32 *next = 0;

  N = vec_len (permutation);
  if (N == 0)
    return;

  M = vec_len (buckets);
  vec_set (buckets, -1);

  vec_validate (next, N - 1);
  vec_zero (next);

  while (1)
    {
      for (i = 0; i < N; i++)
	{
	  u32 c = (permutation[i].offset + next[i] * permutation[i].skip) % M;
	  while (buckets[c] != (u32) -1)
	    {
	      next[i]++;
	      c = (permutation[i].offset + next[i] * permutation[i].skip) % M;
	    }

	  buckets[c] = permutation[i].index;
	  next[i]++;
	  done++;

	  if (done == M)
	    {
	      vec_free (next);
	      return;
	    }
	}
    }
}

void
cnat_translation_init_maglev (cnat_translation_t *ct)
{
  cnat_maglev_perm_t *permutations = NULL;
  cnat_main_t *cm = &cnat_main;
  cnat_ep_trk_t *trk;
  u32 backend_index = 0;

  if (vec_len (ct->ct_active_paths) == 0)
    return;

  vec_foreach (trk, ct->ct_active_paths)
    {
      cnat_maglev_perm_t bk;
      u32 h1, h2;

      if (AF_IP4 == ip_addr_version (&trk->ct_ep[VLIB_TX].ce_ip))
	{
	  u32 a, b, c;
	  a = ip_addr_v4 (&trk->ct_ep[VLIB_TX].ce_ip).data_u32;
	  b = (u64) trk->ct_ep[VLIB_TX].ce_port;
	  c = 0;
	  hash_v3_mix32 (a, b, c);
	  hash_v3_finalize32 (a, b, c);
	  h1 = c;
	  h2 = b;
	}
      else
	{
	  u64 a, b, c;
	  a = ip_addr_v6 (&trk->ct_ep[VLIB_TX].ce_ip).as_u64[0];
	  b = ip_addr_v6 (&trk->ct_ep[VLIB_TX].ce_ip).as_u64[1];
	  c = (u64) trk->ct_ep[VLIB_TX].ce_port;
	  hash_mix64 (a, b, c);
	  h1 = c;
	  h2 = b;
	}

      bk.offset = h1 % cm->maglev_len;
      bk.skip = h2 % (cm->maglev_len - 1) + 1;
      bk.trk = trk;
      bk.index = backend_index++;

      if (trk->ct_flags & CNAT_TRK_FLAG_TEST_DISABLED)
	continue;

      vec_add1 (permutations, bk);
    }

  vec_sort_with_function (permutations, cnat_maglev_perm_compare);

  vec_validate (ct->lb_maglev, cm->maglev_len - 1);

  cnat_maglev_shuffle (permutations, ct->lb_maglev);

  vec_free (permutations);
}

static int
cnat_u32_vec_contains (u32 *v, u32 e)
{
  int i;

  vec_foreach_index (i, v)
    if (v[i] == e)
      return 1;

  return 0;
}

static void
cnat_maglev_print_changes (vlib_main_t *vm, u32 *changed_bk_indices,
			   u32 *old_maglev_lb, u32 *new_maglev_lb)
{
  u32 good_flow_buckets = 0, reset_flow_buckets = 0, stable_to_reset = 0;
  u32 reset_to_stable = 0, switched_stable = 0;
  for (u32 i = 0; i < vec_len (new_maglev_lb); i++)
    {
      u8 is_new_changed =
	cnat_u32_vec_contains (changed_bk_indices, new_maglev_lb[i]);
      u8 is_old_changed =
	cnat_u32_vec_contains (changed_bk_indices, old_maglev_lb[i]);
      if (new_maglev_lb[i] == old_maglev_lb[i])
	{
	  if (is_new_changed)
	    reset_flow_buckets++;
	  else
	    good_flow_buckets++;
	}
      else
	{
	  if (is_new_changed)
	    stable_to_reset++;
	  else if (is_old_changed)
	    reset_to_stable++;
	  else
	    switched_stable++;
	}
    }
  vlib_cli_output (vm,
		   "good B->B:%d | lost A->A':%d A->B:%d ~%0.2f%% | bad "
		   "B->A':%d B->C:%d ~%0.2f%%",
		   good_flow_buckets, reset_flow_buckets, reset_to_stable,
		   (f64) (reset_flow_buckets + reset_to_stable) /
		     vec_len (new_maglev_lb) * 100.0,
		   stable_to_reset, switched_stable,
		   (f64) (stable_to_reset + switched_stable) /
		     vec_len (new_maglev_lb) * 100.0);
}

static u8 *
format_cnat_maglev_buckets (u8 *s, va_list *args)
{
  u32 *buckets = va_arg (*args, u32 *);
  u32 backend_idx = va_arg (*args, u32);
  u32 count = va_arg (*args, u32);

  for (u32 ii = 0; ii < vec_len (buckets); ii++)
    if (buckets[ii] == backend_idx)
      {
	s = format (s, "%d,", ii);
	if (--count == 0)
	  return (s);
      }
  return (s);
}

static clib_error_t *
cnat_translation_test_init_maglev (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  cnat_translation_t *trs = 0, *ct;
  u64 num_backends = 0, n_tests = 0;
  cnat_main_t *cm = &cnat_main;
  cnat_ep_trk_t *trk;
  u32 rnd;
  u32 n_changes = 0, n_remove = 0, verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tests %d", &n_tests))
	;
      else if (unformat (input, "backends %d", &num_backends))
	;
      else if (unformat (input, "len %d", &cm->maglev_len))
	;
      else if (unformat (input, "change %d", &n_changes))
	;
      else if (unformat (input, "rm %d", &n_remove))
	;
      else if (unformat (input, "verbose %d", &verbose))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (num_backends == 0 || n_tests == 0)
    return (clib_error_return (0, "No backends / tests to run"));
  ;

  vlib_cli_output (vm, "generating random backends...");
  rnd = random_default_seed ();

  vec_validate (trs, n_tests - 1);
  vec_foreach (ct, trs)
    {
      vec_validate (ct->ct_active_paths, num_backends - 1);
      vec_foreach (trk, ct->ct_active_paths)
	{
	  trk->ct_flags = 0;
	  ip_addr_version (&trk->ct_ep[VLIB_TX].ce_ip) = AF_IP4;
	  ip_addr_v4 (&trk->ct_ep[VLIB_TX].ce_ip).data_u32 = random_u32 (&rnd);
	  trk->ct_ep[VLIB_TX].ce_port = random_u32 (&rnd);
	}
    }

  vlib_cli_output (vm, "testing...");
  f64 start_time = vlib_time_now (vm);
  vec_foreach (ct, trs)
    cnat_translation_init_maglev (ct);
  f64 d = vlib_time_now (vm) - start_time;

  vlib_cli_output (vm, "Test took : %U", format_duration, d);
  vlib_cli_output (vm, "Per pool  : %U", format_duration, d / n_tests);

  /* sanity checking of the output */
  u32 *backend_freqs = 0;
  vec_validate (backend_freqs, num_backends - 1);
  vec_foreach (ct, trs)
    {
      if (vec_len (ct->lb_maglev) != cm->maglev_len)
	vlib_cli_output (vm, "Unexpected bucket length %d",
			 vec_len (ct->lb_maglev));

      vec_zero (backend_freqs);
      for (u32 i = 0; i < vec_len (ct->lb_maglev); i++)
	{
	  if (ct->lb_maglev[i] >= num_backends)
	    clib_warning ("out of bound backend");
	  backend_freqs[ct->lb_maglev[i]]++;
	}
      u32 fmin = ~0, fmax = 0;
      for (u32 i = 0; i < num_backends; i++)
	{
	  if (backend_freqs[i] > fmax)
	    fmax = backend_freqs[i];
	  if (backend_freqs[i] < fmin)
	    fmin = backend_freqs[i];
	}
      f64 fdiff = (fmax - fmin);
      if (fdiff / vec_len (ct->lb_maglev) - 1 > 0.02)
	vlib_cli_output (vm, "More than 2%% frequency diff (min %d max %d)",
			 fmin, fmax);
    }
  vec_free (backend_freqs);

  int i = 0;
  if (verbose)
    vec_foreach (ct, trs)
      {
	vlib_cli_output (vm, "Translation %d", i++);
	for (u32 i = 0; i < verbose; i++)
	  {
	    u32 j = random_u32 (&rnd) % vec_len (ct->ct_active_paths);
	    trk = &ct->ct_active_paths[j];
	    vlib_cli_output (
	      vm, "[%03d] %U:%d buckets:%U", j, format_ip_address,
	      &trk->ct_ep[VLIB_TX].ce_ip, trk->ct_ep[VLIB_TX].ce_port,
	      format_cnat_maglev_buckets, ct->lb_maglev, j, verbose);
	  }
      }

  if (n_remove != 0)
    {
      vlib_cli_output (
	vm, "Removing %d entries (refered to as A), others (B,C) stay same",
	n_remove);
      vec_foreach (ct, trs)
	{
	  u32 *old_maglev_lb = 0;
	  u32 *changed_bk_indices = 0;
	  if (vec_len (ct->lb_maglev) != cm->maglev_len)
	    vlib_cli_output (vm, "Unexpected bucket length %d",
			     vec_len (ct->lb_maglev));

	  vec_validate (changed_bk_indices, n_remove - 1);
	  for (u32 i = 0; i < n_remove; i++)
	    {
	      /* remove n_remove backends from the LB set */
	      changed_bk_indices[i] =
		random_u32 (&rnd) % vec_len (ct->ct_active_paths);
	      trk = &ct->ct_active_paths[changed_bk_indices[i]];
	      trk->ct_flags |= CNAT_TRK_FLAG_TEST_DISABLED;
	    }

	  old_maglev_lb = vec_dup (ct->lb_maglev);
	  cnat_translation_init_maglev (ct);

	  cnat_maglev_print_changes (vm, changed_bk_indices, old_maglev_lb,
				     ct->lb_maglev);

	  vec_free (changed_bk_indices);
	  vec_free (old_maglev_lb);
	}
    }

  /* Reshuffle and check changes */
  if (n_changes != 0)
    {
      vlib_cli_output (
	vm,
	"Changing %d entries (refered to as A->A'), others (B,C) stay same",
	n_changes);
      vec_foreach (ct, trs)
	{
	  if (vec_len (ct->lb_maglev) != cm->maglev_len)
	    vlib_cli_output (vm, "Unexpected bucket length %d",
			     vec_len (ct->lb_maglev));

	  u32 *old_maglev_lb = 0;
	  u32 *changed_bk_indices = 0;

	  vec_validate (changed_bk_indices, n_changes - 1);
	  for (u32 i = 0; i < n_changes; i++)
	    {
	      /* Change n_changes backends in the LB set */
	      changed_bk_indices[i] =
		random_u32 (&rnd) % vec_len (ct->ct_active_paths);
	      trk = &ct->ct_active_paths[changed_bk_indices[i]];
	      ip_addr_v4 (&trk->ct_ep[VLIB_TX].ce_ip).data_u32 =
		random_u32 (&rnd);
	      trk->ct_ep[VLIB_TX].ce_port = random_u32 (&rnd) & 0xffff;
	    }
	  old_maglev_lb = vec_dup (ct->lb_maglev);

	  cnat_translation_init_maglev (ct);
	  cnat_maglev_print_changes (vm, changed_bk_indices, old_maglev_lb,
				     ct->lb_maglev);

	  vec_free (changed_bk_indices);
	  vec_free (old_maglev_lb);
	}
    }

  vec_foreach (ct, trs)
    vec_free (ct->ct_active_paths);
  vec_free (trs);

  return (NULL);
}

VLIB_CLI_COMMAND (cnat_translation_test_init_maglev_cmd, static) = {
  .path = "test cnat maglev",
  .short_help = "test cnat maglev tests [n_tests] backends [num_backends] len "
		"[maglev_len]",
  .function = cnat_translation_test_init_maglev,
};
