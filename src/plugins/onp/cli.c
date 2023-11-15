/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP CLI implementation.
 */

#include <onp/onp.h>

static const char *ul = "====================================================="
			"=========================";

static void
onp_print_global_counters (vlib_main_t *vm, u64 **stat, u64 *pool_stat,
			   u32 n_threads)
{
  u64 global_stat[ONP_MAX_COUNTERS] = { 0 };
  onp_main_t *om = onp_get_main ();
  unsigned int n_global_stats = 0;
  vlib_simple_counter_main_t *cm;
  u32 cnt_idx, thread_idx = 0;
  u64 global_pool_stat = 0;

  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)
    {
      for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
	{
	  if (stat[cnt_idx][thread_idx])
	    {
	      global_stat[cnt_idx] += stat[cnt_idx][thread_idx];
	      n_global_stats++;
	    }
	}
      global_pool_stat += pool_stat[thread_idx];
    }

  if (!n_global_stats && !global_pool_stat)
    return;

  /* Display cumulative counters */
  vlib_cli_output (vm, "%-16s %-40s %-20s", "", "Global counter", "Value");
  vlib_cli_output (vm, "%-16s %-.40s %-.20s", "", ul, ul);

#define _(i, s, n, v)                                                         \
  cm = &om->onp_counters.s##_counters;                                        \
  if (global_stat[i])                                                         \
    vlib_cli_output (vm, "%-16s %-40s %20Ld", "", cm->name, global_stat[i]);
  foreach_onp_counters;
#undef _

  if (global_pool_stat)
    vlib_cli_output (vm, "%-16s %-40s %20Ld", "",
		     "default-pool-current-refill-deplete-val",
		     global_pool_stat);
}

unsigned int
onp_get_per_thread_stats (u64 **stat, u64 *pool_stat, u32 n_threads,
			  u8 verbose, u8 *is_valid, u64 *threads_with_stats)
{
  unsigned int idx, cnt_idx, thread_idx = 0, n_threads_with_stats = 0;
  onp_main_t *om = onp_get_main ();
  cnxk_per_thread_data_t *ptd;

  for (idx = 0; idx < n_threads; idx++)
    {
      ptd = vec_elt_at_index (om->onp_per_thread_data, idx);
      pool_stat[idx] = ptd->refill_deplete_count_per_pool[0];
    }

#define _(i, s, n, v) is_valid[i] = verbose || !v;
  foreach_onp_counters;
#undef _

  /* Identify threads that have non-zero ONP counters */
  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)
    {
      if (pool_stat[thread_idx])
	{
	  threads_with_stats[n_threads_with_stats] = thread_idx;
	  n_threads_with_stats++;
	  continue;
	}
      for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
	{
	  if (!is_valid[cnt_idx])
	    continue;
	  if (stat[cnt_idx][thread_idx])
	    {
	      threads_with_stats[n_threads_with_stats++] = thread_idx;
	      break;
	    }
	}
    }

  return n_threads_with_stats;
}

static void
onp_print_per_thread_counters (vlib_main_t *vm, u64 **stat, u64 *pool_stat,
			       u32 n_threads, u8 verbose)
{
  unsigned int idx, thread_idx = 0, n_threads_with_stats = 0;
  u8 is_valid[ONP_MAX_COUNTERS] = { 0 };
  u64 threads_with_stats[n_threads];
  onp_main_t *om = onp_get_main ();
  vlib_simple_counter_main_t *cm;

  n_threads_with_stats = onp_get_per_thread_stats (
    stat, pool_stat, n_threads, verbose, is_valid, threads_with_stats);

  if (!n_threads_with_stats)
    return;

  vlib_cli_output (vm, "%-16s %-40s %-20s", "Thread", "Per-thread counter",
		   "Value");
  vlib_cli_output (vm, "%-.16s %-.40s %-.20s", ul, ul, ul);

  for (idx = 0; idx < n_threads_with_stats; idx++)
    {
      thread_idx = threads_with_stats[idx];

      vlib_cli_output (vm, "%-16s", vlib_worker_threads[thread_idx].name);

      /* clang-format off */
#define _(i, s, n, v)                                                       \
      cm = &om->onp_counters.s##_counters;                                  \
      if (is_valid[i] && stat[i][thread_idx])                               \
        vlib_cli_output (vm, "%-16s %-40s %20Ld", "", cm->name,             \
                         stat[i][thread_idx]);
      foreach_onp_counters;
#undef _
      /* clang-format on */

      /* Display stats with "current-refill-deplete-val" counter */
      if (pool_stat[thread_idx])
	vlib_cli_output (vm, "%-16s %-40s %20Ld", "",
			 "default-pool-current-refill-deplete-val",
			 pool_stat[thread_idx]);
    }

  vlib_cli_output (vm, "\n");

  return;
}

static clib_error_t *
onp_counters_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  unsigned int cnt_idx = 0, thread_idx = 0;
  onp_main_t *om = onp_get_main ();
  vlib_simple_counter_main_t *cm;
  cnxk_per_thread_data_t *ptd;
  u64 *stat[ONP_MAX_COUNTERS] = { 0 };
  u64 *pool_stat = NULL;
  counter_t *counters = NULL;
  u8 verbose = 0;
  u32 n_threads = vlib_get_n_threads ();

  while (unformat_check_input (input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	return clib_error_create ("Invalid input '%U'", format_unformat_error,
				  input);
    }

#define _(i, s, n, v)                                                         \
  cm = &om->onp_counters.s##_counters;                                        \
  vec_validate_init_empty (stat[i], n_threads, 0);                            \
  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)                  \
    {                                                                         \
      counters = cm->counters[thread_idx];                                    \
      stat[i][thread_idx] = counters[0];                                      \
    }
  foreach_onp_counters;
#undef _

  vec_validate_init_empty (pool_stat, n_threads, 0);
  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)
    {
      ptd = vec_elt_at_index (om->onp_per_thread_data, thread_idx);
      pool_stat[thread_idx] = ptd->refill_deplete_count_per_pool[0];
    }

  onp_print_per_thread_counters (vm, stat, pool_stat, n_threads, verbose);

  onp_print_global_counters (vm, stat, pool_stat, n_threads);

  for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
    vec_free (stat[cnt_idx]);

  vec_free (pool_stat);

  return 0;
}

/*?
 * This command displays ONP debug counters
 *
 * @cliexpar
 * Example of how to display ONP debug counters:
 * @cliexstart{show onp counters}
 * Per-thread counter                       Value
 * ======================================== ====================
 * default-pool-current-refill-deplete-val                     7
 *
 * Global counter                           Value
 * ======================================== ====================
 * default-pool-current-refill-deplete-val                     7
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_counters_command, static) = {
  .path = "show onp counters",
  .short_help = "show onp counters [verbose]",
  .function = onp_counters_command_fn,
};

static clib_error_t *
onp_counters_clear_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{

  vlib_simple_counter_main_t *cm;
  onp_main_t *om = onp_get_main ();

#define _(i, s, n, v)                                                         \
  cm = &om->onp_counters.s##_counters;                                        \
  vlib_clear_simple_counters (cm);
  foreach_onp_counters;
#undef _

  return 0;
}

/*?
 * This command clears ONP debug counters
 *
 * @cliexpar
 * @cliexstart{clear onp counters}
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_counters_clear_command, static) = {
  .path = "clear onp counters",
  .short_help = "clear onp counters",
  .function = onp_counters_clear_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
