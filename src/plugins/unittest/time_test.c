/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vppinfra/time.h>

/*
 * Test that clib_time_verify_frequency() never reduces total_cpu_time,
 * ensuring time always moves forward.
 *
 * When resyncing with wall clock, total_cpu_time could be recalculated
 * to a smaller value if the previous value was inflated. The clib_max
 * protection ensures this never causes time to go backward.
 */
static clib_error_t *
test_time_monotonicity (vlib_main_t *vm)
{
  clib_time_t ct;
  u64 inflated_total;

  clib_time_init (&ct);

  /* Let some time pass to establish baseline */
  clib_time_now (&ct);

  /*
   * Simulate clock running fast by artificially inflating total_cpu_time.
   * This can happen if TSC runs faster than expected.
   */
  ct.total_cpu_time += (u64) (ct.clocks_per_second * 10.0);
  inflated_total = ct.total_cpu_time;

  /*
   * Call verify_frequency directly to trigger recalculation of total_cpu_time
   * based on wall clock. Without clib_max protection, this would reduce
   * total_cpu_time below the inflated value.
   */
  clib_time_verify_frequency (&ct);

  if (ct.total_cpu_time < inflated_total)
    return clib_error_return (0,
			      "total_cpu_time decreased: was %llu, now %llu (monotonicity broken)",
			      inflated_total, ct.total_cpu_time);

  vlib_cli_output (vm, "Monotonicity test passed: total_cpu_time preserved");
  return 0;
}

/*
 * Test that large CPU time discontinuities (e.g., from CPU migration)
 * are handled correctly and don't cause integer underflow.
 */
static clib_error_t *
test_time_discontinuity (vlib_main_t *vm)
{
  clib_time_t ct;
  f64 t1, t2;
  u64 old_cpu_time;

  clib_time_init (&ct);

  /* Get initial time */
  t1 = clib_time_now (&ct);
  old_cpu_time = ct.last_cpu_time;

  /*
   * Simulate CPU migration by setting timestamps to values larger than
   * what clib_cpu_time_now() will return. This mimics moving to a CPU
   * with a lower TSC value, where both last_cpu_time and last_verify_cpu_time
   * are from the old CPU.
   */
  ct.last_cpu_time = old_cpu_time + (u64) (ct.clocks_per_second * 100.0);
  ct.last_verify_cpu_time = old_cpu_time + (u64) (ct.clocks_per_second * 100.0);

  t2 = clib_time_now (&ct);

  /*
   * Time should still be reasonable - not jumped by years due to underflow.
   */
  if (t2 < t1)
    return clib_error_return (0, "Time went backward after discontinuity: t1=%.6f t2=%.6f", t1, t2);

  if (t2 > t1 + 1000.0)
    return clib_error_return (0, "Time jumped too far forward (underflow?): t1=%.6f t2=%.6f", t1,
			      t2);

  vlib_cli_output (vm, "Discontinuity test passed: t1=%.6f t2=%.6f", t1, t2);
  return 0;
}

/*
 * Test that small CPU time backward jumps are handled correctly.
 *
 * This tests the case where n < last_cpu_time but the jump isn't large
 * enough to trigger the periodic verify check (n - last_verify_cpu_time
 * doesn't overflow enough). Without the n < last_cpu_time check, this
 * would cause integer underflow in total_cpu_time calculation.
 */
static clib_error_t *
test_time_small_backward_jump (vlib_main_t *vm)
{
  clib_time_t ct;
  f64 t1, t2;

  clib_time_init (&ct);

  /* Get initial time */
  t1 = clib_time_now (&ct);

  /*
   * Simulate a small backward jump by only advancing last_cpu_time.
   * Keep last_verify_cpu_time unchanged so the periodic verify check
   * doesn't trigger. This exercises the n < last_cpu_time check.
   */
  ct.last_cpu_time += (u64) (ct.clocks_per_second * 1.0);

  t2 = clib_time_now (&ct);

  /*
   * Time should still be reasonable - not jumped due to underflow.
   */
  if (t2 < t1)
    return clib_error_return (0, "Time went backward after small jump: t1=%.6f t2=%.6f", t1, t2);

  if (t2 > t1 + 1000.0)
    return clib_error_return (0, "Time jumped too far forward (underflow?): t1=%.6f t2=%.6f", t1,
			      t2);

  vlib_cli_output (vm, "Small backward jump test passed: t1=%.6f t2=%.6f", t1, t2);
  return 0;
}

/*
 * Test that barrier sync preserves time monotonicity on worker threads.
 *
 * When a worker thread releases from a barrier, it resyncs its time offset
 * with the main thread. The fix in vlib_worker_thread_barrier_check() ensures
 * that time never goes backward even if the calculated offset would cause
 * time regression.
 *
 * To reliably trigger the bug condition, we inflate workers' time_offset
 * between two barriers. This simulates the effect of TSC drift or CPU
 * migration where a worker's perceived time gets ahead of the main thread.
 * On the next barrier release:
 *   - Without the fix: the worker resyncs to main's time, causing a backward
 *     jump (time_last_barrier_release ≈ main_time, much less than the
 *     pre-barrier worker time of main_time + inflate).
 *   - With the fix: the offset is clamped so the worker's time never
 *     decreases (time_last_barrier_release ≈ main_time + inflate).
 */

#define BARRIER_TEST_TIME_INFLATE 10.0

static clib_error_t *
test_barrier_time_monotonicity (vlib_main_t *vm)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  u32 n_threads = vlib_get_n_threads ();
  f64 *prev_times = 0;
  clib_error_t *error = 0;

  if (n_threads < 2)
    {
      vlib_cli_output (vm, "Test requires workers, skipping");
      return 0;
    }

  /*
   * The CLI handler runs inside a barrier held by the API framework
   * (cli_inband is dispatched with barrier sync, potentially nested
   * inside the RPC barrier). Release all levels so our explicit barrier
   * operations work correctly and vlib_worker_wait_one_loop does not
   * return immediately.
   */
  int outer_barrier_depth = 0;
  while (vlib_worker_thread_barrier_held ())
    {
      vlib_worker_thread_barrier_release (vm);
      outer_barrier_depth++;
    }

  vec_validate (prev_times, n_threads - 1);

  /*
   * Phase 1: Normal barrier to establish baseline.
   */
  vlib_worker_thread_barrier_sync (vm);
  vlib_worker_thread_barrier_release (vm);
  vlib_worker_wait_one_loop ();

  for (u32 i = 1; i < n_threads; i++)
    prev_times[i] = vgm->vlib_mains[i]->time_last_barrier_release;

  /*
   * Phase 2: Inject clock drift by inflating workers' time_offset.
   *
   * After this, workers perceive time as ~BARRIER_TEST_TIME_INFLATE seconds
   * ahead of main. At the next barrier entry, the worker's pre-barrier time
   * t = vlib_time_now(vm) includes this inflation.
   */
  for (u32 i = 1; i < n_threads; i++)
    vgm->vlib_mains[i]->time_offset += BARRIER_TEST_TIME_INFLATE;

  /* Ensure workers run with inflated time before the next barrier */
  vlib_worker_wait_one_loop ();

  /*
   * Phase 3: Barrier with inflated worker time.
   *
   * Workers enter barrier with t ≈ main_time + INFLATE.
   * At release, main_time_release ≈ main_time (no inflation).
   * Without fix: worker time drops to main_time (backward jump).
   * With fix: worker time clamped at t ≈ main_time + INFLATE.
   */
  vlib_worker_thread_barrier_sync (vm);
  vlib_worker_thread_barrier_release (vm);
  vlib_worker_wait_one_loop ();

  {
    f64 main_time = vgm->vlib_mains[0]->time_last_barrier_release;

    for (u32 i = 1; i < n_threads; i++)
      {
	f64 worker_time = vgm->vlib_mains[i]->time_last_barrier_release;
	f64 drift = worker_time - main_time;

	/*
	 * With the fix, drift should be close to BARRIER_TEST_TIME_INFLATE
	 * (offset was clamped to preserve the inflated pre-barrier time).
	 * Without the fix, drift would be ~0 (worker resynced to main).
	 */
	if (drift < BARRIER_TEST_TIME_INFLATE / 2)
	  {
	    error =
	      clib_error_return (0,
				 "Worker %u time not preserved after drift injection: "
				 "worker_time=%.6f main_time=%.6f drift=%.6f (expected ~%.1f)",
				 i, worker_time, main_time, drift, BARRIER_TEST_TIME_INFLATE);
	    goto done;
	  }

	/* Also verify monotonicity vs previous barrier */
	if (worker_time < prev_times[i] - 0.001)
	  {
	    error = clib_error_return (0, "Worker %u time went backward: prev=%.6f curr=%.6f", i,
				       prev_times[i], worker_time);
	    goto done;
	  }

	vlib_cli_output (vm, "  Worker %u: time=%.6f main_time=%.6f drift=%.6f offset=%.6f", i,
			 worker_time, main_time, drift, vgm->vlib_mains[i]->time_offset);

	prev_times[i] = worker_time;
      }
  }

  /*
   * Phase 4: Run a few more normal barriers and verify monotonicity is
   * maintained as workers converge back toward main thread time.
   */
  for (int iter = 0; iter < 5; iter++)
    {
      vlib_worker_thread_barrier_sync (vm);
      vlib_worker_thread_barrier_release (vm);
      vlib_worker_wait_one_loop ();

      for (u32 i = 1; i < n_threads; i++)
	{
	  f64 curr_time = vgm->vlib_mains[i]->time_last_barrier_release;
	  if (curr_time < prev_times[i] - 0.001)
	    {
	      error = clib_error_return (0,
					 "Worker %u time went backward in convergence phase: "
					 "iter=%d prev=%.6f curr=%.6f",
					 i, iter, prev_times[i], curr_time);
	      goto done;
	    }
	  prev_times[i] = curr_time;
	}
    }

  vlib_cli_output (vm, "Barrier time monotonicity test passed");

done:
  vec_free (prev_times);

  /* Re-acquire barrier levels for the API framework */
  for (int i = 0; i < outer_barrier_depth; i++)
    vlib_worker_thread_barrier_sync (vm);

  return error;
}

static clib_error_t *
test_time_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  int test_monotonicity = 0;
  int test_discontinuity = 0;
  int test_small_backward = 0;
  int test_barrier = 0;
  int test_all = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "monotonicity"))
	test_monotonicity = 1;
      else if (unformat (input, "discontinuity"))
	test_discontinuity = 1;
      else if (unformat (input, "small-backward"))
	test_small_backward = 1;
      else if (unformat (input, "barrier"))
	test_barrier = 1;
      else if (unformat (input, "all"))
	test_all = 1;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  if (test_all)
    test_monotonicity = test_discontinuity = test_small_backward = test_barrier = 1;

  if (!test_monotonicity && !test_discontinuity && !test_small_backward && !test_barrier)
    return clib_error_return (
      0, "specify test: monotonicity | discontinuity | small-backward | barrier | all");

  if (test_monotonicity)
    {
      error = test_time_monotonicity (vm);
      if (error)
	return error;
    }

  if (test_discontinuity)
    {
      error = test_time_discontinuity (vm);
      if (error)
	return error;
    }

  if (test_small_backward)
    {
      error = test_time_small_backward_jump (vm);
      if (error)
	return error;
    }

  if (test_barrier)
    {
      error = test_barrier_time_monotonicity (vm);
      if (error)
	return error;
    }

  vlib_cli_output (vm, "All requested time tests passed");
  return 0;
}

VLIB_CLI_COMMAND (test_time_command, static) = {
  .path = "test time",
  .short_help = "test time [monotonicity | discontinuity | small-backward | barrier | all]",
  .function = test_time_command_fn,
};
