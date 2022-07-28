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
 * Test that barrier sync preserves time monotonicity on worker threads.
 *
 * When a worker thread releases from a barrier, it resyncs its time offset
 * with main thread. If main thread's time_last_barrier_release is behind
 * the worker's pre-barrier time, the offset must be clamped to prevent
 * time from going backward.
 *
 * This tests the fix in vlib_worker_thread_barrier_check().
 */

static u32 time_test_worker_ready;
static u32 time_test_main_done;

static uword
time_test_input_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (vm->thread_index == 0)
    return 0;

  /* Tell main we are past the barrier */
  clib_atomic_store_rel_n (&time_test_worker_ready, 1);

  /* Spin until main has finished changing time_offset */
  while (!clib_atomic_load_acq_n (&time_test_main_done))
    CLIB_PAUSE ();

  vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);
  return 0;
}

VLIB_REGISTER_NODE (time_test_input_node) = {
  .function = time_test_input_fn,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "time-test-barrier-input",
  .state = VLIB_NODE_STATE_DISABLED,
};

static clib_error_t *
test_barrier_time_monotonicity (vlib_main_t *vm)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  u32 n_threads = vlib_get_n_threads ();
  clib_error_t *error = 0;
  f64 saved_time_offset;

  if (n_threads < 2)
    {
      vlib_cli_output (vm, "Test requires workers, skipping");
      return 0;
    }

  clib_atomic_store_relax_n (&time_test_worker_ready, 0);
  clib_atomic_store_relax_n (&time_test_main_done, 0);

  /* Enable the input node on the worker under barrier so it will
   * run on the first iteration after barrier release. */
  vlib_worker_thread_barrier_sync (vm);
  foreach_vlib_main ()
    {
      if (this_vlib_main->thread_index != 0)
	vlib_node_set_state (this_vlib_main, time_test_input_node.index, VLIB_NODE_STATE_POLLING);
    }
  vlib_worker_thread_barrier_release (vm);

  /* Wait for the worker to signal it is past the barrier.
   * Main's time is still normal so vlib_process_suspend works. */
  while (!clib_atomic_load_acq_n (&time_test_worker_ready))
    vlib_process_suspend (vm, 1e-4);

  /* Worker is spinning in input node. Record worker's current
   * time_last_barrier_release before we perturb anything. */
  f64 before = vgm->vlib_mains[1]->time_last_barrier_release;

  /* Let worker continue — it will loop back and enter the barrier check
   * on the next barrier sync. */
  clib_atomic_store_rel_n (&time_test_main_done, 1);

  /* Take the barrier with normal time (avoids assert on
   * barrier_no_close_before). Then shift main's time backward while
   * barrier is held — barrier_release will set time_last_barrier_release
   * from the shifted time, making it ~10s behind the worker's time. */
  vlib_worker_thread_barrier_sync (vm);
  saved_time_offset = vm->time_offset;
  vm->time_offset -= 10.0;
  vlib_worker_thread_barrier_release (vm);

  f64 after = vgm->vlib_mains[1]->time_last_barrier_release;

  if (after < before)
    {
      error =
	clib_error_return (0, "Worker 1 time went backward: before=%.6f after=%.6f", before, after);
    }
  else
    {
      vlib_cli_output (vm, "  Worker 1: before=%.6f after=%.6f (ok)", before, after);
      vlib_cli_output (vm, "Barrier time monotonicity test passed");
    }

  /* Restore main's time_offset and do a clean barrier to resync worker */
  vm->time_offset = saved_time_offset;
  vlib_worker_thread_barrier_sync (vm);
  vlib_worker_thread_barrier_release (vm);

  return error;
}

static clib_error_t *
test_time_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  int test_monotonicity = 0;
  int test_discontinuity = 0;
  int test_barrier = 0;
  int test_all = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "monotonicity"))
	test_monotonicity = 1;
      else if (unformat (input, "discontinuity"))
	test_discontinuity = 1;
      else if (unformat (input, "barrier"))
	test_barrier = 1;
      else if (unformat (input, "all"))
	test_all = 1;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  if (test_all)
    test_monotonicity = test_discontinuity = test_barrier = 1;

  if (!test_monotonicity && !test_discontinuity && !test_barrier)
    return clib_error_return (0, "specify test: monotonicity | discontinuity | barrier | all");

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
  .short_help = "test time [monotonicity | discontinuity | barrier | all]",
  .function = test_time_command_fn,
  .is_mp_safe = 1,
};
