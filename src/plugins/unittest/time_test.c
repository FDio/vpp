/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/time.h>
#include <vppinfra/time.h>

/* Verification may rebase the cycle accumulator when the applied rate
 * changes, but it must preserve the elapsed time represented by it. */
static clib_error_t *
test_time_monotonicity (vlib_main_t *vm)
{
  clib_time_t ct;
  f64 before, after;

  clib_time_init (&ct);

  /* Let some time pass to establish baseline */
  clib_time_now (&ct);

  /*
   * Simulate clock running fast by artificially inflating total_cpu_time.
   * This can happen if TSC runs faster than expected.
   */
  ct.total_cpu_time += (u64) (ct.clocks_per_second * 10.0);
  before = ct.total_cpu_time * ct.seconds_per_clock;

  /* A rate change must affect future time, not step the current time. */
  clib_time_verify_frequency (&ct);
  after = ct.total_cpu_time * ct.seconds_per_clock;

  if (after < before || after > before + 1.0)
    return clib_error_return (
      0, "Time stepped during frequency verification: before=%.6f after=%.6f",
      before, after);

  vlib_cli_output (vm, "Monotonicity test passed: elapsed time preserved");
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

/* A small backward move can stay above last_verify_cpu_time and must still
 * enter the slow path before the unsigned fast-path subtraction wraps. */
static clib_error_t *
test_time_small_discontinuity (vlib_main_t *vm)
{
  clib_time_t ct;
  f64 before, after;

  clib_time_init (&ct);
  before = clib_time_now (&ct);
  ct.last_cpu_time += (u64) (ct.clocks_per_second * 0.001);

  after = clib_time_now (&ct);
  if (after < before || after > before + 1.0)
    return clib_error_return (
      0, "Small CPU time discontinuity: before=%.6f after=%.6f", before,
      after);

  vlib_cli_output (vm, "Small discontinuity test passed");
  return 0;
}

/* A normal frequency sample must not erase phase error accumulated earlier. */
static clib_error_t *
test_time_accumulated_error (vlib_main_t *vm)
{
  const f64 errors[] = { 27.0, -0.25 };
  const f64 target_corrections[] = { 0.008, -0.25 / 60.0 };

  for (int i = 0; i < 2; i++)
    {
      clib_time_t ct;
      f64 error, correction, origin, previous_frequency, expected_frequency;

      clib_time_init (&ct);
      previous_frequency = ct.clocks_per_second;
      if (errors[i] > 0.0)
	ct.total_cpu_time += (u64) (ct.clocks_per_second * errors[i]);
      else
	ct.init_reference_time += errors[i];
      origin = ct.init_reference_time;

      /* The latest 16-second CPU/reference sample has the expected rate. */
      ct.last_verify_cpu_time =
	clib_cpu_time_now () - (u64) (16.0 * ct.clocks_per_second);
      ct.last_verify_reference_time = unix_time_now () - 16.0;
      clib_time_verify_frequency (&ct);

      error = ct.total_cpu_time * ct.seconds_per_clock -
	(ct.last_verify_reference_time - ct.init_reference_time);
      correction = 1.0 - previous_frequency / ct.clocks_per_second;
      expected_frequency = previous_frequency *
	(ct.damping_constant + (1.0 - ct.damping_constant) /
	  (1.0 - target_corrections[i]));
      if (ct.init_reference_time != origin ||
	  error < errors[i] - 0.1 || error > errors[i] + 0.1 ||
	  ct.clocks_per_second < expected_frequency * 0.9995 ||
	  ct.clocks_per_second > expected_frequency * 1.0005)
	return clib_error_return (
	  0, "Accumulated error %.3f: phase=%.6f correction=%.6f",
	  errors[i], error, correction);

      if (i == 0)
	{
	  previous_frequency = ct.clocks_per_second;

	  /* A new physical-rate sample is accepted while slewing. */
	  ct.last_verify_cpu_time = clib_cpu_time_now () -
	    (u64) (16.0 * previous_frequency * 1.005);
	  ct.last_verify_reference_time = unix_time_now () - 16.0;
	  clib_time_verify_frequency (&ct);
	  expected_frequency = previous_frequency *
	    (ct.damping_constant + (1.0 - ct.damping_constant) *
	      1.005 / (1.0 - target_corrections[i]));
	  if (ct.clocks_per_second < expected_frequency * 0.9995 ||
	      ct.clocks_per_second > expected_frequency * 1.0005)
	    return clib_error_return (
	      0, "Physical rate sample was not applied during a slew");
	}
    }

  vlib_cli_output (vm, "Accumulated phase error test passed");
  return 0;
}

/* A wall clock step moves the wall origin, but preserves earlier phase error. */
static clib_error_t *
test_time_wall_step (vlib_main_t *vm)
{
  const f64 steps[] = { -27.0, -0.5, 0.5, 27.0 };

  for (int i = 0; i < ARRAY_LEN (steps); i++)
    {
      clib_time_t ct;
      f64 before, after, error, frequency, origin;

      clib_time_init (&ct);
      frequency = ct.clocks_per_second;
      ct.total_cpu_time += (u64) (10.0 * frequency);
      ct.init_reference_time -= steps[i];
      origin = ct.init_reference_time;
      ct.last_verify_reference_time = unix_time_now () - 16.0 - steps[i];
      ct.last_verify_cpu_time =
	clib_cpu_time_now () - (u64) (16.0 * frequency);

      before = ct.total_cpu_time * ct.seconds_per_clock;
      after = clib_time_now (&ct);
      error = after - (ct.last_verify_reference_time - ct.init_reference_time);
      if (after < before || after > before + 1.0 ||
	  ct.clocks_per_second != frequency ||
	  ct.init_reference_time < origin + steps[i] - 0.1 ||
	  ct.init_reference_time > origin + steps[i] + 0.1 ||
	  error < 9.9 || error > 10.1 ||
	  ct.init_reference_time + after < unix_time_now () - 60.0 ||
	  ct.init_reference_time + after > unix_time_now () + 60.0 ||
	  ct.last_verify_reference_time < unix_time_now () - 1.0 ||
	  ct.last_verify_reference_time > unix_time_now () + 1.0)
	return clib_error_return (
	  0, "Wall step %.1f: time %.6f to %.6f, phase %.6f",
	  steps[i], before, after, error);

      /* A normal sample resumes slewing the phase error from before the step. */
      ct.last_verify_reference_time = unix_time_now () - 16.0;
      ct.last_verify_cpu_time =
	clib_cpu_time_now () - (u64) (16.0 * frequency);
      clib_time_verify_frequency (&ct);
      if (ct.clocks_per_second <= frequency)
	return clib_error_return (
	  0, "Wall step %.1f erased the earlier phase error", steps[i]);
    }

  /* Started at the Unix epoch; wall time jumps to today after 32 CPU seconds. */
  {
    clib_time_t ct;
    f64 before, after, frequency;

    clib_time_init (&ct);
    frequency = ct.clocks_per_second;
    ct.init_reference_time = 0.0;
    ct.last_verify_reference_time = 16.0;
    ct.init_cpu_time = ct.last_cpu_time - (u64) (32.0 * frequency);
    ct.last_verify_cpu_time = ct.last_cpu_time - (u64) (16.0 * frequency);
    ct.total_cpu_time = (u64) (32.0 * frequency);

    before = ct.total_cpu_time * ct.seconds_per_clock;
    after = clib_time_now (&ct);
    if (after < before || after > before + 1.0 ||
	ct.clocks_per_second != frequency ||
	ct.init_reference_time + after < unix_time_now () - 1.0 ||
	ct.init_reference_time + after > unix_time_now () + 1.0)
      return clib_error_return (
	0, "Unix epoch step changed elapsed time or left wall time stale");
  }

  vlib_cli_output (vm, "Wall clock step test passed");
  return 0;
}

/* Virtual time offsets must not enter physical frequency or phase correction. */
static clib_error_t *
test_time_virtual_offset (vlib_main_t *vm)
{
  const f64 offsets[] = { -27.0, 27.0 };

  for (int i = 0; i < ARRAY_LEN (offsets); i++)
    {
      vlib_main_t virtual_vm = { .thread_index = vm->thread_index };
      clib_time_t *ct = &virtual_vm.clib_time;
      f64 frequency, origin, physical, virtual;

      clib_time_init (ct);
      vlib_time_adjust (&virtual_vm, offsets[i]);
      frequency = ct->clocks_per_second;
      origin = ct->init_reference_time;
      ct->last_verify_cpu_time =
	clib_cpu_time_now () - (u64) (16.0 * frequency);
      ct->last_verify_reference_time = unix_time_now () - 16.0;

      virtual = vlib_time_now (&virtual_vm);
      physical = clib_time_now (ct);
      if (virtual - physical < offsets[i] - 0.1 ||
	  virtual - physical > offsets[i] + 0.1 ||
	  ct->init_reference_time != origin ||
	  ct->clocks_per_second < frequency * 0.999 ||
	  ct->clocks_per_second > frequency * 1.001)
	return clib_error_return (
	  0, "Virtual offset %.1f affected physical time or slew", offsets[i]);
    }

  vlib_cli_output (vm, "Virtual time offset test passed");
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
  f64 before_origin = vgm->vlib_mains[1]->clib_time.init_reference_time;

  /* Let worker continue — it will loop back and enter the barrier check
   * on the next barrier sync. */
  clib_atomic_store_rel_n (&time_test_main_done, 1);

  /* Take the barrier with normal time (avoids assert on
   * barrier_no_close_before). Then shift main's time backward while
   * barrier is held — barrier_release will set time_last_barrier_release
   * from the shifted time, making it ~10s behind the worker's time. */
  vlib_worker_thread_barrier_sync (vm);
  saved_time_offset = vm->time_offset;
  vlib_time_adjust (vm, -10.0);
  vlib_worker_thread_barrier_release (vm);

  f64 after = vgm->vlib_mains[1]->time_last_barrier_release;

  if (after < before)
    {
      error =
	clib_error_return (0, "Worker 1 time went backward: before=%.6f after=%.6f", before, after);
    }
  else if (vgm->vlib_mains[1]->clib_time.init_reference_time != before_origin)
    {
      error = clib_error_return (0, "Virtual offset changed worker clock origin");
    }
  else
    {
      vlib_cli_output (vm, "  Worker 1: before=%.6f after=%.6f (ok)", before, after);
      vlib_cli_output (vm, "Barrier time monotonicity test passed");
    }

  /* Restore main's time_offset and do a clean barrier to resync worker */
  vlib_time_adjust (vm, saved_time_offset - vm->time_offset);
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
  int test_small_discontinuity = 0;
  int test_accumulated_error = 0;
  int test_wall_step = 0;
  int test_virtual_offset = 0;
  int test_barrier = 0;
  int test_all = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "monotonicity"))
	test_monotonicity = 1;
      else if (unformat (input, "discontinuity"))
	test_discontinuity = 1;
      else if (unformat (input, "small-discontinuity"))
	test_small_discontinuity = 1;
      else if (unformat (input, "accumulated-error"))
	test_accumulated_error = 1;
      else if (unformat (input, "wall-step"))
	test_wall_step = 1;
      else if (unformat (input, "virtual-offset"))
	test_virtual_offset = 1;
      else if (unformat (input, "barrier"))
	test_barrier = 1;
      else if (unformat (input, "all"))
	test_all = 1;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  if (test_all)
    test_monotonicity = test_discontinuity = test_small_discontinuity =
      test_accumulated_error = test_wall_step = test_virtual_offset =
      test_barrier = 1;

  if (!test_monotonicity && !test_discontinuity && !test_small_discontinuity &&
      !test_accumulated_error && !test_wall_step && !test_virtual_offset &&
      !test_barrier)
    return clib_error_return (
      0, "specify test: monotonicity | discontinuity | small-discontinuity | accumulated-error | wall-step | virtual-offset | barrier | all");

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

  if (test_small_discontinuity)
    {
      error = test_time_small_discontinuity (vm);
      if (error)
	return error;
    }

  if (test_accumulated_error)
    {
      error = test_time_accumulated_error (vm);
      if (error)
	return error;
    }

  if (test_wall_step)
    {
      error = test_time_wall_step (vm);
      if (error)
	return error;
    }

  if (test_virtual_offset)
    {
      error = test_time_virtual_offset (vm);
      if (error)
	return error;
    }

  vlib_cli_output (vm, "All requested time tests passed");
  return 0;
}

VLIB_CLI_COMMAND (test_time_command, static) = {
  .path = "test time",
  .short_help = "test time [monotonicity | discontinuity | small-discontinuity | accumulated-error | wall-step | virtual-offset | barrier | all]",
  .function = test_time_command_fn,
  .is_mp_safe = 1,
};
