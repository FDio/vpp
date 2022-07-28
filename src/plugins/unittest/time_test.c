/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vppinfra/time.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

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
 * Timer wheel test infrastructure
 */
typedef struct
{
  u32 *expired_timers;
  int callback_called;
} tw_test_ctx_t;

static tw_test_ctx_t tw_test_ctx;

static void
test_timer_expired_callback (u32 *expired_timers)
{
  tw_test_ctx.callback_called = 1;
  vec_append (tw_test_ctx.expired_timers, expired_timers);
}

/*
 * Test that timer wheel handles backward time jumps gracefully.
 *
 * Normally, the next_run_time check catches backward jumps early.
 * This test bypasses that check by manipulating next_run_time directly
 * to verify the backward time check itself works correctly.
 *
 * When time goes backward, last_run_time must stay at the high-water mark.
 * Otherwise, nticks calculation would underflow (negative time delta),
 * potentially causing massive tick processing or other corruption.
 */
static clib_error_t *
test_timer_wheel_backward_time (vlib_main_t *vm)
{
  TWT (tw_timer_wheel) tw;
  u32 handle;
  f64 now;
  f64 saved_last_run_time;

  clib_memset (&tw, 0, sizeof (tw));
  clib_memset (&tw_test_ctx, 0, sizeof (tw_test_ctx));

  /* Initialize timer wheel: 100 ticks per second, 10ms granularity */
  TW (tw_timer_wheel_init) (&tw, test_timer_expired_callback, 0.01, ~0);

  /* Start at time 1.0 */
  now = 1.0;
  TW (tw_timer_expire_timers) (&tw, now);

  /* Advance to 1.3 to establish last_run_time */
  now = 1.3;
  TW (tw_timer_expire_timers) (&tw, now);

  saved_last_run_time = tw.last_run_time;

  /* Schedule timer to expire at 1.8 (50 ticks from current position) */
  handle = TW (tw_timer_start) (&tw, 0x12345, 0, 50);
  (void) handle;

  /*
   * Bypass next_run_time check by setting it to 0.
   * This simulates an edge case where next_run_time is stale.
   */
  tw.next_run_time = 0;

  /* Time goes backward to 1.1 */
  now = 1.1;
  TW (tw_timer_expire_timers) (&tw, now);

  /*
   * Verify last_run_time was preserved (not set to backward time).
   * With correct code: last_run_time stays at 1.3
   * With buggy code: last_run_time would be set to 1.1
   */
  if (tw.last_run_time < saved_last_run_time)
    {
      TW (tw_timer_wheel_free) (&tw);
      vec_free (tw_test_ctx.expired_timers);
      return clib_error_return (
	0, "last_run_time went backward: was %.2f, now %.2f (should stay at %.2f)",
	saved_last_run_time, tw.last_run_time, saved_last_run_time);
    }

  /* Timer should not have fired during backward jump */
  if (vec_len (tw_test_ctx.expired_timers) > 0)
    {
      TW (tw_timer_wheel_free) (&tw);
      vec_free (tw_test_ctx.expired_timers);
      return clib_error_return (0, "Timer fired during backward time jump");
    }

  /* Advance time past timer expiry */
  now = 2.0;
  TW (tw_timer_expire_timers) (&tw, now);

  /* Timer should have fired now */
  if (vec_len (tw_test_ctx.expired_timers) != 1)
    {
      int n = vec_len (tw_test_ctx.expired_timers);
      TW (tw_timer_wheel_free) (&tw);
      vec_free (tw_test_ctx.expired_timers);
      return clib_error_return (0, "Expected 1 timer, got %d", n);
    }

  vlib_cli_output (vm, "Timer wheel backward time test passed");

  TW (tw_timer_wheel_free) (&tw);
  vec_free (tw_test_ctx.expired_timers);
  return 0;
}

static clib_error_t *
test_time_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  int test_monotonicity = 0;
  int test_discontinuity = 0;
  int test_timer_wheel = 0;
  int test_all = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "monotonicity"))
	test_monotonicity = 1;
      else if (unformat (input, "discontinuity"))
	test_discontinuity = 1;
      else if (unformat (input, "timer-wheel"))
	test_timer_wheel = 1;
      else if (unformat (input, "all"))
	test_all = 1;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  if (test_all)
    test_monotonicity = test_discontinuity = test_timer_wheel = 1;

  if (!test_monotonicity && !test_discontinuity && !test_timer_wheel)
    return clib_error_return (0, "specify test: monotonicity | discontinuity | timer-wheel | all");

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

  if (test_timer_wheel)
    {
      error = test_timer_wheel_backward_time (vm);
      if (error)
	return error;
    }

  vlib_cli_output (vm, "All requested time tests passed");
  return 0;
}

VLIB_CLI_COMMAND (test_time_command, static) = {
  .path = "test time",
  .short_help = "test time [monotonicity | discontinuity | timer-wheel | all]",
  .function = test_time_command_fn,
};
