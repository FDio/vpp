/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Meter, Inc.
 */

/*
 * Process scheduler regression tests for processes sleeping in
 * vlib_process_wait_for_event_or_clock().
 *
 * Such a process can be woken by its sleep timer or by an event, and each
 * suspension must be resumed exactly once. Every resume re-arms a sleep timer,
 * so a duplicate resume leaves one timer armed forever. The process sleep timer
 * is also the only timer a process owns: a timed event has its own timer, and
 * an early event wake must cancel the sleep timer, not the timed event's.
 *
 * Each test creates its own target process and inspects the main timing wheel
 * and the restore queue directly, since neither is visible through an API.
 */

#include <vlib/vlib.h>

typedef enum
{
  TEST_VLIB_PROCESS_EVENT_COLLISION = 1,
  TEST_VLIB_PROCESS_EVENT_IMMEDIATE,
  TEST_VLIB_PROCESS_EVENT_SCHEDULED,
} test_vlib_process_event_t;

/* Number of times the timed event and the sleep timer are made to collide */
#define COLLISION_ROUNDS 50

/* The timed event is due before the sleep timer, and the target busy-waits
 * past both deadlines before it suspends. Wheel deadlines are counted from the
 * last expiry pass, so both timers expire in the next pass, timed event first,
 * however late that pass runs. */
#define COLLISION_EVENT_DELAY 3e-3
#define COLLISION_SLEEP	      5e-3
#define COLLISION_BUSY_WAIT   8e-3

#define EARLY_WAKE_SLEEP       10.0
#define EARLY_WAKE_EVENT_DELAY 0.1

/* How long a test waits for its target process to finish */
#define TEST_VLIB_PROCESS_TIMEOUT 10.0

typedef struct
{
  u32 n_resumes;
  u32 n_resumes_not_by_clock;
  u32 n_resumes_without_event;
  u32 n_duplicate_restores;
  u32 n_sleep_timers_left;
  u8 done;
} collision_test_t;

typedef struct
{
  u32 n_immediate;
  u32 n_scheduled;
  f64 scheduled_received_at;
  u8 done;
} early_wake_test_t;

static collision_test_t collision_test;
static early_wake_test_t early_wake_test;

/* Counts the armed timers of the main timing wheel that belong to a process:
 * its sleep timers, or the timers of the timed events signalled to it. */
static u32
count_process_timers (vlib_main_t *vm, vlib_node_t *n, vlib_tw_event_type_t type)
{
  vlib_node_main_t *nm = &vm->node_main;
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw = vm->timing_wheel;
  tw_timer_1t_3w_1024sl_ov_t *t;
  vlib_signal_timed_event_data_t *te;
  u32 count = 0;

  pool_foreach (t, tw->timers)
    {
      vlib_tw_event_t e = { .as_u32 = t->user_handle };

      if (e.type != type)
	continue;
      if (type == VLIB_TW_EVENT_T_PROCESS_NODE)
	count += e.index == n->runtime_index;
      else if (type == VLIB_TW_EVENT_T_TIMED_EVENT)
	{
	  te = pool_elt_at_index (nm->signal_timed_event_data_pool, e.index);
	  count += te->process_node_index == n->index;
	}
    }

  return count;
}

static u32
count_queued_restores (vlib_main_t *vm, vlib_node_t *n, vlib_process_restore_reason_t reason)
{
  vlib_process_restore_t *r;
  u32 count = 0;

  vec_foreach (r, vm->node_main.process_restore_current)
    count += r->reason == reason && r->runtime_index == n->runtime_index;

  return count;
}

static vlib_node_t *
test_vlib_process_create (vlib_main_t *vm, char *name, vlib_node_function_t *fn)
{
  static u32 n_created;
  u8 *unique_name = format (0, "test-vlib-process-%s-%u%c", name, n_created++, 0);
  u32 node_index = vlib_process_create (vm, (char *) unique_name, fn, 16);

  vec_free (unique_name);
  return vlib_get_node (vm, node_index);
}

static void
test_vlib_process_wait_done (vlib_main_t *vm, u8 *done)
{
  f64 timeout = vlib_time_now (vm) + TEST_VLIB_PROCESS_TIMEOUT;

  while (!*done && vlib_time_now (vm) < timeout)
    vlib_process_suspend (vm, 1e-3);
}

static uword
collision_target_fn (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  collision_test_t *ct = &collision_test;
  vlib_node_t *n = vlib_get_node (vm, rt->node_index);
  uword *event_data = 0;
  f64 busy_until;

  while (ct->n_resumes < COLLISION_ROUNDS)
    {
      vlib_process_signal_event_at_time (vm, COLLISION_EVENT_DELAY, n->index,
					 TEST_VLIB_PROCESS_EVENT_COLLISION, 1, sizeof (uword));
      busy_until = vlib_time_now (vm) + COLLISION_BUSY_WAIT;
      while (vlib_time_now (vm) < busy_until)
	;

      vlib_process_wait_for_event_or_clock (vm, COLLISION_SLEEP);
      ct->n_resumes++;

      /* The clock restore resuming us is still in the queue being drained.
       * Finding it, with the event already delivered, proves both timers
       * expired in this pass with the timed event first. That event must not
       * have queued an event restore behind it. */
      if (count_queued_restores (vm, n, VLIB_PROCESS_RESTORE_REASON_CLOCK) == 0)
	ct->n_resumes_not_by_clock++;
      ct->n_duplicate_restores += count_queued_restores (vm, n, VLIB_PROCESS_RESTORE_REASON_EVENT);
      if (vlib_process_get_events (vm, &event_data) != TEST_VLIB_PROCESS_EVENT_COLLISION)
	ct->n_resumes_without_event++;
      vec_reset_length (event_data);
    }

  /* We are running, so no sleep timer of ours may still be armed */
  ct->n_sleep_timers_left = count_process_timers (vm, n, VLIB_TW_EVENT_T_PROCESS_NODE);
  ct->done = 1;
  vec_free (event_data);
  return 0;
}

/* Both timers of a sleeping process expire in the same pass, the timed event
 * first: the event must ride on the clock restore instead of queueing a second
 * one, and the process must not accumulate sleep timers. */
static clib_error_t *
test_vlib_process_clock_event_collision (vlib_main_t *vm)
{
  collision_test_t *ct = &collision_test;

  clib_memset (ct, 0, sizeof (*ct));
  test_vlib_process_create (vm, "collision", collision_target_fn);
  test_vlib_process_wait_done (vm, &ct->done);

  vlib_cli_output (vm,
		   "resumes %u, not by clock %u, without event %u, duplicate restores %u, "
		   "sleep timers left %u",
		   ct->n_resumes, ct->n_resumes_not_by_clock, ct->n_resumes_without_event,
		   ct->n_duplicate_restores, ct->n_sleep_timers_left);

  if (!ct->done)
    return clib_error_return (0, "target did not finish %u rounds in %.0fs", COLLISION_ROUNDS,
			      TEST_VLIB_PROCESS_TIMEOUT);
  if (ct->n_duplicate_restores || ct->n_resumes_without_event || ct->n_sleep_timers_left)
    return clib_error_return (0, "process resumed more than once per suspension");
  if (ct->n_resumes_not_by_clock)
    return clib_error_return (0, "timed event and sleep timer did not expire together");

  return 0;
}

static uword
early_wake_target_fn (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  early_wake_test_t *et = &early_wake_test;
  uword *event_data = 0;
  uword event_type;

  while (!et->n_scheduled)
    {
      vlib_process_wait_for_event_or_clock (vm, EARLY_WAKE_SLEEP);

      while ((event_type = vlib_process_get_events (vm, &event_data)) != ~0)
	{
	  if (event_type == TEST_VLIB_PROCESS_EVENT_IMMEDIATE)
	    et->n_immediate++;
	  else if (event_type == TEST_VLIB_PROCESS_EVENT_SCHEDULED)
	    {
	      et->n_scheduled++;
	      et->scheduled_received_at = vlib_time_now (vm);
	    }
	}
      vec_reset_length (event_data);
    }

  et->done = 1;
  vec_free (event_data);
  return 0;
}

/* A process sleeping with a timed event scheduled for it is woken early by an
 * immediate event: the wake must cancel the sleep timer and leave the timed
 * event to be delivered at its deadline. */
static clib_error_t *
test_vlib_process_timed_event_early_wake (vlib_main_t *vm)
{
  early_wake_test_t *et = &early_wake_test;
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw = vm->timing_wheel;
  vlib_node_t *n;
  vlib_process_t *p;
  u32 n_sleep_timers, n_timed_event_timers;
  f64 deadline;

  clib_memset (et, 0, sizeof (*et));
  n = test_vlib_process_create (vm, "early-wake", early_wake_target_fn);
  p = vlib_get_process_from_node (vm, n);
  if (p->state != VLIB_PROCESS_STATE_WAIT_FOR_EVENT_OR_CLOCK)
    return clib_error_return (0, "target is not sleeping");

  /* Timed events are due relative to the last expiry pass of the wheel */
  deadline = tw->last_run_time + EARLY_WAKE_EVENT_DELAY;
  vlib_process_signal_event_at_time (vm, EARLY_WAKE_EVENT_DELAY, n->index,
				     TEST_VLIB_PROCESS_EVENT_SCHEDULED, 1, sizeof (uword));
  vlib_process_signal_event (vm, n->index, TEST_VLIB_PROCESS_EVENT_IMMEDIATE, 0);

  n_sleep_timers = count_process_timers (vm, n, VLIB_TW_EVENT_T_PROCESS_NODE);
  n_timed_event_timers = count_process_timers (vm, n, VLIB_TW_EVENT_T_TIMED_EVENT);

  test_vlib_process_wait_done (vm, &et->done);

  vlib_cli_output (vm,
		   "after the immediate event: sleep timers %u, timed event timers %u; "
		   "events received: immediate %u, scheduled %u",
		   n_sleep_timers, n_timed_event_timers, et->n_immediate, et->n_scheduled);

  if (n_sleep_timers != 0)
    return clib_error_return (0, "immediate event did not cancel the sleep timer");
  if (n_timed_event_timers != 1)
    return clib_error_return (0, "immediate event cancelled the timed event");
  if (et->n_immediate != 1 || et->n_scheduled != 1)
    return clib_error_return (0, "expected each event once within %.0fs",
			      TEST_VLIB_PROCESS_TIMEOUT);
  if (et->scheduled_received_at < deadline - 1 / VLIB_TW_TICKS_PER_SECOND)
    return clib_error_return (0, "timed event delivered %.6fs before its deadline",
			      deadline - et->scheduled_received_at);

  return 0;
}

static clib_error_t *
test_vlib_process_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (unformat (input, "clock-event-collision"))
    return test_vlib_process_clock_event_collision (vm);
  if (unformat (input, "timed-event-early-wake"))
    return test_vlib_process_timed_event_early_wake (vm);

  return clib_error_return (0, "specify test: clock-event-collision | timed-event-early-wake");
}

VLIB_CLI_COMMAND (test_vlib_process_command, static) = {
  .path = "test vlib-process",
  .short_help = "test vlib-process [clock-event-collision | timed-event-early-wake]",
  .function = test_vlib_process_command_fn,
  .is_mp_safe = 1,
};
