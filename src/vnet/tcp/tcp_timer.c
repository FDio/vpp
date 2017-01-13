/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "tcp_timer.h"

/** @file
 *  @brief TCP timer implementation
 */

/** construct an internal (pool-index, timer-id) handle */
static inline u32
make_internal_timer_handle (u32 pool_index, u32 timer_id)
{
  u32 handle;

  ASSERT (timer_id < 16);
  ASSERT (pool_index < (1 << 28));

  handle = (timer_id << 28) | (pool_index);
  return handle;
}

static inline void
timer_addhead (tcp_timer_t * pool, u32 head_index, u32 new_index)
{
  tcp_timer_t *head = pool_elt_at_index (pool, head_index);
  tcp_timer_t *old_first;
  u32 old_first_index;
  tcp_timer_t *new;

  new = pool_elt_at_index (pool, new_index);

  if (PREDICT_FALSE (head->next == head_index))
    {
      head->next = head->prev = new_index;
      new->next = new->prev = head_index;
      return;
    }

  old_first_index = head->next;
  old_first = pool_elt_at_index (pool, old_first_index);

  new->next = old_first_index;
  new->prev = old_first->prev;
  old_first->prev = new_index;
  head->next = new_index;
}

static inline void
timer_remove (tcp_timer_t * pool, u32 index)
{
  tcp_timer_t *elt = pool_elt_at_index (pool, index);
  tcp_timer_t *next_elt, *prev_elt;

  ASSERT (elt->user_handle != ~0);

  next_elt = pool_elt_at_index (pool, elt->next);
  prev_elt = pool_elt_at_index (pool, elt->prev);

  next_elt->prev = elt->prev;
  prev_elt->next = elt->next;

  elt->prev = elt->next = ~0;
}

/**
 * @brief Start a Tcp Timer
 * @param tcp_timer_wheel_t * tw timer wheel object pointer
 * @param u32 pool_index user pool index, presumably for a tcp session
 * @param u32 timer_id app-specific timer ID. 4 bits.
 * @param u32 interval timer interval in 100ms ticks
 * @returns handle needed to cancel the timer
 */
u32
tcp_timer_start (tcp_timer_wheel_t * tw, u32 pool_index, u32 timer_id,
		 u32 interval)
{
  u16 slow_ring_offset, fast_ring_offset;
  tcp_timer_wheel_slot_t *ts;
  u32 carry;
  tcp_timer_t *t;

  ASSERT (interval);

  pool_get (tw->timers, t);
  t->next = t->prev = ~0;
  t->fast_ring_offset = ~0;
  t->user_handle = make_internal_timer_handle (pool_index, timer_id);

  fast_ring_offset = interval & TW_RING_MASK;
  fast_ring_offset += tw->current_index[TW_RING_FAST];
  carry = fast_ring_offset >= TW_SLOTS_PER_RING ? 1 : 0;
  fast_ring_offset %= TW_SLOTS_PER_RING;
  slow_ring_offset = (interval >> TW_RING_SHIFT) + carry;

  /* Timer duration exceeds ~7 hrs? Oops */
  ASSERT (slow_ring_offset < TW_SLOTS_PER_RING);

  /* Timer expires more than 51.2 seconds from now? */
  if (slow_ring_offset)
    {
      slow_ring_offset += tw->current_index[TW_RING_SLOW];
      slow_ring_offset %= TW_SLOTS_PER_RING;

      /* We'll want the fast ring offset later... */
      t->fast_ring_offset = fast_ring_offset;
      ASSERT (t->fast_ring_offset < TW_SLOTS_PER_RING);

      ts = &tw->w[TW_RING_SLOW][slow_ring_offset];

      timer_addhead (tw->timers, ts->head_index, t - tw->timers);

      return t - tw->timers;
    }

  /* Timer expires less than 51.2 seconds from now */
  ts = &tw->w[TW_RING_FAST][fast_ring_offset];

  timer_addhead (tw->timers, ts->head_index, t - tw->timers);
  return t - tw->timers;
}

/**
 * @brief Stop a tcp timer
 * @param tcp_timer_wheel_t * tw timer wheel object pointer
 * @param u32 pool_index user pool index, passed for consistency checking only
 * @param u32 timer_id 4 bit timer ID, passed for consistency checking only
 * @param u32 handle timer cancellation returned by tcp_timer_start
 */

void
tcp_timer_stop (tcp_timer_wheel_t * tw, u32 handle)
{
  tcp_timer_t *t;

  t = pool_elt_at_index (tw->timers, handle);

  /* in case of idiotic handle (e.g. passing a listhead index) */
  ASSERT (t->user_handle != ~0);

  timer_remove (tw->timers, handle);

  pool_put_index (tw->timers, handle);
}

/**
 * @brief Initialize a tcp timer wheel
 * @param tcp_timer_wheel_t * tw timer wheel object pointer
 * @param void * expired_timer_callback. Passed a u32 * vector of
 *   expired timer handles.
 * @param void * new_stop_timer_handle_callback. Passed a vector of
 *   new_stop_timer_callback_args_t handles, corresponding to
 *   timers moved from the slow ring to the fast ring. Called approximately
 *   once every 51 seconds.
 */
void
tcp_timer_wheel_init (tcp_timer_wheel_t * tw, void *expired_timer_callback)
{
  int ring, slot;
  tcp_timer_wheel_slot_t *ts;
  tcp_timer_t *t;
  memset (tw, 0, sizeof (*tw));
  tw->expired_timer_callback = expired_timer_callback;

  for (ring = 0; ring < TW_N_RINGS; ring++)
    {
      for (slot = 0; slot < TW_SLOTS_PER_RING; slot++)
	{
	  ts = &tw->w[ring][slot];
	  pool_get (tw->timers, t);
	  memset (t, 0xff, sizeof (*t));
	  t->next = t->prev = t - tw->timers;
	  ts->head_index = t - tw->timers;
	}
    }
}

/**
 * @brief Free a tcp timer wheel
 * @param tcp_timer_wheel_t * tw timer wheel object pointer
 */
void
tcp_timer_wheel_free (tcp_timer_wheel_t * tw)
{
  int i, j;
  tcp_timer_wheel_slot_t *ts;
  tcp_timer_t *head, *t;
  u32 next_index;

  for (i = 0; i < TW_N_RINGS; i++)
    {
      for (j = 0; j < TW_SLOTS_PER_RING; j++)
	{
	  ts = &tw->w[i][j];
	  head = pool_elt_at_index (tw->timers, ts->head_index);
	  next_index = head->next;

	  while (next_index != ts->head_index)
	    {
	      t = pool_elt_at_index (tw->timers, next_index);
	      next_index = t->next;
	      pool_put (tw->timers, t);
	    }
	  pool_put (tw->timers, head);
	}
    }
  memset (tw, 0, sizeof (*tw));
}

/**
 * @brief Advance a tcp timer wheel. Calls the expired timer callback
 * as needed. This routine should be called once every 100ms.
 * @param tcp_timer_wheel_t * tw timer wheel object pointer
 * @param f64 now the current time, e.g. from vlib_time_now(vm)
 */
void
tcp_timer_expire_timers (tcp_timer_wheel_t * tw, f64 now)
{
  u32 nticks, i;
  tcp_timer_wheel_slot_t *ts;
  tcp_timer_t *t, *head;
  u32 fast_wheel_index, slow_wheel_index;
  u32 next_index;

  /* Shouldn't happen */
  if (PREDICT_FALSE (now < tw->next_run_time))
    return;

  /* Number of 100ms ticks which have occurred */
  nticks = (now - tw->last_run_time) * 10.0;
  if (nticks == 0)
    return;

  /* Remember when we ran, compute next runtime */
  tw->next_run_time = (now + 0.1);
  tw->last_run_time = now;

  for (i = 0; i < nticks; i++)
    {
      fast_wheel_index = tw->current_index[TW_RING_FAST];

      /*
       * If we've been around the fast ring once,
       * process one slot in the slow ring before we handle
       * the fast ring.
       */
      if (PREDICT_FALSE (fast_wheel_index == TW_SLOTS_PER_RING))
	{
	  fast_wheel_index = tw->current_index[TW_RING_FAST] = 0;

	  tw->current_index[TW_RING_SLOW]++;
	  tw->current_index[TW_RING_SLOW] %= TW_SLOTS_PER_RING;
	  slow_wheel_index = tw->current_index[TW_RING_SLOW];

	  ts = &tw->w[TW_RING_SLOW][slow_wheel_index];

	  head = pool_elt_at_index (tw->timers, ts->head_index);
	  next_index = head->next;

	  /* Make slot empty */
	  head->next = head->prev = ts->head_index;

	  /* traverse slot, deal timers into fast ring */
	  while (next_index != head - tw->timers)
	    {
	      t = pool_elt_at_index (tw->timers, next_index);
	      next_index = t->next;

	      /* Remove from slow ring slot (hammer) */
	      t->next = t->prev = ~0;
	      ASSERT (t->fast_ring_offset < TW_SLOTS_PER_RING);
	      /* Add to fast ring */
	      ts = &tw->w[TW_RING_FAST][t->fast_ring_offset];
	      timer_addhead (tw->timers, ts->head_index, t - tw->timers);
	    }
	}

      /* Handle the fast ring */
      vec_reset_length (tw->expired_timer_handles);

      ts = &tw->w[TW_RING_FAST][fast_wheel_index];

      head = pool_elt_at_index (tw->timers, ts->head_index);
      next_index = head->next;

      /* Make slot empty */
      head->next = head->prev = ts->head_index;

      /* Construct vector of expired timer handles to give the user */
      while (next_index != ts->head_index)
	{
	  t = pool_elt_at_index (tw->timers, next_index);
	  next_index = t->next;
	  vec_add1 (tw->expired_timer_handles, t->user_handle);
	  pool_put (tw->timers, t);
	}

      /* If any timers expired, tell the user */
      if (vec_len (tw->expired_timer_handles))
	tw->expired_timer_callback (tw->expired_timer_handles);
      tw->current_index[TW_RING_FAST]++;
      tw->current_tick++;
    }
}

#define TCP_TIMER_TEST 1

#if TCP_TIMER_TEST > 0

typedef struct
{
  /** Handle returned from tcp_start_timer */
  u32 stop_timer_handle;

  /** Test item should expire at this clock tick */
  u32 expected_to_expire;
} tcp_timer_test_elt_t;

typedef struct
{
  /** Pool of test objects */
  tcp_timer_test_elt_t *test_elts;

  /** The timer wheel */
  tcp_timer_wheel_t wheel;

  /** random number seed */
  u32 seed;

  /** number of timers */
  u32 ntimers;

  /** number of "churn" iterations */
  u32 niter;

  /** number of clock ticks per churn iteration */
  u32 ticks_per_iter;
} tcp_timer_test_main_t;

tcp_timer_test_main_t tcp_timer_test_main;

static void
run_wheel (tcp_timer_wheel_t * tw, u32 n_ticks)
{
  u32 i;
  f64 now = tw->last_run_time + 0.101;

  for (i = 0; i < n_ticks; i++)
    {
      tcp_timer_expire_timers (tw, now);
      now += 0.101;
    }
}

static void
expired_timer_callback (u32 * expired_timers)
{
  int i;
  u32 pool_index, timer_id;
  tcp_timer_test_elt_t *e;
  tcp_timer_test_main_t *tm = &tcp_timer_test_main;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i] & 0x0FFFFFFF;
      timer_id = expired_timers[i] >> 28;

      ASSERT (timer_id == 3);

      e = pool_elt_at_index (tm->test_elts, pool_index);

      if (e->expected_to_expire != tm->wheel.current_tick)
	{
	  fformat (stdout, "[%d] expired at %d not %d\n",
		   e - tm->test_elts, tm->wheel.current_tick,
		   e->expected_to_expire);
	}
      pool_put (tm->test_elts, e);
    }
}

static clib_error_t *
test2 (vlib_main_t * vm, tcp_timer_test_main_t * tm)
{
  u32 i, j;
  tcp_timer_test_elt_t *e;
  u32 initial_wheel_offset;
  u32 expiration_time;
  u32 max_expiration_time = 0;
  u32 *deleted_indices = 0;
  u32 adds = 0, deletes = 0;
  f64 before, after;

  tcp_timer_wheel_init (&tm->wheel, expired_timer_callback);

  /* Prime offset */
  initial_wheel_offset = 757;

  run_wheel (&tm->wheel, initial_wheel_offset);

  vlib_cli_output (vm,
		   "test %d timers, %d iter, %d ticks per iter, 0x%x seed",
		   tm->ntimers, tm->niter, tm->ticks_per_iter, tm->seed);

  before = vlib_time_now (vm);

  /* Prime the pump */
  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      memset (e, 0, sizeof (*e));

      do
	{
	  expiration_time = random_u32 (&tm->seed) & ((1 << 17) - 1);
	}
      while (expiration_time == 0);

      if (expiration_time > max_expiration_time)
	max_expiration_time = expiration_time;

      e->expected_to_expire = expiration_time + initial_wheel_offset;
      e->stop_timer_handle = tcp_timer_start (&tm->wheel,
					      e - tm->test_elts,
					      3 /* timer id */ ,
					      expiration_time);
    }

  adds += i;

  for (i = 0; i < tm->niter; i++)
    {
      run_wheel (&tm->wheel, tm->ticks_per_iter);

      j = 0;
      vec_reset_length (deleted_indices);
      /* *INDENT-OFF* */
      pool_foreach (e, tm->test_elts,
      ({
        tcp_timer_stop (&tm->wheel, e->stop_timer_handle);
        vec_add1 (deleted_indices, e - tm->test_elts);
        if (++j >= tm->ntimers / 4)
          goto del_and_re_add;
      }));
      /* *INDENT-ON* */

    del_and_re_add:
      for (j = 0; j < vec_len (deleted_indices); j++)
	pool_put_index (tm->test_elts, deleted_indices[j]);

      deletes += j;

      for (j = 0; j < tm->ntimers / 4; j++)
	{
	  pool_get (tm->test_elts, e);
	  memset (e, 0, sizeof (*e));

	  do
	    {
	      expiration_time = random_u32 (&tm->seed) & ((1 << 17) - 1);
	    }
	  while (expiration_time == 0);

	  if (expiration_time > max_expiration_time)
	    max_expiration_time = expiration_time;

	  e->expected_to_expire = expiration_time + tm->wheel.current_tick;
	  e->stop_timer_handle = tcp_timer_start (&tm->wheel,
						  e - tm->test_elts,
						  3 /* timer id */ ,
						  expiration_time);
	}
      adds += j;
    }

  vec_free (deleted_indices);

  run_wheel (&tm->wheel, max_expiration_time + 1);

  after = vlib_time_now (vm);

  vlib_cli_output (vm, "%d adds, %d deletes, %d ticks", adds, deletes,
		   tm->wheel.current_tick);
  vlib_cli_output (vm, "test ran %.2f seconds, %.2f ops/second",
		   (after - before),
		   ((f64) adds + (f64) deletes + (f64) tm->wheel.current_tick)
		   / (after - before));

  if (pool_elts (tm->test_elts))
    vlib_cli_output (vm, "Note: %d elements remain in pool\n",
		     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    vlib_cli_output (vm, "[%d] expected to expire %d\n",
                     e - tm->test_elts,
                     e->expected_to_expire);
  }));
  /* *INDENT-ON* */

  pool_free (tm->test_elts);
  tcp_timer_wheel_free (&tm->wheel);
  return 0;
}

static clib_error_t *
test1 (vlib_main_t * vm, tcp_timer_test_main_t * tm)
{
  u32 i;
  tcp_timer_test_elt_t *e;
  u32 offset;

  tcp_timer_wheel_init (&tm->wheel, expired_timer_callback);


  /*
   * Prime offset, to make sure that the wheel starts in a
   * non-trivial position
   */
  offset = 227989;

  run_wheel (&tm->wheel, offset);

  vlib_cli_output
    (vm, "initial wheel time %d, slow index %d fast index %d\n",
     tm->wheel.current_tick, tm->wheel.current_index[TW_RING_SLOW],
     tm->wheel.current_index[TW_RING_FAST]);

  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      memset (e, 0, sizeof (*e));
      e->expected_to_expire = i + offset + 1;
      e->stop_timer_handle = tcp_timer_start (&tm->wheel,
					      e - tm->test_elts,
					      3 /* timer id */ ,
					      i + 1 /* expiration time */ );
    }
  run_wheel (&tm->wheel, tm->ntimers + 3);

  if (pool_elts (tm->test_elts))
    vlib_cli_output (vm, "Note: %d elements remain in pool\n",
		     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    vlib_cli_output (vm,
                     "[%d] expected to expire %d\n",
                     e - tm->test_elts,
                     e->expected_to_expire);
  }));
  /* *INDENT-ON* */

  vlib_cli_output
    (vm, "final wheel time %d, slow index %d fast index %d\n",
     tm->wheel.current_tick, tm->wheel.current_index[TW_RING_SLOW],
     tm->wheel.current_index[TW_RING_FAST]);

  pool_free (tm->test_elts);
  tcp_timer_wheel_free (&tm->wheel);
  return 0;
}

static clib_error_t *
timer_test_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{

  tcp_timer_test_main_t *tm = &tcp_timer_test_main;
  int is_test1 = 0;
  int is_test2 = 0;

  memset (tm, 0, sizeof (*tm));
  /* Default values */
  tm->ntimers = 100000;
  tm->seed = 0xDEADDABE;
  tm->niter = 1000;
  tm->ticks_per_iter = 727;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "seed %d", &tm->seed))
	;
      else if (unformat (input, "test1"))
	is_test1 = 1;
      else if (unformat (input, "test2"))
	is_test2 = 1;
      else if (unformat (input, "ntimers %d", &tm->ntimers))
	;
      else if (unformat (input, "niter %d", &tm->niter))
	;
      else if (unformat (input, "ticks_per_iter %d", &tm->ticks_per_iter))
	;
    }

  if (is_test1 + is_test2 == 0)
    return clib_error_return (0, "No test specified [test1..n]");

  if (is_test1)
    return test1 (vm, &tcp_timer_test_main);
  if (is_test2)
    return test2 (vm, &tcp_timer_test_main);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (timer_test_command, static) =
{
  .path = "tcp timer test",
  .short_help = "tcp timer test",
  .function = timer_test_command_fn,
};
/* *INDENT-ON* */

#endif /* TCP_TIMER_TEST */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
