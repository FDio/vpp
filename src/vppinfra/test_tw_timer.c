#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>
#include <vppinfra/tw_timer_16t_2w_512sl.h>
#include <vppinfra/tw_timer_4t_3w_256sl.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

typedef struct
{
  /** Handle returned from tw_start_timer */
  u32 stop_timer_handle;

  /** Test item should expire at this clock tick */
  u64 expected_to_expire;
} tw_timer_test_elt_t;

typedef struct
{
  /** Pool of test objects */
  tw_timer_test_elt_t *test_elts;

  /** The single-wheel */
  tw_timer_wheel_2t_1w_2048sl_t single_wheel;

  /** The double-wheel */
  tw_timer_wheel_16t_2w_512sl_t double_wheel;

  /* The triple wheel */
  tw_timer_wheel_4t_3w_256sl_t triple_wheel;

  /* The triple wheel with overflow vector */
  tw_timer_wheel_1t_3w_1024sl_ov_t triple_ov_wheel;

  /** random number seed */
  u64 seed;

  /** number of timers */
  u32 ntimers;

  /** number of "churn" iterations */
  u32 niter;

  /** number of clock ticks per churn iteration */
  u32 ticks_per_iter;

  /** cpu timer */
  clib_time_t clib_time;
} tw_timer_test_main_t;

tw_timer_test_main_t tw_timer_test_main;

static void
run_single_wheel (tw_timer_wheel_2t_1w_2048sl_t * tw, u32 n_ticks)
{
  u32 i;
  f64 now = tw->last_run_time + 1.01;

  for (i = 0; i < n_ticks; i++)
    {
      tw_timer_expire_timers_2t_1w_2048sl (tw, now);
      now += 1.01;
    }
}

static void
run_double_wheel (tw_timer_wheel_16t_2w_512sl_t * tw, u32 n_ticks)
{
  u32 i;
  f64 now = tw->last_run_time + 1.01;

  for (i = 0; i < n_ticks; i++)
    {
      tw_timer_expire_timers_16t_2w_512sl (tw, now);
      now += 1.01;
    }
}

static void
run_triple_wheel (tw_timer_wheel_4t_3w_256sl_t * tw, u32 n_ticks)
{
  u32 i;
  f64 now = tw->last_run_time + 1.01;

  for (i = 0; i < n_ticks; i++)
    {
      tw_timer_expire_timers_4t_3w_256sl (tw, now);
      now += 1.01;
    }
}

static void
run_triple_ov_wheel (tw_timer_wheel_1t_3w_1024sl_ov_t * tw, u32 n_ticks)
{
  u32 i;
  f64 now = tw->last_run_time + 1.01;

  for (i = 0; i < n_ticks; i++)
    {
      tw_timer_expire_timers_1t_3w_1024sl_ov (tw, now);
      now += 1.01;
    }
}

static void
expired_timer_single_callback (u32 * expired_timers)
{
  int i;
  u32 pool_index, timer_id;
  tw_timer_test_elt_t *e;
  tw_timer_test_main_t *tm = &tw_timer_test_main;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i] & 0x7FFFFFFF;
      timer_id = expired_timers[i] >> 31;

      ASSERT (timer_id == 1);

      e = pool_elt_at_index (tm->test_elts, pool_index);

      if (e->expected_to_expire != tm->single_wheel.current_tick)
	{
	  fformat (stdout, "[%d] expired at %lld not %lld\n",
		   e - tm->test_elts, tm->single_wheel.current_tick,
		   e->expected_to_expire);
	}
      pool_put (tm->test_elts, e);
    }
}

static void
expired_timer_double_callback (u32 * expired_timers)
{
  int i;
  u32 pool_index, timer_id;
  tw_timer_test_elt_t *e;
  tw_timer_test_main_t *tm = &tw_timer_test_main;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i] & 0x0FFFFFFF;
      timer_id = expired_timers[i] >> 28;

      ASSERT (timer_id == 14);

      e = pool_elt_at_index (tm->test_elts, pool_index);

      if (e->expected_to_expire != tm->double_wheel.current_tick)
	{
	  fformat (stdout, "[%d] expired at %lld not %lld\n",
		   e - tm->test_elts, tm->double_wheel.current_tick,
		   e->expected_to_expire);
	}
      pool_put (tm->test_elts, e);
    }
}

static void
expired_timer_triple_callback (u32 * expired_timers)
{
  int i;
  u32 pool_index, timer_id;
  tw_timer_test_elt_t *e;
  tw_timer_test_main_t *tm = &tw_timer_test_main;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i] & 0x3FFFFFFF;
      timer_id = expired_timers[i] >> 30;

      ASSERT (timer_id == 3);

      e = pool_elt_at_index (tm->test_elts, pool_index);

      if (e->expected_to_expire != tm->triple_wheel.current_tick)
	{
	  fformat (stdout, "[%d] expired at %lld not %lld\n",
		   e - tm->test_elts, tm->triple_wheel.current_tick,
		   e->expected_to_expire);
	}
      pool_put (tm->test_elts, e);
    }
}

static void
expired_timer_triple_ov_callback (u32 * expired_timers)
{
  int i;
  u32 pool_index;
  tw_timer_test_elt_t *e;
  tw_timer_test_main_t *tm = &tw_timer_test_main;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i];

      e = pool_elt_at_index (tm->test_elts, pool_index);

      if (e->expected_to_expire != tm->triple_ov_wheel.current_tick)
	{
	  fformat (stdout, "[%d] expired at %lld not %lld\n",
		   e - tm->test_elts, tm->triple_ov_wheel.current_tick,
		   e->expected_to_expire);
	}
      pool_put (tm->test_elts, e);
    }
}

static clib_error_t *
test2_single (tw_timer_test_main_t * tm)
{
  u32 i, j;
  tw_timer_test_elt_t *e;
  u32 initial_wheel_offset;
  u64 expiration_time;
  u32 max_expiration_time = 0;
  u32 *deleted_indices = 0;
  u32 adds = 0, deletes = 0;
  f64 before, after;

  clib_time_init (&tm->clib_time);

  tw_timer_wheel_init_2t_1w_2048sl (&tm->single_wheel,
				    expired_timer_single_callback,
				    1.0 /* timer interval */ , ~0);

  /* Prime offset */
  initial_wheel_offset = 757;

  run_single_wheel (&tm->single_wheel, initial_wheel_offset);

  fformat (stdout, "initial wheel time %d, fast index %d\n",
	   tm->single_wheel.current_tick,
	   tm->single_wheel.current_index[TW_TIMER_RING_FAST]);

  initial_wheel_offset = tm->single_wheel.current_tick;

  fformat (stdout,
	   "test %d timers, %d iter, %d ticks per iter, 0x%llx seed\n",
	   tm->ntimers, tm->niter, tm->ticks_per_iter, tm->seed);

  before = clib_time_now (&tm->clib_time);

  /* Prime the pump */
  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      clib_memset (e, 0, sizeof (*e));

      do
	{
	  expiration_time = random_u64 (&tm->seed) & (2047);
	}
      while (expiration_time == 0);

      if (expiration_time > max_expiration_time)
	max_expiration_time = expiration_time;

      e->expected_to_expire = expiration_time + initial_wheel_offset;
      e->stop_timer_handle =
	tw_timer_start_2t_1w_2048sl (&tm->single_wheel, e - tm->test_elts,
				     1 /* timer id */ ,
				     expiration_time);
    }

  adds += i;

  for (i = 0; i < tm->niter; i++)
    {
      run_single_wheel (&tm->single_wheel, tm->ticks_per_iter);

      j = 0;
      vec_reset_length (deleted_indices);
      /* *INDENT-OFF* */
      pool_foreach (e, tm->test_elts,
      ({
        tw_timer_stop_2t_1w_2048sl (&tm->single_wheel, e->stop_timer_handle);
        vec_add1 (deleted_indices, e - tm->test_elts);
        if (++j >= tm->ntimers / 4)
          goto del_and_re_add;
      }));
      /* *INDENT-ON* */

    del_and_re_add:
      for (j = 0; j < vec_len (deleted_indices); j++)
	{
	  pool_put_index (tm->test_elts, deleted_indices[j]);
	}

      deletes += j;

      for (j = 0; j < tm->ntimers / 4; j++)
	{
	  pool_get (tm->test_elts, e);
	  clib_memset (e, 0, sizeof (*e));

	  do
	    {
	      expiration_time = random_u64 (&tm->seed) & (2047);
	    }
	  while (expiration_time == 0);

	  if (expiration_time > max_expiration_time)
	    max_expiration_time = expiration_time;

	  e->expected_to_expire =
	    expiration_time + tm->single_wheel.current_tick;
	  e->stop_timer_handle = tw_timer_start_2t_1w_2048sl
	    (&tm->single_wheel, e - tm->test_elts, 1 /* timer id */ ,
	     expiration_time);
	}
      adds += j;
    }

  vec_free (deleted_indices);

  run_single_wheel (&tm->single_wheel, max_expiration_time + 1);

  after = clib_time_now (&tm->clib_time);

  fformat (stdout, "%d adds, %d deletes, %d ticks\n", adds, deletes,
	   tm->single_wheel.current_tick);
  fformat (stdout, "test ran %.2f seconds, %.2f ops/second\n",
	   (after - before),
	   ((f64) adds + (f64) deletes +
	    (f64) tm->single_wheel.current_tick) / (after - before));

  if (pool_elts (tm->test_elts))
    fformat (stdout, "Note: %d elements remain in pool\n",
	     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    fformat (stdout, "[%d] expected to expire %d\n",
             e - tm->test_elts,
             e->expected_to_expire);
  }));
  /* *INDENT-ON* */

  pool_free (tm->test_elts);
  tw_timer_wheel_free_2t_1w_2048sl (&tm->single_wheel);
  return 0;
}

static clib_error_t *
test2_double (tw_timer_test_main_t * tm)
{
  u32 i, j;
  tw_timer_test_elt_t *e;
  u32 initial_wheel_offset;
  u32 expiration_time;
  u32 max_expiration_time = 0;
  u32 *deleted_indices = 0;
  u32 adds = 0, deletes = 0;
  f64 before, after;

  clib_time_init (&tm->clib_time);

  tw_timer_wheel_init_16t_2w_512sl (&tm->double_wheel,
				    expired_timer_double_callback,
				    1.0 /* timer interval */ , ~0);

  /* Prime offset */
  initial_wheel_offset = 7577;

  run_double_wheel (&tm->double_wheel, initial_wheel_offset);

  fformat (stdout, "initial wheel time %d, fast index %d slow index %d\n",
	   tm->double_wheel.current_tick,
	   tm->double_wheel.current_index[TW_TIMER_RING_FAST],
	   tm->double_wheel.current_index[TW_TIMER_RING_SLOW]);

  initial_wheel_offset = tm->double_wheel.current_tick;

  fformat (stdout,
	   "test %d timers, %d iter, %d ticks per iter, 0x%llx seed\n",
	   tm->ntimers, tm->niter, tm->ticks_per_iter, tm->seed);

  before = clib_time_now (&tm->clib_time);

  /* Prime the pump */
  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      clib_memset (e, 0, sizeof (*e));

      do
	{
	  expiration_time = random_u64 (&tm->seed) & ((1 << 17) - 1);
	}
      while (expiration_time == 0);

      if (expiration_time > max_expiration_time)
	max_expiration_time = expiration_time;

      e->expected_to_expire = expiration_time + initial_wheel_offset;

      e->stop_timer_handle =
	tw_timer_start_16t_2w_512sl (&tm->double_wheel, e - tm->test_elts,
				     14 /* timer id */ ,
				     expiration_time);
    }

  adds += i;

  for (i = 0; i < tm->niter; i++)
    {
      run_double_wheel (&tm->double_wheel, tm->ticks_per_iter);

      j = 0;
      vec_reset_length (deleted_indices);
      /* *INDENT-OFF* */
      pool_foreach (e, tm->test_elts,
      ({
        tw_timer_stop_16t_2w_512sl (&tm->double_wheel, e->stop_timer_handle);
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
	  clib_memset (e, 0, sizeof (*e));

	  do
	    {
	      expiration_time = random_u64 (&tm->seed) & ((1 << 17) - 1);
	    }
	  while (expiration_time == 0);

	  if (expiration_time > max_expiration_time)
	    max_expiration_time = expiration_time;

	  e->expected_to_expire = expiration_time +
	    tm->double_wheel.current_tick;

	  e->stop_timer_handle = tw_timer_start_16t_2w_512sl
	    (&tm->double_wheel, e - tm->test_elts, 14 /* timer id */ ,
	     expiration_time);
	}
      adds += j;
    }

  vec_free (deleted_indices);

  run_double_wheel (&tm->double_wheel, max_expiration_time + 1);

  after = clib_time_now (&tm->clib_time);

  fformat (stdout, "%d adds, %d deletes, %d ticks\n", adds, deletes,
	   tm->double_wheel.current_tick);
  fformat (stdout, "test ran %.2f seconds, %.2f ops/second\n",
	   (after - before),
	   ((f64) adds + (f64) deletes +
	    (f64) tm->double_wheel.current_tick) / (after - before));

  if (pool_elts (tm->test_elts))
    fformat (stdout, "Note: %d elements remain in pool\n",
	     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    fformat (stdout, "[%d] expected to expire %d\n",
             e - tm->test_elts,
             e->expected_to_expire);
  }));
  /* *INDENT-ON* */

  pool_free (tm->test_elts);
  tw_timer_wheel_free_16t_2w_512sl (&tm->double_wheel);
  return 0;
}

static u32
get_expiration_time (tw_timer_test_main_t * tm)
{
  u32 expiration_time;
  do
    {
      expiration_time = random_u64 (&tm->seed) & ((1 << 17) - 1);
    }
  while (expiration_time == 0);
  return expiration_time;
}

static clib_error_t *
test2_double_updates (tw_timer_test_main_t * tm)
{
  u32 i, j;
  tw_timer_test_elt_t *e;
  u32 initial_wheel_offset;
  u32 expiration_time;
  u32 max_expiration_time = 0, updates = 0;
  f64 before, after;

  clib_time_init (&tm->clib_time);
  tw_timer_wheel_init_16t_2w_512sl (&tm->double_wheel,
				    expired_timer_double_callback,
				    1.0 /* timer interval */ , ~0);

  /* Prime offset */
  initial_wheel_offset = 7577;
  run_double_wheel (&tm->double_wheel, initial_wheel_offset);
  fformat (stdout, "initial wheel time %d, fast index %d slow index %d\n",
	   tm->double_wheel.current_tick,
	   tm->double_wheel.current_index[TW_TIMER_RING_FAST],
	   tm->double_wheel.current_index[TW_TIMER_RING_SLOW]);

  initial_wheel_offset = tm->double_wheel.current_tick;
  fformat (stdout,
	   "test %d timers, %d iter, %d ticks per iter, 0x%llx seed\n",
	   tm->ntimers, tm->niter, tm->ticks_per_iter, tm->seed);

  before = clib_time_now (&tm->clib_time);

  /* Prime the pump */
  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      clib_memset (e, 0, sizeof (*e));

      expiration_time = get_expiration_time (tm);
      max_expiration_time = clib_max (expiration_time, max_expiration_time);

      e->expected_to_expire = expiration_time + initial_wheel_offset;
      e->stop_timer_handle = tw_timer_start_16t_2w_512sl (&tm->double_wheel,
							  e - tm->test_elts,
							  14 /* timer id */ ,
							  expiration_time);
    }

  for (i = 0; i < tm->niter; i++)
    {
      run_double_wheel (&tm->double_wheel, tm->ticks_per_iter);

      j = 0;

      /* *INDENT-OFF* */
      pool_foreach (e, tm->test_elts,
      ({
        expiration_time = get_expiration_time (tm);
        max_expiration_time = clib_max (expiration_time, max_expiration_time);
	e->expected_to_expire = expiration_time
				+ tm->double_wheel.current_tick;
        tw_timer_update_16t_2w_512sl (&tm->double_wheel, e->stop_timer_handle,
                                      expiration_time);
        if (++j >= tm->ntimers / 4)
          goto done;
      }));
      /* *INDENT-ON* */

    done:
      updates += j;
    }

  run_double_wheel (&tm->double_wheel, max_expiration_time + 1);

  after = clib_time_now (&tm->clib_time);

  fformat (stdout, "%d updates, %d ticks\n", updates,
	   tm->double_wheel.current_tick);
  fformat (stdout, "test ran %.2f seconds, %.2f ops/second\n",
	   (after - before),
	   ((f64) updates + (f64) tm->double_wheel.current_tick) / (after -
								    before));

  if (pool_elts (tm->test_elts))
    fformat (stdout, "Note: %d elements remain in pool\n",
	     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    fformat (stdout, "[%d] expected to expire %d\n",
             e - tm->test_elts,
             e->expected_to_expire);
  }));
  /* *INDENT-ON* */

  pool_free (tm->test_elts);
  tw_timer_wheel_free_16t_2w_512sl (&tm->double_wheel);
  return 0;
}

static clib_error_t *
test2_triple (tw_timer_test_main_t * tm)
{
  u32 i, j;
  tw_timer_test_elt_t *e;
  u32 initial_wheel_offset = 0;
  u32 expiration_time;
  u32 max_expiration_time = 0;
  u32 *deleted_indices = 0;
  u32 adds = 0, deletes = 0;
  f64 before, after;

  clib_time_init (&tm->clib_time);

  tw_timer_wheel_init_4t_3w_256sl (&tm->triple_wheel,
				   expired_timer_triple_callback,
				   1.0 /* timer interval */ , ~0);


  /* Prime offset */
  initial_wheel_offset = 75700;
  run_triple_wheel (&tm->triple_wheel, initial_wheel_offset);

  fformat (stdout,
	   "initial wheel time %d, fi %d si %d gi %d\n",
	   tm->triple_wheel.current_tick,
	   tm->triple_wheel.current_index[TW_TIMER_RING_FAST],
	   tm->triple_wheel.current_index[TW_TIMER_RING_SLOW],
	   tm->triple_wheel.current_index[TW_TIMER_RING_GLACIER]);

  initial_wheel_offset = tm->triple_wheel.current_tick;

  fformat (stdout,
	   "test %d timers, %d iter, %d ticks per iter, 0x%llx seed\n",
	   tm->ntimers, tm->niter, tm->ticks_per_iter, tm->seed);

  before = clib_time_now (&tm->clib_time);

  /* Prime the pump */
  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      clib_memset (e, 0, sizeof (*e));

      do
	{
	  expiration_time = random_u64 (&tm->seed) & ((1 << 17) - 1);
	}
      while (expiration_time == 0);

      if (expiration_time > max_expiration_time)
	max_expiration_time = expiration_time;

      e->expected_to_expire = expiration_time + initial_wheel_offset;

      e->stop_timer_handle =
	tw_timer_start_4t_3w_256sl (&tm->triple_wheel, e - tm->test_elts,
				    3 /* timer id */ ,
				    expiration_time);
    }

  adds += i;

  for (i = 0; i < tm->niter; i++)
    {
      run_triple_wheel (&tm->triple_wheel, tm->ticks_per_iter);

      j = 0;
      vec_reset_length (deleted_indices);
      /* *INDENT-OFF* */
      pool_foreach (e, tm->test_elts,
      ({
        tw_timer_stop_4t_3w_256sl (&tm->triple_wheel, e->stop_timer_handle);
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
	  clib_memset (e, 0, sizeof (*e));

	  do
	    {
	      expiration_time = random_u64 (&tm->seed) & ((1 << 17) - 1);
	    }
	  while (expiration_time == 0);

	  if (expiration_time > max_expiration_time)
	    max_expiration_time = expiration_time;

	  e->expected_to_expire = expiration_time +
	    tm->triple_wheel.current_tick;

	  e->stop_timer_handle = tw_timer_start_4t_3w_256sl
	    (&tm->triple_wheel, e - tm->test_elts, 3 /* timer id */ ,
	     expiration_time);
	}
      adds += j;
    }

  vec_free (deleted_indices);

  run_triple_wheel (&tm->triple_wheel, max_expiration_time + 1);

  after = clib_time_now (&tm->clib_time);

  fformat (stdout, "%d adds, %d deletes, %d ticks\n", adds, deletes,
	   tm->triple_wheel.current_tick);
  fformat (stdout, "test ran %.2f seconds, %.2f ops/second\n",
	   (after - before),
	   ((f64) adds + (f64) deletes +
	    (f64) tm->triple_wheel.current_tick) / (after - before));

  if (pool_elts (tm->test_elts))
    fformat (stdout, "Note: %d elements remain in pool\n",
	     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    fformat (stdout, "[%d] expected to expire %d\n",
             e - tm->test_elts,
             e->expected_to_expire);
  }));
  /* *INDENT-ON* */

  pool_free (tm->test_elts);
  tw_timer_wheel_free_4t_3w_256sl (&tm->triple_wheel);
  return 0;
}

static clib_error_t *
test2_triple_ov (tw_timer_test_main_t * tm)
{
  u32 i, j;
  tw_timer_test_elt_t *e;
  u32 initial_wheel_offset = 0;
  u32 expiration_time;
  u32 max_expiration_time = 0;
  u32 *deleted_indices = 0;
  u32 adds = 0, deletes = 0;
  f64 before, after;

  clib_time_init (&tm->clib_time);

  tw_timer_wheel_init_1t_3w_1024sl_ov (&tm->triple_ov_wheel,
				       expired_timer_triple_ov_callback,
				       1.0 /* timer interval */ , ~0);


  /* Prime offset */
  initial_wheel_offset = 75700;
  run_triple_ov_wheel (&tm->triple_ov_wheel, initial_wheel_offset);

  fformat (stdout,
	   "initial wheel time %d, fi %d si %d gi %d\n",
	   tm->triple_ov_wheel.current_tick,
	   tm->triple_ov_wheel.current_index[TW_TIMER_RING_FAST],
	   tm->triple_ov_wheel.current_index[TW_TIMER_RING_SLOW],
	   tm->triple_ov_wheel.current_index[TW_TIMER_RING_GLACIER]);

  initial_wheel_offset = tm->triple_ov_wheel.current_tick;

  fformat (stdout,
	   "test %d timers, %d iter, %d ticks per iter, 0x%llx seed\n",
	   tm->ntimers, tm->niter, tm->ticks_per_iter, tm->seed);

  before = clib_time_now (&tm->clib_time);

  /* Prime the pump */
  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      clib_memset (e, 0, sizeof (*e));

      do
	{
	  expiration_time = random_u64 (&tm->seed) & ((1 << 17) - 1);
	}
      while (expiration_time == 0);

      if (expiration_time > max_expiration_time)
	max_expiration_time = expiration_time;

      e->expected_to_expire = expiration_time + initial_wheel_offset;

      e->stop_timer_handle =
	tw_timer_start_1t_3w_1024sl_ov (&tm->triple_ov_wheel,
					e - tm->test_elts, 0 /* timer id */ ,
					expiration_time);
    }

  adds += i;

  for (i = 0; i < tm->niter; i++)
    {
      run_triple_ov_wheel (&tm->triple_ov_wheel, tm->ticks_per_iter);

      j = 0;
      vec_reset_length (deleted_indices);
      /* *INDENT-OFF* */
      pool_foreach (e, tm->test_elts,
      ({
        tw_timer_stop_1t_3w_1024sl_ov (&tm->triple_ov_wheel,
                                       e->stop_timer_handle);
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
	  clib_memset (e, 0, sizeof (*e));

	  do
	    {
	      expiration_time = random_u64 (&tm->seed) & ((1 << 17) - 1);
	    }
	  while (expiration_time == 0);

	  if (expiration_time > max_expiration_time)
	    max_expiration_time = expiration_time;

	  e->expected_to_expire = expiration_time +
	    tm->triple_ov_wheel.current_tick;

	  e->stop_timer_handle = tw_timer_start_1t_3w_1024sl_ov
	    (&tm->triple_ov_wheel, e - tm->test_elts, 0 /* timer id */ ,
	     expiration_time);
	}
      adds += j;
    }

  vec_free (deleted_indices);

  run_triple_ov_wheel (&tm->triple_ov_wheel, max_expiration_time + 1);

  after = clib_time_now (&tm->clib_time);

  fformat (stdout, "%d adds, %d deletes, %d ticks\n", adds, deletes,
	   tm->triple_ov_wheel.current_tick);
  fformat (stdout, "test ran %.2f seconds, %.2f ops/second\n",
	   (after - before),
	   ((f64) adds + (f64) deletes +
	    (f64) tm->triple_ov_wheel.current_tick) / (after - before));

  if (pool_elts (tm->test_elts))
    fformat (stdout, "Note: %d elements remain in pool\n",
	     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    TWT (tw_timer) * t;

    fformat (stdout, "[%d] expected to expire %d\n",
             e - tm->test_elts,
             e->expected_to_expire);
    t = pool_elt_at_index (tm->triple_ov_wheel.timers, e->stop_timer_handle);
    fformat (stdout, "  expiration_time %lld\n", t->expiration_time);
  }));
  /* *INDENT-ON* */

  pool_free (tm->test_elts);
  tw_timer_wheel_free_1t_3w_1024sl_ov (&tm->triple_ov_wheel);
  return 0;
}

static clib_error_t *
test1_single (tw_timer_test_main_t * tm)
{
  u32 i;
  tw_timer_test_elt_t *e;
  u32 offset;

  tw_timer_wheel_init_2t_1w_2048sl (&tm->single_wheel,
				    expired_timer_single_callback,
				    1.0 /* timer interval */ , ~0);

  /*
   * Prime offset, to make sure that the wheel starts in a
   * non-trivial position
   */
  offset = 123;

  run_single_wheel (&tm->single_wheel, offset);

  fformat (stdout, "initial wheel time %d, fast index %d\n",
	   tm->single_wheel.current_tick,
	   tm->single_wheel.current_index[TW_TIMER_RING_FAST]);

  offset = tm->single_wheel.current_tick;

  for (i = 0; i < tm->ntimers; i++)
    {
      u32 expected_to_expire;
      u32 timer_arg;

      timer_arg = 1 + i;
      timer_arg &= 2047;
      if (timer_arg == 0)
	timer_arg = 1;

      expected_to_expire = timer_arg + offset;

      pool_get (tm->test_elts, e);
      clib_memset (e, 0, sizeof (*e));
      e->expected_to_expire = expected_to_expire;
      e->stop_timer_handle = tw_timer_start_2t_1w_2048sl
	(&tm->single_wheel, e - tm->test_elts, 1 /* timer id */ ,
	 timer_arg);
    }
  run_single_wheel (&tm->single_wheel, tm->ntimers + 3);

  if (pool_elts (tm->test_elts))
    fformat (stdout, "Note: %d elements remain in pool\n",
	     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    fformat(stdout, "[%d] expected to expire %d\n",
                     e - tm->test_elts,
                     e->expected_to_expire);
  }));
  /* *INDENT-ON* */

  fformat (stdout,
	   "final wheel time %d, fast index %d\n",
	   tm->single_wheel.current_tick,
	   tm->single_wheel.current_index[TW_TIMER_RING_FAST]);

  pool_free (tm->test_elts);
  tw_timer_wheel_free_2t_1w_2048sl (&tm->single_wheel);
  return 0;
}

static clib_error_t *
test1_double (tw_timer_test_main_t * tm)
{
  u32 i;
  tw_timer_test_elt_t *e;
  u32 offset;

  tw_timer_wheel_init_16t_2w_512sl (&tm->double_wheel,
				    expired_timer_double_callback,
				    1.0 /* timer interval */ , ~0);

  /*
   * Prime offset, to make sure that the wheel starts in a
   * non-trivial position
   */
  offset = 227989;

  run_double_wheel (&tm->double_wheel, offset);

  fformat (stdout, "initial wheel time %d, fast index %d\n",
	   tm->double_wheel.current_tick,
	   tm->double_wheel.current_index[TW_TIMER_RING_FAST]);

  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      clib_memset (e, 0, sizeof (*e));

      e->expected_to_expire = i + offset + 1;
      e->stop_timer_handle = tw_timer_start_16t_2w_512sl
	(&tm->double_wheel, e - tm->test_elts, 14 /* timer id */ ,
	 i + 1);
    }
  run_double_wheel (&tm->double_wheel, tm->ntimers + 3);

  if (pool_elts (tm->test_elts))
    fformat (stdout, "Note: %d elements remain in pool\n",
	     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    fformat(stdout, "[%d] expected to expire %d\n",
                     e - tm->test_elts,
                     e->expected_to_expire);
  }));
  /* *INDENT-ON* */

  fformat (stdout,
	   "final wheel time %d, fast index %d\n",
	   tm->double_wheel.current_tick,
	   tm->double_wheel.current_index[TW_TIMER_RING_FAST]);

  pool_free (tm->test_elts);
  tw_timer_wheel_free_16t_2w_512sl (&tm->double_wheel);
  return 0;
}

static clib_error_t *
test3_triple_double (tw_timer_test_main_t * tm)
{
  tw_timer_test_elt_t *e;
  u32 initial_wheel_offset = 0;
  u32 expiration_time;
  u32 max_expiration_time = 0;
  u32 adds = 0, deletes = 0;
  f64 before, after;

  clib_time_init (&tm->clib_time);

  tw_timer_wheel_init_4t_3w_256sl (&tm->triple_wheel,
				   expired_timer_triple_callback,
				   1.0 /* timer interval */ , ~0);

  initial_wheel_offset = 0;
  run_triple_wheel (&tm->triple_wheel, initial_wheel_offset);

  fformat (stdout,
	   "initial wheel time %d, fi %d si %d gi %d\n",
	   tm->triple_wheel.current_tick,
	   tm->triple_wheel.current_index[TW_TIMER_RING_FAST],
	   tm->triple_wheel.current_index[TW_TIMER_RING_SLOW],
	   tm->triple_wheel.current_index[TW_TIMER_RING_GLACIER]);

  initial_wheel_offset = tm->triple_wheel.current_tick;

  fformat (stdout, "Create a timer which expires at wheel-time (1, 0, 0)\n");

  before = clib_time_now (&tm->clib_time);

  /* Prime the pump */
  pool_get (tm->test_elts, e);
  clib_memset (e, 0, sizeof (*e));

  /* 1 glacier ring tick from now */
  expiration_time = TW_SLOTS_PER_RING * TW_SLOTS_PER_RING;
  e->expected_to_expire = expiration_time + initial_wheel_offset;
  max_expiration_time = expiration_time;

  e->stop_timer_handle =
    tw_timer_start_4t_3w_256sl (&tm->triple_wheel, e - tm->test_elts,
				3 /* timer id */ ,
				expiration_time);

  run_triple_wheel (&tm->triple_wheel, max_expiration_time + 1);

  after = clib_time_now (&tm->clib_time);

  fformat (stdout, "%d adds, %d deletes, %d ticks\n", adds, deletes,
	   tm->triple_wheel.current_tick);
  fformat (stdout, "test ran %.2f seconds, %.2f ops/second\n",
	   (after - before),
	   ((f64) adds + (f64) deletes +
	    (f64) tm->triple_wheel.current_tick) / (after - before));

  if (pool_elts (tm->test_elts))
    fformat (stdout, "Note: %d elements remain in pool\n",
	     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    fformat (stdout, "[%d] expected to expire %d\n",
             e - tm->test_elts,
             e->expected_to_expire);
  }));
  /* *INDENT-ON* */

  pool_free (tm->test_elts);
  tw_timer_wheel_free_4t_3w_256sl (&tm->triple_wheel);
  return 0;
}

static clib_error_t *
test4_double_double (tw_timer_test_main_t * tm)
{
  u32 i;
  tw_timer_test_elt_t *e;
  u32 initial_wheel_offset;
  u32 expiration_time;
  u32 max_expiration_time = 0;
  u32 *deleted_indices = 0;
  u32 adds = 0, deletes = 0;
  f64 before, after;

  clib_time_init (&tm->clib_time);

  tw_timer_wheel_init_16t_2w_512sl (&tm->double_wheel,
				    expired_timer_double_callback,
				    1.0 /* timer interval */ , ~0);
  /* Prime offset */
  initial_wheel_offset = 0;

  run_double_wheel (&tm->double_wheel, initial_wheel_offset);

  fformat (stdout, "initial wheel time %d, fast index %d slow index %d\n",
	   tm->double_wheel.current_tick,
	   tm->double_wheel.current_index[TW_TIMER_RING_FAST],
	   tm->double_wheel.current_index[TW_TIMER_RING_SLOW]);

  initial_wheel_offset = tm->double_wheel.current_tick;

  fformat (stdout, "test timer which expires at 512 ticks\n");

  before = clib_time_now (&tm->clib_time);

  /* Prime the pump */
  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      clib_memset (e, 0, sizeof (*e));

      expiration_time = 512;

      if (expiration_time > max_expiration_time)
	max_expiration_time = expiration_time;

      e->expected_to_expire = expiration_time + initial_wheel_offset;
      e->stop_timer_handle =
	tw_timer_start_16t_2w_512sl (&tm->double_wheel, e - tm->test_elts,
				     14 /* timer id */ ,
				     expiration_time);
    }

  adds = 1;

  vec_free (deleted_indices);

  run_double_wheel (&tm->double_wheel, max_expiration_time + 1);

  after = clib_time_now (&tm->clib_time);

  fformat (stdout, "%d adds, %d deletes, %d ticks\n", adds, deletes,
	   tm->double_wheel.current_tick);
  fformat (stdout, "test ran %.2f seconds, %.2f ops/second\n",
	   (after - before),
	   ((f64) adds + (f64) deletes +
	    (f64) tm->double_wheel.current_tick) / (after - before));

  if (pool_elts (tm->test_elts))
    fformat (stdout, "Note: %d elements remain in pool\n",
	     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    fformat (stdout, "[%d] expected to expire %d\n",
             e - tm->test_elts,
             e->expected_to_expire);
  }));
  /* *INDENT-ON* */

  pool_free (tm->test_elts);
  tw_timer_wheel_free_16t_2w_512sl (&tm->double_wheel);
  return 0;
}

static clib_error_t *
test5_double (tw_timer_test_main_t * tm)
{
  u32 i;
  tw_timer_test_elt_t *e;
  u32 initial_wheel_offset;
  u32 expiration_time;
  u32 max_expiration_time = 0;
  u32 adds = 0, deletes = 0;
  f64 before, after;

  clib_time_init (&tm->clib_time);

  tw_timer_wheel_init_16t_2w_512sl (&tm->double_wheel,
				    expired_timer_double_callback,
				    1.0 /* timer interval */ , ~0);

  /* Prime offset */
  initial_wheel_offset = 7567;

  run_double_wheel (&tm->double_wheel, initial_wheel_offset);

  fformat (stdout, "initial wheel time %d, fast index %d slow index %d\n",
	   tm->double_wheel.current_tick,
	   tm->double_wheel.current_index[TW_TIMER_RING_FAST],
	   tm->double_wheel.current_index[TW_TIMER_RING_SLOW]);

  initial_wheel_offset = tm->double_wheel.current_tick;

  fformat (stdout,
	   "test %d timers, %d iter, %d ticks per iter, 0x%llx seed\n",
	   tm->ntimers, tm->niter, tm->ticks_per_iter, tm->seed);

  before = clib_time_now (&tm->clib_time);

  /* Prime the pump */
  for (i = 0; i < tm->ntimers; i++)
    {
      pool_get (tm->test_elts, e);
      clib_memset (e, 0, sizeof (*e));

      expiration_time = i + 1;

      if (expiration_time > max_expiration_time)
	max_expiration_time = expiration_time;

      e->expected_to_expire = expiration_time + initial_wheel_offset;
      e->stop_timer_handle =
	tw_timer_start_16t_2w_512sl (&tm->double_wheel, e - tm->test_elts,
				     14 /* timer id */ ,
				     expiration_time);
    }

  adds += i;

  run_double_wheel (&tm->double_wheel, max_expiration_time + 1);

  after = clib_time_now (&tm->clib_time);

  fformat (stdout, "%d adds, %d deletes, %d ticks\n", adds, deletes,
	   tm->double_wheel.current_tick);
  fformat (stdout, "test ran %.2f seconds, %.2f ops/second\n",
	   (after - before),
	   ((f64) adds + (f64) deletes +
	    (f64) tm->double_wheel.current_tick) / (after - before));

  if (pool_elts (tm->test_elts))
    fformat (stdout, "Note: %d elements remain in pool\n",
	     pool_elts (tm->test_elts));

  /* *INDENT-OFF* */
  pool_foreach (e, tm->test_elts,
  ({
    fformat (stdout, "[%d] expected to expire %d\n",
             e - tm->test_elts,
             e->expected_to_expire);
  }));
  /* *INDENT-ON* */

  pool_free (tm->test_elts);
  tw_timer_wheel_free_16t_2w_512sl (&tm->double_wheel);
  return 0;
}

static clib_error_t *
timer_test_command_fn (tw_timer_test_main_t * tm, unformat_input_t * input)
{

  int is_test1 = 0, is_updates = 0;
  int num_wheels = 1;
  int is_test2 = 0;
  int is_test3 = 0;
  int is_test4 = 0;
  int is_test5 = 0;
  int overflow = 0;

  clib_memset (tm, 0, sizeof (*tm));
  /* Default values */
  tm->ntimers = 100000;
  tm->seed = 0xDEADDABEB00BFACE;
  tm->niter = 1000;
  tm->ticks_per_iter = 727;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "seed %lld", &tm->seed))
	;
      else if (unformat (input, "test1"))
	is_test1 = 1;
      else if (unformat (input, "test2"))
	is_test2 = 1;
      else if (unformat (input, "overflow"))
	overflow = 1;
      else if (unformat (input, "lebron"))
	is_test3 = 1;
      else if (unformat (input, "wilt"))
	is_test4 = 1;
      else if (unformat (input, "linear"))
	is_test5 = 1;
      else if (unformat (input, "updates"))
	is_updates = 1;
      else if (unformat (input, "wheels %d", &num_wheels))
	;
      else if (unformat (input, "ntimers %d", &tm->ntimers))
	;
      else if (unformat (input, "niter %d", &tm->niter))
	;
      else if (unformat (input, "ticks_per_iter %d", &tm->ticks_per_iter))
	;
      else
	break;
    }

  if (is_test1 + is_test2 + is_test3 + is_test4 + is_test5 == 0)
    return clib_error_return (0, "No test specified [test1..n]");

  if (num_wheels < 1 || num_wheels > 3)
    return clib_error_return (0, "unsupported... 1 or 2 wheels only");

  if (is_test1)
    {
      if (num_wheels == 1)
	return test1_single (tm);
      else
	return test1_double (tm);
    }
  if (is_test2)
    {
      if (num_wheels == 1)
	return test2_single (tm);
      else if (num_wheels == 2)
	if (is_updates)
	  return test2_double_updates (tm);
	else
	  return test2_double (tm);
      else if (num_wheels == 3)
	{
	  if (overflow == 0)
	    return test2_triple (tm);
	  else
	    return test2_triple_ov (tm);
	}
    }
  if (is_test3)
    return test3_triple_double (tm);

  if (is_test4)
    return test4_double_double (tm);

  if (is_test5)
    return test5_double (tm);

  /* NOTREACHED */
  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  clib_error_t *error;
  tw_timer_test_main_t *tm = &tw_timer_test_main;

  clib_mem_init (0, 3ULL << 30);

  unformat_init_command_line (&i, argv);
  error = timer_test_command_fn (tm, &i);
  unformat_free (&i);

  if (error)
    {
      clib_error_report (error);
      return 1;
    }
  return 0;
}
#endif /* CLIB_UNIX */

/* For debugging... */
int
pifi (void *p, u32 index)
{
  return pool_is_free_index (p, index);
}

u32
vl (void *p)
{
  return vec_len (p);
}

uword
pe (void *v)
{
  return (pool_elts (v));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
