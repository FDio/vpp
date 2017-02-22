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

/** @file
 *  @brief TW timer implementation TEMPLATE ONLY, do not compile directly
 *
 *
 */

static inline u32
TW (make_internal_timer_handle) (u32 pool_index, u32 timer_id)
{
  u32 handle;

  ASSERT (timer_id < TW_TIMERS_PER_OBJECT);
  ASSERT (pool_index < (1 << (32 - LOG2_TW_TIMERS_PER_OBJECT)));

  handle = (timer_id << (32 - LOG2_TW_TIMERS_PER_OBJECT)) | (pool_index);
  return handle;
}

static inline void
timer_addhead (TWT (tw_timer) * pool, u32 head_index, u32 new_index)
{
  TWT (tw_timer) * head = pool_elt_at_index (pool, head_index);
  TWT (tw_timer) * old_first;
  u32 old_first_index;
  TWT (tw_timer) * new;

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
timer_remove (TWT (tw_timer) * pool, u32 index)
{
  TWT (tw_timer) * elt = pool_elt_at_index (pool, index);
  TWT (tw_timer) * next_elt, *prev_elt;

  ASSERT (elt->user_handle != ~0);

  next_elt = pool_elt_at_index (pool, elt->next);
  prev_elt = pool_elt_at_index (pool, elt->prev);

  next_elt->prev = elt->prev;
  prev_elt->next = elt->next;

  elt->prev = elt->next = ~0;
}

/**
 * @brief Start a Tw Timer
 * @param tw_timer_wheel_t * tw timer wheel object pointer
 * @param u32 pool_index user pool index, presumably for a tw session
 * @param u32 timer_id app-specific timer ID. 4 bits.
 * @param u32 interval timer interval in ticks
 * @returns handle needed to cancel the timer
 */
u32
TW (tw_timer_start) (TWT (tw_timer_wheel) * tw, u32 pool_index, u32 timer_id,
		     u32 interval)
{
#if TW_TIMER_WHEELS > 1
  u16 slow_ring_offset;
  u32 carry;
#endif
  u16 fast_ring_offset;
  tw_timer_wheel_slot_t *ts;
  TWT (tw_timer) * t;

  ASSERT (interval);

  pool_get (tw->timers, t);
  t->next = t->prev = ~0;
#if TW_TIMER_WHEELS > 1
  t->fast_ring_offset = ~0;
#endif
  t->user_handle = TW (make_internal_timer_handle) (pool_index, timer_id);

  fast_ring_offset = interval & TW_RING_MASK;
  fast_ring_offset += tw->current_index[TW_TIMER_RING_FAST];
#if TW_TIMER_WHEELS > 1
  carry = fast_ring_offset >= TW_SLOTS_PER_RING ? 1 : 0;
  fast_ring_offset %= TW_SLOTS_PER_RING;
  slow_ring_offset = (interval >> TW_RING_SHIFT) + carry;

  /* Timer duration exceeds ~7 hrs? Oops */
  ASSERT (slow_ring_offset < TW_SLOTS_PER_RING);

  /* Timer expires more than 51.2 seconds from now? */
  if (slow_ring_offset)
    {
      slow_ring_offset += tw->current_index[TW_TIMER_RING_SLOW];
      slow_ring_offset %= TW_SLOTS_PER_RING;

      /* We'll want the fast ring offset later... */
      t->fast_ring_offset = fast_ring_offset;
      ASSERT (t->fast_ring_offset < TW_SLOTS_PER_RING);

      ts = &tw->w[TW_TIMER_RING_SLOW][slow_ring_offset];

      timer_addhead (tw->timers, ts->head_index, t - tw->timers);

      return t - tw->timers;
    }
#else
  fast_ring_offset %= TW_SLOTS_PER_RING;
  ASSERT (interval < TW_SLOTS_PER_RING);
#endif

  /* Timer expires less than one fast-ring revolution from now */
  ts = &tw->w[TW_TIMER_RING_FAST][fast_ring_offset];

  timer_addhead (tw->timers, ts->head_index, t - tw->timers);
  return t - tw->timers;
}

/**
 * @brief Stop a tw timer
 * @param tw_timer_wheel_t * tw timer wheel object pointer
 * @param u32 handle timer cancellation returned by tw_timer_start
 */
void TW (tw_timer_stop) (TWT (tw_timer_wheel) * tw, u32 handle)
{
  TWT (tw_timer) * t;

  t = pool_elt_at_index (tw->timers, handle);

  /* in case of idiotic handle (e.g. passing a listhead index) */
  ASSERT (t->user_handle != ~0);

  timer_remove (tw->timers, handle);

  pool_put_index (tw->timers, handle);
}

/**
 * @brief Initialize a tw timer wheel template instance
 * @param tw_timer_wheel_t * tw timer wheel object pointer
 * @param void * expired_timer_callback. Passed a u32 * vector of
 *   expired timer handles.
 * @param f64 timer_interval_in_seconds
 */
void
TW (tw_timer_wheel_init) (TWT (tw_timer_wheel) * tw,
			  void *expired_timer_callback,
			  f64 timer_interval_in_seconds, u32 max_expirations)
{
  int ring, slot;
  tw_timer_wheel_slot_t *ts;
  TWT (tw_timer) * t;
  memset (tw, 0, sizeof (*tw));
  tw->expired_timer_callback = expired_timer_callback;
  tw->max_expirations = max_expirations;
  if (timer_interval_in_seconds == 0.0)
    {
      clib_warning ("timer interval is zero");
      abort ();
    }
  tw->timer_interval = timer_interval_in_seconds;
  tw->ticks_per_second = 1.0 / timer_interval_in_seconds;

  for (ring = 0; ring < TW_TIMER_WHEELS; ring++)
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
 * @brief Free a tw timer wheel template instance
 * @param tw_timer_wheel_t * tw timer wheel object pointer
 */
void TW (tw_timer_wheel_free) (TWT (tw_timer_wheel) * tw)
{
  int i, j;
  tw_timer_wheel_slot_t *ts;
  TWT (tw_timer) * head, *t;
  u32 next_index;

  for (i = 0; i < TW_TIMER_WHEELS; i++)
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
 * @brief Advance a tw timer wheel. Calls the expired timer callback
 * as needed. This routine should be called once every timer_interval seconds
 * @param tw_timer_wheel_t * tw timer wheel template instance pointer
 * @param f64 now the current time, e.g. from vlib_time_now(vm)
 */
u32 TW (tw_timer_expire_timers) (TWT (tw_timer_wheel) * tw, f64 now)
{
  u32 nticks, i;
  tw_timer_wheel_slot_t *ts;
  TWT (tw_timer) * t, *head;
  u32 fast_wheel_index;
  u32 next_index;
  u32 nexpirations, total_nexpirations;
#if TW_TIMER_WHEELS > 1
  u32 slow_wheel_index;
#endif

  /* Shouldn't happen */
  if (PREDICT_FALSE (now < tw->next_run_time))
    return 0;

  /* Number of ticks which have occurred */
  nticks = tw->ticks_per_second * (now - tw->last_run_time);
  if (nticks == 0)
    return 0;

  /* Remember when we ran, compute next runtime */
  tw->next_run_time = (now + tw->timer_interval);

  total_nexpirations = 0;
  for (i = 0; i < nticks; i++)
    {
      fast_wheel_index = tw->current_index[TW_TIMER_RING_FAST];

      /*
       * If we've been around the fast ring once,
       * process one slot in the slow ring before we handle
       * the fast ring.
       */
      if (PREDICT_FALSE (fast_wheel_index == TW_SLOTS_PER_RING))
	{
	  fast_wheel_index = tw->current_index[TW_TIMER_RING_FAST] = 0;

#if TW_TIMER_WHEELS > 1
	  tw->current_index[TW_TIMER_RING_SLOW]++;
	  tw->current_index[TW_TIMER_RING_SLOW] %= TW_SLOTS_PER_RING;
	  slow_wheel_index = tw->current_index[TW_TIMER_RING_SLOW];

	  ts = &tw->w[TW_TIMER_RING_SLOW][slow_wheel_index];

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
	      ts = &tw->w[TW_TIMER_RING_FAST][t->fast_ring_offset];
	      timer_addhead (tw->timers, ts->head_index, t - tw->timers);
	    }
#endif
	}

      /* Handle the fast ring */
      vec_reset_length (tw->expired_timer_handles);

      ts = &tw->w[TW_TIMER_RING_FAST][fast_wheel_index];

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
      nexpirations = vec_len (tw->expired_timer_handles);
      if (nexpirations)
	{
	  tw->expired_timer_callback (tw->expired_timer_handles);
	  total_nexpirations += nexpirations;
	}
      tw->current_index[TW_TIMER_RING_FAST]++;
      tw->current_tick++;

      if (total_nexpirations >= tw->max_expirations)
	break;
    }

  tw->last_run_time += i * tw->timer_interval;
  return total_nexpirations;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
