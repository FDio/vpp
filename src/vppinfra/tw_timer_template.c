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
#if TW_START_STOP_TRACE_SIZE > 0

void TW (tw_timer_trace) (TWT (tw_timer_wheel) * tw, u32 timer_id,
			  u32 pool_index, u32 handle)
{
  TWT (trace) * t = &tw->traces[tw->trace_index];

  t->timer_id = timer_id;
  t->pool_index = pool_index;
  t->handle = handle;

  tw->trace_index++;
  if (tw->trace_index == TW_START_STOP_TRACE_SIZE)
    {
      tw->trace_index = 0;
      tw->trace_wrapped++;
    }
}

void TW (tw_search_trace) (TWT (tw_timer_wheel) * tw, u32 handle)
{
  u32 i, start_pos;
  TWT (trace) * t;
  char *s = "bogus!";

  /* reverse search for the supplied handle */

  start_pos = tw->trace_index;
  if (start_pos == 0)
    start_pos = TW_START_STOP_TRACE_SIZE - 1;
  else
    start_pos--;

  for (i = start_pos; i > 0; i--)
    {
      t = &tw->traces[i];
      if (t->handle == handle)
	{
	  switch (t->timer_id)
	    {
	    case 0xFF:
	      s = "stopped";
	      break;
	    case 0xFE:
	      s = "expired";
	      break;
	    default:
	      s = "started";
	      break;
	    }
	  fformat (stderr, "handle 0x%x (%d) %s at trace %d\n",
		   handle, handle, s, i);
	}
    }
  if (tw->trace_wrapped > 0)
    {
      for (i = TW_START_STOP_TRACE_SIZE; i >= tw->trace_index; i--)
	{
	  t = &tw->traces[i];
	  if (t->handle == handle)
	    {
	      switch (t->timer_id)
		{
		case 0xFF:
		  s = "stopped";
		  break;
		case 0xFE:
		  s = "expired";
		  break;
		default:
		  s = "started";
		  break;
		}
	      fformat (stderr, "handle 0x%x (%d) %s at trace %d\n",
		       handle, handle, s, i);
	    }
	}
    }
}
#endif /* TW_START_STOP_TRACE_SIZE > 0 */

static inline u32
TW (make_internal_timer_handle) (u32 pool_index, u32 timer_id)
{
  u32 handle;

  ASSERT (timer_id < TW_TIMERS_PER_OBJECT);
#if LOG2_TW_TIMERS_PER_OBJECT > 0
  ASSERT (pool_index < (1 << (32 - LOG2_TW_TIMERS_PER_OBJECT)));

  handle = (timer_id << (32 - LOG2_TW_TIMERS_PER_OBJECT)) | (pool_index);
#else
  handle = pool_index;
#endif
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
timer_remove (TWT (tw_timer) * pool, TWT (tw_timer) * elt)
{
  TWT (tw_timer) * next_elt, *prev_elt;

  ASSERT (elt->user_handle != ~0);

  next_elt = pool_elt_at_index (pool, elt->next);
  prev_elt = pool_elt_at_index (pool, elt->prev);

  next_elt->prev = elt->prev;
  prev_elt->next = elt->next;

  elt->prev = elt->next = ~0;
}

static inline void
timer_add (TWT (tw_timer_wheel) * tw, TWT (tw_timer) * t, u64 interval)
{
#if TW_TIMER_WHEELS > 1
  u16 slow_ring_offset;
  u32 carry;
#endif
#if TW_TIMER_WHEELS > 2
  u16 glacier_ring_offset;
#endif
#if TW_OVERFLOW_VECTOR > 0
  u64 interval_plus_time_to_wrap, triple_wrap_mask;
#endif
  u16 fast_ring_offset;
  tw_timer_wheel_slot_t *ts;

  /* Factor interval into 1..3 wheel offsets */
#if TW_TIMER_WHEELS > 2
#if TW_OVERFLOW_VECTOR > 0
  /*
   * This is tricky. Put a timer onto the overflow
   * vector if the interval PLUS the time
   * until the next triple-wrap exceeds one full revolution
   * of all three wheels.
   */
  triple_wrap_mask = (1 << (3 * TW_RING_SHIFT)) - 1;
  interval_plus_time_to_wrap =
    interval + (tw->current_tick & triple_wrap_mask);
  if ((interval_plus_time_to_wrap >= 1 << (3 * TW_RING_SHIFT)))
    {
      t->expiration_time = tw->current_tick + interval;
      ts = &tw->overflow;
      timer_addhead (tw->timers, ts->head_index, t - tw->timers);
#if TW_START_STOP_TRACE_SIZE > 0
      TW (tw_timer_trace) (tw, timer_id, user_id, t - tw->timers);
#endif
      return;
    }
#endif

  glacier_ring_offset = interval >> (2 * TW_RING_SHIFT);
  ASSERT ((u64) glacier_ring_offset < TW_SLOTS_PER_RING);
  interval -= (((u64) glacier_ring_offset) << (2 * TW_RING_SHIFT));
#endif
#if TW_TIMER_WHEELS > 1
  slow_ring_offset = interval >> TW_RING_SHIFT;
  ASSERT ((u64) slow_ring_offset < TW_SLOTS_PER_RING);
  interval -= (((u64) slow_ring_offset) << TW_RING_SHIFT);
#endif
  fast_ring_offset = interval & TW_RING_MASK;

  /*
   * Account for the current wheel positions(s)
   * This is made slightly complicated by the fact that the current
   * index vector will contain (TW_SLOTS_PER_RING, ...) when
   * the actual position is (0, ...)
   */

  fast_ring_offset += tw->current_index[TW_TIMER_RING_FAST] & TW_RING_MASK;

#if TW_TIMER_WHEELS > 1
  carry = fast_ring_offset >= TW_SLOTS_PER_RING ? 1 : 0;
  fast_ring_offset %= TW_SLOTS_PER_RING;
  slow_ring_offset += (tw->current_index[TW_TIMER_RING_SLOW] & TW_RING_MASK)
    + carry;
  carry = slow_ring_offset >= TW_SLOTS_PER_RING ? 1 : 0;
  slow_ring_offset %= TW_SLOTS_PER_RING;
#endif

#if TW_TIMER_WHEELS > 2
  glacier_ring_offset +=
    (tw->current_index[TW_TIMER_RING_GLACIER] & TW_RING_MASK) + carry;
  glacier_ring_offset %= TW_SLOTS_PER_RING;
#endif

#if TW_TIMER_WHEELS > 2
  if (glacier_ring_offset !=
      (tw->current_index[TW_TIMER_RING_GLACIER] & TW_RING_MASK))
    {
      /* We'll need slow and fast ring offsets later */
      t->slow_ring_offset = slow_ring_offset;
      t->fast_ring_offset = fast_ring_offset;

      ts = &tw->w[TW_TIMER_RING_GLACIER][glacier_ring_offset];

      timer_addhead (tw->timers, ts->head_index, t - tw->timers);
#if TW_START_STOP_TRACE_SIZE > 0
      TW (tw_timer_trace) (tw, timer_id, user_id, t - tw->timers);
#endif
      return;
    }
#endif

#if TW_TIMER_WHEELS > 1
  /* Timer expires more than 51.2 seconds from now? */
  if (slow_ring_offset !=
      (tw->current_index[TW_TIMER_RING_SLOW] & TW_RING_MASK))
    {
      /* We'll need the fast ring offset later... */
      t->fast_ring_offset = fast_ring_offset;

      ts = &tw->w[TW_TIMER_RING_SLOW][slow_ring_offset];

      timer_addhead (tw->timers, ts->head_index, t - tw->timers);
#if TW_START_STOP_TRACE_SIZE > 0
      TW (tw_timer_trace) (tw, timer_id, user_id, t - tw->timers);
#endif
      return;
    }
#else
  fast_ring_offset %= TW_SLOTS_PER_RING;
#endif

  /* Timer expires less than one fast-ring revolution from now */
  ts = &tw->w[TW_TIMER_RING_FAST][fast_ring_offset];

  timer_addhead (tw->timers, ts->head_index, t - tw->timers);

#if TW_FAST_WHEEL_BITMAP
  tw->fast_slot_bitmap = clib_bitmap_set (tw->fast_slot_bitmap,
					  fast_ring_offset, 1);
#endif
#if TW_START_STOP_TRACE_SIZE > 0
  TW (tw_timer_trace) (tw, timer_id, user_id, t - tw->timers);
#endif
}

/**
 * @brief Start a Tw Timer
 * @param tw_timer_wheel_t * tw timer wheel object pointer
 * @param u32 user_id user defined timer id, presumably for a tw session
 * @param u32 timer_id app-specific timer ID. 4 bits.
 * @param u64 interval timer interval in ticks
 * @returns handle needed to cancel the timer
 */
u32
TW (tw_timer_start) (TWT (tw_timer_wheel) * tw, u32 user_id, u32 timer_id,
		     u64 interval)
{
  TWT (tw_timer) * t;

  ASSERT (interval);

  pool_get (tw->timers, t);
  clib_memset (t, 0xff, sizeof (*t));

  t->user_handle = TW (make_internal_timer_handle) (user_id, timer_id);

  timer_add (tw, t, interval);
  return t - tw->timers;
}

#if TW_TIMER_SCAN_FOR_HANDLE > 0
int TW (scan_for_handle) (TWT (tw_timer_wheel) * tw, u32 handle)
{
  int i, j;
  tw_timer_wheel_slot_t *ts;
  TWT (tw_timer) * t, *head;
  u32 next_index;
  int rv = 0;

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
	      if (next_index == handle)
		{
		  clib_warning ("handle %d found in ring %d slot %d",
				handle, i, j);
		  clib_warning ("user handle 0x%x", t->user_handle);
		  rv = 1;
		}
	      next_index = t->next;
	    }
	}
    }
  return rv;
}
#endif /* TW_TIMER_SCAN_FOR_HANDLE */

/**
 * @brief Stop a tw timer
 * @param tw_timer_wheel_t * tw timer wheel object pointer
 * @param u32 handle timer cancellation returned by tw_timer_start
 */
void TW (tw_timer_stop) (TWT (tw_timer_wheel) * tw, u32 handle)
{
  TWT (tw_timer) * t;

#if TW_TIMER_ALLOW_DUPLICATE_STOP
  /*
   * A vlib process may have its timer expire, and receive
   * an event before the expiration is processed.
   * That results in a duplicate tw_timer_stop.
   */
  if (pool_is_free_index (tw->timers, handle))
    return;
#endif
#if TW_START_STOP_TRACE_SIZE > 0
  TW (tw_timer_trace) (tw, ~0, ~0, handle);
#endif

  t = pool_elt_at_index (tw->timers, handle);

  /* in case of idiotic handle (e.g. passing a listhead index) */
  ASSERT (t->user_handle != ~0);

  timer_remove (tw->timers, t);

  pool_put_index (tw->timers, handle);
}

int TW (tw_timer_handle_is_free) (TWT (tw_timer_wheel) * tw, u32 handle)
{
  return pool_is_free_index (tw->timers, handle);
}

/**
 * @brief Update a tw timer
 * @param tw_timer_wheel_t * tw timer wheel object pointer
 * @param u32 handle timer returned by tw_timer_start
 * @param u32 interval timer interval in ticks
 */
void TW (tw_timer_update) (TWT (tw_timer_wheel) * tw, u32 handle,
			   u64 interval)
{
  TWT (tw_timer) * t;
  t = pool_elt_at_index (tw->timers, handle);
  timer_remove (tw->timers, t);
  timer_add (tw, t, interval);
}

/**
 * @brief Initialize a tw timer wheel template instance
 * @param tw_timer_wheel_t * tw timer wheel object pointer
 * @param void * expired_timer_callback. Passed a u32 * vector of
 *   expired timer handles. The callback is optional.
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
  clib_memset (tw, 0, sizeof (*tw));
  tw->expired_timer_callback = expired_timer_callback;
  tw->max_expirations = max_expirations;
  if (timer_interval_in_seconds == 0.0)
    {
      clib_warning ("timer interval is zero");
      abort ();
    }
  tw->timer_interval = timer_interval_in_seconds;
  tw->ticks_per_second = 1.0 / timer_interval_in_seconds;
  tw->first_expires_tick = ~0ULL;

  vec_validate (tw->expired_timer_handles, 0);
  _vec_len (tw->expired_timer_handles) = 0;

  for (ring = 0; ring < TW_TIMER_WHEELS; ring++)
    {
      for (slot = 0; slot < TW_SLOTS_PER_RING; slot++)
	{
	  ts = &tw->w[ring][slot];
	  pool_get (tw->timers, t);
	  clib_memset (t, 0xff, sizeof (*t));
	  t->next = t->prev = t - tw->timers;
	  ts->head_index = t - tw->timers;
	}
    }

#if TW_OVERFLOW_VECTOR > 0
  ts = &tw->overflow;
  pool_get (tw->timers, t);
  clib_memset (t, 0xff, sizeof (*t));
  t->next = t->prev = t - tw->timers;
  ts->head_index = t - tw->timers;
#endif
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

#if TW_OVERFLOW_VECVOR > 0
  ts = &tw->overflow;
  head = pool_elt_at_index (tw->timers, ts->head_index);
  next_index = head->next;

  while (next_index != ts->head_index)
    {
      t = pool_elt_at_index (tw->timers, next_index);
      next_index = t->next;
      pool_put (tw->timers, t);
    }
  pool_put (tw->timers, head);
#endif

  clib_memset (tw, 0, sizeof (*tw));
}

/**
 * @brief Advance a tw timer wheel. Calls the expired timer callback
 * as needed. This routine should be called once every timer_interval seconds
 * @param tw_timer_wheel_t * tw timer wheel template instance pointer
 * @param f64 now the current time, e.g. from vlib_time_now(vm)
 * @returns u32 * vector of expired user handles
 */
static inline
  u32 * TW (tw_timer_expire_timers_internal) (TWT (tw_timer_wheel) * tw,
					      f64 now,
					      u32 * callback_vector_arg)
{
  u32 nticks, i;
  tw_timer_wheel_slot_t *ts;
  TWT (tw_timer) * t, *head;
  u32 *callback_vector;
  u32 fast_wheel_index;
  u32 next_index;
  u32 slow_wheel_index __attribute__ ((unused));
  u32 glacier_wheel_index __attribute__ ((unused));

  /* Shouldn't happen */
  if (PREDICT_FALSE (now < tw->next_run_time))
    return callback_vector_arg;

  /* Number of ticks which have occurred */
  nticks = tw->ticks_per_second * (now - tw->last_run_time);
  if (nticks == 0)
    return callback_vector_arg;

  /* Remember when we ran, compute next runtime */
  tw->next_run_time = (now + tw->timer_interval);

  if (callback_vector_arg == 0)
    {
      _vec_len (tw->expired_timer_handles) = 0;
      callback_vector = tw->expired_timer_handles;
    }
  else
    callback_vector = callback_vector_arg;

  for (i = 0; i < nticks; i++)
    {
      fast_wheel_index = tw->current_index[TW_TIMER_RING_FAST];
      if (TW_TIMER_WHEELS > 1)
	slow_wheel_index = tw->current_index[TW_TIMER_RING_SLOW];
      if (TW_TIMER_WHEELS > 2)
	glacier_wheel_index = tw->current_index[TW_TIMER_RING_GLACIER];

#if TW_OVERFLOW_VECTOR > 0
      /* Triple odometer-click? Process the overflow vector... */
      if (PREDICT_FALSE (fast_wheel_index == TW_SLOTS_PER_RING
			 && slow_wheel_index == TW_SLOTS_PER_RING
			 && glacier_wheel_index == TW_SLOTS_PER_RING))
	{
	  u64 interval;
	  u32 new_glacier_ring_offset, new_slow_ring_offset;
	  u32 new_fast_ring_offset;

	  ts = &tw->overflow;
	  head = pool_elt_at_index (tw->timers, ts->head_index);
	  next_index = head->next;

	  /* Make slot empty */
	  head->next = head->prev = ts->head_index;

	  /* traverse slot, place timers wherever they go */
	  while (next_index != head - tw->timers)
	    {
	      t = pool_elt_at_index (tw->timers, next_index);
	      next_index = t->next;

	      /* Remove from the overflow vector (hammer) */
	      t->next = t->prev = ~0;

	      ASSERT (t->expiration_time >= tw->current_tick);

	      interval = t->expiration_time - tw->current_tick;

	      /* Right back onto the overflow vector? */
	      if (interval >= (1 << (3 * TW_RING_SHIFT)))
		{
		  ts = &tw->overflow;
		  timer_addhead (tw->timers, ts->head_index, t - tw->timers);
		  continue;
		}
	      /* Compute ring offsets */
	      new_glacier_ring_offset = interval >> (2 * TW_RING_SHIFT);

	      interval -= (new_glacier_ring_offset << (2 * TW_RING_SHIFT));

	      /* Note: the wheels are at (0,0,0), no add-with-carry needed */
	      new_slow_ring_offset = interval >> TW_RING_SHIFT;
	      interval -= (new_slow_ring_offset << TW_RING_SHIFT);
	      new_fast_ring_offset = interval & TW_RING_MASK;
	      t->slow_ring_offset = new_slow_ring_offset;
	      t->fast_ring_offset = new_fast_ring_offset;

	      /* Timer expires Right Now */
	      if (PREDICT_FALSE (t->slow_ring_offset == 0 &&
				 t->fast_ring_offset == 0 &&
				 new_glacier_ring_offset == 0))
		{
		  vec_add1 (callback_vector, t->user_handle);
#if TW_START_STOP_TRACE_SIZE > 0
		  TW (tw_timer_trace) (tw, 0xfe, t->user_handle,
				       t - tw->timers);
#endif
		  pool_put (tw->timers, t);
		}
	      /* Timer moves to the glacier ring */
	      else if (new_glacier_ring_offset)
		{
		  ts = &tw->w[TW_TIMER_RING_GLACIER][new_glacier_ring_offset];
		  timer_addhead (tw->timers, ts->head_index, t - tw->timers);
		}
	      /* Timer moves to the slow ring */
	      else if (t->slow_ring_offset)
		{
		  /* Add to slow ring */
		  ts = &tw->w[TW_TIMER_RING_SLOW][t->slow_ring_offset];
		  timer_addhead (tw->timers, ts->head_index, t - tw->timers);
		}
	      /* Timer timer moves to the fast ring */
	      else
		{
		  ts = &tw->w[TW_TIMER_RING_FAST][t->fast_ring_offset];
		  timer_addhead (tw->timers, ts->head_index, t - tw->timers);
#if TW_FAST_WHEEL_BITMAP
		  tw->fast_slot_bitmap =
		    clib_bitmap_set (tw->fast_slot_bitmap,
				     t->fast_ring_offset, 1);
#endif
		}
	    }
	}
#endif

#if TW_TIMER_WHEELS > 2
      /*
       * Double odometer-click? Process one slot in the glacier ring...
       */
      if (PREDICT_FALSE (fast_wheel_index == TW_SLOTS_PER_RING
			 && slow_wheel_index == TW_SLOTS_PER_RING))
	{
	  glacier_wheel_index %= TW_SLOTS_PER_RING;
	  ts = &tw->w[TW_TIMER_RING_GLACIER][glacier_wheel_index];

	  head = pool_elt_at_index (tw->timers, ts->head_index);
	  next_index = head->next;

	  /* Make slot empty */
	  head->next = head->prev = ts->head_index;

	  /* traverse slot, deal timers into slow ring */
	  while (next_index != head - tw->timers)
	    {
	      t = pool_elt_at_index (tw->timers, next_index);
	      next_index = t->next;

	      /* Remove from glacier ring slot (hammer) */
	      t->next = t->prev = ~0;

	      /* Timer expires Right Now */
	      if (PREDICT_FALSE (t->slow_ring_offset == 0 &&
				 t->fast_ring_offset == 0))
		{
		  vec_add1 (callback_vector, t->user_handle);
#if TW_START_STOP_TRACE_SIZE > 0
		  TW (tw_timer_trace) (tw, 0xfe, t->user_handle,
				       t - tw->timers);
#endif
		  pool_put (tw->timers, t);
		}
	      /* Timer expires during slow-wheel tick 0 */
	      else if (PREDICT_FALSE (t->slow_ring_offset == 0))
		{
		  ts = &tw->w[TW_TIMER_RING_FAST][t->fast_ring_offset];
		  timer_addhead (tw->timers, ts->head_index, t - tw->timers);
#if TW_FAST_WHEEL_BITMAP
		  tw->fast_slot_bitmap =
		    clib_bitmap_set (tw->fast_slot_bitmap,
				     t->fast_ring_offset, 1);
#endif
		}
	      else		/* typical case */
		{
		  /* Add to slow ring */
		  ts = &tw->w[TW_TIMER_RING_SLOW][t->slow_ring_offset];
		  timer_addhead (tw->timers, ts->head_index, t - tw->timers);
		}
	    }
	}
#endif

#if TW_TIMER_WHEELS > 1
      /*
       * Single odometer-click? Process a slot in the slow ring,
       */
      if (PREDICT_FALSE (fast_wheel_index == TW_SLOTS_PER_RING))
	{
	  slow_wheel_index %= TW_SLOTS_PER_RING;
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

	      /* Remove from sloe ring slot (hammer) */
	      t->next = t->prev = ~0;

	      /* Timer expires Right Now */
	      if (PREDICT_FALSE (t->fast_ring_offset == 0))
		{
		  vec_add1 (callback_vector, t->user_handle);
#if TW_START_STOP_TRACE_SIZE > 0
		  TW (tw_timer_trace) (tw, 0xfe, t->user_handle,
				       t - tw->timers);
#endif
		  pool_put (tw->timers, t);
		}
	      else		/* typical case */
		{
		  /* Add to fast ring */
		  ts = &tw->w[TW_TIMER_RING_FAST][t->fast_ring_offset];
		  timer_addhead (tw->timers, ts->head_index, t - tw->timers);
#if TW_FAST_WHEEL_BITMAP
		  tw->fast_slot_bitmap =
		    clib_bitmap_set (tw->fast_slot_bitmap,
				     t->fast_ring_offset, 1);
#endif
		}
	    }
	}
#endif

      /* Handle the fast ring */
      fast_wheel_index %= TW_SLOTS_PER_RING;
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
	  vec_add1 (callback_vector, t->user_handle);
#if TW_START_STOP_TRACE_SIZE > 0
	  TW (tw_timer_trace) (tw, 0xfe, t->user_handle, t - tw->timers);
#endif
	  pool_put (tw->timers, t);
	}

      /* If any timers expired, tell the user */
      if (callback_vector_arg == 0 && vec_len (callback_vector))
	{
	  /* The callback is optional. We return the u32 * handle vector */
	  if (tw->expired_timer_callback)
	    {
	      tw->expired_timer_callback (callback_vector);
	      vec_reset_length (callback_vector);
	    }
	  tw->expired_timer_handles = callback_vector;
	}

#if TW_FAST_WHEEL_BITMAP
      tw->fast_slot_bitmap = clib_bitmap_set (tw->fast_slot_bitmap,
					      fast_wheel_index, 0);
#endif

      tw->current_tick++;
      fast_wheel_index++;
      tw->current_index[TW_TIMER_RING_FAST] = fast_wheel_index;

#if TW_TIMER_WHEELS > 1
      if (PREDICT_FALSE (fast_wheel_index == TW_SLOTS_PER_RING))
	slow_wheel_index++;
      tw->current_index[TW_TIMER_RING_SLOW] = slow_wheel_index;
#endif

#if TW_TIMER_WHEELS > 2
      if (PREDICT_FALSE (slow_wheel_index == TW_SLOTS_PER_RING))
	glacier_wheel_index++;
      tw->current_index[TW_TIMER_RING_GLACIER] = glacier_wheel_index;
#endif

      if (vec_len (callback_vector) >= tw->max_expirations)
	break;
    }

  if (callback_vector_arg == 0)
    tw->expired_timer_handles = callback_vector;

  tw->last_run_time += i * tw->timer_interval;
  return callback_vector;
}

u32 *TW (tw_timer_expire_timers) (TWT (tw_timer_wheel) * tw, f64 now)
{
  return TW (tw_timer_expire_timers_internal) (tw, now, 0 /* no vector */ );
}

u32 *TW (tw_timer_expire_timers_vec) (TWT (tw_timer_wheel) * tw, f64 now,
				      u32 * vec)
{
  return TW (tw_timer_expire_timers_internal) (tw, now, vec);
}

#if TW_FAST_WHEEL_BITMAP
/** Returns an approximation to the first timer expiration in
 * timer-ticks from "now". To avoid wasting an unjustifiable
 * amount of time on the problem, we maintain an approximate fast-wheel slot
 * occupancy bitmap. We don't worry about clearing fast wheel bits
 * when timers are removed from fast wheel slots.
 */

u32 TW (tw_timer_first_expires_in_ticks) (TWT (tw_timer_wheel) * tw)
{
  u32 first_expiring_index, fast_ring_index;
  i32 delta;

  if (clib_bitmap_is_zero (tw->fast_slot_bitmap))
    return TW_SLOTS_PER_RING;

  fast_ring_index = tw->current_index[TW_TIMER_RING_FAST];
  if (fast_ring_index == TW_SLOTS_PER_RING)
    fast_ring_index = 0;

  first_expiring_index = clib_bitmap_next_set (tw->fast_slot_bitmap,
					       fast_ring_index);
  if (first_expiring_index == ~0 && fast_ring_index != 0)
    first_expiring_index = clib_bitmap_first_set (tw->fast_slot_bitmap);

  ASSERT (first_expiring_index != ~0);

  delta = (i32) first_expiring_index - (i32) fast_ring_index;
  if (delta < 0)
    delta += TW_SLOTS_PER_RING;

  ASSERT (delta >= 0);

  return (u32) delta;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
