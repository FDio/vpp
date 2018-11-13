/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <igmp/igmp_timer.h>
#include <igmp/igmp.h>

/**
 * Default timer values as per RFC
 */

static igmp_timer_type_t igmp_default_timer_values[] = {
  [IGMP_TIMER_QUERY] = 60,
  [IGMP_TIMER_SRC] = (3 * 60),
  [IGMP_TIMER_LEAVE] = 60,
  [IGMP_TIMER_REPORT_INTERVAL] = 1,
};

#define IGMP_N_TIMERS (IGMP_TIMER_REPORT_INTERVAL+1)

/**
 * Timer
 */
typedef struct igmp_timer_t_
{
  /** Expiration timer */
  f64 exp_time;

  /** Call-back function to invoke on expiry */
  igmp_timer_function_t func;

  /** index of the object that scheduled the timer */
  u32 obj;

  /** Data registered by the client and passed back when the timer expires */
  void *data;
} igmp_timer_t;

enum
{
  IGMP_PROCESS_EVENT_UPDATE_TIMER = 1,
} igmp_process_event_t;

/**
 * pool of timers
 */
static igmp_timer_t *timer_pool;

/**
 * Vector of pending timers
 */
static u32 *pending_timers;

u32
igmp_timer_type_get (igmp_timer_type_t t)
{
  ASSERT (t < IGMP_N_TIMERS);
  return (igmp_default_timer_values[t]);
}

void
igmp_timer_type_set (igmp_timer_type_t t, u32 v)
{
  ASSERT (t < IGMP_N_TIMERS);
  igmp_default_timer_values[t] = v;
}


static int
igmp_timer_compare (const void *_v1, const void *_v2)
{
  const u32 *i1 = _v1, *i2 = _v2;
  const igmp_timer_t *t1, *t2;
  f64 dt;

  t1 = pool_elt_at_index (timer_pool, *i1);
  t2 = pool_elt_at_index (timer_pool, *i2);

  dt = t2->exp_time - t1->exp_time;

  return (dt < 0 ? -1 : (dt > 0 ? +1 : 0));
}

/** \brief igmp get next timer
    @param im - igmp main

    Get next timer.
*/
u32
igmp_get_next_timer (void)
{
  if (0 == vec_len (pending_timers))
    return (IGMP_TIMER_ID_INVALID);

  return (pending_timers[vec_len (pending_timers) - 1]);
}

void *
igmp_timer_get_data (igmp_timer_id_t tid)
{
  igmp_timer_t *timer;

  timer = pool_elt_at_index (timer_pool, tid);

  return (timer->data);
}

void
igmp_timer_set_data (igmp_timer_id_t tid, void *data)
{
  igmp_timer_t *timer;

  timer = pool_elt_at_index (timer_pool, tid);

  timer->data = data;
}

int
igmp_timer_is_running (igmp_timer_id_t tid)
{
  return (IGMP_TIMER_ID_INVALID == tid);
}

/** \brief igmp timer process
    @param vm - vlib main
    @param rt - vlib runtime node
    @param f - vlib frame

    Handle igmp timers.
*/
static uword
igmp_timer_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		    vlib_frame_t * f)
{
  uword *event_data = 0, event_type;
  igmp_timer_id_t tid;
  igmp_timer_t *timer;

  tid = IGMP_TIMER_ID_INVALID;

  while (1)
    {
      /* suspend util timer expires */
      if (IGMP_TIMER_ID_INVALID != tid)
	{
	  timer = pool_elt_at_index (timer_pool, tid);
	  vlib_process_wait_for_event_or_clock
	    (vm, timer->exp_time - vlib_time_now (vm));
	}
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      if (event_type == IGMP_PROCESS_EVENT_UPDATE_TIMER)
	goto next_timer;

      /* timer expired */
      ASSERT (tid != IGMP_TIMER_ID_INVALID);

      timer = pool_elt_at_index (timer_pool, tid);
      ASSERT (timer->func != NULL);
      timer->func (timer->obj, timer->data);

    next_timer:
      tid = igmp_get_next_timer ();
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (igmp_timer_process_node) =
{
  .function = igmp_timer_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "igmp-timer-process",
  .n_next_nodes = 0,
};
/* *INDENT-ON* */

igmp_timer_id_t
igmp_timer_schedule (f64 when, u32 obj, igmp_timer_function_t fn, void *data)
{
  igmp_timer_t *timer;
  vlib_main_t *vm;

  ASSERT (fn);

  vm = vlib_get_main ();
  pool_get (timer_pool, timer);

  timer->exp_time = vlib_time_now (vm) + when;
  timer->obj = obj;
  timer->func = fn;
  timer->data = data;

  vec_add1 (pending_timers, timer - timer_pool);

  vec_sort_with_function (pending_timers, igmp_timer_compare);

  vlib_process_signal_event (vm, igmp_timer_process_node.index,
			     IGMP_PROCESS_EVENT_UPDATE_TIMER, 0);

  return (timer - timer_pool);
}

void
igmp_timer_retire (igmp_timer_id_t * tid)
{
  if (IGMP_TIMER_ID_INVALID == *tid)
    return;
  vec_del1 (pending_timers, vec_search (pending_timers, *tid));
  pool_put_index (timer_pool, *tid);
  *tid = IGMP_TIMER_ID_INVALID;

  vlib_process_signal_event (vlib_get_main (),
			     igmp_timer_process_node.index,
			     IGMP_PROCESS_EVENT_UPDATE_TIMER, 0);
}

u8 *
format_igmp_timer_id (u8 * s, va_list * args)
{
  igmp_timer_id_t tid = va_arg (*args, igmp_timer_id_t);
  igmp_timer_t *timer;

  if (IGMP_TIMER_ID_INVALID == tid)
    {
      s = format (s, "not-running");
    }
  else
    {
      timer = pool_elt_at_index (timer_pool, tid);

      s =
	format (s, "[expires-in:%f]",
		timer->exp_time - vlib_time_now (vlib_get_main ()));
    }

  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
