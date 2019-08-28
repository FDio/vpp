/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020, LabN Consulting, L.L.C
 * March 2 2020, Christian E. Hopps <chopps@labn.net>
 */
#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <vppinfra/time.h>
#include <iptfs/deferred.h>

char *deferred_event_type_strings[DEFERRED_EVENT_N_TYPES] = {
#define _(sym, string) string,
  foreach_deferred_event_type
#undef _
};

#define DEFERRED_DEBUG 0

#if DEFERRED_DEBUG
#define defer_debug(...) clib_warning (__VA_ARGS__)
#else
#define defer_debug(...)
#endif

static deferred_t **deferred_queue;

#define vec_insert_sorted(V, E, cmp)                                                               \
  do                                                                                               \
    {                                                                                              \
      int __right, __left = 0;                                                                     \
      if ((__right = vec_len (V)))                                                                 \
	{                                                                                          \
	  int __cmp, __mid;                                                                        \
	  while (__left < __right)                                                                 \
	    {                                                                                      \
	      __mid = (__left + __right) / 2;                                                      \
	      __cmp = (cmp) ((E), (V)[__mid]);                                                     \
	      if (__cmp < 0) /* E is lower */                                                      \
		__right = __mid;                                                                   \
	      else if (__cmp > 0) /* E is higher */                                                \
		__left = __mid + 1;                                                                \
	      else                                                                                 \
		{                                                                                  \
		  __left = __mid;                                                                  \
		  break;                                                                           \
		}                                                                                  \
	    }                                                                                      \
	}                                                                                          \
      vec_insert_elts (V, &(E), 1, __left);                                                        \
    }                                                                                              \
  while (0)

/*
 * Return the new timeout delta
 */
static inline f64
deferred_get_remaining (vlib_main_t *vm)
{
  u32 len = vec_len (deferred_queue);
  if (!len)
    return 0;

  f64 now = vlib_time_now (vm);
  f64 end = deferred_queue[len - 1]->end;
  if (now > end)
    return 0;

  f64 delta = end - now;
  if (vlib_process_suspend_time_is_zero (delta))
    return 0;
  return delta;
}

static int
cmp_decending (deferred_t *a, deferred_t *b)
{
  if (a->end > b->end)
    return -1;
  else if (a->end < b->end)
    return 1;
  return 0;
}

static inline f64
deferred_process_event (vlib_main_t *vm, uword event_type, deferred_t *deferred)
{
  f64 remaining;

  if (event_type == ~0u)
    /* Timeout */;
  else if (event_type == DEFERRED_EVENT_TYPE_SCHEDULE)
    /* Schedule a callback */
    {
      defer_debug ("%s: schedled defer for: %.16f which is %.16f from now", __FUNCTION__,
		   deferred->end, deferred->end - vlib_time_now (vm));
      defer_debug ("%s: schedled defer for: %f which is %f from now", __FUNCTION__, deferred->end,
		   deferred->end - vlib_time_now (vm));
      vec_insert_sorted (deferred_queue, deferred, cmp_decending);
    }
  else if (event_type != DEFERRED_EVENT_TYPE_SCHEDULE)
    clib_warning ("%s: unexpected event type: %u", __FUNCTION__, event_type);

  /*
   * Process all deferred that have expired
   */
  defer_debug ("%s: checking queue (len %u)", __FUNCTION__, vec_len (deferred_queue));
  while (vec_len (deferred_queue))
    {
      remaining = deferred_get_remaining (vm);
      if (!vlib_process_suspend_time_is_zero (remaining))
	return remaining;

      deferred = vec_pop (deferred_queue);
      deferred->callback (deferred->data);
      vec_free (deferred);
    }

  defer_debug ("%s: queue empty", __FUNCTION__);
  return 0;
}

static uword
deferred_process (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  uword event_type, *event_data;
  f64 remaining = 0;

  defer_debug ("%s: Enter", __FUNCTION__);

  while (1)
    {
      if (vlib_process_suspend_time_is_zero (remaining) && vec_len (deferred_queue))
	{
	  defer_debug ("%s: Processing queue len %u", __FUNCTION__, vec_len (deferred_queue));
	  event_type = ~0u;
	  event_data = NULL;
	}
      else
	{
	  if (vec_len (deferred_queue))
	    {
	      defer_debug ("%s: Waiting for event or time %.16f queue len %d", __FUNCTION__,
			   remaining, vec_len (deferred_queue));
	      vlib_process_wait_for_event_or_clock (vm, remaining);
	    }
	  else
	    {
	      ASSERT (!vec_len (deferred_queue));
	      defer_debug ("%s: Waiting for event", __FUNCTION__);
	      vlib_process_wait_for_event (vm);
	    }
	  if (!(event_data = vlib_process_get_event_data (vm, &event_type)))
	    event_type = ~0u;
	}

      deferred_t *deferred = event_data ? (deferred_t *) *event_data : NULL;
      defer_debug ("%s: event_type %u, event_data: %p *data = %p, vec_len() == %d", __FUNCTION__,
		   (u32) event_type, event_data, deferred, vec_len (event_data));
      if (event_type == ~0u)
	ASSERT (event_data == NULL);
      else
	ASSERT (event_data != NULL);
      remaining = deferred_process_event (vm, event_type, deferred);
      vec_reset_length (event_data);
    }

  /*NOTREACHED*/
  return 0;
}

VLIB_REGISTER_NODE (deferred_process_node) = {
  .function = deferred_process,
  .name = "deferred-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};
