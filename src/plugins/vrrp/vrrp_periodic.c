/*
 * vrrp_periodic.c - vrrp plug-in periodic function
 *
 * Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <vrrp/vrrp.h>
#include <vrrp/vrrp_packet.h>

static int
vrrp_vr_timer_compare (const void *v1, const void *v2)
{
  vrrp_main_t *vmp = &vrrp_main;
  const u32 *idx1, *idx2;
  vrrp_vr_timer_t *timer1, *timer2;

  idx1 = v1;
  idx2 = v2;

  timer1 = pool_elt_at_index (vmp->vr_timers, *idx1);
  timer2 = pool_elt_at_index (vmp->vr_timers, *idx2);

  /* don't check equality, they are unlikely to be exactly equal and
   * if it occurs, it won't matter what order they were in.
   * sort the list in reverse so we can pick the next timer off the end */
  if (timer1->expire_time > timer2->expire_time)
    return -1;
  else
    return 1;
}

static u32
vrrp_vr_timer_get_next (void)
{
  vrrp_main_t *vmp = &vrrp_main;
  int n_timers;

  n_timers = vec_len (vmp->pending_timers);

  if (!n_timers)
    return ~0;

  return vec_elt (vmp->pending_timers, n_timers - 1);
}

/* cancel an existing timer. This could happen because:
 * - adv timer expired on master. another adv should be scheduled.
 * - a shutdown event is received
 * - a master is preempted by a higher priority master
 * - adv received on backup. master down timer should be rescheduled.
 */
void
vrrp_vr_timer_cancel (vrrp_vr_t * vr)
{
  vrrp_main_t *vmp = &vrrp_main;
  u32 *t;

  /* don't search for a timer that was already canceled or never set */
  if (vr->runtime.timer_index == ~0)
    return;

  /* timers stored in descending order, start at the end of the list */
  /* vec_foreach_backwards does not deal with 0 pointers, check first */
  if (vmp->pending_timers)
    vec_foreach_backwards (t, vmp->pending_timers)
    {
      if (*t == vr->runtime.timer_index)
	{
	  vec_delete (vmp->pending_timers, 1, t - vmp->pending_timers);
	  break;
	}
    }

  if (!pool_is_free_index (vmp->vr_timers, vr->runtime.timer_index))
    pool_put_index (vmp->vr_timers, vr->runtime.timer_index);

  vr->runtime.timer_index = ~0;

  vlib_process_signal_event (vmp->vlib_main, vrrp_periodic_node.index,
			     VRRP_EVENT_VR_TIMER_UPDATE, 0);
}

void
vrrp_vr_timer_set (vrrp_vr_t * vr, vrrp_vr_timer_type_t type)
{
  vrrp_main_t *vmp = &vrrp_main;
  vlib_main_t *vm = vlib_get_main ();
  vrrp_vr_timer_t *timer;
  f64 now;

  /* Each VR should be waiting on at most 1 timer at any given time.
   * If there is already a timer set for this VR, cancel it.
   */
  if (vr->runtime.timer_index != ~0)
    vrrp_vr_timer_cancel (vr);

  pool_get (vmp->vr_timers, timer);
  vr->runtime.timer_index = timer - vmp->vr_timers;

  timer->vr_index = vr - vmp->vrs;
  timer->type = type;

  now = vlib_time_now (vm);

  /* RFC 5798 specifies that timers are in centiseconds, so x / 100.0 */
  switch (type)
    {
    case VRRP_VR_TIMER_ADV:
      timer->expire_time = now + (vr->config.adv_interval / 100.0);
      break;
    case VRRP_VR_TIMER_MASTER_DOWN:
      timer->expire_time = now + (vr->runtime.master_down_int / 100.0);
      break;
    default:
      /* should never reach here */
      clib_warning ("Unrecognized VRRP timer type (%d)", type);
      return;
    }

  vec_add1 (vmp->pending_timers, vr->runtime.timer_index);

  vec_sort_with_function (vmp->pending_timers, vrrp_vr_timer_compare);

  vlib_process_signal_event (vmp->vlib_main, vrrp_periodic_node.index,
			     VRRP_EVENT_VR_TIMER_UPDATE, 0);
}

void
vrrp_vr_timer_timeout (u32 timer_index)
{
  vrrp_main_t *vmp = &vrrp_main;
  vrrp_vr_timer_t *timer;
  vrrp_vr_t *vr;

  if (pool_is_free_index (vmp->vr_timers, timer_index))
    {
      clib_warning ("Timeout on free timer index %u", timer_index);
      return;
    }

  timer = pool_elt_at_index (vmp->vr_timers, timer_index);
  vr = pool_elt_at_index (vmp->vrs, timer->vr_index);

  switch (timer->type)
    {
    case VRRP_VR_TIMER_ADV:
      vrrp_adv_send (vr, 0);
      vrrp_vr_timer_set (vr, VRRP_VR_TIMER_ADV);
      break;
    case VRRP_VR_TIMER_MASTER_DOWN:
      vrrp_vr_transition (vr, VRRP_VR_STATE_MASTER, NULL);
      break;
    default:
      clib_warning ("Unrecognized timer type %d", timer->type);
      return;
    }

}

static uword
vrrp_periodic_process (vlib_main_t * vm,
		       vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vrrp_main_t *pm = &vrrp_main;
  f64 now;
  f64 timeout = 10.0;
  uword *event_data = 0;
  uword event_type;
  u32 next_timer = ~0;
  vrrp_vr_timer_t *timer;

  while (1)
    {
      now = vlib_time_now (vm);

      if (next_timer == ~0)
	{
	  vlib_process_wait_for_event (vm);
	}
      else
	{
	  timer = pool_elt_at_index (pm->vr_timers, next_timer);
	  timeout = timer->expire_time - now;

	  /*
	   * Adding a virtual MAC to some NICs can take a significant amount
	   * of time (~1s). If a lot of VRs enter the master state around the
	   * same time, the process node can stay active for a very long time
	   * processing all of the transitions.
	   *
	   * Try to force a 10us sleep between processing events to ensure
	   * that the process node does not prevent API messages and RPCs
	   * from being handled for an extended period. This prevents
	   * vlib_process_wait_for_event_or_clock() from returning
	   * immediately.
	   */
	  vlib_process_wait_for_event_or_clock (vm, clib_max (timeout, 10e-6));
	}

      event_type = vlib_process_get_events (vm, (uword **) & event_data);

      switch (event_type)
	{
	  /* Handle VRRP_EVENT_VR_TIMER_UPDATE */
	case VRRP_EVENT_VR_TIMER_UPDATE:
	  next_timer = vrrp_vr_timer_get_next ();
	  break;

	  /* Handle periodic timeouts */
	case ~0:
	  vrrp_vr_timer_timeout (next_timer);
	  next_timer = vrrp_vr_timer_get_next ();
	  break;
	}
      vec_reset_length (event_data);
    }
  return 0;
}

VLIB_REGISTER_NODE (vrrp_periodic_node) = {
  .function = vrrp_periodic_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "vrrp-periodic-process",
  .process_log2_n_stack_bytes = 17,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
