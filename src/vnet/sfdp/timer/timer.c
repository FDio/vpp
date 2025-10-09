/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/sfdp/timer/timer.h>

#include <vlib/vlib.h>

#include <vnet/sfdp/expiry/expiry.h>
#include <vnet/sfdp/sfdp.h>

sfdp_timer_main_t sfdp_timer_main;

static void
expired_timer_callback (u32 *expired)
{
  u32 *e;
  uword thread_index = vlib_get_thread_index ();
  sfdp_timer_main_t *t = &sfdp_timer_main;
  sfdp_timer_per_thread_data_t *ptd =
    vec_elt_at_index (t->per_thread_data, thread_index);
  vec_foreach (e, expired)
    {
      u32 session_idx = e[0] & SFDP_TIMER_SI_MASK;
      vec_add1 (ptd->expired_sessions, session_idx);
    }
}

static void
timer_expiry_cb_enable ()
{
  sfdp_timer_main_t *t = &sfdp_timer_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vec_validate (t->per_thread_data, tm->n_vlib_mains - 1);
  sfdp_timer_per_thread_data_t *ptd;
  vec_foreach (ptd, t->per_thread_data)
    {
      ptd->expired_sessions = 0;
      sfdp_tw_init (&ptd->wheel, expired_timer_callback, SFDP_TIMER_INTERVAL,
		    ~0);
    }
}

static void
timer_expiry_cb_disable ()
{
  // Cleanup timer wheel ? Disabling not supported for now.
}

static u32 *
timer_expiry_cb_expire_or_evict_sessions (u32 desired_expiries,
					  u32 *expired_sessions_vec)
{
  (void) desired_expiries; // TODO: Early discards not supported for now.

  sfdp_timer_main_t *t = &sfdp_timer_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 tidx = vlib_get_thread_index ();
  sfdp_timer_per_thread_data_t *ptd =
    vec_elt_at_index (t->per_thread_data, tidx);
  u32 session_index;

  f64 now = vlib_time_now (vm);
  ptd->current_time = now;

  sfdp_expire_timers (&ptd->wheel, now);

  sfdp_session_index_iterate_expired (ptd, session_index)
  {
    sfdp_session_t *session = sfdp_session_at_index (session_index);
    sfdp_session_timer_t *timer = SFDP_SESSION_TIMER (session);
    f64 diff =
      (timer->next_expiration - (ptd->current_time + SFDP_TIMER_INTERVAL)) /
      SFDP_TIMER_INTERVAL;
    if (diff > (f64) 1.)
      {
	/* Rearm the timer accordingly */
	sfdp_session_timer_start (&ptd->wheel, timer, session_index,
				  ptd->current_time, diff);
      }
    else
      {
	vec_add1 (expired_sessions_vec, session_index);
      }
  }

  return expired_sessions_vec;
}

static void
timer_expiry_cb_notify_new_sessions (const u32 *new_sessions, u32 len)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_timer_main_t *t = &sfdp_timer_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 tidx = vlib_get_thread_index ();
  sfdp_timer_per_thread_data_t *ptd =
    vec_elt_at_index (t->per_thread_data, tidx);
  const u32 *session_index = new_sessions;
  f64 time_now = vlib_time_now (vm);
  ptd->current_time = time_now;

  // Start session timer in embryonic mode
  while (len)
    {
      sfdp_session_t *session = sfdp_session_at_index (*session_index);
      sfdp_session_timer_t *timer = SFDP_SESSION_TIMER (session);
      sfdp_tenant_t *tenant = sfdp_tenant_at_index (sfdp, session->tenant_idx);
      sfdp_session_timer_start (&ptd->wheel, timer, *session_index, time_now,
				tenant->timeouts[SFDP_TIMEOUT_EMBRYONIC]);

      len--;
      session_index++;
    }
}

static f64
timer_expiry_cb_session_remaining_time (sfdp_session_t *session, f64 now)
{
  return SFDP_SESSION_TIMER (session)->next_expiration - now;
}

static u8 *
timer_expiry_cb_format_session_details (u8 *s, va_list *args)
{
  sfdp_session_t *session = va_arg (*args, sfdp_session_t *);
  f64 now = va_arg (*args, f64);
  sfdp_session_timer_t *timer = SFDP_SESSION_TIMER (session);
  f64 remaining_time = timer->next_expiration - now;
  s = format (s, "expires after: %fs\n", remaining_time);
  return s;
}

u32
sfdp_timer_register_as_expiry_module ()
{
  sfdp_timeout_t timeouts[SFDP_MAX_TIMEOUTS] = {};
  int ret;
  u32 i = 0;
#define _(n, v, str)                                                          \
  timeouts[i].name = str;                                                     \
  timeouts[i].val = v;                                                        \
  i++;
  foreach_sfdp_timeout
#undef _

    if ((ret = sfdp_init_timeouts (timeouts, i)))
  {
    return ret;
  }

  sfdp_expiry_callbacks_t cbs = {
    .enable = timer_expiry_cb_enable,
    .disable = timer_expiry_cb_disable,
    .expire_or_evict_sessions = timer_expiry_cb_expire_or_evict_sessions,
    .notify_new_sessions = timer_expiry_cb_notify_new_sessions,
    .session_remaining_time = timer_expiry_cb_session_remaining_time,
    .format_session_details = timer_expiry_cb_format_session_details
  };
  return sfdp_set_expiry_callbacks (&cbs);
}
