/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_sfdp_timer_h__
#define __included_sfdp_timer_h__
#include <vppinfra/tw_timer_2t_1w_2048sl.h>
#include <vppinfra/vec.h>

#include <vnet/sfdp/sfdp.h>

typedef tw_timer_wheel_2t_1w_2048sl_t sfdp_tw_t;

typedef struct
{
  sfdp_tw_t wheel;
  f64 current_time;
  u32 *expired_sessions;
} sfdp_timer_per_thread_data_t;

typedef struct
{
  sfdp_timer_per_thread_data_t *per_thread_data;
} sfdp_timer_main_t;

extern sfdp_timer_main_t sfdp_timer_main;

// Per session state held in sfdp session expiry opaque data
typedef struct
{
  f64 next_expiration;
  u32 handle;
  u32 __unused;
} __attribute__ ((may_alias)) sfdp_session_timer_t;

#define foreach_sfdp_timeout                                                  \
  _ (EMBRYONIC, 5, "embryonic")                                               \
  _ (ESTABLISHED, 120, "established")                                         \
  _ (TCP_ESTABLISHED, 3600, "tcp-established")                                \
  _ (SECURITY, 30, "security")

typedef enum
{
#define _(name, val, str) SFDP_TIMEOUT_##name,
  foreach_sfdp_timeout
#undef _
    SFDP_N_TIMEOUT
} sfdp_timeout_type_t;

#define SFDP_SESSION_TIMER(session)                                           \
  SFDP_EXPIRY_SESSION (session, sfdp_session_timer_t)

SFDP_EXPIRY_STATIC_ASSERT_FITS_IN_EXPIRY_OPAQUE (sfdp_session_timer_t);

#define sfdp_timer_start_internal  tw_timer_start_2t_1w_2048sl
#define sfdp_timer_stop_internal   tw_timer_stop_2t_1w_2048sl
#define sfdp_timer_update_internal tw_timer_update_2t_1w_2048sl
#define sfdp_expire_timers	   tw_timer_expire_timers_2t_1w_2048sl
#define SFDP_TIMER_SI_MASK	   (0x7fffffff)
#define SFDP_TIMER_INTERVAL	   ((f64) 1.0) /*in seconds*/
#define SFDP_SECONDS_TO_TICKS	   (seconds) ((seconds) / SFDP_TIMER_INTERVAL)
#define SFDP_TICKS_TO_SECONDS	   (ticks) ((ticks) *SFDP_TIMER_INTERVAL)

static_always_inline sfdp_timer_per_thread_data_t *
sfdp_timer_get_per_thread_data (u32 thread_index)
{
  return vec_elt_at_index (sfdp_timer_main.per_thread_data, thread_index);
}

static_always_inline void
sfdp_tw_init (sfdp_tw_t *tw, void *expired_timer_callback, f64 timer_interval,
	      u32 max_expirations)
{
  tw_timer_wheel_init_2t_1w_2048sl (tw, expired_timer_callback, timer_interval,
				    max_expirations);
}

/* Use timer mechanism for expiry.
 * This must be called while sfdp is not running yet.
 * Will return 0 on success, -1 otherwise. */
u32 sfdp_timer_register_as_expiry_module ();

static_always_inline void
sfdp_session_timer_start (sfdp_tw_t *tw, sfdp_session_timer_t *timer,
			  u32 session_index, f64 now, u32 ticks)
{
  timer->handle = sfdp_timer_start_internal (tw, session_index, 0, ticks);
  timer->next_expiration = now + ticks * SFDP_TIMER_INTERVAL;
}

static_always_inline void
sfdp_session_timer_stop (sfdp_tw_t *tw, sfdp_session_timer_t *timer)
{
  sfdp_timer_stop_internal (tw, timer->handle);
}

static_always_inline void
sfdp_session_timer_update (sfdp_tw_t *tw, sfdp_session_timer_t *timer, f64 now,
			   u32 ticks)
{
  if (PREDICT_FALSE (ticks == 0))
    vlib_node_set_interrupt_pending (vlib_get_main (), sfdp_expire_node.index);
  timer->next_expiration = now + ticks * SFDP_TIMER_INTERVAL;
}

static_always_inline void
sfdp_session_timer_update_maybe_past (sfdp_tw_t *tw,
				      sfdp_session_timer_t *timer, f64 now,
				      u32 ticks)
{
  if (timer->next_expiration > now + (ticks * SFDP_TIMER_INTERVAL))
    sfdp_timer_update_internal (tw, timer->handle, ticks);

  sfdp_session_timer_update (tw, timer, now, ticks);
}

static_always_inline void
sfdp_session_timer_update_unlikely_past (sfdp_tw_t *tw,
					 sfdp_session_timer_t *timer, f64 now,
					 u32 ticks)
{
  if (PREDICT_FALSE (timer->next_expiration >
		     now + (ticks * SFDP_TIMER_INTERVAL)))
    {
      sfdp_timer_update_internal (tw, timer->handle, ticks);
    }
  sfdp_session_timer_update (tw, timer, now, ticks);
}

static_always_inline uword
vec_reset_len_return (u32 *v)
{
  vec_reset_length (v);
  return 0;
}

#define sfdp_session_index_iterate_expired(ptd, s)                            \
  for (u32 *s_ptr = (ptd)->expired_sessions;                                  \
       ((s_ptr < vec_end (ptd->expired_sessions)) &&                          \
	(((s) = s_ptr[0]) || 1)) ||                                           \
       vec_reset_len_return ((ptd)->expired_sessions);                        \
       s_ptr++)

#endif /* __included_sfdp_timer_h__ */
