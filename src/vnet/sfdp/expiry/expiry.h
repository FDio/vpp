/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_sfdp_expiry_h__
#define __included_sfdp_expiry_h__
#include <vppinfra/format.h>
#include <vppinfra/types.h>
#include <vlib/vlib.h>

/* Default margin before eviction is requested to expiry module. */
#define SFDP_DEFAULT_EVICTION_SESSIONS_MARGIN (256 * 256) /* 256 vectors */

/* Defined in sfdp.h, but needed in callback functions definitions */
typedef struct sfdp_session sfdp_session_t;
typedef struct sfdp_timeout sfdp_timeout_t;

/* Defines callbacks used by sfdp to call expiry module. */
typedef struct
{
  /* Called by sfdp when it's being enabled.
   * The expiry module shouldn't do anything before this is called. */
  void (*enable) ();

  /* Called by sfdp when it's being disabled.
   * The expiry module shouldn't do anything after this is called. */
  void (*disable) ();

  /* Called by sfdp on every pre-input step, on every worker thread.
   * Provides an opportunity for the session expiry module to timeout flows,
   * but also for sfdp to request a specific number of flows to be evicted.
   * This is best-effort, and the module could return less than the number
   * of evicted sessions.
   * desired_expiries: number of requested flow expiries to be added to the
   * vector. expired_sessions_vec: vec pointer to be filled with expired
   * sessions. return: updated expired_sessions_vec (resize may change the
   * vector pointer value). The expiry module may add fewer, or more, sessions
   * than the requested number.
   *
   * Note: Upon placing a session index in expired_sessions_vec, the expiry
   *       module shall have freed any associated resources, as sfdp will free
   * it definitely.
   */
  u32 *(*expire_or_evict_sessions) (u32 desired_expiries,
				    u32 *expired_sessions_vec);

  /* Called by sfdp-lookup after new session entry is created,
   * but before the first packet gets procesed with it.
   * This gives the opportunity for the session expiry module to initialize
   * per-flow state before the packet is processed by any service. */
  void (*notify_new_sessions) (const u32 *new_sessions, u32 len);

  /* Shall return the flow's remaining time to live.
   * Used by CLI table dump and API. */
  f64 (*session_remaining_time) (sfdp_session_t *session, f64 now);

  /* Shall format the session expiry information details.
   * The variadic arguments used are:
   * - sfdp_session_t *session
   * - f64 now
   * Note: If printed on more than one line, use provided indentation.
   */
  u8 *(*format_session_details) (u8 *s, va_list *args);

} sfdp_expiry_callbacks_t;

/* Check that sfdp_session_t::expiry_opaque holds expiry module data. */
#define SFDP_EXPIRY_STATIC_ASSERT_FITS_IN_EXPIRY_OPAQUE(type)                 \
  STATIC_ASSERT (sizeof (type) <=                                             \
		   sizeof (((sfdp_session_t *) (0))->expiry_opaque),          \
		 #type " too big to fit in expiry_opaque");

/* Casts sfdp_session_t::expiry_opaque into provided type. */
#define SFDP_EXPIRY_SESSION(session, type)                                    \
  ((type *) (sfdp_get_session_expiry_opaque (session)))

/** Sets the expiry callbacks.
 *
 *  Returns 0 upon success, or a different value if called while sfdp is
 *  already enabled.
 */
int sfdp_set_expiry_callbacks (const sfdp_expiry_callbacks_t *callbacks);

/** Provides initial timeout names and defaults to sfdp-core.
 *
 *  Returns 0 upon success, or a different value if called while sfdp is
 *  already enabled.
 */
int sfdp_init_timeouts (const sfdp_timeout_t *timeouts, u32 n);

/** Called by sfdp when enabling/disabling expiry. */
void sfdp_enable_disable_expiry (u8 is_disable);

/** Called by sfdp_enable_disable_expiry to set the sfdp-expiry sched node
 *  to disabled or polling state. */
void sfdp_enable_disable_expiry_node (u8 is_disable, int skip_main);

/** Sets the sessions-count margin used to enable flow eviction
 *
 *  Once the number of remaining available sessions passes below the margin.
 *  the expiry module will be asked to remove existing sessions.
 *
 *  The value used depends on the expiry module implementation. If the
 *  expiry module can synchronously delete all the needed sessions, then
 *  the value shall be equal to the maximum number of new sessions that
 *  can be processed in a single VPP loop.
 *  Otherwise, a greater value shall be used, as to leave enough time
 *  for the expiry module to evict flows without taking a risk to run out
 *  of flow entries.
 *
 *  This function accepts ~0, which will set the margin to a default value.
 */
clib_error_t *sfdp_set_eviction_sessions_margin (u32 margin);

void sfdp_check_eviction_sessions_margin ();

extern vlib_node_registration_t sfdp_expire_node;

#endif /* __included_sfdp_expiry_h__ */
