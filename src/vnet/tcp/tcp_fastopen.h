/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Cisco and/or its affiliates. */

#ifndef __tcp_fastopen_h__
#define __tcp_fastopen_h__

#include <vnet/tcp/tcp_types.h>
#include <vnet/tcp/tcp_packet.h>

/*
 * RFC 7413: TCP Fast Open (TFO)
 *
 * All TFO cookie-cache, blackhole-detection, key-rotation
 * and sweep state lives in tcp_main_t (declared in tcp.h).
 * This header provides the public API, types, constants
 * and small inline helpers that consolidate TFO logic.
 */

/** @name TFO constants */
/** @{ */
#define TCP_TFO_BLACKHOLE_THRESH    3	   /**< failures before disabling TFO */
#define TCP_TFO_BLACKHOLE_TIMEOUT   300	   /**< cooldown in seconds (5 min) */
#define TCP_TFO_CACHE_EXPIRATION    3600   /**< cookie-cache entry TTL (1 h) */
#define TCP_TFO_KEY_ROTATE_INTERVAL 120	   /**< key rotation interval (sec) */
#define TCP_TFO_SWEEP_INTERVAL	    900	   /**< background sweep interval (sec) */
#define TCP_TFO_PENDING_MAX	    300000 /**< max pending fast-open slots */
/** @} */

/** @name TFO per-connection helper macros */
/** @{ */
#define tcp_tfo_enabled(tc)	((tc)->cfg_flags & TCP_CFG_F_TFO)
#define tcp_fast_opened(tc)	((tc)->flags & TCP_CONN_FAST_OPENED)
#define tcp_fast_opened_on(tc)	((tc)->flags |= TCP_CONN_FAST_OPENED)
#define tcp_fast_opened_off(tc) ((tc)->flags &= ~TCP_CONN_FAST_OPENED)

/* Sticky bit: our first SYN included a TFO option (cached cookie).
 * Used by the SYN retransmit path to record a blackhole for the
 * destination when the TFO SYN failed to elicit a SYN-ACK. */
#define tcp_tfo_syn_sent(tc)	 ((tc)->flags & TCP_CONN_TFO_SYN_SENT)
#define tcp_tfo_syn_sent_on(tc)	 ((tc)->flags |= TCP_CONN_TFO_SYN_SENT)
#define tcp_tfo_syn_sent_off(tc) ((tc)->flags &= ~TCP_CONN_TFO_SYN_SENT)

/* Sticky bit: peer included a TFO option in the SYN we received.
 * Set in the listen handler, consumed by tcp_make_synack() to decide
 * whether the SYN-ACK carries a TFO cookie option. Survives SYN-ACK
 * retransmits since rcv_opts.flags is clobbered on every parse. */
#define tcp_tfo_opt_rcvd(tc)	((tc)->flags & TCP_CONN_TFO_OPT_RCVD)
#define tcp_tfo_opt_rcvd_on(tc) ((tc)->flags |= TCP_CONN_TFO_OPT_RCVD)
/** @} */

/** @name TFO early-SYN data accessors
 *
 * The TFO early-SYN data pointer (client side only) is stored
 * in @ref tcp_options_t.tfo_syn_data, which unions with
 * @ref tcp_options_t.sacks inside the connection's snd_opts.
 * The two are time-disjoint (sacks is populated only after handshake
 * completion), so they share a cache slot without ambiguity.
 *
 * Owned only during SYN_SENT. Must be cleared/freed before the
 * connection transitions to ESTABLISHED, so the slot reverts to
 * its post-handshake SACK semantics.
 * @{ */
#define tcp_tfo_syn_data(tc) ((tc)->snd_opts.tfo_syn_data)

always_inline void
tcp_tfo_syn_data_free (tcp_connection_t *tc)
{
  /* vec_free safely handles NULL. It zeroes the union slot, so
   * subsequent post-handshake code that consults snd_opts.sacks
   * will see NULL until SACK generation actually populates it.
   */
  vec_free (tc->snd_opts.tfo_syn_data);
}
/** @} */

/**
 * Outcome of TFO listen-side processing for a received SYN.
 *
 * Returned by @ref tcp_tfo_listen_handle to drive per-node error
 * counters in the calling listen node. The helper performs all
 * state mutation (flags, pending counter, SYN-data enqueue);
 * the caller only reports the action via tcp_inc_counter().
 */
typedef enum tcp_tfo_listen_action_
{
  TCP_TFO_LISTEN_NONE = 0,	 /**< No TFO option, fall through to 3WHS */
  TCP_TFO_LISTEN_COOKIE_SENT,	 /**< Cookie request: SYN-ACK carries cookie */
  TCP_TFO_LISTEN_FAST_OPEN,	 /**< Valid cookie + slot: fast-open, SYN data
				      enqueued to the session */
  TCP_TFO_LISTEN_COOKIE_INVALID, /**< Bad cookie: fall back to 3WHS, refresh
				      cookie in SYN-ACK */
  TCP_TFO_LISTEN_PENDING_FULL,	 /**< Pending limit reached: fall back to
				      3WHS, refresh cookie in SYN-ACK */
} tcp_tfo_listen_action_t;

/** Cookie-cache pool entry (one per destination IP). */
typedef struct tcp_tfo_cc_entry_
{
  uword ip_key; /**< hash key (remote IP) for background sweep */
  u8 cookie[TCP_TFO_COOKIE_LEN_MAX];
  u8 cookie_len;
  f64 timestamp;
} tcp_tfo_cc_entry_t;

/** Blackhole-detection pool entry (one per destination IP). */
typedef struct tcp_tfo_bh_entry_
{
  uword ip_key; /**< hash key (remote IP) for background sweep */
  u8 failures;
  f64 last_failure;
} tcp_tfo_bh_entry_t;

/* Cookie generation & validation (RFC 7413 Sec 4.1.2) */
void tcp_tfo_get_cookie (tcp_connection_t *tc, u8 *cookie, u8 *len);
int tcp_tfo_cookie_is_valid (tcp_connection_t *tc, u8 *cookie, u8 len);

/* Cookie cache */
void tcp_tfo_cache_cookie (tcp_connection_t *tc, u8 *cookie, u8 len);
int tcp_tfo_lookup_cookie (tcp_connection_t *tc, u8 *cookie, u8 *len);

/* Blackhole detection */
void tcp_tfo_blackhole_record (tcp_connection_t *tc);
int tcp_tfo_blackhole_check (tcp_connection_t *tc);
void tcp_tfo_blackhole_clear (tcp_connection_t *tc);

/* Cache management */
void tcp_tfo_cache_flush (u32 *n_cache_freed, u32 *n_bh_freed);

/* Initialization (called from tcp_main_enable) */
void tcp_fastopen_init (vlib_main_t *vm);

/**
 * Process the TFO option on a received SYN at the listen node.
 *
 * Returns @ref TCP_TFO_LISTEN_NONE when TFO is disabled on the listener
 * @p lc or when the SYN carries no TFO option. Otherwise validates the
 * cookie, reserves a fast-open pending slot on success, marks @p child
 * appropriately and enqueues any SYN data into the session. The peer's
 * TFO bit is recorded in @p child so that @ref tcp_make_synack emits a
 * fresh cookie option on the SYN-ACK.
 *
 * @return One of @ref tcp_tfo_listen_action_t. The caller must increment
 *         the matching per-node error counter (TCP_ERROR_TFO_*).
 */
tcp_tfo_listen_action_t tcp_tfo_listen_handle (tcp_connection_t *lc, tcp_connection_t *child,
					       vlib_buffer_t *b);

/**
 * Build the TFO option payload for an outgoing SYN-ACK.
 *
 * Examines @p tc for the OPT_RCVD bit; if set, fills @p cookie_buf with
 * a freshly computed cookie, attaches the option to @p opts, advances
 * @p tcp_opts_len by the encoded option length (with realignment) and
 * sets @p *cookie_p to point at @p cookie_buf so that @ref tcp_options_write
 * copies the bytes on the wire. No-op when no TFO option was received in SYN.
 */
void tcp_tfo_synack_options (tcp_connection_t *tc, tcp_options_t *opts, u8 *cookie_buf,
			     u8 **cookie_p, u8 *tcp_opts_len);

/**
 * Decide whether to attempt TFO on this SYN, look up a cached cookie
 * and update connection state accordingly.
 *
 * Performs the blackhole gate, cache lookup and @ref tcp_tfo_syn_sent_on()
 * bookkeeping. On entry @p *cookie_buf is a caller-provided stack scratch
 * of @ref TCP_TFO_COOKIE_LEN_MAX bytes; on return @p *cookie_len is the
 * cookie length found in the cache (0 when no cached cookie or when
 * blackholed). When this function returns non-zero, the caller MUST emit
 * the TFO option in the SYN (cookie request iff @p *cookie_len == 0);
 * when it returns 0, no TFO option is emitted.
 *
 * @param tc          half-open connection
 * @param vm          vlib main of the calling worker (for counter inc)
 * @param cookie_buf  caller scratch buffer for the looked-up cookie
 * @param cookie_len  out: cookie length stored in @p cookie_buf
 * @return            non-zero iff the SYN should carry a TFO option
 */
u8 tcp_tfo_prepare_send_syn (tcp_connection_t *tc, vlib_main_t *vm, u8 *cookie_buf, u8 *cookie_len);

/**
 * Copy the application-supplied early SYN data (held in @ref tcp_tfo_syn_data)
 * into the SYN buffer, capped to the per-segment limit (derived from MSS minus
 * options length). No-op when there is no cached cookie, no SYN data or
 * @ref tcp_tfo_enabled is false (RFC 7413 Sec 4.1.2). SYN data is included only
 * when a cached cookie is available; otherwise the SYN is a pure cookie probe.
 *
 * @return number of data bytes written to the buffer.
 */
u16 tcp_tfo_write_syn_data (tcp_connection_t *tc, vlib_buffer_t *b, u8 cookie_len);

/**
 * Cache the TFO cookie carried in an incoming SYN-ACK and, on success, clear
 * any blackhole entry for the destination. Reads the option directly from the
 * wire header to avoid duplicating the cookie into per-connection scratch.
 */
void tcp_tfo_handle_synack_cookie (tcp_connection_t *tc, tcp_header_t *th);

/**
 * SYN retransmit-time TFO bookkeeping. Records a blackhole hit if the
 * original SYN included a TFO option (sticky @ref tcp_tfo_syn_sent flag),
 * clears that flag and frees any early SYN data since, as per RFC 7413,
 * retransmits MUST NOT carry early data (Sec 4.1.3).
 */
void tcp_tfo_syn_retransmit_cleanup (tcp_connection_t *tc);

/**
 * Post-handshake connection-cleanup hook. Releases the TFO pending slot
 * if the connection was fast-opened but never reached ESTABLISHED. Called
 * from @ref tcp_connection_cleanup for non-SYN_SENT states; the SYN_SENT
 * path uses @ref tcp_tfo_syn_data_free directly.
 */
void tcp_tfo_connection_cleanup (tcp_connection_t *tc);

/**
 * Release the TFO pending slot on transition to ESTABLISHED. Called from
 * the SYN-RCVD->ESTABLISHED path on the server side once the client's ACK
 * is observed. No-op when the connection was not fast-opened.
 */
void tcp_tfo_established_release (tcp_connection_t *tc);

#endif /* __tcp_fastopen_h__ */
