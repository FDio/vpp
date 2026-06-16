/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Cisco and/or its affiliates. */

#ifndef __tcp_fastopen_h__
#define __tcp_fastopen_h__

#include <vnet/tcp/tcp_types.h>
#include <vnet/tcp/tcp_packet.h>

/*
 * TCP Fast Open (RFC 7413)
 *
 * All TFO cookie-cache, blackhole-detection, key-rotation, and
 * sweep state lives in tcp_main_t (declared in tcp.h). This header
 * provides the public API, types, and constants.
 */

/** @name TFO constants */
/** @{ */
#define TCP_TFO_BLACKHOLE_THRESH    3	 /**< failures before disabling TFO */
#define TCP_TFO_BLACKHOLE_TIMEOUT   300	 /**< cooldown in seconds (5 min) */
#define TCP_TFO_CACHE_EXPIRATION    3600 /**< cookie-cache entry TTL (1 h) */
#define TCP_TFO_KEY_ROTATE_INTERVAL 120	 /**< key rotation interval (sec) */
#define TCP_TFO_SWEEP_INTERVAL	    900	 /**< background sweep interval (sec) */
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

#endif /* __tcp_fastopen_h__ */
