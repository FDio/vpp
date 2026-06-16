/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Cisco and/or its affiliates. */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_fastopen.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vppinfra/xxhash.h>

/**
 * Compute TFO cookie using an explicit key pair (RFC 7413 Sec 4.1.2).
 * Returns an 8-byte cookie as a u64. Caller copies to wire buffer.
 */
static u64
tcp_tfo_compute_cookie (tcp_connection_t *tc, u64 key0, u64 key1)
{
  u64 x;
  if (tc->c_is_ip4)
    x = key0 ^ (u64) tc->c_rmt_ip.ip4.as_u32;
  else
    x = key0 ^ tc->c_rmt_ip.ip6.as_u64[0] ^ tc->c_rmt_ip.ip6.as_u64[1];
  return clib_xxhash (x) ^ key1;
}

/**
 * Rotate TFO secret key if rotation interval has elapsed (RFC 7413 Sec 4.1.2).
 * Promotes current key to prev, generates new current key.
 */
static void
tcp_tfo_maybe_rotate_keys (void)
{
  tcp_main_t *tm = &tcp_main;
  f64 now = vlib_time_now (vlib_get_main ());

  if (now - tm->tfo_key_rotate_ts < TCP_TFO_KEY_ROTATE_INTERVAL)
    return;

  tm->tfo_key_rotate_ts = now;
  tm->tfo_key_prev[0] = tm->tfo_key[0];
  tm->tfo_key_prev[1] = tm->tfo_key[1];
  tm->tfo_key[0] = clib_xxhash (clib_cpu_time_now () ^ (u64) now);
  tm->tfo_key[1] = clib_xxhash (tm->tfo_key[0] ^ tm->tfo_key_prev[0]);
}

/**
 * Constant-time 8-byte memory comparison. Returns 0 iff equal.
 *
 * Used for TFO cookie validation to avoid leaking cookie bytes through a
 * timing side channel. clib_memcmp may early-exit on the first differing
 * byte, so we OR all byte differences and only branch on the aggregate.
 */
static inline int
tcp_tfo_ct_cmp8 (const u8 *a, const u8 *b)
{
  u8 r = 0;
  int i;
  for (i = 0; i < 8; i++)
    r |= (u8) (a[i] ^ b[i]);
  return r;
}

void
tcp_tfo_get_cookie (tcp_connection_t *tc, u8 *cookie, u8 *len)
{
  tcp_main_t *tm = &tcp_main;
  u64 h;

  clib_spinlock_lock (&tm->tfo_lock);
  tcp_tfo_maybe_rotate_keys ();
  h = tcp_tfo_compute_cookie (tc, tm->tfo_key[0], tm->tfo_key[1]);
  clib_spinlock_unlock (&tm->tfo_lock);
  clib_memcpy_fast (cookie, &h, sizeof (h));
  *len = sizeof (h); /* 8 bytes */
}

int
tcp_tfo_cookie_is_valid (tcp_connection_t *tc, u8 *cookie, u8 len)
{
  tcp_main_t *tm = &tcp_main;
  u64 cur, prev_a = 0, prev_b = 0;
  int has_prev, eq_cur, eq_prev = 0;

  if (PREDICT_FALSE (len != sizeof (u64)))
    return 0;

  clib_spinlock_lock (&tm->tfo_lock);
  cur = tcp_tfo_compute_cookie (tc, tm->tfo_key[0], tm->tfo_key[1]);
  has_prev = (tm->tfo_key_prev[0] != 0 || tm->tfo_key_prev[1] != 0);
  if (has_prev)
    {
      prev_a = tm->tfo_key_prev[0];
      prev_b = tm->tfo_key_prev[1];
    }
  clib_spinlock_unlock (&tm->tfo_lock);

  eq_cur = (tcp_tfo_ct_cmp8 (cookie, (u8 *) &cur) == 0);
  if (has_prev)
    {
      u64 prev_exp = tcp_tfo_compute_cookie (tc, prev_a, prev_b);
      eq_prev = (tcp_tfo_ct_cmp8 (cookie, (u8 *) &prev_exp) == 0);
    }
  return eq_cur | eq_prev;
}

static inline uword
tcp_tfo_ip_key (tcp_connection_t *tc)
{
  if (tc->c_is_ip4)
    return (uword) tc->c_rmt_ip.ip4.as_u32;
  return (uword) (tc->c_rmt_ip.ip6.as_u64[0] ^ tc->c_rmt_ip.ip6.as_u64[1]);
}

void
tcp_tfo_cache_cookie (tcp_connection_t *tc, u8 *cookie, u8 len)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_cc_entry_t *e;
  uword key = tcp_tfo_ip_key (tc);
  uword *p;

  if (PREDICT_FALSE (len > TCP_TFO_COOKIE_LEN_MAX))
    return;

  clib_spinlock_lock (&tm->tfo_lock);
  p = hash_get (tm->tfo_cookie_cache, key);
  if (p)
    e = pool_elt_at_index (tm->tfo_cc_entries, p[0]);
  else
    {
      pool_get_zero (tm->tfo_cc_entries, e);
      hash_set (tm->tfo_cookie_cache, key, e - tm->tfo_cc_entries);
    }
  e->ip_key = key;
  e->cookie_len = len;
  clib_memcpy_fast (e->cookie, cookie, len);
  e->timestamp = vlib_time_now (vlib_get_main ());
  clib_spinlock_unlock (&tm->tfo_lock);
}

int
tcp_tfo_lookup_cookie (tcp_connection_t *tc, u8 *cookie, u8 *len)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_cc_entry_t *e;
  uword key = tcp_tfo_ip_key (tc);
  uword *p;
  int found = 0;

  clib_spinlock_lock (&tm->tfo_lock);
  p = hash_get (tm->tfo_cookie_cache, key);
  if (!p)
    goto done;

  e = pool_elt_at_index (tm->tfo_cc_entries, p[0]);

  if (vlib_time_now (vlib_get_main ()) - e->timestamp > TCP_TFO_CACHE_EXPIRATION)
    {
      pool_put (tm->tfo_cc_entries, e);
      hash_unset (tm->tfo_cookie_cache, key);
      goto done;
    }

  *len = e->cookie_len;
  clib_memcpy_fast (cookie, e->cookie, e->cookie_len);
  found = 1;

done:
  clib_spinlock_unlock (&tm->tfo_lock);
  return found;
}

void
tcp_tfo_blackhole_record (tcp_connection_t *tc)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_bh_entry_t *e;
  uword key = tcp_tfo_ip_key (tc);
  uword *p;

  clib_spinlock_lock (&tm->tfo_lock);
  p = hash_get (tm->tfo_blackhole, key);
  if (p)
    e = pool_elt_at_index (tm->tfo_bh_entries, p[0]);
  else
    {
      pool_get_zero (tm->tfo_bh_entries, e);
      hash_set (tm->tfo_blackhole, key, e - tm->tfo_bh_entries);
      e->ip_key = key;
    }
  e->failures++;
  e->last_failure = vlib_time_now (vlib_get_main ());
  clib_spinlock_unlock (&tm->tfo_lock);
}

int
tcp_tfo_blackhole_check (tcp_connection_t *tc)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_bh_entry_t *e;
  uword key = tcp_tfo_ip_key (tc);
  uword *p;
  int blackholed = 0;

  clib_spinlock_lock (&tm->tfo_lock);
  p = hash_get (tm->tfo_blackhole, key);
  if (!p)
    goto done;

  e = pool_elt_at_index (tm->tfo_bh_entries, p[0]);

  if (vlib_time_now (vlib_get_main ()) - e->last_failure > TCP_TFO_BLACKHOLE_TIMEOUT)
    {
      e->failures = 0;
      goto done;
    }

  blackholed = (e->failures >= TCP_TFO_BLACKHOLE_THRESH);

done:
  clib_spinlock_unlock (&tm->tfo_lock);
  return blackholed;
}

void
tcp_tfo_blackhole_clear (tcp_connection_t *tc)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_bh_entry_t *e;
  uword key = tcp_tfo_ip_key (tc);
  uword *p;

  clib_spinlock_lock (&tm->tfo_lock);
  p = hash_get (tm->tfo_blackhole, key);
  if (!p)
    goto done;

  e = pool_elt_at_index (tm->tfo_bh_entries, p[0]);
  pool_put (tm->tfo_bh_entries, e);
  hash_unset (tm->tfo_blackhole, key);

done:
  clib_spinlock_unlock (&tm->tfo_lock);
}

void
tcp_tfo_cache_flush (u32 *n_cache_freed, u32 *n_bh_freed)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_cc_entry_t *ce;
  tcp_tfo_bh_entry_t *be;
  u32 nc = 0, nb = 0;

  if (!tm->tfo_lock)
    goto out;

  clib_spinlock_lock (&tm->tfo_lock);

  pool_foreach (ce, tm->tfo_cc_entries)
    nc++;
  pool_free (tm->tfo_cc_entries);
  hash_free (tm->tfo_cookie_cache);
  tm->tfo_cookie_cache = hash_create (0, sizeof (uword));

  pool_foreach (be, tm->tfo_bh_entries)
    nb++;
  pool_free (tm->tfo_bh_entries);
  hash_free (tm->tfo_blackhole);
  tm->tfo_blackhole = hash_create (0, sizeof (uword));

  clib_spinlock_unlock (&tm->tfo_lock);

out:
  if (n_cache_freed)
    *n_cache_freed = nc;
  if (n_bh_freed)
    *n_bh_freed = nb;
}

static void
tcp_tfo_cache_sweep_inline (void)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_cc_entry_t *ce;
  tcp_tfo_bh_entry_t *be;
  u32 *del_cc = 0, *del_bh = 0, *idx;
  f64 now;

  if (!tm->tfo_lock)
    return;

  now = vlib_time_now (vlib_get_main ());

  clib_spinlock_lock (&tm->tfo_lock);

  pool_foreach (ce, tm->tfo_cc_entries)
    {
      if (now - ce->timestamp > TCP_TFO_CACHE_EXPIRATION)
	vec_add1 (del_cc, (u32) (ce - tm->tfo_cc_entries));
    }

  vec_foreach (idx, del_cc)
    {
      ce = pool_elt_at_index (tm->tfo_cc_entries, *idx);
      hash_unset (tm->tfo_cookie_cache, ce->ip_key);
      pool_put (tm->tfo_cc_entries, ce);
    }

  pool_foreach (be, tm->tfo_bh_entries)
    {
      if (be->failures == 0 && now - be->last_failure > TCP_TFO_BLACKHOLE_TIMEOUT)
	vec_add1 (del_bh, (u32) (be - tm->tfo_bh_entries));
    }

  vec_foreach (idx, del_bh)
    {
      be = pool_elt_at_index (tm->tfo_bh_entries, *idx);
      hash_unset (tm->tfo_blackhole, be->ip_key);
      pool_put (tm->tfo_bh_entries, be);
    }

  clib_spinlock_unlock (&tm->tfo_lock);

  vec_free (del_cc);
  vec_free (del_bh);
}

static uword
tcp_tfo_sweep_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, TCP_TFO_SWEEP_INTERVAL);
      vlib_process_get_events (vm, 0);
      tcp_tfo_cache_sweep_inline ();
    }
  return 0;
}

VLIB_REGISTER_NODE (tcp_tfo_sweep_node) = {
  .name = "tcp-tfo-sweep",
  .type = VLIB_NODE_TYPE_PROCESS,
  .function = tcp_tfo_sweep_process,
};

void
tcp_fastopen_init (vlib_main_t *vm)
{
  tcp_main_t *tm = &tcp_main;

  clib_spinlock_init (&tm->tfo_lock);
  tm->tfo_key[0] = clib_cpu_time_now () ^ tm->iss_seed.first;
  tm->tfo_key[1] = clib_xxhash (tm->tfo_key[0]) ^ tm->iss_seed.second;
  tm->tfo_key_prev[0] = 0;
  tm->tfo_key_prev[1] = 0;
  tm->tfo_key_rotate_ts = vlib_time_now (vm);
  tm->tfo_pending = 0;
  tm->tfo_pending_max = TCP_TFO_PENDING_MAX;
  tm->tfo_cookie_cache = hash_create (0, sizeof (uword));
  tm->tfo_blackhole = hash_create (0, sizeof (uword));
}

/**
 * Atomically reserve a TFO pending-fast-open slot.
 *
 * Returns 1 on success, 0 if @ref tcp_main_t::tfo_pending_max would be
 * exceeded. Lock-free CAS keeps this safe under concurrent SYN bursts.
 */
static inline u8
tcp_tfo_reserve_pending_slot (void)
{
  u32 cur = clib_atomic_load_relax_n (&tcp_main.tfo_pending);
  while (cur < tcp_main.tfo_pending_max)
    {
      if (clib_atomic_cmp_and_swap_acq_relax_n (&tcp_main.tfo_pending, &cur, cur + 1, 0))
	return 1;
    }
  return 0;
}

/**
 * Release one previously reserved TFO pending slot.
 *
 * Underflow-safe: stops at zero. Used both on success (transition to
 * ESTABLISHED) and on failure paths (RST/timeout before ESTABLISHED).
 */
static inline void
tcp_tfo_release_pending_slot (void)
{
  u32 cur = clib_atomic_load_relax_n (&tcp_main.tfo_pending);
  while (cur > 0 && !clib_atomic_cmp_and_swap_acq_relax_n (&tcp_main.tfo_pending, &cur, cur - 1, 0))
    ;
}

tcp_tfo_listen_action_t
tcp_tfo_listen_handle (tcp_connection_t *lc, tcp_connection_t *child, vlib_buffer_t *b)
{
  u8 *syn_cookie;
  u8 cookie_ok;
  u32 data_len;
  int written;

  if (!(lc->cfg_flags & TCP_CFG_F_TFO) || !tcp_opts_tfo (&child->rcv_opts))
    return TCP_TFO_LISTEN_NONE;

  /* Sticky bit: peer included a TFO option in the SYN. Drives whether
   * tcp_make_synack() emits a fresh cookie option. Survives SYN-ACK
   * retransmits where rcv_opts is reparsed. */
  tcp_tfo_opt_rcvd_on (child);

  /* Empty TFO option = cookie request: regular 3WHS, SYN-ACK carries
   * a fresh cookie (RFC 7413 Sec 4.1.1). No early data is accepted. */
  if (!tcp_opts_tfo_cookie (&child->rcv_opts))
    return TCP_TFO_LISTEN_COOKIE_SENT;

  /* TFO option carrying a cookie. Validate first, then reserve a
   * pending-fast-open slot ONLY if the cookie is good — otherwise
   * we could blow past tfo_pending_max under a SYN burst. */
  syn_cookie = tcp_options_get_tfo_cookie (tcp_buffer_hdr (b));
  cookie_ok = tcp_tfo_cookie_is_valid (child, syn_cookie, child->rcv_opts.tfo_cookie_len);
  if (!cookie_ok)
    return TCP_TFO_LISTEN_COOKIE_INVALID;

  if (!tcp_tfo_reserve_pending_slot ())
    return TCP_TFO_LISTEN_PENDING_FULL;

  /* Valid cookie + slot reserved: commit to fast-open. The SYN-ACK
   * still refreshes the cookie via the OPT_RCVD sticky flag. */
  tcp_fast_opened_on (child);

  data_len = vnet_buffer (b)->tcp.data_len;
  if (data_len)
    {
      /* MUST NOT accept more data than MSS (RFC 7413 Sec 4.2.2). */
      data_len = clib_min (data_len, child->snd_mss);
      vlib_buffer_advance (b, vnet_buffer (b)->tcp.data_offset);
      if (b->current_length > data_len)
	b->current_length = data_len;
      written = session_enqueue_stream_connection (&child->connection, b, 0, 1 /* queue_event */,
						   1 /* is_in_order */);
      if (written > 0)
	{
	  child->rcv_nxt += written;
	  child->rcv_las = child->rcv_nxt;
	}
    }
  return TCP_TFO_LISTEN_FAST_OPEN;
}

void
tcp_tfo_synack_options (tcp_connection_t *tc, tcp_options_t *opts, u8 *cookie_buf, u8 **cookie_p,
			u8 *tcp_opts_len)
{
  u8 cookie_len = 0;

  if (PREDICT_TRUE (!tcp_tfo_opt_rcvd (tc)))
    return;

  tcp_tfo_get_cookie (tc, cookie_buf, &cookie_len);
  ASSERT (cookie_len == TCP_TFO_COOKIE_LEN_DEFAULT);

  opts->flags |= TCP_OPTS_FLAG_TFO;
  opts->tfo_cookie_len = cookie_len;
  *tcp_opts_len += TCP_OPTION_LEN_FAST_OPEN (cookie_len);
  /* Realign after adding the variable-length TFO option. */
  *tcp_opts_len += (TCP_OPTS_ALIGN - *tcp_opts_len % TCP_OPTS_ALIGN) % TCP_OPTS_ALIGN;
  *cookie_p = cookie_buf;
}

u8
tcp_tfo_prepare_send_syn (tcp_connection_t *tc, vlib_main_t *vm, u8 *cookie_buf, u8 *cookie_len)
{
  *cookie_len = 0;

  /* RFC 7413: TFO is only attempted on the first SYN (rto_boff == 0). */
  if (!tcp_tfo_enabled (tc) || tc->rto_boff != 0)
    return 0;

  /* If the destination is in the blackhole table, suppress the
   * TFO option entirely and bump the per-output-node counter. */
  if (PREDICT_FALSE (tcp_tfo_blackhole_check (tc)))
    {
      vlib_node_increment_counter (vm,
				   tc->c_is_ip4 ? tcp4_output_node.index : tcp6_output_node.index,
				   TCP_ERROR_TFO_BLACKHOLED, 1);
      return 0;
    }

  /* Look up a cached cookie. Cache miss => empty TFO option (cookie
   * request); cache hit => attach cookie + arm blackhole tracking. */
  tcp_tfo_lookup_cookie (tc, cookie_buf, cookie_len);
  if (*cookie_len)
    tcp_tfo_syn_sent_on (tc);
  return 1;
}

u16
tcp_tfo_write_syn_data (tcp_connection_t *tc, vlib_buffer_t *b, u8 cookie_len)
{
  u8 *syn_data = tcp_tfo_syn_data (tc);
  u32 ip_hdr;
  u8 opts_len;
  u16 base_mss, max_data, data_len;
  u8 *out;

  /* RFC 7413 Sec 4.1.2: include early SYN data only if a cached
   * cookie is available; otherwise SYN is a pure cookie probe. */
  if (!cookie_len || !syn_data || !vec_len (syn_data))
    return 0;

  ip_hdr = tc->c_is_ip4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t);
  opts_len = TCP_OPTION_LEN_MSS + TCP_OPTION_LEN_WINDOW_SCALE + TCP_OPTION_LEN_TIMESTAMP;
  if (TCP_USE_SACKS)
    opts_len += TCP_OPTION_LEN_SACK_PERMITTED;
  opts_len += TCP_OPTION_LEN_FAST_OPEN (cookie_len);
  opts_len += (TCP_OPTS_ALIGN - opts_len % TCP_OPTS_ALIGN) % TCP_OPTS_ALIGN;

  base_mss = tc->mss ? tc->mss : (u16) (tcp_cfg.default_mtu - ip_hdr - sizeof (tcp_header_t));
  max_data = (u16) (base_mss - opts_len);
  data_len = clib_min ((u16) vec_len (syn_data), max_data);

  out = vlib_buffer_get_current (b);
  clib_memcpy_fast (out, syn_data, data_len);
  b->current_length = data_len;
  return data_len;
}

void
tcp_tfo_handle_synack_cookie (tcp_connection_t *tc, tcp_header_t *th)
{
  if (!tcp_opts_tfo_cookie (&tc->rcv_opts))
    return;

  u8 *ck = tcp_options_get_tfo_cookie (th);
  u8 cklen = tc->rcv_opts.tfo_cookie_len;
  tcp_tfo_cache_cookie (tc, ck, cklen);
  tcp_tfo_blackhole_clear (tc);
}

void
tcp_tfo_syn_retransmit_cleanup (tcp_connection_t *tc)
{
  if (tcp_tfo_syn_sent (tc))
    {
      tcp_tfo_blackhole_record (tc);
      tcp_tfo_syn_sent_off (tc);
    }
  /* Retransmits MUST NOT carry early data (RFC 7413 Sec 4.1.3). */
  tcp_tfo_syn_data_free (tc);
}

void
tcp_tfo_connection_cleanup (tcp_connection_t *tc)
{
  /* Release pending slot if connection was fast-opened but never
   * reached ESTABLISHED. The flag is per-connection and the caller
   * (tcp_connection_cleanup) is sole owner. */
  if (tcp_fast_opened (tc))
    {
      tcp_fast_opened_off (tc);
      tcp_tfo_release_pending_slot ();
    }
}

void
tcp_tfo_established_release (tcp_connection_t *tc)
{
  if (!tcp_fast_opened (tc))
    return;
  tcp_fast_opened_off (tc);
  tcp_tfo_release_pending_slot ();
}
