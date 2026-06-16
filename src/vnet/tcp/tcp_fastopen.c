/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Cisco and/or its affiliates. */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_fastopen.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vppinfra/crc32.h>
#include <sys/random.h>

/* TFO cookie generation: two-CRC32C-chain 64-bit mixer keyed by a
 * 128-bit secret derived from the kernel CSPRNG. CRC32C is a hash,
 * NOT a MAC, so this is best-effort spam protection rather than a
 * cryptographic unforgeability proof. */

static_always_inline u64
tcp_tfo_hash64 (u64 x)
{
  u32 hi = clib_crc32c_u64 (~0u, x);
  u32 lo = clib_crc32c_u64 (hi ^ 0x9e3779b1u, x);
  return ((u64) hi << 32) | (u64) lo;
}

/* Compute the 64-bit TFO cookie for @p tc under the given 128-bit key. */
static_always_inline u64
tcp_tfo_compute_cookie (tcp_connection_t *tc, const u64 key[2])
{
  u64 x;
  if (tc->c_is_ip4)
    x = key[0] ^ (u64) tc->c_rmt_ip.ip4.as_u32;
  else
    x = key[0] ^ tc->c_rmt_ip.ip6.as_u64[0] ^ tc->c_rmt_ip.ip6.as_u64[1];
  return tcp_tfo_hash64 (x) ^ key[1];
}

/* Derive a fresh 128-bit key from the kernel CSPRNG into @p out. */
static_always_inline void
tcp_tfo_derive_key (u64 out[2])
{
  ssize_t n = getrandom (out, 2 * sizeof (u64), 0);
  if (PREDICT_FALSE (n != (ssize_t) (2 * sizeof (u64))))
    clib_panic ("TFO: getrandom() returned %zd", n);
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
  f64 now = transport_time_now (tc->c_thread_index);
  u64 key[2];
  u64 h;

  /* Fast path: rotation not due. Reader lock to snapshot the key.
   * The pre-check is a relaxed (unlocked) read of tfo_key_rotate_ts.
   * This is safe because:
   * - False negative: another worker already rotated; we still compute a
   *   valid cookie with the key we end up reading under the reader lock.
   * - False positive: we take the writer lock and re-check; if the rotation
   *   is no longer due, the re-check prevents a double rotation. */
  if (PREDICT_TRUE (now - tm->tfo_key_rotate_ts < TCP_TFO_KEY_ROTATE_INTERVAL))
    {
      clib_rwlock_reader_lock (&tm->tfo_lock);
      key[0] = tm->tfo_key[0];
      key[1] = tm->tfo_key[1];
      clib_rwlock_reader_unlock (&tm->tfo_lock);
    }
  else
    {
      clib_rwlock_writer_lock (&tm->tfo_lock);
      if (now - tm->tfo_key_rotate_ts >= TCP_TFO_KEY_ROTATE_INTERVAL)
	{
	  /* Promote current key to prev, derive a fresh one. */
	  tm->tfo_key_prev[0] = tm->tfo_key[0];
	  tm->tfo_key_prev[1] = tm->tfo_key[1];
	  tcp_tfo_derive_key (tm->tfo_key);
	  tm->tfo_key_rotate_ts = now;
	}
      key[0] = tm->tfo_key[0];
      key[1] = tm->tfo_key[1];
      clib_rwlock_writer_unlock (&tm->tfo_lock);
    }

  h = tcp_tfo_compute_cookie (tc, key);
  clib_memcpy_fast (cookie, &h, sizeof (h));
  *len = sizeof (h); /* 8 bytes */
}

int
tcp_tfo_cookie_is_valid (tcp_connection_t *tc, u8 *cookie, u8 len)
{
  tcp_main_t *tm = &tcp_main;
  u64 key_cur[2], key_prev[2];
  u8 have_prev;
  u64 cur;
  int eq_cur, eq_prev = 0;

  if (PREDICT_FALSE (len != sizeof (u64)))
    return 0;

  /* Pure reader path: validation never rotates keys. */
  clib_rwlock_reader_lock (&tm->tfo_lock);
  key_cur[0] = tm->tfo_key[0];
  key_cur[1] = tm->tfo_key[1];
  key_prev[0] = tm->tfo_key_prev[0];
  key_prev[1] = tm->tfo_key_prev[1];
  clib_rwlock_reader_unlock (&tm->tfo_lock);

  /* "no previous key yet" is encoded as the all-zero key. */
  have_prev = (key_prev[0] | key_prev[1]) != 0;

  cur = tcp_tfo_compute_cookie (tc, key_cur);
  eq_cur = (tcp_tfo_ct_cmp8 (cookie, (u8 *) &cur) == 0);

  if (have_prev)
    {
      u64 prev_exp = tcp_tfo_compute_cookie (tc, key_prev);
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
  tcp_tfo_cc_entry_t *e, *head;
  uword key = tcp_tfo_ip_key (tc);
  f64 now = transport_time_now (tc->c_thread_index);
  uword *p;

  if (PREDICT_FALSE (len > TCP_TFO_COOKIE_LEN_MAX))
    return;

  clib_rwlock_writer_lock (&tm->tfo_lock);
  p = hash_get (tm->tfo_cookie_cache, key);
  if (p)
    {
      e = pool_elt_at_index (tm->tfo_cc_entries, p[0]);
      /* Refresh: unlink from current LRU position, will re-add at tail. */
      clib_llist_remove (tm->tfo_cc_entries, lru_anchor, e);
    }
  else
    {
      /* pool_get_zero may realloc; recompute head pointer afterwards. */
      pool_get_zero (tm->tfo_cc_entries, e);
      hash_set (tm->tfo_cookie_cache, key, e - tm->tfo_cc_entries);
    }
  e->ip_key = key;
  e->cookie_len = len;
  clib_memcpy_fast (e->cookie, cookie, len);
  e->timestamp = now;
  head = clib_llist_elt (tm->tfo_cc_entries, tm->tfo_cc_lru_head_index);
  clib_llist_add_tail (tm->tfo_cc_entries, lru_anchor, e, head);
  clib_rwlock_writer_unlock (&tm->tfo_lock);
}

int
tcp_tfo_lookup_cookie (tcp_connection_t *tc, u8 *cookie, u8 *len)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_cc_entry_t *e;
  uword key = tcp_tfo_ip_key (tc);
  f64 now = transport_time_now (tc->c_thread_index);
  uword *p;
  int found = 0;

  /* Read-only fast path: aged entries are treated as misses but left in place;
   * the periodic sweep reclaims them so we never need a writer lock here. */
  clib_rwlock_reader_lock (&tm->tfo_lock);
  p = hash_get (tm->tfo_cookie_cache, key);
  if (!p)
    goto done;

  e = pool_elt_at_index (tm->tfo_cc_entries, p[0]);

  if (now - e->timestamp > TCP_TFO_CACHE_EXPIRATION)
    goto done; /* expired; sweep will reclaim */

  *len = e->cookie_len;
  clib_memcpy_fast (cookie, e->cookie, e->cookie_len);
  found = 1;

done:
  clib_rwlock_reader_unlock (&tm->tfo_lock);
  return found;
}

void
tcp_tfo_blackhole_record (tcp_connection_t *tc)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_bh_entry_t *e, *head;
  uword key = tcp_tfo_ip_key (tc);
  uword *p;

  clib_rwlock_writer_lock (&tm->tfo_lock);
  p = hash_get (tm->tfo_blackhole, key);
  if (p)
    {
      e = pool_elt_at_index (tm->tfo_bh_entries, p[0]);
      /* Refresh: re-position at tail of LRU below. */
      clib_llist_remove (tm->tfo_bh_entries, lru_anchor, e);
    }
  else
    {
      /* pool_get_zero may realloc; recompute head pointer afterwards. */
      pool_get_zero (tm->tfo_bh_entries, e);
      hash_set (tm->tfo_blackhole, key, e - tm->tfo_bh_entries);
      e->ip_key = key;
    }
  e->failures++;
  e->last_failure = transport_time_now (tc->c_thread_index);
  head = clib_llist_elt (tm->tfo_bh_entries, tm->tfo_bh_lru_head_index);
  clib_llist_add_tail (tm->tfo_bh_entries, lru_anchor, e, head);
  clib_rwlock_writer_unlock (&tm->tfo_lock);
}

int
tcp_tfo_blackhole_check (tcp_connection_t *tc)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_bh_entry_t *e;
  uword key = tcp_tfo_ip_key (tc);
  f64 now = transport_time_now (tc->c_thread_index);
  uword *p;
  int blackholed = 0;

  /* Read-only fast path: aged entries are treated as not-blackholed
   * and left in place; the periodic sweep reclaims them. */
  clib_rwlock_reader_lock (&tm->tfo_lock);
  p = hash_get (tm->tfo_blackhole, key);
  if (!p)
    goto done;

  e = pool_elt_at_index (tm->tfo_bh_entries, p[0]);

  if (now - e->last_failure > TCP_TFO_BLACKHOLE_TIMEOUT)
    goto done; /* aged out; sweep will reclaim */

  blackholed = (e->failures >= TCP_TFO_BLACKHOLE_THRESH);

done:
  clib_rwlock_reader_unlock (&tm->tfo_lock);
  return blackholed;
}

void
tcp_tfo_blackhole_clear (tcp_connection_t *tc)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_bh_entry_t *e;
  uword key = tcp_tfo_ip_key (tc);
  uword *p;

  clib_rwlock_writer_lock (&tm->tfo_lock);
  p = hash_get (tm->tfo_blackhole, key);
  if (!p)
    goto done;

  e = pool_elt_at_index (tm->tfo_bh_entries, p[0]);
  clib_llist_remove (tm->tfo_bh_entries, lru_anchor, e);
  clib_llist_put (tm->tfo_bh_entries, e);
  hash_unset (tm->tfo_blackhole, key);

done:
  clib_rwlock_writer_unlock (&tm->tfo_lock);
}

void
tcp_tfo_cache_flush (u32 *n_cache_freed, u32 *n_bh_freed)
{
  tcp_main_t *tm = &tcp_main;
  u32 nc = 0, nb = 0;

  if (!tm->tfo_lock)
    goto out;

  clib_rwlock_writer_lock (&tm->tfo_lock);

  /* pool_elts() includes the clib_llist sentinel head; subtract it
   * to report only the number of real cache entries freed. */
  nc = pool_elts (tm->tfo_cc_entries);
  nc = nc ? nc - 1 : 0;
  pool_free (tm->tfo_cc_entries);
  hash_free (tm->tfo_cookie_cache);
  tm->tfo_cookie_cache = hash_create (0, sizeof (uword));
  tm->tfo_cc_lru_head_index = clib_llist_make_head (tm->tfo_cc_entries, lru_anchor);

  nb = pool_elts (tm->tfo_bh_entries);
  nb = nb ? nb - 1 : 0;
  pool_free (tm->tfo_bh_entries);
  hash_free (tm->tfo_blackhole);
  tm->tfo_blackhole = hash_create (0, sizeof (uword));
  tm->tfo_bh_lru_head_index = clib_llist_make_head (tm->tfo_bh_entries, lru_anchor);

  clib_rwlock_writer_unlock (&tm->tfo_lock);

out:
  if (n_cache_freed)
    *n_cache_freed = nc;
  if (n_bh_freed)
    *n_bh_freed = nb;
}

/**
 * Periodic LRU-bounded sweep. Walks the head of each clib_llist FIFO and
 * stops at the first entry whose timestamp is within the retention window,
 * bounding cost to O(expired) instead of O(N).
 */
static void
tcp_tfo_cache_sweep_inline (vlib_main_t *vm)
{
  tcp_main_t *tm = &tcp_main;
  tcp_tfo_cc_entry_t *ce, *cc_head;
  tcp_tfo_bh_entry_t *be, *bh_head;
  f64 now;

  if (!tm->tfo_lock)
    return;

  now = vlib_time_now (vm);

  clib_rwlock_writer_lock (&tm->tfo_lock);

  /* Cookie cache: oldest immediately after the sentinel head; stop at the
   * first non-expired entry. pool_put never reallocates so the head
   * pointer obtained here stays valid for the duration of the loop. */
  cc_head = clib_llist_elt (tm->tfo_cc_entries, tm->tfo_cc_lru_head_index);
  while (!clib_llist_is_empty (tm->tfo_cc_entries, lru_anchor, cc_head))
    {
      ce = clib_llist_next (tm->tfo_cc_entries, lru_anchor, cc_head);
      if (now - ce->timestamp <= TCP_TFO_CACHE_EXPIRATION)
	break;
      hash_unset (tm->tfo_cookie_cache, ce->ip_key);
      clib_llist_remove (tm->tfo_cc_entries, lru_anchor, ce);
      clib_llist_put (tm->tfo_cc_entries, ce);
    }

  /* Blackhole table: same trick. */
  bh_head = clib_llist_elt (tm->tfo_bh_entries, tm->tfo_bh_lru_head_index);
  while (!clib_llist_is_empty (tm->tfo_bh_entries, lru_anchor, bh_head))
    {
      be = clib_llist_next (tm->tfo_bh_entries, lru_anchor, bh_head);
      if (now - be->last_failure <= TCP_TFO_BLACKHOLE_TIMEOUT)
	break;
      hash_unset (tm->tfo_blackhole, be->ip_key);
      clib_llist_remove (tm->tfo_bh_entries, lru_anchor, be);
      clib_llist_put (tm->tfo_bh_entries, be);
    }

  clib_rwlock_writer_unlock (&tm->tfo_lock);
}

static uword
tcp_tfo_sweep_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, TCP_TFO_SWEEP_INTERVAL);
      vlib_process_get_events (vm, 0);
      tcp_tfo_cache_sweep_inline (vm);
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

  clib_rwlock_init (&tm->tfo_lock);
  tcp_tfo_derive_key (tm->tfo_key);
  tm->tfo_key_prev[0] = 0;
  tm->tfo_key_prev[1] = 0;
  tm->tfo_key_rotate_ts = vlib_time_now (vm);
  tm->tfo_pending = 0;
  tm->tfo_pending_max = TCP_TFO_PENDING_MAX;
  tm->tfo_cookie_cache = hash_create (0, sizeof (uword));
  tm->tfo_blackhole = hash_create (0, sizeof (uword));
  /* Allocate the clib_llist sentinel head for each LRU FIFO. */
  tm->tfo_cc_lru_head_index = clib_llist_make_head (tm->tfo_cc_entries, lru_anchor);
  tm->tfo_bh_lru_head_index = clib_llist_make_head (tm->tfo_bh_entries, lru_anchor);
}

/**
 * Atomically reserve a TFO pending-fast-open slot.
 *
 * Returns 1 on success, 0 if @ref tcp_main_t::tfo_pending_max would be
 * exceeded. Uses a single relaxed fetch-add, rolling back on overshoot.
 */
static inline u8
tcp_tfo_reserve_pending_slot (void)
{
  u32 prev = clib_atomic_fetch_add_relax (&tcp_main.tfo_pending, 1);
  if (PREDICT_FALSE (prev >= tcp_main.tfo_pending_max))
    {
      clib_atomic_fetch_sub_relax (&tcp_main.tfo_pending, 1);
      return 0;
    }
  return 1;
}

/**
 * Release one previously reserved TFO pending slot.
 *
 * A single relaxed fetch-sub: every successful reserve is paired with
 * exactly one release, so the counter should not underflow.
 */
static inline void
tcp_tfo_release_pending_slot (void)
{
  u32 prev = clib_atomic_fetch_sub_relax (&tcp_main.tfo_pending, 1);
  ASSERT (prev != 0);
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
tcp_tfo_synack_options (tcp_connection_t *tc, tcp_options_t *opts, u8 *cookie_buf, u8 *tcp_opts_len)
{
  u8 cookie_len = 0;

  if (PREDICT_TRUE (!tcp_tfo_opt_rcvd (tc)))
    return;

  tcp_tfo_get_cookie (tc, cookie_buf, &cookie_len);
  ASSERT (cookie_len == TCP_TFO_COOKIE_LEN_DEFAULT);

  opts->flags |= TCP_OPTS_FLAG_TFO;
  opts->tfo_cookie_len = cookie_len;
  opts->tfo_cookie = cookie_buf;
  *tcp_opts_len += TCP_OPTION_LEN_FAST_OPEN (cookie_len);
  /* Realign after adding the variable-length TFO option. */
  *tcp_opts_len += (TCP_OPTS_ALIGN - *tcp_opts_len % TCP_OPTS_ALIGN) % TCP_OPTS_ALIGN;
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
