/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Cisco and/or its affiliates. */

/**
 * @file tcp_fastopen.c
 * @brief TCP Fast Open (RFC 7413) — cookie generation/validation, cookie
 *        cache, blackhole detection, key rotation, and background sweep.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_fastopen.h>
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
  tm->tfo_pending_max = 1000;
  tm->tfo_cookie_cache = hash_create (0, sizeof (uword));
  tm->tfo_blackhole = hash_create (0, sizeof (uword));
}
