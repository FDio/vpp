/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#include <vlib/vlib.h>
#include <vlib/stats/stats.h>
#include <vnet/vnet.h>
#include <fastacl/fastacl.h>

static_always_inline int
rule_counter_ready (fastacl_main_t *fsm, u32 rule_index)
{
  return fsm->rule_counters.counters != 0 &&
	 rule_index < vlib_combined_counter_n_counters (&fsm->rule_counters);
}

static counter_t *
rule_gen_row (fastacl_main_t *fsm)
{
  if (fsm->rule_gen_stat_index == ~0u)
    return 0;
  counter_t **rows = vlib_stats_get_entry_data_pointer (fsm->rule_gen_stat_index);
  return (rows && vec_len (rows)) ? rows[0] : 0;
}

void
fastacl_rule_gen_bump (fastacl_main_t *fsm, u32 rule_index)
{
  if (fsm->rule_gen_stat_index == ~0u)
    return;

  if (rule_index >= fsm->rule_gen_len)
    {
      vlib_stats_validate (fsm->rule_gen_stat_index, 0, rule_index);
      fsm->rule_gen_len = rule_index + 1;
    }

  counter_t *row = rule_gen_row (fsm);
  if (row && rule_index < vec_len (row))
    row[rule_index]++;
}

u64
fastacl_rule_gen_get (fastacl_main_t *fsm, u32 rule_index)
{
  counter_t *row = rule_gen_row (fsm);
  return (row && rule_index < vec_len (row)) ? row[rule_index] : 0;
}

void
fastacl_per_worker_rule_vecs_validate (fastacl_main_t *fsm, u32 max_index)
{
  vlib_validate_combined_counter (&fsm->rule_counters, max_index);

  if (fsm->rule_counter_len < max_index + 1)
    fsm->rule_counter_len = max_index + 1;

  foreach_fastacl_per_worker (pw, fsm)
  {
#define _(v) vec_validate (pw->v, max_index);
    foreach_fastacl_per_worker_rule_vec
#undef _
  }
}

void
fastacl_per_worker_rule_reset (fastacl_main_t *fsm, u32 rule_index)
{
  if (rule_counter_ready (fsm, rule_index))
    vlib_zero_combined_counter (&fsm->rule_counters, rule_index);

  foreach_fastacl_per_worker (pw, fsm)
  {
#define _(v)                                                                                       \
  if (rule_index < vec_len (pw->v))                                                                \
    clib_memset (&pw->v[rule_index], 0, sizeof (pw->v[0]));
    foreach_fastacl_per_worker_rule_vec
#undef _
  }
}

static void
fastacl_rule_counter_read (fastacl_main_t *fsm, u32 rule_index, u64 *packets, u64 *bytes)
{
  vlib_counter_t c = { 0, 0 };

  if (rule_counter_ready (fsm, rule_index))
    vlib_get_combined_counter (&fsm->rule_counters, rule_index, &c);

  *packets = c.packets;
  *bytes = c.bytes;
}

static void
fastacl_per_worker_clear (fastacl_main_t *fsm)
{
  vlib_clear_combined_counters (&fsm->rule_counters);

  foreach_fastacl_per_worker (pw, fsm)
  {
    pw->total_processed = 0;
    pw->total_dropped = 0;
    pw->total_bytes_processed = 0;
    pw->total_bytes_dropped = 0;
    vec_zero (pw->rule_sample_count);
    vec_zero (pw->rule_sample_missed);
  }
}

void
fastacl_per_worker_rule_sample_sum (fastacl_main_t *fsm, u32 rule_index, u64 *sampled, u64 *missed)
{
  u64 total_sampled = 0, total_missed = 0;

  foreach_fastacl_per_worker (pw, fsm)
  {
    if (rule_index < vec_len (pw->rule_sample_count))
      total_sampled += pw->rule_sample_count[rule_index];
    if (rule_index < vec_len (pw->rule_sample_missed))
      total_missed += pw->rule_sample_missed[rule_index];
  }

  *sampled = total_sampled;
  *missed = total_missed;
}

static void
fastacl_per_worker_totals_sum (fastacl_main_t *fsm, u64 *processed, u64 *dropped,
			       u64 *bytes_processed, u64 *bytes_dropped)
{
  u64 n_processed = 0, n_dropped = 0;
  u64 n_bytes_processed = 0, n_bytes_dropped = 0;

  foreach_fastacl_per_worker (pw, fsm)
  {
    n_processed += pw->total_processed;
    n_dropped += pw->total_dropped;
    n_bytes_processed += pw->total_bytes_processed;
    n_bytes_dropped += pw->total_bytes_dropped;
  }

  *processed = n_processed;
  *dropped = n_dropped;
  *bytes_processed = n_bytes_processed;
  *bytes_dropped = n_bytes_dropped;
}

static void
fastacl_snapshot_reset (fastacl_rate_snapshot_t *snap, f64 now)
{
  clib_memset (snap, 0, sizeof (*snap));
  snap->time = now;
}

void
fastacl_clear_counters (void)
{
  fastacl_main_t *fsm = &fastacl_main;
  f64 now = vlib_time_now (fsm->vlib_main);
  fastacl_rule_t *rule;

  fastacl_per_worker_clear (fsm);

  pool_foreach (rule, fsm->rules)
    {
      rule->packet_count = 0;
      rule->byte_count = 0;
      fastacl_snapshot_reset (&rule->rate_snap, now);
    }

  clib_memset (&fsm->counters, 0, sizeof (fsm->counters));
  fastacl_snapshot_reset (&fsm->counters.processed_rate, now);
  fastacl_snapshot_reset (&fsm->counters.dropped_rate, now);
}

static void
fastacl_snapshot_update (fastacl_rate_snapshot_t *snap, u64 packets, u64 bytes, f64 now)
{
  f64 dt = now - snap->time;
  int rebase = packets < snap->packets || bytes < snap->bytes;

  if (!rebase && dt < FASTACL_RATE_MIN_INTERVAL)
    return;

  snap->pps = rebase ? 0.0 : (f64) (packets - snap->packets) / dt;
  snap->l3_bps = rebase ? 0.0 : (f64) (bytes - snap->bytes) * 8.0 / dt;
  snap->l1_bps = snap->l3_bps + snap->pps * (FASTACL_L1_OVERHEAD_BYTES * 8.0);
  snap->packets = packets;
  snap->bytes = bytes;
  snap->time = now;
}

void
fastacl_update_aggregate_rates (vlib_main_t *vm)
{
  fastacl_main_t *fsm = &fastacl_main;
  f64 now = vlib_time_now (vm);

  fastacl_per_worker_totals_sum (fsm, &fsm->counters.total_processed, &fsm->counters.total_dropped,
				 &fsm->counters.total_bytes_processed,
				 &fsm->counters.total_bytes_dropped);

  fastacl_snapshot_update (&fsm->counters.processed_rate, fsm->counters.total_processed,
			   fsm->counters.total_bytes_processed, now);
  fastacl_snapshot_update (&fsm->counters.dropped_rate, fsm->counters.total_dropped,
			   fsm->counters.total_bytes_dropped, now);
}

void
fastacl_update_rates (vlib_main_t *vm)
{
  fastacl_main_t *fsm = &fastacl_main;
  fastacl_rule_t *rule;
  f64 now = vlib_time_now (vm);

  fastacl_update_aggregate_rates (vm);

  pool_foreach (rule, fsm->rules)
    {
      fastacl_rule_counter_read (fsm, rule->index, &rule->packet_count, &rule->byte_count);
      fastacl_snapshot_update (&rule->rate_snap, rule->packet_count, rule->byte_count, now);
    }
}
