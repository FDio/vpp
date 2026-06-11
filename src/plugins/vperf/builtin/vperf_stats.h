/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_VPERF_STATS_H_
#define SRC_PLUGINS_VPERF_STATS_H_

#include <vperf/builtin/vperf_builtin.h>

typedef struct vp_rtt_stat_
{
  f64 min_rtt;
  f64 max_rtt;
  f64 sum_rtt;
  f64 last_rtt;
  u32 n_sum;
  clib_spinlock_t w_lock;
} vp_rtt_stat_t;

typedef struct vp_stats_
{
  u64 rx_total;
  u64 tx_total;
  u64 rx_total_dgrams;
  u64 tx_total_dgrams;
  u64 peer_dgrams_received;
  u64 peer_bytes_received;
  u64 last_total_tx_bytes;
  u64 last_total_rx_bytes;
  u64 last_total_tx_dgrams;
  u64 last_total_rx_dgrams;
  f64 test_start_time;
  f64 test_end_time;
  f64 last_print_time;
  vp_rtt_stat_t rtt_stats;
} vp_stats_t;

void vp_update_rtt_stats_tcp (vp_test_session_t *es, vp_rtt_stat_t *rtt_stats);

void vp_update_rtt_stats_udp (vp_test_session_t *es, vp_rtt_stat_t *rtt_stats);

void vp_print_footer (vlib_main_t *vm, vp_test_proto_t proto);

void vp_print_final_stats (vlib_main_t *vm, f64 total_delta, vp_test_cfg_t *cfg, vp_stats_t *stats,
			   vp_test_worker_t *wrks);

void vp_print_periodic_stats (vlib_main_t *vm, u8 print_header, vp_test_cfg_t *cfg,
			      vp_stats_t *stats, vp_test_worker_t *wrks);

#endif /* SRC_PLUGINS_VPERF_STATS_H_ */
