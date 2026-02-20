/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HSA_ECHO_STATS_H_
#define SRC_PLUGINS_HSA_ECHO_STATS_H_

#include <hs_apps/builtin_echo/echo_test.h>

typedef struct echo_rtt_stat_
{
  f64 min_rtt;
  f64 max_rtt;
  f64 sum_rtt;
  f64 last_rtt;
  u32 n_sum;
  clib_spinlock_t w_lock;
} echo_rtt_stat_t;

typedef struct echo_stats_
{
  volatile u64 rx_total;
  volatile u64 tx_total;
  volatile u64 rx_total_dgrams;
  volatile u64 tx_total_dgrams;
  u64 peer_dgrams_received;
  u64 peer_bytes_received;
  u64 last_total_tx_bytes;
  u64 last_total_rx_bytes;
  u64 last_total_tx_dgrams;
  u64 last_total_rx_dgrams;
  f64 test_start_time;
  f64 test_end_time;
  f64 last_print_time;
  echo_rtt_stat_t rtt_stats;
} echo_stats_t;

void echo_update_rtt_stats_tcp (echo_test_session_t *es, echo_rtt_stat_t *rtt_stats);

void echo_update_rtt_stats_udp (echo_test_session_t *es, echo_rtt_stat_t *rtt_stats);

void echo_print_footer (vlib_main_t *vm, transport_proto_t proto);

void echo_print_final_stats (vlib_main_t *vm, f64 total_delta, echo_test_cfg_t *cfg,
			     echo_stats_t *stats);

void echo_print_periodic_stats (vlib_main_t *vm, u8 print_header, echo_test_cfg_t *cfg,
				echo_stats_t *stats, echo_test_worker_t *wrks);

#endif /* SRC_PLUGINS_HSA_ECHO_STATS_H_ */
