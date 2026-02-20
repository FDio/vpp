
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

/* echo_client.h - built-in application layer echo client */

#ifndef __included_echo_client_h__
#define __included_echo_client_h__

#include <hs_apps/hs_test.h>
#include <hs_apps/builtin_echo/echo_test.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

typedef struct ec_rttstat_
{
  f64 min_rtt;
  f64 max_rtt;
  f64 sum_rtt;
  f64 last_rtt;
  u32 n_sum;
  clib_spinlock_t w_lock;
} ec_rttstat_t;

typedef struct
{
  echo_test_worker_t *wrk;	 /**< Per-thread state */
  u8 *connect_test_data;	 /**< Pre-computed test data */

  volatile u32 ready_connections;
  volatile u64 rx_total;
  volatile u64 tx_total;
  volatile u64 rx_total_dgrams;
  volatile u64 tx_total_dgrams;
  volatile int run_test; /**< Signal start of test */
  volatile bool end_test; /**< Signal end of test */

  f64 syn_start_time;
  f64 test_start_time;
  f64 test_end_time;
  f64 last_print_time;
  u64 last_total_tx_bytes;
  u64 last_total_rx_bytes;
  u64 last_total_tx_dgrams;
  u64 last_total_rx_dgrams;
  u32 prev_conns;
  u32 repeats;
  ec_rttstat_t rtt_stats;

  f64
    pacing_window_len; /**< Time between data chunk sends when limiting tput */
  u32 connect_conn_index; /**< Connects attempted progress */

  /*
   * Application setup parameters
   */

  u32 cli_node_index;			/**< cli process node index */
  u32 app_index;			/**< app index after attach */
  session_handle_t ctrl_session_handle; /**< control session handle */

  /*
   * Configuration params
   */
  echo_test_cfg_t cfg;
  u32 fifo_fill_threshold;
  u32 expected_connections;		/**< Number of clients/connections */
  u32 connections_per_batch;		/**< Connections to rx/tx at once */
  u64 throughput;			/**< Target bytes per second */
  u32 no_copy;				/**< Don't memcpy data to tx fifo */
  u64 attach_flags;			/**< App attach flags */
  u8 *appns_id;				/**< App namespaces id */
  u64 appns_secret;			/**< App namespace secret */
  f64 syn_timeout;			/**< Test syn timeout (s) */
  f64 test_timeout;			/**< Test timeout (s) */
  f64 run_time;				/**< Length of a test (s) */
  u64 max_chunk_bytes;
  u64 report_interval;	    /**< Time between periodic reports (s) */
  u8 report_interval_total; /**< Shown data are totals since the start of the
			       test */
  u8 report_interval_jitter; /**< Report jitter in periodic reports */

  /*
   * Flags
   */
  u8 app_is_init;
  u8 test_client_attached;
  u8 test_return_packets;
  int drop_packets;		/**< drop all packets */
  u8 prealloc_fifos;		/**< Request fifo preallocation */
  u8 prealloc_sessions;
  u8 test_failed;
  u8 barrier_acq_needed;
  u8 include_buffer_offset;

  vlib_main_t *vlib_main;

  void (*rx_callback) (session_t *session);
  void (*tx_callback) (echo_test_session_t *es);
} ec_main_t;

typedef enum ec_state_
{
  EC_STARTING,
  EC_RUNNING,
  EC_EXITING
} ec_state_t;

typedef enum ec_cli_signal_
{
  EC_CLI_CONNECTS_DONE = 1,
  EC_CLI_CONNECTS_FAILED,
  EC_CLI_CFG_SYNC,
  EC_CLI_START,
  EC_CLI_STOP,
  EC_CLI_TEST_DONE
} ec_cli_signal_t;

void ec_program_connects (void);

#endif /* __included_echo_client_h__ */
