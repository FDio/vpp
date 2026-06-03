
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

/* vperf_client.h - built-in host stack performance client */

#ifndef __included_vperf_client_h__
#define __included_vperf_client_h__

#include <vperf/vperf_test.h>
#include <vperf/builtin/vperf_stats.h>
#include <vperf/builtin/vperf_builtin.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

typedef struct
{
  vp_test_worker_t *wrk;   /**< Per-thread state */
  u8 *connect_test_data;   /**< Pre-computed test data */

  volatile u32 ready_connections;
  volatile u32 failed_session_closes;
  volatile u32 reset_count;
  volatile u32 disconnect_count;
  volatile int run_test;  /**< Signal start of test */
  volatile bool end_test; /**< Signal end of test */

  f64 syn_start_time;
  u32 prev_conns;
  u32 repeats;
  vp_stats_t stats;

  f64 pacing_window_len;  /**< Time between data chunk sends when limiting tput */
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
  vp_test_cfg_t cfg;
  u32 expected_connections;  /**< Number of clients/connections */
  u32 connections_per_batch; /**< Connections to rx/tx at once */
  u64 throughput;	     /**< Target bytes per second */
  u64 attach_flags;	     /**< App attach flags */
  u8 *appns_id;		     /**< App namespaces id */
  u64 appns_secret;	     /**< App namespace secret */
  f64 syn_timeout;	     /**< Test syn timeout (s) */
  f64 test_timeout;	     /**< Test timeout (s) */
  u64 max_chunk_bytes;

  /*
   * Flags
   */
  u8 app_is_init;
  u8 test_client_attached;
  u8 prealloc_fifos; /**< Request fifo preallocation */
  u8 prealloc_sessions;
  u8 test_failed;
  u8 barrier_acq_needed;
  u8 include_buffer_offset;

  vlib_main_t *vlib_main;

  void (*rx_callback) (session_t *session);
  void (*tx_callback) (vp_test_session_t *es);
} vp_client_main_t;

extern vp_client_main_t vp_client_main;

typedef enum vp_client_state_
{
  VP_CLIENT_STARTING,
  VP_CLIENT_RUNNING,
  VP_CLIENT_EXITING
} vp_client_state_t;

typedef enum vp_client_cli_signal_
{
  VP_CLIENT_CLI_CONNECTS_DONE = 1,
  VP_CLIENT_CLI_CONNECTS_FAILED,
  VP_CLIENT_CLI_CFG_SYNC,
  VP_CLIENT_CLI_START,
  VP_CLIENT_CLI_STOP,
  VP_CLIENT_CLI_TEST_DONE
} vp_client_cli_signal_t;

void vp_client_program_connects (void);

int vp_client_init (vlib_main_t *vm);

void vp_client_prealloc_sessions (vp_client_main_t *vpcm);

clib_error_t *vp_client_attach ();

clib_error_t *vp_client_run (vlib_main_t *vm);

int vp_client_detach ();

void vp_client_cleanup (vp_client_main_t *vpcm);

#endif /* __included_vperf_client_h__ */
