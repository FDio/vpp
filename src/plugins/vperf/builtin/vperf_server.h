/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_VPERF_SERVER_H_
#define SRC_PLUGINS_VPERF_SERVER_H_

#include <vperf/builtin/vperf_stats.h>
#include <vperf/vperf_test.h>
#include <vperf/builtin/vperf_builtin.h>

typedef struct
{
  u32 app_index; /**< Server app index */

  /*
   * Config params
   */
  vp_test_cfg_t cfg;
  /*
   * Test state
   */
  vp_test_worker_t *wrk;
  int (*rx_callback) (session_t *session);
  session_handle_t listener_handle; /**< Session handle of the root listener */
  session_handle_t ctrl_listener_handle;

  vp_stats_t stats;

  u32 cli_node_index;
  vlib_main_t *vlib_main;
} vp_server_main_t;

extern vp_server_main_t vp_server_main;

typedef enum
{
  VP_SERVER_CLI_START = 1,
  VP_SERVER_CLI_STOP,
} vp_server_cli_signal_t;

void vp_server_init (vlib_main_t *vm);

int vp_server_create (vlib_main_t *vm, u8 *appns_id, u64 appns_flags, u64 appns_secret);

int vp_server_detach (void);

#endif /* SRC_PLUGINS_VPERF_SERVER_H_ */
