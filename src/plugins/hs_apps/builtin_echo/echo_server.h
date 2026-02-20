/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HSA_ECHO_SERVER_H_
#define SRC_PLUGINS_HSA_ECHO_SERVER_H_

#include <hs_apps/hs_test.h>
#include <hs_apps/builtin_echo/echo_test.h>

typedef struct
{
  u32 app_index; /**< Server app index */

  /*
   * Config params
   */
  echo_test_cfg_t cfg;
  /*
   * Test state
   */
  echo_test_worker_t *wrk;
  int (*rx_callback) (session_t *session);
  session_handle_t listener_handle; /**< Session handle of the root listener */
  session_handle_t ctrl_listener_handle;

  vlib_main_t *vlib_main;
} echo_server_main_t;

extern echo_server_main_t echo_server_main;

int echo_server_create (vlib_main_t *vm, u8 *appns_id, u64 appns_flags, u64 appns_secret);

int echo_server_detach (void);

#endif /* SRC_PLUGINS_HSA_ECHO_SERVER_H_ */
