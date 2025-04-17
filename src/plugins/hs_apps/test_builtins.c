/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <http_static/http_static.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

typedef struct
{
  u32 stop_timer_handle;
  hss_session_handle_t sh;
} tw_timer_elt_t;

typedef struct tb_main_
{
  tw_timer_elt_t *delayed_resps;
  tw_timer_wheel_2t_1w_2048sl_t tw;
  hss_session_send_fn send_data;
  u8 *test_data;
} tb_main_t;

static tb_main_t tb_main;

static uword
test_builtins_timer_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
			     vlib_frame_t *f)
{
  tb_main_t *tbm = &tb_main;
  f64 now, timeout = 1.0;
  uword *event_data = 0;
  uword __clib_unused event_type;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      now = vlib_time_now (vm);
      event_type = vlib_process_get_events (vm, (uword **) &event_data);

      /* expire timers */
      tw_timer_expire_timers_2t_1w_2048sl (&tbm->tw, now);

      vec_reset_length (event_data);
    }
  return 0;
}

VLIB_REGISTER_NODE (test_builtins_timer_process_node) = {
  .function = test_builtins_timer_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "test-builtins-timer-process",
  .state = VLIB_NODE_STATE_DISABLED,
};

static void
send_data_to_hss (hss_session_handle_t sh, u8 *data, uword data_len,
		  u8 free_vec_data)
{
  tb_main_t *tbm = &tb_main;
  hss_url_handler_args_t args = {};

  args.sh = sh;
  args.data = data;
  args.data_len = data_len;
  args.ct = HTTP_CONTENT_TEXT_PLAIN;
  args.sc = HTTP_STATUS_OK;
  args.free_vec_data = free_vec_data;

  tbm->send_data (&args);
}

static hss_url_handler_rc_t
handle_get_test1 (hss_url_handler_args_t *args)
{
  u8 *data;

  clib_warning ("get request on test1");
  data = format (0, "hello");
  send_data_to_hss (args->sh, data, vec_len (data), 1);

  return HSS_URL_HANDLER_ASYNC;
}

static hss_url_handler_rc_t
handle_get_test2 (hss_url_handler_args_t *args)
{
  u8 *data;

  clib_warning ("get request on test2");
  data = format (0, "some data");
  send_data_to_hss (args->sh, data, vec_len (data), 1);

  return HSS_URL_HANDLER_ASYNC;
}

static void
delayed_resp_cb (u32 *expired_timers)
{
  tb_main_t *tbm = &tb_main;
  int i;
  u32 pool_index;
  tw_timer_elt_t *e;
  u8 *data;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i] & 0x7FFFFFFF;
      e = pool_elt_at_index (tbm->delayed_resps, pool_index);
      clib_warning ("sending delayed data");
      data = format (0, "delayed data");
      send_data_to_hss (e->sh, data, vec_len (data), 1);
      pool_put (tbm->delayed_resps, e);
    }
}

static hss_url_handler_rc_t
handle_get_test_delayed (hss_url_handler_args_t *args)
{
  tb_main_t *tbm = &tb_main;
  tw_timer_elt_t *e;

  clib_warning ("get request on test_delayed");
  pool_get (tbm->delayed_resps, e);
  e->sh = args->sh;
  e->stop_timer_handle =
    tw_timer_start_2t_1w_2048sl (&tbm->tw, e - tbm->delayed_resps, 0, 5);

  return HSS_URL_HANDLER_ASYNC;
}

static hss_url_handler_rc_t
handle_post_test3 (hss_url_handler_args_t *args)
{
  send_data_to_hss (args->sh, 0, 0, 0);
  return HSS_URL_HANDLER_ASYNC;
}

static hss_url_handler_rc_t
handle_get_64bytes (hss_url_handler_args_t *args)
{
  tb_main_t *tbm = &tb_main;
  send_data_to_hss (args->sh, tbm->test_data, 64, 0);
  return HSS_URL_HANDLER_ASYNC;
}

static hss_url_handler_rc_t
handle_get_4kbytes (hss_url_handler_args_t *args)
{
  tb_main_t *tbm = &tb_main;
  send_data_to_hss (args->sh, tbm->test_data, 4 << 10, 0);
  return HSS_URL_HANDLER_ASYNC;
}

static void
test_builtins_init (vlib_main_t *vm)
{
  tb_main_t *tbm = &tb_main;
  hss_register_url_fn fp;
  vlib_node_t *n;

  fp = vlib_get_plugin_symbol ("http_static_plugin.so",
			       "hss_register_url_handler");

  if (fp == 0)
    {
      clib_warning ("http_static_plugin.so not loaded...");
      return;
    }

  /* init test data, big buffer */
  vec_validate_init_empty (tbm->test_data, (4 << 10) - 1, 'x');

  (*fp) (handle_get_test1, "test1", HTTP_REQ_GET);
  (*fp) (handle_get_test1, "test1", HTTP_REQ_POST);
  (*fp) (handle_get_test2, "test2", HTTP_REQ_GET);
  (*fp) (handle_get_test_delayed, "test_delayed", HTTP_REQ_GET);
  (*fp) (handle_post_test3, "test3", HTTP_REQ_POST);
  (*fp) (handle_get_64bytes, "64B", HTTP_REQ_GET);
  (*fp) (handle_get_4kbytes, "4kB", HTTP_REQ_GET);

  tbm->send_data =
    vlib_get_plugin_symbol ("http_static_plugin.so", "hss_session_send_data");

  tw_timer_wheel_init_2t_1w_2048sl (&tbm->tw, delayed_resp_cb, 1.0, ~0);

  vlib_node_set_state (vm, test_builtins_timer_process_node.index,
		       VLIB_NODE_STATE_POLLING);
  n = vlib_get_node (vm, test_builtins_timer_process_node.index);
  vlib_start_process (vm, n->runtime_index);
}

static clib_error_t *
test_builtins_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  test_builtins_init (vm);
  return 0;
}

VLIB_CLI_COMMAND (test_builtins_enable_command, static) = {
  .path = "test-url-handler enable",
  .short_help = "test-url-handler enable",
  .function = test_builtins_enable_command_fn,
};
