/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cnat/cnat_session.h>
#include <vlibmemory/api.h>
#include <cnat/cnat_client.h>

static uword
cnat_scanner_process (vlib_main_t * vm,
		      vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  uword event_type, *event_data = 0;
  cnat_main_t *cm = &cnat_main;
  f64 start_time;
  int enabled = 0, i = 0;

  while (1)
    {
      if (enabled)
	vlib_process_wait_for_event_or_clock (vm, cm->scanner_timeout);
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      start_time = vlib_time_now (vm);

      switch (event_type)
	{
	  /* timer expired */
	case ~0:
	  break;
	case CNAT_SCANNER_OFF:
	  enabled = 0;
	  break;
	case CNAT_SCANNER_ON:
	  enabled = 1;
	  break;
	default:
	  ASSERT (0);
	}

      cnat_client_throttle_pool_process ();
      i = cnat_session_scan (vm, start_time, i);
    }
  return 0;
}

VLIB_REGISTER_NODE (cnat_scanner_process_node) = {
  .function = cnat_scanner_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cnat-scanner-process",
};

static clib_error_t *
cnat_scanner_cmd (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * c)
{
  cnat_scanner_cmd_t cmd;

  cmd = CNAT_SCANNER_ON;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "on"))
	cmd = CNAT_SCANNER_ON;
      else if (unformat (input, "off"))
	cmd = CNAT_SCANNER_OFF;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }
  cnat_enable_disable_scanner (cmd);

  return (NULL);
}

VLIB_CLI_COMMAND (cnat_scanner_cmd_node, static) = {
  .path = "test cnat scanner",
  .function = cnat_scanner_cmd,
  .short_help = "test cnat scanner",
};

static clib_error_t *
cnat_scanner_init (vlib_main_t * vm)
{
  cnat_main_t *cm = &cnat_main;
  cm->scanner_node_index = cnat_scanner_process_node.index;

  return (NULL);
}

VLIB_INIT_FUNCTION (cnat_scanner_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
