/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlib/vlib.h>

static clib_error_t *
monitor_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  const vnet_main_t *vnm = vnet_get_main ();
  const vlib_combined_counter_main_t *counters =
    vnm->interface_main.combined_sw_if_counters;
  f64 refresh_interval = 1.0;
  u32 refresh_count = ~0;
  clib_error_t *error = 0;
  vlib_counter_t vrx[2], vtx[2];
  f64 ts[2];
  u32 hw_if_index = ~0;
  u8 spin = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	;
      else if (unformat (input, "interval %f", &refresh_interval))
	;
      else if (unformat (input, "count %u", &refresh_count))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (hw_if_index == ~0)
    {
      error = clib_error_return (0, "no interface passed");
      goto done;
    }

  vlib_get_combined_counter (counters + VNET_INTERFACE_COUNTER_RX, hw_if_index,
			     &vrx[spin]);
  vlib_get_combined_counter (counters + VNET_INTERFACE_COUNTER_TX, hw_if_index,
			     &vtx[spin]);
  ts[spin] = vlib_time_now (vm);

  while (refresh_count--)
    {
      f64 sleep_interval, tsd;

      while (((sleep_interval =
		 ts[spin] + refresh_interval - vlib_time_now (vm)) > 0.0))
	{
	  uword event_type, *event_data = 0;
	  vlib_process_wait_for_event_or_clock (vm, sleep_interval);
	  event_type = vlib_process_get_events (vm, &event_data);
	  switch (event_type)
	    {
	    case ~0: /* no events => timeout */
	      break;
	    default:
	      /* someone pressed a key, abort */
	      vlib_cli_output (vm, "Aborted due to a keypress.");
	      goto done;
	    }
	  vec_free (event_data);
	}
      spin ^= 1;
      vlib_get_combined_counter (counters + VNET_INTERFACE_COUNTER_RX,
				 hw_if_index, &vrx[spin]);
      vlib_get_combined_counter (counters + VNET_INTERFACE_COUNTER_TX,
				 hw_if_index, &vtx[spin]);
      ts[spin] = vlib_time_now (vm);

      tsd = ts[spin] - ts[spin ^ 1];
      vlib_cli_output (
	vm, "rx: %Upps %Ubps tx: %Upps %Ubps", format_base10,
	(u32) ((vrx[spin].packets - vrx[spin ^ 1].packets) / tsd),
	format_base10, (u32) ((vrx[spin].bytes - vrx[spin ^ 1].bytes) / tsd),
	format_base10,
	(u32) ((vtx[spin].packets - vtx[spin ^ 1].packets) / tsd),
	format_base10, (u32) ((vtx[spin].bytes - vtx[spin ^ 1].bytes) / tsd));
    }

done:
  return error;
}

VLIB_CLI_COMMAND (monitor_interface_command, static) = {
  .path = "monitor interface",
  .short_help =
    "monitor interface <interface> [interval <intv>] [count <count>]",
  .function = monitor_interface_command_fn,
  .is_mp_safe = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
