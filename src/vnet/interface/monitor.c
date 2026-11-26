/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vnet/interface/cli_types.h>

static clib_error_t *
monitor_interface_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  const vnet_main_t *vnm = vnet_get_main ();
  const vlib_combined_counter_main_t *counters =
    vnm->interface_main.combined_sw_if_counters;
  cli_value_t *interval = cli_get (ctx, "interval");
  f64 refresh_interval = interval ? interval->f64 : 1.0;
  u32 refresh_count = cli_u64 (ctx, "count", ~0);
  clib_error_t *error = 0;
  vlib_counter_t vrx[2], vtx[2];
  f64 ts[2];
  u32 sw_if_index = cli_index (ctx, "interface");
  u8 spin = 0;

  vlib_get_combined_counter (counters + VNET_INTERFACE_COUNTER_RX, sw_if_index,
			     &vrx[spin]);
  vlib_get_combined_counter (counters + VNET_INTERFACE_COUNTER_TX, sw_if_index,
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
				 sw_if_index, &vrx[spin]);
      vlib_get_combined_counter (counters + VNET_INTERFACE_COUNTER_TX,
				 sw_if_index, &vtx[spin]);
      ts[spin] = vlib_time_now (vm);

      tsd = ts[spin] - ts[spin ^ 1];
      vlib_cli_output (
	vm, "rx: %Upps %Ubps tx: %Upps %Ubps", format_base10,
	(u64) ((vrx[spin].packets - vrx[spin ^ 1].packets) / tsd),
	format_base10,
	(u64) (8 * (vrx[spin].bytes - vrx[spin ^ 1].bytes) / tsd),
	format_base10,
	(u64) ((vtx[spin].packets - vtx[spin ^ 1].packets) / tsd),
	format_base10,
	(u64) (8 * (vtx[spin].bytes - vtx[spin ^ 1].bytes) / tsd));
    }

done:
  return error;
}

VLIB_CLI_COMMAND (monitor_interface_command, static) = {
  .path = "monitor interface",
  .short_help = "Print the packet and bit rates of an interface",
  .args = CLI_ARGS (
    CLI_VALUE ("interface", cli_type_sw_interface),
    CLI_OPT_KEYWORD ("interval", cli_type_f64, .help = "seconds between samples, default 1"),
    CLI_OPT_KEYWORD ("count", cli_type_u32, .help = "number of samples, default until a key")),
  .handler = monitor_interface_command_fn,
  .is_mp_safe = 1,
};
