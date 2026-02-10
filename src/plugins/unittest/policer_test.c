/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Graphiant, Inc.
 */

#include <policer/policer.h>

#define PKT_LEN 500

static clib_error_t *
policer_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd_arg)
{
  int policer_index, i;
  unsigned int rate_kbps, burst, num_pkts;
  double total_bytes, cpu_ticks_per_pkt, time = 0;
  double cpu_speed, cpu_ticks_per_byte;
  policer_result_e result, input_colour = POLICE_CONFORM;
  uint64_t policer_time;

  policer_t *pol;
  policer_main_t *pm = policer_get_main ();
  vlib_combined_counter_main_t *counters = policer_get_counters ();

  if (!pm || !counters)
    return clib_error_return (0, "policer plugin not loaded");

  if (!unformat (input, "index %d", &policer_index) || /* policer to use */
      !unformat (input, "rate %u", &rate_kbps) ||      /* rate to send at in kbps */
      !unformat (input, "burst %u", &burst) ||	       /* burst to send in ms */
      !unformat (input, "colour %u", &input_colour))   /* input colour if aware */
    return clib_error_return (0, "Policer test failed to parse params");

  total_bytes = (rate_kbps * burst) / 8;
  num_pkts = total_bytes / PKT_LEN;

  cpu_speed = (double) os_cpu_clock_frequency ();
  cpu_ticks_per_byte = cpu_speed / (rate_kbps * 125);
  cpu_ticks_per_pkt = cpu_ticks_per_byte * PKT_LEN;

  pol = &pm->policers[policer_index];

  for (i = 0; i < num_pkts; i++)
    {
      time += cpu_ticks_per_pkt;
      policer_time = ((uint64_t) time) >> POLICER_TICKS_PER_PERIOD_SHIFT;
      result = vnet_police_packet (pol, PKT_LEN, input_colour, policer_time);
      vlib_increment_combined_counter (&counters[result], 0, policer_index, 1, PKT_LEN);
    }

  return NULL;
}

VLIB_CLI_COMMAND (test_policer_command, static) = {
  .path = "test policing",
  .short_help = "policer unit test helper - DO NOT RUN ON A LIVE SYSTEM",
  .function = policer_test,
};

clib_error_t *
policer_test_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (policer_test_init);
