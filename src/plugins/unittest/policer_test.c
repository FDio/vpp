/*
 * Copyright (c) 2021 Graphiant, Inc.
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
#include <vnet/policer/policer.h>

#define PKT_LEN 500

static clib_error_t *
policer_test (vlib_main_t *vm, unformat_input_t *input,
	      vlib_cli_command_t *cmd_arg)
{
  int policer_index, i;
  uint rate_kbps, burst, num_pkts;
  double total_bytes, cpu_ticks_per_pkt, time = 0;
  double cpu_speed, cpu_ticks_per_byte;
  policer_result_e result, input_colour = POLICE_CONFORM;
  uint64_t policer_time;

  policer_t *pol;
  vnet_policer_main_t *pm = &vnet_policer_main;

  if (!unformat (input, "index %d", &policer_index) || /* policer to use */
      !unformat (input, "rate %u", &rate_kbps) || /* rate to send at in kbps */
      !unformat (input, "burst %u", &burst) ||	  /* burst to send in ms */
      !unformat (input, "colour %u",
		 &input_colour)) /* input colour if aware */
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
      vlib_increment_combined_counter (&policer_counters[result], 0,
				       policer_index, 1, PKT_LEN);
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
