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

#include <fcntl.h>
#include <unistd.h>

#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/vec.h>

#include "crypto_sw_scheduler.h"

/**
 * @file
 * @brief CLI for SW Scheduler engine.
 *
 * This file contains the source code for CLI for sw_scheduler
 */

static clib_error_t *
sw_scheduler_set_worker_crypto (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  crypto_sw_scheduler_main_t *cm = &crypto_sw_scheduler_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 worker_thread_index;
  u8 crypto_enable;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "worker %u", &worker_thread_index))
	{
	  if (worker_thread_index > tm->n_vlib_mains - 1)
	    {
	      return (clib_error_return (0, "invalid worker thread idx"));
	    }
	  else if (unformat (line_input, "crypto"))
	    {
	      if (unformat (line_input, "on"))
		crypto_enable = 1;
	      else if (unformat (line_input, "off"))
		crypto_enable = 0;
	      else
		return (clib_error_return (0, "unknown input '%U'",
					   format_unformat_error,
					   line_input));
	    }
	  else
	    return (clib_error_return (0, "unknown input '%U'",
				       format_unformat_error, line_input));
	}
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input));
    }

  cm->per_thread_data[worker_thread_index].self_crypto_enabled =
    crypto_enable;

  return 0;
}

/*?
 * This command sets if worker will do crypto processing.
 *
 * @cliexpar
 * Example of how to set worker crypto processing off:
 * @cliexstart{set sw_scheduler worker 1 crypto off}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_buffer, static) = {
  .path = "set sw_scheduler",
  .short_help = "set sw_scheduler worker <id> crypto <on|off>",
  .function = sw_scheduler_set_worker_crypto,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/* Dummy function to get us linked in. */
void
sw_scheduler_cli_reference (void)
{
}

clib_error_t *
sw_scheduler_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (sw_scheduler_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
