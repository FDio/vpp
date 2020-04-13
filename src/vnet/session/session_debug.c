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

#include <vnet/session/session_debug.h>

#if SESSION_DEBUG > 0

session_dbg_main_t session_dbg_main;

static clib_error_t *
show_session_dbg_clock_cycles_fn (vlib_main_t * vm, unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  u32 thread;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);

  for (thread = 0; thread < vec_len (session_dbg_main.wrk); thread++)
    {
      vlib_cli_output (vm, "Threads %u:\n", thread);
      session_dbg_evts_t *sdm = &session_dbg_main.wrk[thread];

#define _(sym, disp, type, str) 								         \
  if(disp)								\
    {									\
      if (!type)							\
	vlib_cli_output (vm, "\t %25s : %12lu ",                       	\
	                 str, sdm->sess_dbg_evt_type[SESS_Q_##sym].u64);\
      else								\
	vlib_cli_output (vm, "\t %25s : %12.3f ",                       \
	                 str, sdm->sess_dbg_evt_type[SESS_Q_##sym].f64);\
    }

      foreach_session_events
#undef _
    }
  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_session_dbg_clock_cycles_command, static) =
{
  .path = "show session dbg clock_cycles",
  .short_help = "show session dbg clock_cycles",
  .function = show_session_dbg_clock_cycles_fn,
};
/* *INDENT-ON* */


static clib_error_t *
clear_session_dbg_clock_cycles_fn (vlib_main_t * vm, unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  session_dbg_evts_t *sdb;
  u32 thread;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);

  for (thread = 0; thread < vec_len (session_dbg_main.wrk); thread++)
    {
      sdb = &session_dbg_main.wrk[thread];
      clib_memset (sdb, 0, sizeof (session_dbg_evts_t));
      sdb->last_time = vlib_time_now (vlib_mains[thread]);
    }

  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_session_clock_cycles_command, static) =
{
  .path = "clear session dbg clock_cycles",
  .short_help = "clear session dbg clock_cycles",
  .function = clear_session_dbg_clock_cycles_fn,
};
/* *INDENT-ON* */

void
session_debug_init (void)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  session_dbg_main_t *sdm = &session_dbg_main;
  u32 num_threads, thread;

  num_threads = vtm->n_vlib_mains;

  vec_validate_aligned (sdm->wrk, num_threads - 1, CLIB_CACHE_LINE_BYTES);
  for (thread = 0; thread < num_threads; thread++)
    {
      clib_memset (&sdm->wrk[thread], 0, sizeof (session_dbg_evts_t));
    }
}
#else
session_debug_init (void)
{
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
