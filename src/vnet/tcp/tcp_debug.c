/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <vnet/tcp/tcp_debug.h>

tcp_dbg_main_t tcp_dbg_main;

void
tcp_evt_track_register (elog_track_t * et)
{
  tcp_dbg_main_t *tdm = &tcp_dbg_main;
  u32 fl_len, track_index;

  fl_len = vec_len (tdm->free_track_indices);
  if (fl_len)
    {
      track_index = tdm->free_track_indices[fl_len - 1];
      _vec_len (tdm->free_track_indices) -= 1;
      et->track_index_plus_one = track_index + 1;
    }
  else
    elog_track_register (&vlib_global_main.elog_main, et);
}

static const char *tcp_evt_grp_str[] = {
#define _(sym, str) str,
  foreach_tcp_evt_grp
#undef _
};

static void
tcp_debug_show_groups (void)
{
  tcp_dbg_main_t *tdm = &tcp_dbg_main;
  vlib_main_t *vm = vlib_get_main ();
  int i = 0;

  vlib_cli_output (vm, "%-10s%-30s%-10s", "Index", "Group", "Level");

  for (i = 0; i < TCP_EVT_N_GRP; i++)
    vlib_cli_output (vm, "%-10d%-30s%-10d", i, tcp_evt_grp_str[i],
		     tdm->grp_dbg_lvl[i]);
}

static clib_error_t *
tcp_debug_fn (vlib_main_t * vm, unformat_input_t * input,
	      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  tcp_dbg_main_t *tdm = &tcp_dbg_main;
  u32 group = ~0, level = ~0;
  clib_error_t *error = 0;
  u8 is_show = 0;

  if (!TCP_DEBUG_ALWAYS)
    return clib_error_return (0, "must compile with TCP_DEBUG_ALWAYS set");

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected enable | disable");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "show"))
	is_show = 1;
      else if (unformat (line_input, "group %d", &group))
	;
      else if (unformat (line_input, "level %d", &level))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (is_show)
    {
      tcp_debug_show_groups ();
      goto done;
    }
  if (group >= TCP_EVT_N_GRP)
    {
      error = clib_error_return (0, "group out of bounds");
      goto done;
    }
  if (group == ~0 || level == ~0)
    {
      error = clib_error_return (0, "group and level must be set");
      goto done;
    }

  tdm->grp_dbg_lvl[group] = level;

done:

  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tcp_debug_command, static) =
{
  .path = "tcp debug",
  .short_help = "tcp [show] [debug group <N> level <N>]",
  .function = tcp_debug_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
