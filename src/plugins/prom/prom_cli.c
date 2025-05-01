/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <prom/prom.h>

static uword
unformat_stats_patterns (unformat_input_t *input, va_list *args)
{
  u8 ***patterns = va_arg (*args, u8 ***);
  u8 *pattern;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%s", &pattern))
	vec_add1 (*patterns, pattern);
      else
	return 0;
    }
  return 1;
}

static clib_error_t *
prom_patterns_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_clear = 0, is_show = 0, **pattern = 0;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "show"))
	is_show = 1;
      else if (unformat (line_input, "clear"))
	is_clear = 1;
      else if (unformat (line_input, "add %U", unformat_stats_patterns,
			 &pattern))
	{
	  prom_stat_patterns_add (pattern);
	  vec_free (pattern);
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }
  unformat_free (line_input);

  if (error)
    return error;

  if (is_clear)
    prom_stat_patterns_free ();

  if (is_show)
    {
      u8 **patterns = prom_stat_patterns_get ();
      vec_foreach (pattern, patterns)
	vlib_cli_output (vm, " %v\n", *pattern);
    }

  return 0;
}

VLIB_CLI_COMMAND (prom_patterns_command, static) = {
  .path = "prom patterns",
  .short_help = "prom patterns [show] [clear] [add <patterns>...]",
  .function = prom_patterns_command_fn,
};

static clib_error_t *
prom_command_fn (vlib_main_t *vm, unformat_input_t *input,
		 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 **patterns = 0, *stat_name_prefix = 0;
  prom_main_t *pm = prom_get_main ();
  clib_error_t *error = 0;
  u8 is_enable = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    goto no_input;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	is_enable = 1;
      else if (unformat (line_input, "min-scrape-interval %f",
			 &pm->min_scrape_interval))
	;
      else if (unformat (line_input, "used-only"))
	prom_report_used_only (1 /* used only */);
      else if (unformat (line_input, "all-stats"))
	prom_report_used_only (0 /* used only */);
      else if (unformat (line_input, "stat-name-prefix %_%v%_",
			 &stat_name_prefix))
	prom_stat_name_prefix_set (stat_name_prefix);
      else if (unformat (line_input, "stat-patterns %U",
			 unformat_stats_patterns, &patterns))
	prom_stat_patterns_set (patterns);
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }

  unformat_free (line_input);

  if (error)
    return error;

no_input:

  if (is_enable && !pm->is_enabled)
    return prom_enable (vm);

  return 0;
}

VLIB_CLI_COMMAND (prom_enable_command, static) = {
  .path = "prom",
  .short_help = "prom [enable] [min-scrape-interval <n>] [used-only] "
		"[all-stats] [stat-name-prefix <prefix>] "
		"[stat-patterns <patterns>...]",
  .function = prom_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
