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

#include <http/http.h>

static clib_error_t *
show_http_cache_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  http_cache_entry_t *ep, **entries = 0;
  http_main_t *hm = http_get_main ();
  http_cache_t *hc = &hm->cache;
  clib_error_t *error;
  u8 verbose = 0;
  u32 index;
  f64 now;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, line_input);
	      unformat_free (line_input);
	      return error;
	    }
	}
      unformat_free (line_input);
    }

  if (verbose == 0)
    {
      vlib_cli_output (vm,
		       "cache size %lld bytes, limit %lld bytes, "
		       "evictions %lld",
		       hc->cache_size, hc->cache_limit, hc->cache_evictions);
      return 0;
    }

  now = vlib_time_now (vm);

  vlib_cli_output (vm, "%U", format_http_cache_entry, 0 /* header */, now);

  for (index = hc->first_index; index != ~0;)
    {
      ep = http_cache_entry_get (hc, index);
      index = ep->next_index;
      vlib_cli_output (vm, "%U", format_http_cache_entry, ep, now);
    }

  vlib_cli_output (vm, "%40s%12lld", "Total Size", hc->cache_size);

  vec_free (entries);
}

VLIB_CLI_COMMAND (http_cache_command, static) = {
  .path = "show http cache",
  .short_help = "show http cache [verbose]",
  .function = show_http_cache_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
