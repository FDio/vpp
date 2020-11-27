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

#include <vnet/vnet.h>
#include <perfmon2/perfmon2.h>

uword
unformat_perfmon2_bundle_name (unformat_input_t * input, va_list * args)
{
  perfmon2_main_t *pm = &perfmon2_main;
  perfmon2_bundle_t **b = va_arg (*args, perfmon2_bundle_t **);
  uword *p;
  u8 *str = 0;

  if (unformat (input, "%s", &str) == 0)
    return 0;

  p = hash_get_mem (pm->bundle_by_name, str);

  if (p)
    b[0] = (perfmon2_bundle_t *) p[0];

  vec_free (str);
  return p ? 1 : 0;
}

u8 *
format_perfmon2_bundle (u8 * s, va_list * args)
{
  perfmon2_bundle_t *b = va_arg (*args, perfmon2_bundle_t *);
  int verbose = va_arg (*args, int);

  const char *bundle_type[] = {
    [PERFMON2_BUNDLE_TYPE_NODE] = "node",
    [PERFMON2_BUNDLE_TYPE_THREAD] = "thread",
    [PERFMON2_BUNDLE_TYPE_SYSTEM] = "system",
  };

  if (b == 0)
    return format (s, "%-20s%-10s%-20s%s",
		   "Name", "Type", "Source", "Description");

  if (verbose)
    {
      s = format (s, "name: %s\n", b->name);
      s = format (s, "description: %s\n", b->description);
    }
  else
    s = format (s, "%-20s%-10s%-20s%s", b->name, bundle_type[b->type],
		b->src->name, b->description);

  return s;
}

static clib_error_t *
show_perfmon2_bundle_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  perfmon2_main_t *pm = &perfmon2_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  perfmon2_bundle_t *b = 0, **vb = 0;
  int verbose = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else if (unformat (line_input, "%U",
			     unformat_perfmon2_bundle_name, &b))
	    vec_add (vb, &b, 1);
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, input);
	}
      unformat_free (line_input);
    }

  if (vb == 0)
    {
      char *key;

      /* *INDENT-OFF* */
      hash_foreach_mem (key, b, pm->bundle_by_name,
        {
	  vec_add (vb, &b, 1);
	});
      /* *INDENT-ON* */
    }
  else
    verbose = 1;

  if (verbose == 0)
    vlib_cli_output (vm, "%U\n", format_perfmon2_bundle, 0, 0);

  for (int i = 0; i < vec_len (vb); i++)
    vlib_cli_output (vm, "%U\n", format_perfmon2_bundle, vb[i], verbose);

  vec_free (vb);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_perfmon2_bundle_command, static) =
{
  .path = "show perfmon2 bundle",
  .short_help = "show perfmon2 bundle [<bundle-name>] [verbose]",
  .function = show_perfmon2_bundle_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
