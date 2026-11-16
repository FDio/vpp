/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* A command line application which uses only vppinfra. It reads commands
 * from the standard input:
 *
 *   hello [name <word>] [times <1-10>] [loud]
 *   calc {add|sub|mul|div} <a> <b>
 *   wait <duration>
 *   paint <color>
 *   colors
 *   complete <partial command line>
 *   help | quit
 *
 * Every command accepts "| grep|head|tail|count" and, for those which emit
 * structured output, "| json" and "| where". A line which ends with '?'
 * prints the help of the command.
 */

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>

#include <vppinfra/cli.h>
#include <vppinfra/json.h>

/* A type of our own. Types describe how a value is parsed and completed. */

static const char *colors[] = { "red", "green", "blue", 0 };

static u8 *
parse_color (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  for (u32 i = 0; colors[i]; i++)
    if (strlen (colors[i]) == vec_len (tok) && memcmp (colors[i], tok, vec_len (tok)) == 0)
      {
	v->index = i;
	return 0;
      }
  return format (0, "'%v' is not a color", tok);
}

static void
complete_color (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  for (u32 i = 0; colors[i]; i++)
    if (cli_prefix_match (colors[i], prefix))
      cli_candidate_add (out, colors[i], 0);
}

CLIB_CLI_TYPE (cli_type_color) = {
  .name = "color",
  .help = "red, green or blue",
  .parse = parse_color,
  .complete = complete_color,
};

/* The handlers. They get the parsed arguments in ctx and append their text
 * output to *out. */

static const cli_arg_t *hello_args =
  CLI_ARGS (CLI_OPT_KEYWORD ("name", cli_type_string, .def = "world", .help = "who to greet"),
	    CLI_OPT_KEYWORD ("times", cli_type_u32, .def = "1", .min = 1, .max = 10,
			     .help = "how many times"),
	    CLI_FLAG ("loud", .help = "add some enthusiasm"));

static clib_error_t *
cmd_hello (cli_ctx_t *ctx, u8 **out)
{
  cli_value_t *name = cli_get (ctx, "name");
  u32 times = cli_u64 (ctx, "times", 1);

  for (u32 i = 0; i < times; i++)
    *out = format (*out, "Hello, %v%s\n", name->str, cli_flag (ctx, "loud") ? "!!!" : ".");
  return 0;
}

static const cli_arg_t *calc_args =
  CLI_ARGS (CLI_ENUM ("op", 0, { "add", "a + b", 0 }, { "sub", "a - b", 1 }, { "mul", "a * b", 2 },
		      { "div", "a / b", 3 }),
	    CLI_VALUE ("a", cli_type_f64), CLI_VALUE ("b", cli_type_f64));

static clib_error_t *
cmd_calc (cli_ctx_t *ctx, u8 **out)
{
  f64 a = cli_get (ctx, "a")->f64, b = cli_get (ctx, "b")->f64, r = 0;

  switch (cli_index (ctx, "op"))
    {
    case 0:
      r = a + b;
      break;
    case 1:
      r = a - b;
      break;
    case 2:
      r = a * b;
      break;
    case 3:
      if (b == 0)
	return clib_error_return (0, "division by zero");
      r = a / b;
      break;
    }
  *out = format (*out, "%.3f\n", r);
  return 0;
}

/* "250ms", "1.5s", "2m" ... are all accepted, the value is in seconds */
static const cli_arg_t *wait_args = CLI_ARGS (CLI_VALUE ("time", cli_type_duration));

static clib_error_t *
cmd_wait (cli_ctx_t *ctx, u8 **out)
{
  *out = format (*out, "would wait %.0f ms\n", cli_get (ctx, "time")->f64 * 1000);
  return 0;
}

static const cli_arg_t *paint_args = CLI_ARGS (CLI_VALUE ("color", cli_type_color));

static clib_error_t *
cmd_paint (cli_ctx_t *ctx, u8 **out)
{
  *out = format (*out, "painting it %s\n", colors[cli_index (ctx, "color")]);
  return 0;
}

/* A command with structured output: the same data is shown as a table, as
 * JSON with "| json" or filtered with "| where index > 0". */
static const cli_column_t color_columns[] = { { "name", "Name" }, { "index", "Index" }, {} };

static clib_error_t *
cmd_colors (cli_ctx_t *ctx, u8 **out)
{
  clib_json_text_t j;

  if (!cli_is_structured (ctx))
    {
      for (u32 i = 0; colors[i]; i++)
	*out = format (*out, "%-8s %u\n", colors[i], i);
      return 0;
    }

  clib_json_init (&j);
  clib_json_add_array (&j, 0);
  for (u32 i = 0; colors[i]; i++)
    {
      clib_json_add_object (&j, 0);
      clib_json_add_string (&j, "name", "%s", colors[i]);
      clib_json_add_number (&j, "index", i);
      clib_json_parent (&j);
    }
  clib_json_parent (&j);
  return cli_emit_table (ctx, &j, color_columns);
}

/* The command table. vppinfra only parses, finding and calling the command
 * is up to the application. */

typedef struct
{
  const char *name;
  const char *help;
  const cli_arg_t **args;
  clib_error_t *(*fn) (cli_ctx_t *ctx, u8 **out);
} command_t;

static const command_t commands[] = {
  { "hello", "Greet someone", &hello_args, cmd_hello },
  { "calc", "Do some math", &calc_args, cmd_calc },
  { "wait", "Parse a duration", &wait_args, cmd_wait },
  { "paint", "Use a type of our own", &paint_args, cmd_paint },
  { "colors", "List the colors, with structured output", 0, cmd_colors },
  {},
};

static const command_t *
find_command (u8 *line, u8 **rest)
{
  u32 n = 0;

  while (n < vec_len (line) && !isspace (line[n]))
    n++;
  for (const command_t *c = commands; c->name; c++)
    if (strlen (c->name) == n && memcmp (c->name, line, n) == 0)
      {
	vec_add (*rest, line + n, vec_len (line) - n);
	return c;
      }
  return 0;
}

static void
print_error (clib_error_t *err)
{
  u8 *s = format (0, "%v\n", err->what);

  fwrite (s, 1, vec_len (s), stdout);
  vec_free (s);
  clib_error_free (err);
}

static void
run_line (u8 *line)
{
  const command_t *c;
  const cli_arg_t *args;
  cli_ctx_t ctx = {};
  u8 *rest = 0, *text = 0, *out = 0;
  clib_error_t *err;

  c = find_command (line, &rest);
  if (!c)
    {
      printf ("unknown command, try 'help'\n");
      goto done;
    }
  args = c->args ? *c->args : 0;

  err = cli_parse_line (args, rest, &ctx);
  if (!err && ctx.help)
    {
      out = format (0, "%U", format_cli_help, c->name, c->help, 0, args);
      goto print;
    }
  if (!err)
    {
      if (vec_len (ctx.warnings))
	fwrite (ctx.warnings, 1, vec_len (ctx.warnings), stdout);
      err = c->fn (&ctx, &text);
    }
  if (!err)
    err = cli_check_output (&ctx);
  if (err)
    {
      print_error (err);
      goto done;
    }

  /* text and structured output go through the same filters */
  vec_append (text, ctx.out);
  out = cli_has_text_filters (&ctx) ? cli_apply_text_filters (&ctx, text) : vec_dup (text);

print:
  fwrite (out, 1, vec_len (out), stdout);
done:
  vec_free (out);
  vec_free (text);
  vec_free (rest);
  cli_ctx_free (&ctx);
}

/* what the Tab key would offer after the given text */
static void
complete_line (u8 *line)
{
  cli_candidate_t *cands = 0, *cand;
  const command_t *c;
  u8 *rest = 0;
  u32 n = 0;

  while (n < vec_len (line) && !isspace (line[n]))
    n++;

  if (n == vec_len (line))
    {
      for (c = commands; c->name; c++)
	if (cli_prefix_match (c->name, line))
	  cli_candidate_add (&cands, c->name, c->help);
    }
  else if ((c = find_command (line, &rest)))
    cli_complete_args (c->args ? *c->args : 0, rest, &cands);

  vec_foreach (cand, cands)
    {
      u8 *s = format (0, "%v%s%v\n", cand->text, cand->help ? "\t" : "", cand->help);

      fwrite (s, 1, vec_len (s), stdout);
      vec_free (s);
    }
  cli_candidates_free (cands);
  vec_free (rest);
}

int
main (int argc, char *argv[])
{
  char buf[1024];

  clib_mem_init (0, 64 << 20);

  for (;;)
    {
      u8 *line;

      if (isatty (0))
	printf ("> ");
      fflush (stdout);
      if (!fgets (buf, sizeof (buf), stdin))
	break;

      line = format (0, "%s", buf);
      while (vec_len (line) &&
	     (line[vec_len (line) - 1] == '\n' || line[vec_len (line) - 1] == '\r'))
	vec_set_len (line, vec_len (line) - 1);

      if (strcmp ((char *) line, "quit") == 0 && vec_len (line) == 4)
	{
	  vec_free (line);
	  break;
	}
      if (vec_len (line) == 4 && memcmp (line, "help", 4) == 0)
	for (const command_t *c = commands; c->name; c++)
	  printf ("%-8s %s\n", c->name, c->help);
      else if (vec_len (line) >= 9 && memcmp (line, "complete ", 9) == 0)
	{
	  u8 *partial = 0;

	  vec_add (partial, line + 9, vec_len (line) - 9);
	  complete_line (partial);
	  vec_free (partial);
	}
      else if (vec_len (line))
	run_line (line);
      vec_free (line);
    }
  return 0;
}
