/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* cli_decl.c: connects the declarative CLI to the vlib CLI.
 *
 * A VLIB_CLI_COMMAND with a handler has its function set to cli_dispatch ()
 * when it is registered, so it lives in the same command tree as the other
 * commands and keeps abbreviations, help and barrier handling. The function
 * parses the rest of the line using the declared arguments, see
 * vppinfra/cli.h, and calls the handler with the parsed values.
 */

#include <vlib/vlib.h>
#include <vlib/cli_decl.h>

void
vlib_cli_completions_free (vlib_cli_completion_t *c)
{
  cli_candidates_free (c);
}

/* Graph node */
static u8 *
parse_node (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  unformat_input_t in;
  u32 node_index;
  int ok;

  unformat_init_vector (&in, vec_dup (tok));
  ok = unformat (&in, "%U", unformat_vlib_node, vlib_get_main (), &node_index) &&
       unformat_check_input (&in) == UNFORMAT_END_OF_INPUT;
  unformat_free (&in);
  if (!ok)
    return format (0, "unknown node '%v'", tok);
  v->index = node_index;
  return 0;
}

static void
complete_node (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  vlib_node_main_t *nm = &vlib_get_main ()->node_main;
  vlib_node_t **n;

  vec_foreach (n, nm->nodes)
    if (vec_len (n[0]->name) >= vec_len (prefix) &&
	(vec_len (prefix) == 0 || memcmp (n[0]->name, prefix, vec_len (prefix)) == 0))
      {
	cli_candidate_t *c;

	vec_add2 (*out, c, 1);
	c->text = vec_dup (n[0]->name);
	if (n[0]->type == VLIB_NODE_TYPE_INPUT)
	  c->help = format (0, "input node");
      }
}

CLIB_CLI_TYPE (cli_type_node) = {
  .name = "node",
  .help = "graph node name",
  .parse = parse_node,
  .complete = complete_node,
};

static void
capture_output (uword arg, u8 *buffer, uword n)
{
  u8 **v = (u8 **) arg;

  vec_add (*v, buffer, n);
}

static int
is_filter_name (u8 *buf, u32 start, u32 end, const char **names)
{
  while (start < end && is_white_space (buf[start]))
    start++;
  for (const char **n = names; *n; n++)
    {
      u32 len = strlen (*n);

      if (start + len <= end && memcmp (buf + start, *n, len) == 0 &&
	  (start + len == end || is_white_space (buf[start + len])))
	return 1;
    }
  return 0;
}

static int
is_text_filter_name (u8 *buf, u32 start, u32 end)
{
  static const char *names[] = { "grep", "head", "tail", "count", 0 };

  return is_filter_name (buf, start, end, names);
}

static int
is_structured_filter_name (u8 *buf, u32 start, u32 end)
{
  static const char *names[] = { "json", "where", 0 };

  return is_filter_name (buf, start, end, names);
}

/* Commands which parse their own arguments are called with the line as
 * typed, but a trailing "| grep|head|tail|count ..." is not for them, it is
 * applied to their output. */
clib_error_t *
vlib_cli_call_function (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *c)
{
  u8 *buf = input->buffer, *left = 0, *text = 0, *captured = 0, *out;
  u32 start = input->index, n = vec_len (buf), end, pipe = ~0;
  vlib_process_t *cp;
  vlib_cli_output_function_t *save_fn;
  unformat_input_t line_input;
  cli_ctx_t ctx = {};
  clib_error_t *error;
  uword save_arg;

  if (c->handler || start >= n)
    return c->function (vm, input, c);

  /* sub-inputs and quoted text are not touched */
  for (end = start; end < n && buf[end] != '\n'; end++)
    {
      if (buf[end] == '{' || buf[end] == '"')
	return c->function (vm, input, c);
      if (pipe == ~0 && buf[end] == '|' && (end == start || is_white_space (buf[end - 1])) &&
	  (end + 1 == n || is_white_space (buf[end + 1])))
	pipe = end;
    }

  if (pipe != ~0 && is_structured_filter_name (buf, pipe + 1, end))
    {
      vec_add (text, buf + pipe + 1, end - pipe - 1);
      error = cli_parse_pipeline (text, &ctx);
      vec_free (text);
      if (!error)
	error = cli_check_output (&ctx);
      cli_ctx_free (&ctx);
      input->index = end;
      return error;
    }

  if (pipe == ~0 || !is_text_filter_name (buf, pipe + 1, end))
    return c->function (vm, input, c);

  vec_add (text, buf + pipe + 1, end - pipe - 1);
  error = cli_parse_pipeline (text, &ctx);
  vec_free (text);
  if (error)
    {
      cli_ctx_free (&ctx);
      return error;
    }

  vec_add (left, buf + start, pipe - start);
  unformat_init_vector (&line_input, left);
  input->index = end;

  cp = vlib_get_current_process (vm);
  save_fn = cp->output_function;
  save_arg = cp->output_function_arg;
  cp->output_function = capture_output;
  cp->output_function_arg = (uword) &captured;
  error = c->function (vm, &line_input, c);
  cp->output_function = save_fn;
  cp->output_function_arg = save_arg;
  unformat_free (&line_input);

  out = cli_apply_text_filters (&ctx, captured);
  if (vec_len (out))
    vlib_cli_output (vm, "%v", out);
  vec_free (out);
  vec_free (captured);
  cli_ctx_free (&ctx);
  return error;
}

clib_error_t *
cli_dispatch (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *c)
{
  const vlib_cli_command_t *cmd = (vlib_cli_command_t *) c->function_arg;
  cli_ctx_t ctx = {};
  u8 *line = 0, *captured = 0, *out;
  clib_error_t *error;
  uword ch;

  while ((ch = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT && ch != '\n')
    vec_add1 (line, ch);

  error = cli_parse_line (cmd->args, line, &ctx);
  if (error)
    goto done;

  if (ctx.help)
    {
      vlib_cli_output (vm, "%U", format_cli_help, cmd->path, cmd->short_help, cmd->long_help,
		       cmd->args);
      goto done;
    }

  if (cli_has_text_filters (&ctx))
    {
      vlib_process_t *cp = vlib_get_current_process (vm);
      vlib_cli_output_function_t *save_fn = cp->output_function;
      uword save_arg = cp->output_function_arg;

      cp->output_function = capture_output;
      cp->output_function_arg = (uword) &captured;
      error = cmd->handler (vm, &ctx);
      cp->output_function = save_fn;
      cp->output_function_arg = save_arg;
    }
  else
    error = cmd->handler (vm, &ctx);

  if (!error)
    error = cli_check_output (&ctx);
  if (error)
    goto done;

  /* text printed by the handler, if it was captured, and structured output
   * go through the same filters */
  vec_append (captured, ctx.out);
  if (cli_has_text_filters (&ctx))
    out = cli_apply_text_filters (&ctx, captured);
  else
    out = vec_dup (ctx.out);

  if (vec_len (out))
    vlib_cli_output (vm, "%v", out);
  vec_free (out);

done:
  vec_free (captured);
  cli_ctx_free (&ctx);
  vec_free (line);
  return error;
}

static clib_error_t *
show_schema_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vlib_cli_main_t *cm = &vgm->cli_main;
  clib_json_text_t j;
  vlib_cli_command_t *c, *x;

  clib_json_init (&j);
  clib_json_add_object (&j, 0);

  clib_json_add_array (&j, "types");
  cli_types_to_json (&j);
  clib_json_parent (&j);

  clib_json_add_array (&j, "commands");
  vec_foreach (c, cm->commands)
    {
      if (!c->function || c->handler)
	continue;
      clib_json_add_object (&j, 0);
      clib_json_add_string (&j, "path", "%v", c->path);
      if (c->short_help)
	clib_json_add_string (&j, "help", "%s", c->short_help);
      clib_json_add_false (&j, "v2");
      clib_json_parent (&j);
    }

  for (x = cm->cli_command_registrations; x; x = x->next_cli_command)
    {
      if (!x->handler)
	continue;
      clib_json_add_object (&j, 0);
      clib_json_add_string (&j, "path", "%s", x->path);
      if (x->short_help)
	clib_json_add_string (&j, "help", "%s", x->short_help);
      clib_json_add_true (&j, "v2");
      clib_json_add_array (&j, "args");
      cli_args_to_json (&j, x->args);
      clib_json_parent (&j);
      clib_json_parent (&j);
    }
  clib_json_parent (&j);

  vlib_cli_output (vm, "%U", format_clib_json_text, &j);
  clib_json_free (&j);
  return 0;
}

VLIB_CLI_COMMAND (show_cli_schema, static) = {
  .path = "show cli schema",
  .short_help = "Dump all CLI commands and their arguments as JSON",
  .handler = show_schema_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
test_complete_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  cli_value_t *v = cli_get (ctx, "line");
  vlib_cli_completion_t *c, *cands;

  cands = vlib_cli_get_completions (v->str);
  vec_foreach (c, cands)
    {
      if (c->help)
	vlib_cli_output (vm, "%v\t%v", c->text, c->help);
      else
	vlib_cli_output (vm, "%v", c->text);
    }
  vlib_cli_completions_free (cands);
  return 0;
}

VLIB_CLI_COMMAND (test_cli_complete, static) = {
  .path = "test cli complete",
  .short_help = "Print completion candidates for a (quoted) command line",
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("line", cli_type_string, .help = "quoted command line"),
      {},
    },
  .handler = test_complete_fn,
  .is_mp_safe = 1,
};
