/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vppinfra/cli_decl.h>
#include <vppinfra/pool.h>

#define TEST_ASSERT(c)                                                                             \
  if (!(c))                                                                                        \
    return clib_error_return (0, "%s:%d: assertion failed: %s", __func__, __LINE__, #c);

static const char *names[] = { "alpha", "beta", "gamma", 0 };

static u8 *
parse_name (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  for (u32 i = 0; names[i]; i++)
    if (strlen (names[i]) == vec_len (tok) && memcmp (names[i], tok, vec_len (tok)) == 0)
      {
	v->index = i;
	return 0;
      }
  return format (0, "unknown name '%v'", tok);
}

static void
complete_name (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  for (u32 i = 0; names[i]; i++)
    if (cli_prefix_match (names[i], prefix))
      cli_candidate_add (out, names[i], "a name");
}

CLIB_CLI_TYPE (test_type_name) = {
  .name = "name",
  .help = "one of the test names",
  .parse = parse_name,
  .complete = complete_name,
};

static const cli_arg_t test_args[] = {
  CLI_ONEOF ("op", 0, CLI_KEYWORD ("add", cli_type_u32), CLI_KEYWORD ("del", cli_type_u32)),
  CLI_VALUE ("name", test_type_name),
  CLI_KEYWORD ("count", cli_type_u32, .max = 100, .flags = CLI_F_OPTIONAL),
  CLI_FLAG ("verbose", .alias = "v"),
  CLI_ENUM ("mode", CLI_F_OPTIONAL, { "fast", "go fast", 1 }, { "slow", "go slow", 2 }),
  CLI_GROUP ("tunnel", "tunnel options",
	     CLI_KEYWORD ("src", test_type_name, .flags = CLI_F_OPTIONAL), CLI_FLAG ("mp")),
  CLI_VALUE ("range", cli_type_range, .max = 1000, .flags = CLI_F_OPTIONAL),
  {},
};

static const cli_column_t test_columns[] = { { "name", "Name" }, { "n", "N" }, {} };

static int
contains (const clib_error_t *e, char *s)
{
  return e && e->what && strstr ((char *) format (0, "%v%c", e->what, 0), s);
}

static u8 *
complete (char *line)
{
  cli_candidate_t *c, *cands = 0;
  u8 *l = format (0, "%s", line), *s = 0;

  cli_complete_args (test_args, l, &cands);
  vec_foreach (c, cands)
    s = format (s, "%s%v", c == cands ? "" : ",", c->text);
  s = format (s, "%c", 0);
  cli_candidates_free (cands);
  vec_free (l);
  return s;
}

#define TEST_COMPLETE(line, expected)                                                              \
  {                                                                                                \
    u8 *s = complete (line);                                                                       \
    int ok = strcmp ((char *) s, expected) == 0;                                                   \
    vec_free (s);                                                                                  \
    TEST_ASSERT (ok);                                                                              \
  }

static clib_error_t *
test_parse (void)
{
  cli_ctx_t ctx = {};
  u8 *line = format (0, "add 5 beta count 7 v slow tunnel src gamma mp 10-20");
  clib_error_t *e = cli_parse_line (test_args, line, &ctx);
  cli_value_t *v;

  TEST_ASSERT (e == 0);
  TEST_ASSERT (cli_get (&ctx, "add")->u64 == 5);
  TEST_ASSERT (cli_get (&ctx, "del") == 0);
  TEST_ASSERT (cli_index (&ctx, "name") == 1);
  TEST_ASSERT (cli_u64 (&ctx, "count", 0) == 7);
  TEST_ASSERT (cli_flag (&ctx, "verbose"));
  TEST_ASSERT (cli_index (&ctx, "mode") == 2);
  TEST_ASSERT (cli_flag (&ctx, "tunnel") && cli_flag (&ctx, "mp"));
  TEST_ASSERT (cli_index (&ctx, "src") == 2);
  v = cli_get (&ctx, "range");
  TEST_ASSERT (v && v->range.start == 10 && v->range.stop == 20);
  cli_ctx_free (&ctx);

  /* order of keywords and flags does not matter, unique prefix of enum */
  vec_reset_length (line);
  line = format (line, "del 9 alpha fa verbose count 1");
  e = cli_parse_line (test_args, line, &ctx);
  TEST_ASSERT (e == 0 && cli_get (&ctx, "del")->u64 == 9 && cli_index (&ctx, "mode") == 1);
  cli_ctx_free (&ctx);

  /* quoted tokens and the alias */
  vec_reset_length (line);
  line = format (line, "add 1 \"alpha\" v");
  e = cli_parse_line (test_args, line, &ctx);
  TEST_ASSERT (e == 0 && cli_flag (&ctx, "verbose"));
  cli_ctx_free (&ctx);

  vec_reset_length (line);
  line = format (line, "add 1 alpha ?");
  e = cli_parse_line (test_args, line, &ctx);
  TEST_ASSERT (e == 0 && ctx.help);
  cli_ctx_free (&ctx);

  vec_free (line);
  return 0;
}

#define TEST_ERROR(line_, substr)                                                                  \
  {                                                                                                \
    cli_ctx_t c = {};                                                                              \
    u8 *l = format (0, "%s", line_);                                                               \
    clib_error_t *e = cli_parse_line (test_args, l, &c);                                           \
    int ok = contains (e, substr);                                                                 \
    clib_error_t *r =                                                                              \
      ok ? 0 :                                                                                     \
	   clib_error_return (0, "'%s': expected '%s' in '%v'", line_, substr, e ? e->what : 0);   \
    clib_error_free (e);                                                                           \
    cli_ctx_free (&c);                                                                             \
    vec_free (l);                                                                                  \
    if (r)                                                                                         \
      return r;                                                                                    \
  }

static clib_error_t *
test_errors (void)
{
  TEST_ERROR ("add 5 alpah", "did you mean 'alpha'");
  TEST_ERROR ("add 5 alpah", "^^^^^");
  TEST_ERROR ("add 5", "missing argument");
  TEST_ERROR ("", "missing argument");
  TEST_ERROR ("add x alpha", "'x' is not a number");
  TEST_ERROR ("add 5 alpha count 101", "out of range");
  TEST_ERROR ("add 5 alpha count", "missing value");
  TEST_ERROR ("add 5 alpha count 1 count 2", "given more than once");
  TEST_ERROR ("add 5 alpha src beta", "only valid after 'tunnel'");
  TEST_ERROR ("add 5 alpha verbos", "did you mean 'verbose'");
  TEST_ERROR ("add 5 alpha mode", "unexpected argument");
  TEST_ERROR ("add 5 alpha 20-10", "larger than its end");
  TEST_ERROR ("add 5 alpha 2000-3000", "out of range");
  TEST_ERROR ("add 5 alpha bogus", "unexpected argument 'bogus': 'bogus' is not a range");
  TEST_ERROR ("add 5 alpha | foo", "unknown filter 'foo'");
  TEST_ERROR ("add 5 alpha | grep", "grep needs a pattern");
  TEST_ERROR ("add 5 alpha | where n ?? 3", "unknown operator");
  return 0;
}

static clib_error_t *
test_completion (void)
{
  TEST_COMPLETE ("", "add,count,del,tunnel,verbose");
  TEST_COMPLETE ("a", "add");
  TEST_COMPLETE ("add ", "");
  TEST_COMPLETE ("add 5 ", "alpha,beta,count,gamma,tunnel,verbose");
  TEST_COMPLETE ("add 5 b", "beta");
  TEST_COMPLETE ("add 5 beta ", "count,fast,slow,tunnel,verbose");
  TEST_COMPLETE ("add 5 beta count ", "");
  TEST_COMPLETE ("add 5 beta f", "fast");
  TEST_COMPLETE ("add 5 beta tunnel ", "count,fast,mp,slow,src,verbose");
  TEST_COMPLETE ("add 5 beta tunnel src ", "alpha,beta,gamma");
  TEST_COMPLETE ("add 5 beta count 5 verbose count", "");
  TEST_COMPLETE ("add 5 beta | ", "json,where,grep,head,tail,count");
  TEST_COMPLETE ("add 5 beta | g", "grep");
  TEST_COMPLETE ("bogus ", "");
  return 0;
}

static clib_error_t *
test_filters (void)
{
  cli_ctx_t ctx = {};
  u8 *line = format (0, "add 1 alpha | grep -i B | head 2 | tail 1");
  u8 *text = format (0, "a\nB1\nb2\nb3\nc\n"), *out;
  clib_error_t *e = cli_parse_line (test_args, line, &ctx);

  TEST_ASSERT (e == 0 && cli_has_text_filters (&ctx));
  out = cli_apply_text_filters (&ctx, text);
  TEST_ASSERT (vec_len (out) == 3 && memcmp (out, "b2\n", 3) == 0);
  vec_free (out);
  cli_ctx_free (&ctx);

  vec_reset_length (line);
  line = format (line, "add 1 alpha | grep -v b | count");
  e = cli_parse_line (test_args, line, &ctx);
  TEST_ASSERT (e == 0);
  out = cli_apply_text_filters (&ctx, text);
  TEST_ASSERT (vec_len (out) == 2 && memcmp (out, "3\n", 2) == 0);
  vec_free (out);
  cli_ctx_free (&ctx);

  vec_free (text);
  vec_free (line);
  return 0;
}

static void
make_rows (clib_json_text_t *j)
{
  clib_json_init (j);
  clib_json_add_array (j, 0);
  for (u32 i = 0; i < 3; i++)
    {
      clib_json_add_object (j, 0);
      clib_json_add_string (j, "name", "row%u", i);
      clib_json_add_number (j, "n", i);
      clib_json_parent (j);
    }
  clib_json_parent (j);
}

static clib_error_t *
test_output (void)
{
  cli_ctx_t ctx = {};
  clib_json_text_t j;
  u8 *line = format (0, "| where n >= 1 | where name != row2");
  clib_error_t *e = cli_parse_line (0, line, &ctx);

  TEST_ASSERT (e == 0 && cli_is_structured (&ctx) && !cli_is_json (&ctx));
  make_rows (&j);
  e = cli_emit_table (&ctx, &j, test_columns);
  TEST_ASSERT (e == 0 && cli_check_output (&ctx) == 0);
  TEST_ASSERT (strstr ((char *) format (ctx.out, "%c", 0), "row1") != 0);
  TEST_ASSERT (vec_len (ctx.out) > 0 && !strstr ((char *) format (0, "%v%c", ctx.out, 0), "row0"));
  TEST_ASSERT (!strstr ((char *) format (0, "%v%c", ctx.out, 0), "row2"));
  cli_ctx_free (&ctx);

  /* unknown field */
  vec_reset_length (line);
  line = format (line, "| where foo == 1");
  e = cli_parse_line (0, line, &ctx);
  TEST_ASSERT (e == 0);
  make_rows (&j);
  e = cli_emit_table (&ctx, &j, test_columns);
  TEST_ASSERT (contains (e, "unknown field 'foo'"));
  clib_error_free (e);
  cli_ctx_free (&ctx);

  /* json */
  vec_reset_length (line);
  line = format (line, "| json");
  e = cli_parse_line (0, line, &ctx);
  TEST_ASSERT (e == 0 && cli_is_json (&ctx));
  TEST_ASSERT (cli_check_output (&ctx) != 0);
  make_rows (&j);
  e = cli_emit_table (&ctx, &j, test_columns);
  TEST_ASSERT (e == 0 && cli_check_output (&ctx) == 0);
  TEST_ASSERT (ctx.out[0] == '[' && strstr ((char *) format (0, "%v%c", ctx.out, 0), "\"row2\""));
  cli_ctx_free (&ctx);

  vec_free (line);
  return 0;
}

static const cli_arg_t rest_args[] = {
  CLI_VALUE ("name", test_type_name),
  CLI_VALUE ("text", cli_type_rest, .flags = CLI_F_OPTIONAL),
  CLI_KEYWORD ("delay", cli_type_f64, .flags = CLI_F_OPTIONAL),
  {},
};

static clib_error_t *
test_rest_and_pipeline (void)
{
  cli_ctx_t ctx = {};
  u8 *line = format (0, "alpha  two   words \"and quotes\" delay 1");
  clib_error_t *e = cli_parse_line (rest_args, line, &ctx);
  cli_value_t *v;

  /* the rest of the line is kept as typed, keywords in it are not special */
  TEST_ASSERT (e == 0 && !cli_flag (&ctx, "delay"));
  v = cli_get (&ctx, "text");
  TEST_ASSERT (v && vec_len (v->str) == strlen ("two   words \"and quotes\" delay 1"));
  TEST_ASSERT (memcmp (v->str, "two   words \"and quotes\" delay 1", vec_len (v->str)) == 0);
  cli_ctx_free (&ctx);

  /* it stops at a '|' and the filters apply to the output */
  vec_reset_length (line);
  line = format (line, "beta hello world | grep h | count");
  e = cli_parse_line (rest_args, line, &ctx);
  TEST_ASSERT (e == 0 && cli_has_text_filters (&ctx));
  v = cli_get (&ctx, "text");
  TEST_ASSERT (v && vec_len (v->str) == strlen ("hello world") &&
	       memcmp (v->str, "hello world", vec_len (v->str)) == 0);
  cli_ctx_free (&ctx);

  /* optional */
  vec_reset_length (line);
  line = format (line, "gamma");
  e = cli_parse_line (rest_args, line, &ctx);
  TEST_ASSERT (e == 0 && cli_get (&ctx, "text") == 0);
  cli_ctx_free (&ctx);

  /* float */
  vec_reset_length (line);
  line = format (line, "gamma delay 1.5");
  e = cli_parse_line (rest_args, line, &ctx);
  TEST_ASSERT (e == 0 && cli_get (&ctx, "delay")->f64 == 1.5);
  cli_ctx_free (&ctx);
  vec_reset_length (line);
  line = format (line, "gamma delay abc");
  e = cli_parse_line (rest_args, line, &ctx);
  TEST_ASSERT (contains (e, "'abc' is not a number"));
  clib_error_free (e);
  cli_ctx_free (&ctx);
  vec_free (line);

  /* pipelines of commands which parse their own arguments */
  line = format (0, "grep -v x | head 3");
  e = cli_parse_pipeline (line, &ctx);
  TEST_ASSERT (e == 0 && cli_has_text_filters (&ctx) && !ctx.json);
  cli_ctx_free (&ctx);
  vec_reset_length (line);
  line = format (line, "grep");
  e = cli_parse_pipeline (line, &ctx);
  TEST_ASSERT (contains (e, "grep needs a pattern"));
  clib_error_free (e);
  cli_ctx_free (&ctx);
  vec_reset_length (line);
  line = format (line, "json");
  e = cli_parse_pipeline (line, &ctx);
  TEST_ASSERT (e == 0 && ctx.json);
  cli_ctx_free (&ctx);
  vec_free (line);
  return 0;
}

static clib_error_t *
test_help_and_schema (void)
{
  u8 *s = format (0, "%U%c", format_cli_help, "test cmd", "short help", 0, test_args, 0);
  clib_json_text_t j;
  u8 *js;

  TEST_ASSERT (strstr ((char *) s, "usage: test cmd (add <add> | del <del>) <name>") != 0);
  TEST_ASSERT (strstr ((char *) s, "[count <count>]") != 0);
  TEST_ASSERT (strstr ((char *) s, "tunnel [src <src>] [mp]") != 0 ||
	       strstr ((char *) s, "[tunnel") != 0);
  TEST_ASSERT (strstr ((char *) s, "arguments:") != 0 && strstr ((char *) s, "short help"));
  vec_free (s);

  clib_json_init (&j);
  clib_json_add_object (&j, 0);
  clib_json_add_array (&j, "args");
  cli_args_to_json (&j, test_args);
  clib_json_parent (&j);
  clib_json_add_array (&j, "types");
  cli_types_to_json (&j);
  clib_json_parent (&j);
  clib_json_parent (&j);
  js = format (0, "%U%c", format_clib_json_text, &j, 0);
  TEST_ASSERT (strstr ((char *) js, "\"kind\": \"group\"") != 0);
  TEST_ASSERT (strstr ((char *) js, "\"name\": \"fast\"") != 0);
  TEST_ASSERT (strstr ((char *) js, "\"name\": \"name\"") != 0);
  vec_free (js);
  clib_json_free (&j);
  return 0;
}

int
main (int argc, char *argv[])
{
  clib_error_t *err;

  clib_mem_init (0, 256 << 20);

  if ((err = test_parse ()) || (err = test_errors ()) || (err = test_completion ()) ||
      (err = test_filters ()) || (err = test_output ()) || (err = test_rest_and_pipeline ()) ||
      (err = test_help_and_schema ()))
    {
      fformat (stdout, "%U\n", format_clib_error, err);
      clib_error_free (err);
      return 1;
    }

  return 0;
}
