/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* cli_types.c: built-in argument types for VLIB_CLI_COMMAND */

#include <vppinfra/cli.h>
#include <vppinfra/bitmap.h>
#include <errno.h>

static u8 *
parse_uint (u64 def_max, const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u64 max = a->max ? a->max : def_max;
  char *end;
  u8 *z = format (0, "%v%c", tok, 0);
  u64 val;
  u8 *err = 0;

  errno = 0;
  val = strtoull ((char *) z, &end, 0);
  if (vec_len (tok) == 0 || !cli_is_digit (tok[0]) || *end)
    err = format (0, "'%v' is not a number", tok);
  else if (errno || val < a->min || val > max)
    err = format (0, "'%v' is out of range (%llu - %llu)", tok, a->min, max);
  else
    v->u64 = val;
  vec_free (z);
  return err;
}

static u8 *
parse_u32 (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  return parse_uint (0xffffffffULL, a, tok, v);
}

static u8 *
parse_u64 (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  return parse_uint ((u64) ~0, a, tok, v);
}

CLIB_CLI_TYPE (cli_type_u32) = {
  .name = "number",
  .help = "unsigned integer",
  .parse = parse_u32,
};

CLIB_CLI_TYPE (cli_type_u64) = {
  .name = "number",
  .help = "unsigned integer",
  .parse = parse_u64,
};

static u8 *
parse_string (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  if (vec_len (tok) == 0)
    return format (0, "empty string");
  v->str = vec_dup (tok);
  return 0;
}

CLIB_CLI_TYPE (cli_type_string) = {
  .name = "string",
  .help = "text",
  .owns_str = 1,
  .parse = parse_string,
};

/* Enumeration. The value is the 'value' of the matching choice. */
static u8 *
parse_enum (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  const cli_choice_t *c, *match = 0;
  u32 n_match = 0;
  u8 *err;

  for (c = a->choices; c->name; c++)
    {
      if (vec_len (tok) == strlen (c->name) && memcmp (tok, c->name, vec_len (tok)) == 0)
	{
	  v->index = c->value;
	  return 0;
	}
      if (cli_prefix_match (c->name, tok))
	{
	  match = c;
	  n_match++;
	}
    }

  if (n_match == 1 && vec_len (tok))
    {
      v->index = match->value;
      return 0;
    }

  err = format (0, "'%v' is not valid for <%s>, expected ", tok, a->name);
  for (c = a->choices; c->name; c++)
    err = format (err, "%s%s", c == a->choices ? "" : "|", c->name);
  return err;
}

static void
complete_enum (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  for (const cli_choice_t *c = a->choices; c->name; c++)
    if (cli_prefix_match (c->name, prefix))
      cli_candidate_add (out, c->name, c->help);
}

CLIB_CLI_TYPE (cli_type_enum) = {
  .name = "choice",
  .help = "one of the listed values",
  .parse = parse_enum,
  .complete = complete_enum,
};

/* "<start>-<stop>" */
static u8 *
parse_range (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  cli_value_t lo = {}, hi = {};
  u8 *err, *first = 0, *second = 0;
  u32 i;

  for (i = 0; i < vec_len (tok); i++)
    if (tok[i] == '-')
      break;
  if (i == 0 || i >= vec_len (tok) - 1)
    return format (0, "'%v' is not a range, expected <first>-<last>", tok);

  vec_add (first, tok, i);
  vec_add (second, tok + i + 1, vec_len (tok) - i - 1);
  err = parse_uint (0xffffffffULL, a, first, &lo);
  if (!err)
    err = parse_uint (0xffffffffULL, a, second, &hi);
  if (!err && lo.u64 > hi.u64)
    err = format (0, "range start %u is larger than its end %u", (u32) lo.u64, (u32) hi.u64);
  if (!err)
    {
      v->range.start = lo.u64;
      v->range.stop = hi.u64;
    }
  vec_free (first);
  vec_free (second);
  return err;
}

CLIB_CLI_TYPE (cli_type_range) = {
  .name = "range",
  .help = "<first>-<last>",
  .parse = parse_range,
};

/* handled by the parser, see cli_type_t.greedy */
CLIB_CLI_TYPE (cli_type_rest) = {
  .name = "text",
  .help = "rest of the line",
  .owns_str = 1,
  .greedy = 1,
};

static u8 *
parse_f64 (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u8 *z = format (0, "%v%c", tok, 0), *err = 0;
  char *end;

  v->f64 = strtod ((char *) z, &end);
  if (vec_len (tok) == 0 || *end)
    err = format (0, "'%v' is not a number", tok);
  vec_free (z);
  return err;
}

CLIB_CLI_TYPE (cli_type_f64) = {
  .name = "float",
  .help = "number",
  .parse = parse_f64,
};

/* list of numbers and ranges, e.g. 0-3,5, the value is a bitmap in v->str */
static u8 *
parse_bitmap (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  unformat_input_t in;
  uword *bm = 0;
  int ok;

  unformat_init_vector (&in, vec_dup (tok));
  ok = unformat (&in, "%U", unformat_bitmap_list, &bm) &&
       unformat_check_input (&in) == UNFORMAT_END_OF_INPUT;
  unformat_free (&in);

  if (!ok)
    {
      clib_bitmap_free (bm);
      return format (0, "'%v' is not a list like 0-3,5", tok);
    }

  v->str = (u8 *) bm;
  return 0;
}

CLIB_CLI_TYPE (cli_type_bitmap) = {
  .name = "list",
  .help = "list of numbers and ranges, e.g. 0-3,5",
  .owns_str = 1,
  .parse = parse_bitmap,
};
