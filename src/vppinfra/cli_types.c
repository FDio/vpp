/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* cli_types.c: built-in argument types for VLIB_CLI_COMMAND */

#include <vppinfra/cli.h>
#include <vppinfra/bitmap.h>
#include <errno.h>
#include <dirent.h>

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

/* names, the types with next_name use these as parse and complete */
u8 *
cli_names_parse (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  const cli_type_t *t = a->type;
  const char *name;
  u32 iter = 0, value;

  while ((name = t->next_name (a, &iter, &value, 0)))
    if (strlen (name) == vec_len (tok) && memcmp (name, tok, vec_len (tok)) == 0)
      {
	v->index = value;
	return 0;
      }

  return format (0, "unknown %s '%v'", t->name, tok);
}

void
cli_names_complete (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  const char *name, *help = 0;
  u32 iter = 0, value;

  while ((name = a->type->next_name (a, &iter, &value, &help)))
    {
      if (cli_prefix_match (name, prefix))
	cli_candidate_add (out, name, help);
      help = 0;
    }
}

/* number followed by a suffix, returns the suffix or 0 if there is no number */
static char *
number_and_suffix (u8 *z, double *d)
{
  char *end;

  if (!cli_is_digit (z[0]) && z[0] != '.')
    return 0;
  *d = strtod ((char *) z, &end);
  return end == (char *) z ? 0 : end;
}

static u8 *
parse_duration (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  /* a negative scale divides, so that 250ms is exactly 0.25 */
  static const struct
  {
    const char *suffix;
    f64 scale;
  } units[] = { { "", 1 },   { "s", 1 },    { "ms", -1000 }, { "us", -1e6 },
		{ "m", 60 }, { "h", 3600 }, { "d", 86400 },  {} };
  u8 *z = format (0, "%v%c", tok, 0);
  u8 *err = format (0, "'%v' is not a duration like 10, 250ms, 10s, 5m, 2h or 1d", tok);
  double d;
  char *suffix = number_and_suffix (z, &d);

  if (suffix)
    for (int i = 0; units[i].suffix; i++)
      if (strcmp (suffix, units[i].suffix) == 0)
	{
	  v->f64 = units[i].scale < 0 ? d / -units[i].scale : d * units[i].scale;
	  vec_free (err);
	  err = 0;
	  break;
	}

  vec_free (z);
  return err;
}

CLIB_CLI_TYPE (cli_type_duration) = {
  .name = "duration",
  .help = "time, in seconds unless it has a unit: ms, s, m, h, d",
  .parse = parse_duration,
};

static u8 *
parse_size (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u8 *z = format (0, "%v%c", tok, 0);
  u8 *err = 0;
  char *end;
  u64 val, mul = 1;

  errno = 0;
  val = strtoull ((char *) z, &end, 0);
  if (vec_len (tok) == 0 || !cli_is_digit (tok[0]) || errno)
    err = format (0, "'%v' is not a size like 4096, 4K, 64M, 2G or 1T", tok);
  else
    {
      switch (end[0] ? cli_to_lower (end[0]) : 0)
	{
	case 0:
	  break;
	case 'k':
	  mul = 1ULL << 10;
	  end++;
	  break;
	case 'm':
	  mul = 1ULL << 20;
	  end++;
	  break;
	case 'g':
	  mul = 1ULL << 30;
	  end++;
	  break;
	case 't':
	  mul = 1ULL << 40;
	  end++;
	  break;
	}
      if (end[0] && cli_to_lower (end[0]) == 'b')
	end++;

      if (*end || val > (u64) ~0 / mul)
	err = format (0, "'%v' is not a size like 4096, 4K, 64M, 2G or 1T", tok);
      else if (val * mul < a->min || (a->max && val * mul > a->max))
	err = format (0, "'%v' is out of range (%llu - %llu bytes)", tok, a->min,
		      a->max ? a->max : (u64) ~0);
      else
	v->u64 = val * mul;
    }
  vec_free (z);
  return err;
}

CLIB_CLI_TYPE (cli_type_size) = {
  .name = "size",
  .help = "bytes, with an optional unit: K, M, G, T",
  .parse = parse_size,
};

static u8 *
parse_bool (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  static const struct
  {
    const char *name;
    u32 value;
  } names[] = {
    { "on", 1 },      { "enable", 1 }, { "yes", 1 },   { "true", 1 }, { "1", 1 }, { "off", 0 },
    { "disable", 0 }, { "no", 0 },     { "false", 0 }, { "0", 0 },    {}
  };

  for (int i = 0; names[i].name; i++)
    {
      u32 n = strlen (names[i].name), j = 0;

      if (n != vec_len (tok))
	continue;
      while (j < n && cli_to_lower (tok[j]) == names[i].name[j])
	j++;
      if (j == n)
	{
	  v->index = names[i].value;
	  return 0;
	}
    }
  return format (0, "'%v' is not on or off", tok);
}

static void
complete_bool (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  if (cli_prefix_match ("on", prefix))
    cli_candidate_add (out, "on", 0);
  if (cli_prefix_match ("off", prefix))
    cli_candidate_add (out, "off", 0);
}

CLIB_CLI_TYPE (cli_type_bool) = {
  .name = "on|off",
  .usage = "{on|off}",
  .help = "on or off, also enable, disable, yes, no, true, false",
  .parse = parse_bool,
  .complete = complete_bool,
};

static int
hex_digit (u8 c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  c = cli_to_lower (c);
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

static u8 *
parse_hex (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u32 start = vec_len (tok) > 2 && tok[0] == '0' && cli_to_lower (tok[1]) == 'x' ? 2 : 0;
  u32 n = vec_len (tok) - start;
  u8 *bytes = 0;

  if (n == 0 || (n & 1))
    return format (0, "'%v' is not a hex string with an even number of digits", tok);
  if (a->max && n / 2 > a->max)
    return format (0, "'%v' is longer than %llu bytes", tok, a->max);

  for (u32 i = 0; i < n; i += 2)
    {
      int hi = hex_digit (tok[start + i]), lo = hex_digit (tok[start + i + 1]);

      if (hi < 0 || lo < 0)
	{
	  vec_free (bytes);
	  return format (0, "'%v' is not a hex string", tok);
	}
      vec_add1 (bytes, hi << 4 | lo);
    }

  v->str = bytes;
  return 0;
}

CLIB_CLI_TYPE (cli_type_hex) = {
  .name = "hex",
  .help = "hex string, e.g. 0xdeadbeef",
  .owns_str = 1,
  .parse = parse_hex,
};

static u8 *
parse_file (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  if (vec_len (tok) == 0)
    return format (0, "missing file name");
  v->str = vec_dup (tok);
  return 0;
}

static void
complete_file (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  u32 base = 0;
  u8 *dir = 0, *name_prefix = 0;
  struct dirent *e;
  DIR *d;

  for (u32 i = 0; i < vec_len (prefix); i++)
    if (prefix[i] == '/')
      base = i + 1;

  if (base == 0)
    dir = format (0, ".%c", 0);
  else
    {
      vec_add (dir, prefix, base);
      vec_add1 (dir, 0);
    }
  vec_add (name_prefix, prefix + base, vec_len (prefix) - base);

  d = opendir ((char *) dir);
  while (d && (e = readdir (d)))
    {
      u8 *text = 0;

      if (e->d_name[0] == '.' && vec_len (name_prefix) == 0)
	continue;
      if (strncmp (e->d_name, (char *) name_prefix, vec_len (name_prefix)) != 0)
	continue;

      vec_add (text, prefix, base);
      text = format (text, "%s%s%c", e->d_name, e->d_type == DT_DIR ? "/" : "", 0);
      cli_candidate_add (out, (char *) text, 0);
      vec_free (text);
    }
  if (d)
    closedir (d);
  vec_free (dir);
  vec_free (name_prefix);
}

CLIB_CLI_TYPE (cli_type_file) = {
  .name = "file",
  .help = "path of a file",
  .owns_str = 1,
  .parse = parse_file,
  .complete = complete_file,
};

static u8 *
parse_percent (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u8 *z = format (0, "%v%c", tok, 0);
  u8 *err = format (0, "'%v' is not a percentage between 0 and 100", tok);
  double d;
  char *suffix = number_and_suffix (z, &d);

  if (suffix && (suffix[0] == 0 || (suffix[0] == '%' && suffix[1] == 0)) && d >= 0 && d <= 100)
    {
      v->f64 = d;
      vec_free (err);
      err = 0;
    }
  vec_free (z);
  return err;
}

CLIB_CLI_TYPE (cli_type_percent) = {
  .name = "percent",
  .help = "0 to 100, with an optional %",
  .parse = parse_percent,
};

/* the names of flags and the words typed are compared in upper case, with
 * '-' and '_' the same */
static u8
flag_char (u8 c)
{
  if (c == '-')
    return '_';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 'A';
  return c;
}

static int
flag_name_matches (const char *name, u8 *word, u32 len, int prefix)
{
  u32 n = strlen (name);

  if (prefix ? len > n : len != n)
    return 0;
  for (u32 i = 0; i < len; i++)
    if (flag_char (name[i]) != flag_char (word[i]))
      return 0;
  return 1;
}

static u8 *
parse_flags (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u32 start = 0;

  v->u64 = 0;
  for (u32 i = 0; i <= vec_len (tok); i++)
    {
      const cli_choice_t *c;

      if (i < vec_len (tok) && tok[i] != ',')
	continue;

      for (c = a->choices; c->name; c++)
	if (flag_name_matches (c->name, tok + start, i - start, 0))
	  break;

      if (!c->name)
	{
	  u8 *word = 0, *err;

	  vec_add (word, tok + start, i - start);
	  err = format (0, "unknown flag '%v'", word);
	  vec_free (word);
	  return err;
	}

      v->u64 |= c->value;
      start = i + 1;
    }
  return 0;
}

static void
complete_flags (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  u32 base = 0;

  for (u32 i = 0; i < vec_len (prefix); i++)
    if (prefix[i] == ',')
      base = i + 1;

  for (const cli_choice_t *c = a->choices; c->name; c++)
    if (flag_name_matches (c->name, prefix + base, vec_len (prefix) - base, 1))
      {
	u8 *text = 0;

	vec_add (text, prefix, base);
	text = format (text, "%s%c", c->name, 0);
	cli_candidate_add (out, (char *) text, c->help);
	vec_free (text);
      }
}

CLIB_CLI_TYPE (cli_type_flags) = {
  .name = "flags",
  .help = "comma separated list of flags",
  .parse = parse_flags,
  .complete = complete_flags,
};

static u8 *
parse_u32_list (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u32 *list = 0;
  u64 max_entries = a->max ? a->max : 1 << 20;
  u32 start = 0;

  for (u32 i = 0; i <= vec_len (tok); i++)
    {
      u64 first = 0, last = 0, n = 0;
      int have_last = 0;

      if (i < vec_len (tok) && tok[i] != ',')
	continue;

      if (i == start)
	goto bad;
      for (u32 j = start; j < i; j++)
	{
	  if (tok[j] == '-' && !have_last && n)
	    {
	      first = n;
	      n = 0;
	      have_last = 1;
	    }
	  else if (cli_is_digit (tok[j]) && n < 0xffffffffULL)
	    n = n * 10 + tok[j] - '0';
	  else
	    goto bad;
	}
      if (n > 0xffffffffULL || (have_last && (!i || tok[i - 1] == '-')))
	goto bad;
      last = n;
      if (!have_last)
	first = last;
      if (first > last || vec_len (list) + (last - first + 1) > max_entries)
	goto bad;
      for (u64 x = first; x <= last; x++)
	vec_add1 (list, x);
      start = i + 1;
    }

  v->str = (u8 *) list;
  return 0;

bad:
  vec_free (list);
  return format (0, "'%v' is not a list of up to %llu numbers like 1,2,5-7", tok, max_entries);
}

CLIB_CLI_TYPE (cli_type_u32_list) = {
  .name = "numbers",
  .help = "list of numbers and ranges, e.g. 1,2,5-7",
  .owns_str = 1,
  .parse = parse_u32_list,
};
