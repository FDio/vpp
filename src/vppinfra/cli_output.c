/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* cli_output.c: output pipeline and structured output for the CLI.
 *
 * Output is plain ASCII, it never depends on terminal capabilities so it
 * works unchanged with ANSI disabled and on non-interactive sessions.
 *
 *   <command> | json              structured output as JSON
 *   <command> | where <f> <op> <v> keep rows of structured output
 *   <command> | grep [-v] [-i] <text>
 *   <command> | head [n] | tail [n] | count
 */

#include <vppinfra/cli.h>
#include <vppinfra/pool.h>

const char *cli_filter_names[] = { "json", "where", "grep", "head", "tail", "count", 0 };

static int
tok_is (cli_tok_t *t, const char *s)
{
  return vec_len (t->s) == strlen (s) && memcmp (t->s, s, vec_len (t->s)) == 0;
}

u8 *
cli_parse_filters (cli_ctx_t *ctx, cli_tok_t *toks, u32 n_tok, u32 *err_tok)
{
  u32 i = 0;

  while (i < n_tok)
    {
      cli_filter_t f = {};
      cli_tok_t *t = &toks[i];

      *err_tok = i;
      if (tok_is (t, "json"))
	{
	  f.kind = CLI_FILTER_JSON;
	  ctx->json = 1;
	  i++;
	}
      else if (tok_is (t, "count"))
	{
	  f.kind = CLI_FILTER_COUNT;
	  i++;
	}
      else if (tok_is (t, "head") || tok_is (t, "tail"))
	{
	  f.kind = tok_is (t, "head") ? CLI_FILTER_HEAD : CLI_FILTER_TAIL;
	  f.n = 10;
	  i++;
	  if (i < n_tok && vec_len (toks[i].s) && cli_is_digit (toks[i].s[0]))
	    {
	      u8 *z = format (0, "%v%c", toks[i].s, 0);

	      f.n = atoi ((char *) z);
	      vec_free (z);
	      i++;
	    }
	}
      else if (tok_is (t, "grep"))
	{
	  f.kind = CLI_FILTER_GREP;
	  i++;
	  for (; i < n_tok; i++)
	    {
	      if (tok_is (&toks[i], "-v"))
		f.invert = 1;
	      else if (tok_is (&toks[i], "-i"))
		f.icase = 1;
	      else
		break;
	    }
	  if (i >= n_tok)
	    {
	      *err_tok = n_tok;
	      return format (0, "grep needs a pattern");
	    }
	  f.pat = vec_dup (toks[i++].s);
	}
      else if (tok_is (t, "where"))
	{
	  f.kind = CLI_FILTER_WHERE;
	  if (i + 3 >= n_tok)
	    {
	      *err_tok = n_tok;
	      return format (0, "usage: where <field> <==|!=|~|<|<=|>|>=> <value>");
	    }
	  f.field = vec_dup (toks[i + 1].s);
	  f.op = vec_dup (toks[i + 2].s);
	  f.pat = vec_dup (toks[i + 3].s);
	  if (!(tok_is (&toks[i + 2], "==") || tok_is (&toks[i + 2], "!=") ||
		tok_is (&toks[i + 2], "~") || tok_is (&toks[i + 2], "<") ||
		tok_is (&toks[i + 2], "<=") || tok_is (&toks[i + 2], ">") ||
		tok_is (&toks[i + 2], ">=")))
	    {
	      *err_tok = i + 2;
	      return format (0, "unknown operator '%v'", toks[i + 2].s);
	    }
	  ctx->has_where = 1;
	  i += 4;
	}
      else
	{
	  cli_candidate_t *all = 0;
	  u8 *best, *err;

	  for (const char **n = cli_filter_names; *n; n++)
	    cli_candidate_add (&all, *n, 0);
	  best = cli_suggest (t->s, all);
	  err = format (0, "unknown filter '%v'", t->s);
	  if (best)
	    err = format (err, ", did you mean '%v'?", best);
	  cli_candidates_free (all);
	  return err;
	}
      vec_add1 (ctx->filters, f);

      if (i < n_tok)
	{
	  if (!tok_is (&toks[i], "|"))
	    {
	      *err_tok = i;
	      return format (0, "expected '|' before '%v'", toks[i].s);
	    }
	  i++;
	}
    }
  return 0;
}

int
cli_has_text_filters (cli_ctx_t *ctx)
{
  cli_filter_t *f;

  vec_foreach (f, ctx->filters)
    if (f->kind != CLI_FILTER_JSON && f->kind != CLI_FILTER_WHERE)
      return 1;
  return 0;
}

static int
line_contains (u8 *line, u32 len, u8 *pat, int icase)
{
  u32 n = vec_len (pat);

  if (n == 0)
    return 1;
  for (u32 i = 0; i + n <= len; i++)
    {
      u32 j;

      for (j = 0; j < n; j++)
	{
	  u8 a = line[i + j], b = pat[j];

	  if (icase ? cli_to_lower (a) != cli_to_lower (b) : a != b)
	    break;
	}
      if (j == n)
	return 1;
    }
  return 0;
}

typedef struct
{
  u8 *start;
  u32 len;
} cli_line_t;

/* Applies grep/head/tail/count in order, input and result are text. */
u8 *
cli_apply_text_filters (cli_ctx_t *ctx, u8 *text)
{
  cli_line_t *lines = 0, *l;
  cli_filter_t *f;
  u8 *out = 0;
  u32 s = 0;

  for (u32 i = 0; i < vec_len (text); i++)
    if (text[i] == '\n')
      {
	vec_add2 (lines, l, 1);
	l->start = text + s;
	l->len = i - s;
	s = i + 1;
      }
  if (s < vec_len (text))
    {
      vec_add2 (lines, l, 1);
      l->start = text + s;
      l->len = vec_len (text) - s;
    }

  vec_foreach (f, ctx->filters)
    {
      switch (f->kind)
	{
	case CLI_FILTER_GREP:
	  {
	    cli_line_t *keep = 0;

	    vec_foreach (l, lines)
	      if (line_contains (l->start, l->len, f->pat, f->icase) != f->invert)
		vec_add1 (keep, *l);
	    vec_free (lines);
	    lines = keep;
	  }
	  break;
	case CLI_FILTER_HEAD:
	  if (vec_len (lines) > f->n)
	    vec_set_len (lines, f->n);
	  break;
	case CLI_FILTER_TAIL:
	  if (vec_len (lines) > f->n)
	    vec_delete (lines, vec_len (lines) - f->n, 0);
	  break;
	case CLI_FILTER_COUNT:
	  {
	    u32 n = vec_len (lines);

	    vec_free (lines);
	    return format (0, "%u\n", n);
	  }
	default:
	  break;
	}
    }

  vec_foreach (l, lines)
    {
      vec_add (out, l->start, l->len);
      vec_add1 (out, '\n');
    }
  vec_free (lines);
  return out;
}

/* Structured output */

int
cli_is_json (cli_ctx_t *ctx)
{
  return ctx->json;
}

int
cli_is_structured (cli_ctx_t *ctx)
{
  return ctx->json || ctx->has_where;
}

static u8 *
format_cell (u8 *s, clib_json_text_t *j, int index)
{
  clib_json_value_t *v;

  if (index < 0)
    return format (s, "-");

  v = pool_elt_at_index (j->values, index);
  switch (v->type)
    {
    case CLIB_JSON_VALUE_TRUE:
      return format (s, "true");
    case CLIB_JSON_VALUE_FALSE:
      return format (s, "false");
    case CLIB_JSON_VALUE_STRING:
      return format (s, "%v", v->string);
    case CLIB_JSON_VALUE_NUMBER:
      if (v->number == (f64) (i64) v->number)
	return format (s, "%lld", (i64) v->number);
      return format (s, "%g", v->number);
    case CLIB_JSON_VALUE_ARRAY:
      for (u32 i = 0; i < vec_len (v->array_val_indices); i++)
	{
	  if (i)
	    s = format (s, ", ");
	  s = format_cell (s, j, v->array_val_indices[i]);
	}
      return s;
    case CLIB_JSON_VALUE_OBJECT:
      return format (s, "{...}");
    default:
      return format (s, "-");
    }
}

static int
field_index (clib_json_text_t *j, int obj, u8 *field)
{
  u8 *name = format (0, "%v%c", field, 0);
  int rv = clib_json_find_object_value_by_name (j, obj, "%s", name);

  vec_free (name);
  return rv;
}

static int
field_index_c (clib_json_text_t *j, int obj, const char *key)
{
  return clib_json_find_object_value_by_name (j, obj, "%s", key);
}

static int
row_matches (clib_json_text_t *j, int row, cli_filter_t *f)
{
  int idx = field_index (j, row, f->field);
  u8 *cell = 0, *pat = format (0, "%v%c", f->pat, 0);
  int r = 0, cmp;
  double a, b;
  char *e1, *e2;

  if (idx < 0)
    goto done;

  cell = format_cell (0, j, idx);
  vec_add1 (cell, 0);
  a = strtod ((char *) cell, &e1);
  b = strtod ((char *) pat, &e2);
  cmp = (*e1 == 0 && *e2 == 0 && e1 != (char *) cell) ? (a < b ? -1 :
							 a > b ? 1 :
								 0) :
							strcmp ((char *) cell, (char *) pat);

  if (vec_len (f->op) == 1 && f->op[0] == '~')
    r = strstr ((char *) cell, (char *) pat) != 0;
  else if (vec_len (f->op) == 2 && f->op[0] == '=')
    r = cmp == 0;
  else if (vec_len (f->op) == 2 && f->op[0] == '!')
    r = cmp != 0;
  else if (f->op[0] == '<')
    r = vec_len (f->op) == 1 ? cmp < 0 : cmp <= 0;
  else
    r = vec_len (f->op) == 1 ? cmp > 0 : cmp >= 0;

done:
  vec_free (cell);
  vec_free (pat);
  return r;
}

static void
apply_where (cli_ctx_t *ctx, clib_json_text_t *j)
{
  clib_json_value_t *arr = pool_elt_at_index (j->values, j->root_value);
  cli_filter_t *f;

  vec_foreach (f, ctx->filters)
    {
      if (f->kind != CLI_FILTER_WHERE)
	continue;
      for (u32 i = vec_len (arr->array_val_indices); i-- > 0;)
	if (!row_matches (j, arr->array_val_indices[i], f))
	  vec_del1 (arr->array_val_indices, i);
    }
}

static clib_error_t *
check_where_fields (cli_ctx_t *ctx, const cli_column_t *cols)
{
  cli_filter_t *f;

  vec_foreach (f, ctx->filters)
    {
      const cli_column_t *c;
      u8 *keys = 0;

      if (f->kind != CLI_FILTER_WHERE)
	continue;
      for (c = cols; c->key; c++)
	{
	  if (strlen (c->key) == vec_len (f->field) &&
	      memcmp (c->key, f->field, vec_len (f->field)) == 0)
	    break;
	  keys = format (keys, "%s%s", vec_len (keys) ? ", " : "", c->key);
	}
      if (!c->key)
	{
	  clib_error_t *e =
	    clib_error_return (0, "unknown field '%v', available fields: %v", f->field, keys);

	  vec_free (keys);
	  return e;
	}
      vec_free (keys);
    }
  return 0;
}

/* Keys of the structured output are lower case with underscores, see the
 * conventions in the developer documentation. */
static void
check_column_keys (const cli_column_t *cols)
{
  for (; cols->key; cols++)
    for (const char *c = cols->key; *c; c++)
      if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '_'))
	{
	  clib_warning ("structured output key '%s' is not snake_case", cols->key);
	  break;
	}
}

clib_error_t *
cli_emit_table (cli_ctx_t *ctx, clib_json_text_t *j, const cli_column_t *cols)
{
  clib_json_value_t *arr;
  u32 n_cols = 0, *width = 0, n_rows;
  u8 ***cells = 0, **row_cells, *line;
  clib_error_t *error;

  if (CLIB_DEBUG > 0)
    check_column_keys (cols);

  ctx->emitted = 1;
  error = check_where_fields (ctx, cols);
  if (error)
    {
      clib_json_free (j);
      return error;
    }
  apply_where (ctx, j);

  if (ctx->json)
    {
      ctx->out = format (ctx->out, "%U\n", format_clib_json_text, j);
      clib_json_free (j);
      return 0;
    }

  arr = pool_elt_at_index (j->values, j->root_value);
  while (cols[n_cols].key)
    n_cols++;
  vec_validate (width, n_cols - 1);
  for (u32 c = 0; c < n_cols; c++)
    width[c] = strlen (cols[c].header);

  n_rows = vec_len (arr->array_val_indices);
  for (u32 r = 0; r < n_rows; r++)
    {
      int row = arr->array_val_indices[r];

      row_cells = 0;
      for (u32 c = 0; c < n_cols; c++)
	{
	  u8 *cell = format_cell (0, j, field_index_c (j, row, cols[c].key));

	  width[c] = clib_max (width[c], vec_len (cell));
	  vec_add1 (row_cells, cell);
	}
      vec_add1 (cells, row_cells);
    }

  line = 0;
  for (u32 c = 0; c < n_cols; c++)
    {
      line = format (line, "%-*s", c + 1 < n_cols ? width[c] : 0, cols[c].header);
      if (c + 1 < n_cols)
	line = format (line, "  ");
    }
  ctx->out = format (ctx->out, "%v\n", line);
  vec_free (line);

  for (u32 r = 0; r < n_rows; r++)
    {
      line = 0;
      for (u32 c = 0; c < n_cols; c++)
	{
	  line = format (line, "%-*v", c + 1 < n_cols ? width[c] : 0, cells[r][c]);
	  if (c + 1 < n_cols)
	    line = format (line, "  ");
	  vec_free (cells[r][c]);
	}
      vec_free (cells[r]);
      ctx->out = format (ctx->out, "%v\n", line);
      vec_free (line);
    }
  vec_free (cells);
  vec_free (width);
  clib_json_free (j);
  return 0;
}

clib_error_t *
cli_emit_object (cli_ctx_t *ctx, clib_json_text_t *j, const cli_column_t *cols)
{
  u32 w = 0;

  if (CLIB_DEBUG > 0)
    check_column_keys (cols);

  ctx->emitted = 1;
  if (ctx->json)
    {
      ctx->out = format (ctx->out, "%U\n", format_clib_json_text, j);
      clib_json_free (j);
      return 0;
    }

  for (const cli_column_t *c = cols; c->key; c++)
    w = clib_max (w, strlen (c->header));
  for (const cli_column_t *c = cols; c->key; c++)
    {
      u8 *v = format_cell (0, j, field_index_c (j, j->root_value, c->key));

      ctx->out = format (ctx->out, "%-*s : %v\n", w, c->header, v);
      vec_free (v);
    }
  clib_json_free (j);
  return 0;
}
