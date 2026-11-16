/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* cli.c: declarative CLI infrastructure.
 *
 * Tokenizer, parser, completion, usage and help, error reporting and schema
 * of the commands declared with an array of cli_arg_t. It depends on vppinfra
 * only, see vlib/cli_decl.c for the part which connects it to the CLI.
 */

#include <vppinfra/cli.h>

enum
{
  P_OK,
  P_NOMATCH, /* nothing consumed, p->err describes why */
  P_ERR,     /* hard error, p->err and p->err_tok set */
  P_STOP,    /* completion candidates collected */
};

typedef struct
{
  u8 *line;
  cli_tok_t *tok;
  u32 n_tok;
  u32 i;
  cli_value_t *values;
  int complete;
  cli_candidate_t *cands;
  u8 *err;
  u32 err_tok;
} cli_parse_t;

static const cli_arg_t cli_no_args[1];
static cli_type_t *cli_types;

void
cli_type_registration_helper (cli_type_t *x)
{
  x->next = cli_types;
  cli_types = x;
}

void
cli_type_unregistration_helper (cli_type_t *x)
{
  cli_type_t **p = &cli_types;

  while (*p && *p != x)
    p = &(*p)->next;
  if (*p)
    *p = x->next;
}

/* Candidates */

void
cli_candidate_add (cli_candidate_t **out, const char *text, const char *help)
{
  cli_candidate_t *c;

  vec_add2 (*out, c, 1);
  c->text = format (0, "%s", text);
  if (help)
    c->help = format (0, "%s", help);
}

void
cli_candidates_free (cli_candidate_t *c)
{
  cli_candidate_t *i;

  vec_foreach (i, c)
    {
      vec_free (i->text);
      vec_free (i->help);
    }
  vec_free (c);
}

int
cli_prefix_match (const char *s, const u8 *prefix)
{
  return vec_len (prefix) <= strlen (s) &&
	 (vec_len (prefix) == 0 || memcmp (s, prefix, vec_len (prefix)) == 0);
}

static int
cli_cmp_candidate (void *a1, void *a2)
{
  cli_candidate_t *c1 = a1, *c2 = a2;

  return vec_cmp (c1->text, c2->text);
}

static void
cli_sort_unique (cli_candidate_t **cands)
{
  cli_candidate_t *c = *cands, *out = 0, *i;

  vec_sort_with_function (c, cli_cmp_candidate);
  vec_foreach (i, c)
    {
      if (vec_len (out) && vec_cmp (vec_end (out)[-1].text, i->text) == 0)
	{
	  vec_free (i->text);
	  vec_free (i->help);
	}
      else
	vec_add1 (out, *i);
    }
  vec_free (c);
  *cands = out;
}

/* Closest candidate to word, 0 if nothing is close enough. */
u8 *
cli_suggest (u8 *word, cli_candidate_t *cands)
{
  cli_candidate_t *c;
  u32 best = ~0, best_d = ~0, n = vec_len (word), thr = clib_max (2, n / 3);
  u32 row[2][65];

  if (n == 0 || n > 64)
    return 0;

  /* a word which starts exactly one candidate is most likely that candidate */
  if (n >= 2)
    {
      u32 n_prefix = 0, prefix_best = 0;

      vec_foreach (c, cands)
	{
	  u32 j = 0;

	  if (vec_len (c->text) <= n)
	    continue;
	  while (j < n && cli_to_lower (word[j]) == cli_to_lower (c->text[j]))
	    j++;
	  if (j == n)
	    {
	      n_prefix++;
	      prefix_best = c - cands;
	    }
	}
      if (n_prefix == 1)
	return cands[prefix_best].text;
    }

  vec_foreach (c, cands)
    {
      u32 m = vec_len (c->text), cur = 0;

      if (m > 64 || m == 0 || (m > n ? m - n : n - m) > thr)
	continue;

      for (u32 j = 0; j <= m; j++)
	row[0][j] = j;
      for (u32 i = 1; i <= n; i++)
	{
	  u32 *prev = row[cur], *next = row[cur ^ 1];

	  next[0] = i;
	  for (u32 j = 1; j <= m; j++)
	    {
	      u32 cost = cli_to_lower (word[i - 1]) != cli_to_lower (c->text[j - 1]);

	      next[j] = clib_min (clib_min (prev[j] + 1, next[j - 1] + 1), prev[j - 1] + cost);
	    }
	  cur ^= 1;
	}
      if (row[cur][m] < best_d)
	{
	  best_d = row[cur][m];
	  best = c - cands;
	}
    }

  if (best_d > thr)
    return 0;
  return cands[best].text;
}

/* Tokenizer */

static int
tok_eq (cli_tok_t *t, const char *s)
{
  u32 n = strlen (s);

  return vec_len (t->s) == n && (n == 0 || memcmp (t->s, s, n) == 0);
}

static void
tokens_free (cli_tok_t *toks)
{
  cli_tok_t *t;

  vec_foreach (t, toks)
    vec_free (t->s);
  vec_free (toks);
}

/* Splits on white space, supports "quoted tokens". For completion an empty
 * token is added when the line ends with white space, it is the token under
 * the cursor. */
static cli_tok_t *
tokenize (u8 *line, int for_complete)
{
  cli_tok_t *toks = 0, *t;
  u32 i = 0, n = vec_len (line);

  while (1)
    {
      while (i < n && is_white_space (line[i]))
	i++;
      if (i >= n)
	break;

      vec_add2 (toks, t, 1);
      t->pos = i;
      while (i < n && !is_white_space (line[i]))
	{
	  if (line[i] == '"')
	    {
	      t->quoted = 1;
	      for (i++; i < n && line[i] != '"'; i++)
		vec_add1 (t->s, line[i]);
	      if (i < n)
		i++;
	    }
	  else
	    vec_add1 (t->s, line[i++]);
	}
      t->end = i;
    }

  if (for_complete && (n == 0 || is_white_space (line[n - 1])))
    {
      vec_add2 (toks, t, 1);
      t->pos = t->end = n;
    }
  return toks;
}

/* Usage / help formatting */

static u8 *format_arg_usage (u8 *s, va_list *va);

/* not advertised in the usage, the help and the completion */
static int
is_hidden (const cli_arg_t *a)
{
  return (a->flags & CLI_F_HIDDEN) || a->deprecated;
}

static u8 *
format_arg_list (u8 *s, const cli_arg_t *a, const char *sep)
{
  int first = 1;

  for (; a->kind; a++)
    {
      if (is_hidden (a))
	continue;
      if (!first)
	s = format (s, "%s", sep);
      s = format (s, "%U", format_arg_usage, a);
      first = 0;
    }
  return s;
}

static u8 *
format_arg_usage (u8 *s, va_list *va)
{
  const cli_arg_t *a = va_arg (*va, const cli_arg_t *);
  int opt = !!(a->flags & CLI_F_OPTIONAL) || a->kind == CLI_K_FLAG;

  if (opt)
    s = format (s, "[");

  switch (a->kind)
    {
    case CLI_K_VALUE:
      if (a->choices)
	{
	  const cli_choice_t *c;

	  s = format (s, "{");
	  for (c = a->choices; c->name; c++)
	    s = format (s, "%s%s", c == a->choices ? "" : "|", c->name);
	  s = format (s, "}");
	}
      else if (a->type && a->type->usage)
	s = format (s, "%s", a->type->usage);
      else
	s = format (s, "<%s>", a->name);
      break;
    case CLI_K_KEYWORD:
      s = format (s, "%s <%s>", a->name, a->name);
      break;
    case CLI_K_FLAG:
      s = format (s, "%s", a->name);
      break;
    case CLI_K_ONEOF:
      s = format (s, "%s", opt ? "" : "(");
      s = format_arg_list (s, a->children, " | ");
      s = format (s, "%s", opt ? "" : ")");
      break;
    case CLI_K_SEQ:
      s = format_arg_list (s, a->children, " ");
      break;
    case CLI_K_GROUP:
      s = format (s, "%s ", a->name);
      s = format_arg_list (s, a->children, " ");
      break;
    default:
      break;
    }

  if (a->flags & CLI_F_REPEAT)
    s = format (s, " ...");
  if (opt)
    s = format (s, "]");
  return s;
}

static u8 *
format_cmd_usage (u8 *s, va_list *va)
{
  const char *path = va_arg (*va, const char *);
  const cli_arg_t *args = va_arg (*va, const cli_arg_t *);

  s = format (s, "%s", path);
  if (args && args->kind)
    {
      s = format (s, " ");
      s = format_arg_list (s, args, " ");
    }
  return s;
}

static u8 *
format_arg_label (u8 *s, va_list *va)
{
  const cli_arg_t *a = va_arg (*va, const cli_arg_t *);

  switch (a->kind)
    {
    case CLI_K_KEYWORD:
      s = format (s, "%s <%s>", a->name, a->type->name);
      break;
    case CLI_K_FLAG:
    case CLI_K_GROUP:
      s = format (s, "%s", a->name);
      if (a->alias)
	s = format (s, "|%s", a->alias);
      break;
    default:
      s = format (s, "<%s>", a->name);
      break;
    }
  return s;
}

static u8 *
format_arg_table (u8 *s, const cli_arg_t *a, u32 width)
{
  for (; a->kind; a++)
    {
      if (is_hidden (a))
	continue;

      if (a->kind == CLI_K_ONEOF || a->kind == CLI_K_SEQ)
	{
	  s = format_arg_table (s, a->children, width);
	  continue;
	}

      s = format (s, "  %-*U", width, format_arg_label, a);
      if (a->help)
	s = format (s, " %s", a->help);
      else if (a->type && a->type->help)
	s = format (s, " %s", a->type->help);
      if (a->def)
	s = format (s, " (default %s)", a->def);
      if (a->requires)
	s = format (s, " (needs %s)", a->requires);
      if (a->excludes)
	s = format (s, " (not with %s)", a->excludes);
      s = format (s, "\n");

      if (a->choices)
	for (const cli_choice_t *c = a->choices; c->name; c++)
	  s = format (s, "      %-*s %s\n", width - 4, c->name, c->help ? c->help : "");
      if (a->kind == CLI_K_GROUP)
	s = format_arg_table (s, a->children, width);
    }
  return s;
}

static u32
arg_label_width (const cli_arg_t *a)
{
  u32 w = 0;

  for (; a->kind; a++)
    {
      u8 *l;

      if (is_hidden (a))
	continue;

      if (a->kind == CLI_K_ONEOF || a->kind == CLI_K_SEQ)
	{
	  w = clib_max (w, arg_label_width (a->children));
	  continue;
	}
      l = format (0, "%U", format_arg_label, a);
      w = clib_max (w, vec_len (l));
      vec_free (l);
      if (a->kind == CLI_K_GROUP)
	w = clib_max (w, arg_label_width (a->children));
    }
  return w;
}

u8 *
format_cli_help (u8 *s, va_list *args)
{
  const char *path = va_arg (*args, const char *);
  const char *short_help = va_arg (*args, const char *);
  const char *long_help = va_arg (*args, const char *);
  const cli_arg_t *cmd_args = va_arg (*args, const cli_arg_t *);

  s = format (s, "usage: %U\n", format_cmd_usage, path, cmd_args);
  if (short_help)
    s = format (s, "  %s\n", short_help);
  if (long_help)
    s = format (s, "\n%s\n", long_help);
  if (cmd_args && cmd_args->kind)
    {
      u32 w = clib_max (arg_label_width (cmd_args), 8);

      s = format (s, "\narguments:\n");
      s = format_arg_table (s, cmd_args, w);
    }
  s = format (s, "\noutput can be filtered: <cmd> | json|where|grep|head|tail|"
		 "count\n");
  return s;
}

/* Parser */

static void
set_err (cli_parse_t *p, u32 tok, u8 *err)
{
  vec_free (p->err);
  p->err = err;
  p->err_tok = tok;
}

static int
is_positional (const cli_arg_t *a)
{
  return a->kind == CLI_K_VALUE || a->kind == CLI_K_ONEOF || a->kind == CLI_K_SEQ;
}

static void
add_first_candidates (cli_parse_t *p, const cli_arg_t *a, u8 *prefix)
{
  if (is_hidden (a))
    return;

  switch (a->kind)
    {
    case CLI_K_VALUE:
      if (a->type->complete)
	a->type->complete (a, prefix, &p->cands);
      break;
    case CLI_K_KEYWORD:
    case CLI_K_FLAG:
    case CLI_K_GROUP:
      if (cli_prefix_match (a->name, prefix))
	cli_candidate_add (&p->cands, a->name, a->help);
      break;
    case CLI_K_ONEOF:
      for (const cli_arg_t *c = a->children; c->kind; c++)
	add_first_candidates (p, c, prefix);
      break;
    case CLI_K_SEQ:
      for (const cli_arg_t *c = a->children; c->kind; c++)
	{
	  add_first_candidates (p, c, prefix);
	  if (!(c->flags & CLI_F_OPTIONAL) && c->kind != CLI_K_FLAG)
	    break;
	}
      break;
    default:
      break;
    }
}

/* Collect everything which can come at the token under the cursor. */
static void
collect (cli_parse_t *p, const cli_arg_t *seq, u32 n, u64 done, u32 pos, u64 gactive)
{
  u8 *prefix = p->tok[p->i].s;

  for (u32 k = 0; k < n; k++)
    {
      if ((seq[k].kind == CLI_K_KEYWORD || seq[k].kind == CLI_K_FLAG ||
	   seq[k].kind == CLI_K_GROUP) &&
	  (!(done & (1ULL << k)) || (seq[k].flags & CLI_F_REPEAT)))
	add_first_candidates (p, &seq[k], prefix);

      if (seq[k].kind == CLI_K_GROUP && (gactive & (1ULL << k)))
	for (const cli_arg_t *c = seq[k].children; c->kind; c++)
	  add_first_candidates (p, c, prefix);
    }

  for (u32 j = pos; j < n; j++)
    {
      if (!is_positional (&seq[j]))
	continue;
      add_first_candidates (p, &seq[j], prefix);
      if (!(seq[j].flags & CLI_F_OPTIONAL) && !(done & (1ULL << j)))
	break;
    }
}

static int
parse_value (cli_parse_t *p, const cli_arg_t *a)
{
  cli_value_t v = { .arg = a };
  cli_tok_t *t;
  u8 *err;

  if (p->i >= p->n_tok)
    {
      set_err (p, p->n_tok, format (0, "missing value for '%s'", a->name));
      return P_NOMATCH;
    }

  t = &p->tok[p->i];

  /* rest of the line, as it was typed */
  if (a->type->greedy)
    {
      if (p->complete)
	return P_STOP;
      vec_add (v.str, p->line + t->pos, p->tok[p->n_tok - 1].end - t->pos);
      v.tok = p->i;
      vec_add1 (p->values, v);
      p->i = p->n_tok;
      return P_OK;
    }

  if (p->complete && p->i == p->n_tok - 1)
    {
      if (a->type->complete)
	a->type->complete (a, t->s, &p->cands);
      return P_STOP;
    }

  err = a->type->parse (a, t->s, &v);
  if (err)
    {
      if (a->type->complete)
	{
	  cli_candidate_t *all = 0;
	  u8 *best;
	  u8 *empty = 0;

	  a->type->complete (a, empty, &all);
	  best = cli_suggest (t->s, all);
	  if (best)
	    err = format (err, ", did you mean '%v'?", best);
	  cli_candidates_free (all);
	}
      set_err (p, p->i, err);
      return P_NOMATCH;
    }

  v.tok = p->i;
  vec_add1 (p->values, v);
  p->i++;
  return P_OK;
}

static int parse_seq (cli_parse_t *p, const cli_arg_t *seq, int top);

static int
parse_keyword (cli_parse_t *p, const cli_arg_t *a)
{
  u32 kw = p->i;
  int r;

  p->i++;
  if (a->kind == CLI_K_FLAG)
    {
      cli_value_t v = { .arg = a, .u64 = 1, .tok = kw };

      vec_add1 (p->values, v);
      return P_OK;
    }

  r = parse_value (p, a);
  if (r == P_NOMATCH)
    return P_ERR;
  if (r == P_OK)
    vec_elt (p->values, vec_len (p->values) - 1).tok = kw;
  return r;
}

static int
tok_is_keyword (cli_tok_t *t, const cli_arg_t *a)
{
  return !t->quoted && (tok_eq (t, a->name) || (a->alias && tok_eq (t, a->alias)));
}

static int
parse_oneof (cli_parse_t *p, const cli_arg_t *a)
{
  u8 *alts = 0;
  int r;

  for (const cli_arg_t *c = a->children; c->kind; c++)
    {
      if (c->kind == CLI_K_FLAG || c->kind == CLI_K_KEYWORD)
	{
	  if (p->i < p->n_tok && tok_is_keyword (&p->tok[p->i], c))
	    return parse_keyword (p, c);
	  continue;
	}
      if (c->kind == CLI_K_SEQ)
	r = parse_seq (p, c->children, 0);
      else
	r = parse_value (p, c);
      if (r != P_NOMATCH)
	{
	  if (r == P_OK)
	    {
	      vec_free (p->err);
	      vec_free (alts);
	    }
	  return r;
	}
      if (!alts)
	alts = p->err;
      else
	vec_free (p->err);
      p->err = 0;
    }

  vec_free (p->err);
  if (alts)
    p->err = format (0, "%v, expected %U", alts, format_arg_usage, a);
  else
    p->err = format (0, "expected %U", format_arg_usage, a);
  vec_free (alts);
  p->err_tok = p->i;
  return P_NOMATCH;
}

static int
parse_positional (cli_parse_t *p, const cli_arg_t *a)
{
  if (a->kind == CLI_K_VALUE)
    return parse_value (p, a);
  if (a->kind == CLI_K_ONEOF)
    return parse_oneof (p, a);
  return parse_seq (p, a->children, 0);
}

static int
parse_seq (cli_parse_t *p, const cli_arg_t *seq, int top)
{
  u32 n = 0, start = p->i, pos = 0;
  u64 done = 0, gactive = 0;

  while (seq[n].kind)
    n++;
  ASSERT (n <= 64);

  while (1)
    {
      cli_tok_t *t;
      int r, found = 0;

      if (p->complete && p->i == p->n_tok - 1)
	{
	  collect (p, seq, n, done, pos, gactive);
	  return P_STOP;
	}
      if (p->i >= p->n_tok)
	break;

      t = &p->tok[p->i];
      for (u32 k = 0; k < n && !found; k++)
	{
	  const cli_arg_t *a = &seq[k];

	  if (a->kind == CLI_K_GROUP)
	    {
	      if (tok_is_keyword (t, a))
		{
		  cli_value_t v = { .arg = a, .u64 = 1, .tok = p->i };

		  if (done & (1ULL << k))
		    {
		      set_err (p, p->i, format (0, "'%s' given more than once", a->name));
		      return P_ERR;
		    }
		  vec_add1 (p->values, v);
		  p->i++;
		  done |= 1ULL << k;
		  gactive |= 1ULL << k;
		  found = 1;
		}
	      else if (gactive & (1ULL << k))
		for (const cli_arg_t *c = a->children; c->kind; c++)
		  {
		    if ((c->kind != CLI_K_KEYWORD && c->kind != CLI_K_FLAG) ||
			!tok_is_keyword (t, c))
		      continue;
		    r = parse_keyword (p, c);
		    if (r != P_OK)
		      return r;
		    found = 1;
		    break;
		  }
	      continue;
	    }

	  if ((a->kind != CLI_K_KEYWORD && a->kind != CLI_K_FLAG) || !tok_is_keyword (t, a))
	    continue;
	  if ((done & (1ULL << k)) && !(a->flags & CLI_F_REPEAT))
	    {
	      set_err (p, p->i, format (0, "'%s' given more than once", a->name));
	      return P_ERR;
	    }
	  r = parse_keyword (p, a);
	  if (r != P_OK)
	    return r;
	  done |= 1ULL << k;
	  found = 1;
	}
      if (found)
	continue;

      while (1)
	{
	  u32 j = pos;

	  while (j < n && !is_positional (&seq[j]))
	    j++;
	  if (j >= n)
	    goto out;

	  r = parse_positional (p, &seq[j]);
	  if (r == P_OK)
	    {
	      done |= 1ULL << j;
	      if (!(seq[j].flags & CLI_F_REPEAT))
		pos = j + 1;
	      else
		pos = j;
	      break;
	    }
	  if (r != P_NOMATCH)
	    return r;

	  if ((seq[j].flags & CLI_F_OPTIONAL) || (done & (1ULL << j)))
	    {
	      pos = j + 1;
	      continue;
	    }
	  if (!top && p->i == start)
	    return P_NOMATCH;
	  return P_ERR;
	}
    }

out:
  for (u32 k = 0; k < n; k++)
    {
      if ((done & (1ULL << k)) || (seq[k].flags & CLI_F_OPTIONAL) || seq[k].kind == CLI_K_FLAG)
	continue;
      if (!top && p->i == start)
	{
	  vec_free (p->err);
	  p->err = format (0, "expected %U", format_arg_usage, &seq[k]);
	  p->err_tok = p->i;
	  return P_NOMATCH;
	}
      set_err (p, p->n_tok, format (0, "missing argument %U", format_arg_usage, &seq[k]));
      return P_ERR;
    }

  if (!top && p->i == start)
    return P_NOMATCH;

  return P_OK;
}

/* Group which has to be given before keyword tok is accepted, if any */
static const cli_arg_t *
find_group_of_keyword (const cli_arg_t *a, cli_tok_t *t)
{
  for (; a->kind; a++)
    if (a->kind == CLI_K_GROUP)
      for (const cli_arg_t *c = a->children; c->kind; c++)
	if ((c->kind == CLI_K_KEYWORD || c->kind == CLI_K_FLAG) && tok_is_keyword (t, c))
	  return a;
  return 0;
}

static void
collect_keywords (const cli_arg_t *a, cli_candidate_t **out)
{
  for (; a->kind; a++)
    {
      if (is_hidden (a))
	continue;
      if (a->kind == CLI_K_KEYWORD || a->kind == CLI_K_FLAG || a->kind == CLI_K_GROUP)
	cli_candidate_add (out, a->name, 0);
      if (a->kind == CLI_K_ONEOF || a->kind == CLI_K_SEQ || a->kind == CLI_K_GROUP)
	collect_keywords (a->children, out);
    }
}

/* Output of parse errors: message, offending line and a marker */
static clib_error_t *
format_parse_error (u8 *line, cli_tok_t *toks, u32 n_tok, u32 tok, u8 *msg)
{
  u32 pos = vec_len (line), end = pos + 1;
  clib_error_t *e;
  u8 *s;

  if (tok < n_tok)
    {
      pos = toks[tok].pos;
      end = toks[tok].end;
    }
  s = format (0, "%v\n  %v\n  %U", msg, line, format_white_space, pos);
  for (u32 i = pos; i < end; i++)
    s = format (s, "^");
  e = clib_error_return (0, "%v", s);
  vec_free (s);
  return e;
}

/* Value access */

cli_value_t *
cli_get (cli_ctx_t *ctx, const char *name)
{
  cli_value_t *v;

  vec_foreach (v, ctx->values)
    if (strcmp (v->arg->name, name) == 0)
      return v;
  return 0;
}

cli_value_t *
cli_get_next (cli_ctx_t *ctx, cli_value_t *prev)
{
  cli_value_t *v;

  for (v = prev + 1; v < vec_end (ctx->values); v++)
    if (v->arg == prev->arg)
      return v;
  return 0;
}

void
cli_ctx_free (cli_ctx_t *ctx)
{
  cli_value_t *v;
  cli_filter_t *f;

  vec_foreach (v, ctx->values)
    if (v->arg->type && v->arg->type->owns_str)
      vec_free (v->str);
  vec_free (ctx->values);
  vec_foreach (f, ctx->filters)
    {
      vec_free (f->pat);
      vec_free (f->field);
      vec_free (f->op);
    }
  vec_free (ctx->filters);
  vec_free (ctx->out);
  vec_free (ctx->warnings);
  *ctx = (cli_ctx_t) {};
}

/* Completion */

static cli_candidate_t *
complete_filters (u8 *prefix)
{
  cli_candidate_t *out = 0;

  for (const char **f = cli_filter_names; *f; f++)
    if (cli_prefix_match (*f, prefix))
      cli_candidate_add (&out, *f, 0);
  return out;
}

void
cli_complete_args (const cli_arg_t *args, u8 *rest, cli_candidate_t **out)
{
  cli_tok_t *toks = tokenize (rest, 1);
  cli_parse_t p = { .line = rest, .tok = toks, .n_tok = vec_len (toks), .complete = 1 };
  u32 last_pipe = ~0;

  for (u32 i = 0; i < p.n_tok; i++)
    if (!toks[i].quoted && tok_eq (&toks[i], "|"))
      last_pipe = i;

  if (last_pipe != ~0)
    {
      if (last_pipe + 2 == p.n_tok)
	*out = complete_filters (toks[p.n_tok - 1].s);
      goto done;
    }

  if (parse_seq (&p, args ? args : cli_no_args, 1) == P_STOP)
    {
      *out = p.cands;
      p.cands = 0;
      cli_sort_unique (out);
    }

done:
  cli_candidates_free (p.cands);
  vec_free (p.err);
  vec_free (p.values);
  tokens_free (toks);
}

/* Constraints and defaults, after the line was parsed */

static cli_value_t *
find_value (cli_value_t *values, const cli_arg_t *a)
{
  cli_value_t *v;

  vec_foreach (v, values)
    if (v->arg == a)
      return v;
  return 0;
}

static cli_value_t *
find_value_by_name (cli_value_t *values, const char *name, u32 len)
{
  cli_value_t *v;

  vec_foreach (v, values)
    if (strlen (v->arg->name) == len && memcmp (v->arg->name, name, len) == 0)
      return v;
  return 0;
}

/* returns the error, err_tok is the token to mark */
static u8 *
check_constraints (const cli_arg_t *args, cli_value_t *values, u32 *err_tok)
{
  for (const cli_arg_t *a = args; a->kind; a++)
    {
      cli_value_t *v;
      u8 *err;

      if (a->children && (err = check_constraints (a->children, values, err_tok)))
	return err;

      if (!a->name || !(v = find_value (values, a)) || v->is_default)
	continue;

      for (const char *n = a->requires; n && *n;)
	{
	  const char *e = strchr (n, ',') ? strchr (n, ',') : n + strlen (n);

	  if (!find_value_by_name (values, n, e - n))
	    {
	      *err_tok = v->tok;
	      return format (0, "'%s' needs '%.*s'", a->name, (int) (e - n), n);
	    }
	  n = *e ? e + 1 : e;
	}

      for (const char *n = a->excludes; n && *n;)
	{
	  const char *e = strchr (n, ',') ? strchr (n, ',') : n + strlen (n);
	  cli_value_t *o = find_value_by_name (values, n, e - n);

	  if (o && !o->is_default)
	    {
	      *err_tok = clib_max (v->tok, o->tok);
	      return format (0, "'%s' can not be used together with '%.*s'", a->name, (int) (e - n),
			     n);
	    }
	  n = *e ? e + 1 : e;
	}
    }
  return 0;
}

/* the arguments of a group, and those of a sequence, have defaults only when the
 * group is given, the alternatives of a oneof do not have any */
static u8 *
apply_defaults (const cli_arg_t *args, cli_value_t **values)
{
  for (const cli_arg_t *a = args; a->kind; a++)
    {
      cli_value_t v = { .arg = a, .is_default = 1, .tok = ~0 };
      u8 *def, *err;

      if (a->kind == CLI_K_SEQ)
	{
	  if ((err = apply_defaults (a->children, values)))
	    return err;
	  continue;
	}
      if (a->kind == CLI_K_GROUP)
	{
	  if (find_value (*values, a) && (err = apply_defaults (a->children, values)))
	    return err;
	  continue;
	}
      if ((a->kind != CLI_K_VALUE && a->kind != CLI_K_KEYWORD) || !a->def ||
	  find_value (*values, a))
	continue;

      def = format (0, "%s", a->def);
      if (a->type->greedy)
	{
	  v.str = def;
	  vec_add1 (*values, v);
	  continue;
	}
      err = a->type->parse (a, def, &v);
      vec_free (def);
      if (err)
	{
	  u8 *msg = format (0, "the default '%s' of '%s' is not valid: %v", a->def, a->name, err);

	  vec_free (err);
	  return msg;
	}
      vec_add1 (*values, v);
    }
  return 0;
}

/* Parsing of a command line */

clib_error_t *
cli_parse_line (const cli_arg_t *args, u8 *line, cli_ctx_t *ctx)
{
  cli_parse_t p = {};
  u8 *err_msg = 0;
  clib_error_t *error = 0;
  u32 err_tok = 0, n_args, n_all;
  cli_tok_t *toks = tokenize (line, 0);
  cli_value_t *v;
  int r;

  if (!args)
    args = cli_no_args;

  n_all = vec_len (toks);
  for (n_args = 0; n_args < n_all; n_args++)
    if (!toks[n_args].quoted && tok_eq (&toks[n_args], "|"))
      break;

  if (n_all && !toks[n_all - 1].quoted && tok_eq (&toks[n_all - 1], "?"))
    {
      ctx->help = 1;
      goto done;
    }

  if (n_args < n_all)
    {
      err_msg = cli_parse_filters (ctx, toks + n_args + 1, n_all - n_args - 1, &err_tok);
      if (err_msg)
	{
	  err_tok += n_args + 1;
	  goto parse_error;
	}
    }

  p.line = line;
  p.tok = toks;
  p.n_tok = n_args;
  r = parse_seq (&p, args ? args : cli_no_args, 1);
  if (r == P_OK && p.i < p.n_tok)
    {
      cli_candidate_t *kw = 0;
      const cli_arg_t *group = find_group_of_keyword (args, &toks[p.i]);
      u8 *best;

      collect_keywords (args, &kw);
      best = cli_suggest (toks[p.i].s, kw);
      err_msg = format (0, "unexpected argument '%v'", toks[p.i].s);
      if (group)
	err_msg = format (err_msg, ", it is only valid after '%s'", group->name);
      else if (best)
	err_msg = format (err_msg, ", did you mean '%v'?", best);
      else if (p.err && p.err_tok == p.i)
	/* the optional argument which was tried for this token and why it did not match */
	err_msg = format (err_msg, ": %v", p.err);
      err_tok = p.i;
      cli_candidates_free (kw);
      goto parse_error;
    }
  if (r != P_OK)
    {
      err_msg = p.err;
      p.err = 0;
      err_tok = p.err_tok;
      goto parse_error;
    }

  err_msg = check_constraints (args, p.values, &err_tok);
  if (err_msg)
    goto parse_error;

  err_msg = apply_defaults (args, &p.values);
  if (err_msg)
    {
      /* the default is wrong, not the line: no token to mark */
      err_tok = n_all;
      goto parse_error;
    }

  vec_foreach (v, p.values)
    if (v->arg->deprecated && !v->is_default)
      ctx->warnings = format (ctx->warnings, "warning: '%s' is deprecated, %s\n", v->arg->name,
			      v->arg->deprecated);

  ctx->values = p.values;
  p.values = 0;
  goto done;

parse_error:
  error = format_parse_error (line, toks, n_all, err_tok, err_msg);
  vec_free (err_msg);

done:
  vec_free (p.err);
  vec_free (p.values);
  tokens_free (toks);
  return error;
}

clib_error_t *
cli_parse_pipeline (u8 *text, cli_ctx_t *ctx)
{
  cli_tok_t *toks = tokenize (text, 0);
  clib_error_t *error = 0;
  u32 err_tok = 0;
  u8 *err_msg = cli_parse_filters (ctx, toks, vec_len (toks), &err_tok);

  if (err_msg)
    {
      error = format_parse_error (text, toks, vec_len (toks), err_tok, err_msg);
      vec_free (err_msg);
    }
  tokens_free (toks);
  return error;
}

clib_error_t *
cli_check_output (cli_ctx_t *ctx)
{
  if ((ctx->json || ctx->has_where) && !ctx->emitted)
    return clib_error_return (0, "command has no structured output");
  return 0;
}

/* Schema export */

void
cli_args_to_json (clib_json_text_t *j, const cli_arg_t *args)
{
  static const char *kinds[] = { 0, "value", "keyword", "flag", "oneof", "sequence", "group" };

  for (const cli_arg_t *a = args; a && a->kind; a++)
    {
      clib_json_add_object (j, 0);
      clib_json_add_string (j, "kind", "%s", kinds[a->kind]);
      if (a->name)
	clib_json_add_string (j, "name", "%s", a->name);
      if (a->alias)
	clib_json_add_string (j, "alias", "%s", a->alias);
      if (a->help)
	clib_json_add_string (j, "help", "%s", a->help);
      if (a->type)
	clib_json_add_string (j, "type", "%s", a->type->name);
      if (a->flags & CLI_F_OPTIONAL)
	clib_json_add_true (j, "optional");
      if (a->flags & CLI_F_REPEAT)
	clib_json_add_true (j, "repeat");
      if (a->flags & CLI_F_HIDDEN)
	clib_json_add_true (j, "hidden");
      if (a->def)
	clib_json_add_string (j, "default", "%s", a->def);
      if (a->requires)
	clib_json_add_string (j, "requires", "%s", a->requires);
      if (a->excludes)
	clib_json_add_string (j, "excludes", "%s", a->excludes);
      if (a->deprecated)
	clib_json_add_string (j, "deprecated", "%s", a->deprecated);
      if (a->min)
	clib_json_add_number (j, "min", a->min);
      if (a->max)
	clib_json_add_number (j, "max", a->max);
      if (a->choices)
	{
	  clib_json_add_array (j, "choices");
	  for (const cli_choice_t *c = a->choices; c->name; c++)
	    {
	      clib_json_add_object (j, 0);
	      clib_json_add_string (j, "name", "%s", c->name);
	      if (c->help)
		clib_json_add_string (j, "help", "%s", c->help);
	      clib_json_parent (j);
	    }
	  clib_json_parent (j);
	}
      if (a->children)
	{
	  clib_json_add_array (j, "children");
	  cli_args_to_json (j, a->children);
	  clib_json_parent (j);
	}
      clib_json_parent (j);
    }
}

void
cli_types_to_json (clib_json_text_t *j)
{
  for (cli_type_t *t = cli_types; t; t = t->next)
    {
      clib_json_add_object (j, 0);
      clib_json_add_string (j, "name", "%s", t->name);
      if (t->help)
	clib_json_add_string (j, "help", "%s", t->help);
      if (t->complete)
	clib_json_add_true (j, "completes");
      clib_json_parent (j);
    }
}
