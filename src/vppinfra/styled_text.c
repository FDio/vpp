/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vppinfra/styled_text.h>
#include <vppinfra/unicode.h>

typedef enum
{
  ST_BOLD,
  ST_ITALIC,
  ST_UNDERLINE,
  ST_REVERSE,
  ST_N_ATTRS,
} st_attr_t;

__clib_export const styled_text_profile_t styled_text_default_profile = {
  .role = {
    [ST_R_VALUE] = { .fg = ST_C_256_BASE + 153 }, /* light blue */
    [ST_R_HEADING] = { .bold = ST_A_ON },
    [ST_R_SUCCESS] = { .fg = ST_C_GREEN },
    [ST_R_WARNING] = { .fg = ST_C_YELLOW },
    [ST_R_ERROR] = { .fg = ST_C_256_BASE + 211 }, /* light red */
    [ST_R_TABLE_TITLE] = { .bold = ST_A_ON },
    [ST_R_TABLE_COL_HEADING] = { .bold = ST_A_ON },
    [ST_R_TABLE_ROW_HEADING] = { .bold = ST_A_ON },
    [ST_R_TABLE_CELL] = { .fg = ST_C_256_BASE + 153 }, /* light blue */
  },
};

static const u8 st_rgb16[16][3] = {
  { 0, 0, 0 },	     { 205, 0, 0 },   { 0, 205, 0 },   { 205, 205, 0 },
  { 0, 0, 238 },     { 205, 0, 205 }, { 0, 205, 205 }, { 229, 229, 229 },
  { 127, 127, 127 }, { 255, 0, 0 },   { 0, 255, 0 },   { 255, 255, 0 },
  { 92, 92, 255 },   { 255, 0, 255 }, { 0, 255, 255 }, { 255, 255, 255 },
};

static const u8 st_cube[6] = { 0, 95, 135, 175, 215, 255 };

/* what the terminal shows after a color or attribute change, as far as we track it */
typedef struct
{
  styled_text_color_t fg, bg;
  u8 attr[ST_N_ATTRS];
} st_state_t;

static styled_text_style_t
st_merge (styled_text_style_t base, styled_text_style_t over)
{
  styled_text_style_t r = base;

  if (over.fg)
    r.fg = over.fg;

  if (over.bg)
    r.bg = over.bg;

  if (over.bold)
    r.bold = over.bold;

  if (over.italic)
    r.italic = over.italic;

  if (over.underline)
    r.underline = over.underline;

  if (over.reverse)
    r.reverse = over.reverse;

  if (over.wrap)
    r.wrap = over.wrap;

  return r;
}

static styled_text_color_t
st_color16 (u32 n)
{
  return ST_C_BLACK + n;
}

static u32
st_dist (u32 r1, u32 g1, u32 b1, u32 r2, u32 g2, u32 b2)
{
  i32 dr = (i32) r1 - (i32) r2, dg = (i32) g1 - (i32) g2, db = (i32) b1 - (i32) b2;

  return dr * dr + dg * dg + db * db;
}

static void
st_color256_to_rgb (u32 n, u32 *r, u32 *g, u32 *b)
{
  if (n < 16)
    {
      *r = st_rgb16[n][0];
      *g = st_rgb16[n][1];
      *b = st_rgb16[n][2];
    }
  else if (n < 232)
    {
      n -= 16;
      *r = st_cube[n / 36];
      *g = st_cube[(n / 6) % 6];
      *b = st_cube[n % 6];
    }
  else
    *r = *g = *b = 8 + 10 * (n - 232);
}

static u32
st_rgb_to_16 (u32 r, u32 g, u32 b)
{
  u32 best = 0, best_d = ~0;

  for (u32 i = 0; i < 16; i++)
    {
      u32 d = st_dist (r, g, b, st_rgb16[i][0], st_rgb16[i][1], st_rgb16[i][2]);

      if (d < best_d)
	{
	  best_d = d;
	  best = i;
	}
    }

  return best;
}

static u32
st_cube_level (u32 v)
{
  u32 best = 0, best_d = ~0;

  for (u32 i = 0; i < 6; i++)
    {
      u32 d = st_dist (v, 0, 0, st_cube[i], 0, 0);

      if (d < best_d)
	{
	  best_d = d;
	  best = i;
	}
    }

  return best;
}

static u32
st_rgb_to_256 (u32 r, u32 g, u32 b)
{
  u32 ri = st_cube_level (r), gi = st_cube_level (g), bi = st_cube_level (b);
  u32 cube_d = st_dist (r, g, b, st_cube[ri], st_cube[gi], st_cube[bi]);
  u32 avg = (r + g + b) / 3, grey = 0, grey_d;

  if (avg > 8)
    grey = clib_min ((avg - 8 + 5) / 10, 23);

  grey_d = st_dist (r, g, b, 8 + 10 * grey, 8 + 10 * grey, 8 + 10 * grey);

  if (grey_d < cube_d)
    return 232 + grey;

  return 16 + 36 * ri + 6 * gi + bi;
}

/* nothing set anywhere is the terminal's default color */
static styled_text_color_t
st_cap_color (styled_text_color_t c, styled_text_output_t output)
{
  styled_text_color_value_t v = { .as_u32 = c };
  u32 r, g, b;

  if (v.kind == ST_CK_INHERIT)
    return ST_C_DEFAULT;

  if (v.kind == ST_CK_256 && output == ST_O_16)
    {
      if (v.index < 16)
	return st_color16 (v.index);

      st_color256_to_rgb (v.index, &r, &g, &b);
      return st_color16 (st_rgb_to_16 (r, g, b));
    }

  if (v.kind == ST_CK_RGB)
    {
      if (output == ST_O_256)
	return styled_text_color256 (st_rgb_to_256 (v.r, v.g, v.b));

      if (output == ST_O_16)
	return st_color16 (st_rgb_to_16 (v.r, v.g, v.b));
    }

  return c;
}

static st_state_t
st_state (styled_text_style_t st, styled_text_output_t output)
{
  st_state_t r = {
    .fg = st_cap_color (st.fg, output),
    .bg = st_cap_color (st.bg, output),
    .attr = {
      [ST_BOLD] = st.bold == ST_A_ON,
      [ST_ITALIC] = st.italic == ST_A_ON,
      [ST_UNDERLINE] = st.underline == ST_A_ON,
      [ST_REVERSE] = st.reverse == ST_A_ON,
    },
  };

  return r;
}

static int
st_state_eq (st_state_t *a, st_state_t *b)
{
  return a->fg == b->fg && a->bg == b->bg && a->attr[ST_BOLD] == b->attr[ST_BOLD] &&
	 a->attr[ST_ITALIC] == b->attr[ST_ITALIC] &&
	 a->attr[ST_UNDERLINE] == b->attr[ST_UNDERLINE] &&
	 a->attr[ST_REVERSE] == b->attr[ST_REVERSE];
}

static u8 *
st_color_param (u8 *s, styled_text_color_t c, u32 bg)
{
  styled_text_color_value_t v = { .as_u32 = c };

  if (v.kind == ST_CK_16)
    return format (s, "%u", (v.index < 8 ? 30 : 82) + v.index + (bg ? 10 : 0));

  if (v.kind == ST_CK_256)
    return format (s, "%u;5;%u", bg ? 48 : 38, v.index);

  if (v.kind == ST_CK_RGB)
    return format (s, "%u;2;%u;%u;%u", bg ? 48 : 38, v.r, v.g, v.b);

  return format (s, "%u", bg ? 49 : 39);
}

/* emits one sequence with only what differs, and makes cur what the terminal shows */
static u8 *
st_transition (u8 *s, st_state_t *cur, st_state_t *want)
{
  static const u8 on[ST_N_ATTRS] = { 1, 3, 4, 7 };
  static const u8 off[ST_N_ATTRS] = { 22, 23, 24, 27 };
  u32 n = 0;

  if (st_state_eq (cur, want))
    return s;

  s = format (s, "\x1b[");

  for (u32 i = 0; i < ST_N_ATTRS; i++)
    if (cur->attr[i] != want->attr[i])
      s = format (s, "%s%u", n++ ? ";" : "", want->attr[i] ? on[i] : off[i]);

  if (cur->fg != want->fg)
    {
      s = format (s, "%s", n++ ? ";" : "");
      s = st_color_param (s, want->fg, 0);
    }

  if (cur->bg != want->bg)
    {
      s = format (s, "%s", n++ ? ";" : "");
      s = st_color_param (s, want->bg, 1);
    }

  s = format (s, "m");
  *cur = *want;

  return s;
}

/*
 * Length in bytes of the UTF-8 character at p, n_left > 0 bytes are left, and
 * the number of columns it takes. A byte which is not valid UTF-8 is a
 * character of one byte and one column.
 */
static u32
st_char (u8 *p, u32 n_left, u32 *n_cols)
{
  u8 buf[4] = {};
  u32 cp, n;

  if (p[0] < 0x80)
    {
      *n_cols = 1;
      return 1;
    }

  /* the decoder looks at up to 4 bytes */
  if (n_left < 4)
    {
      clib_memcpy (buf, p, n_left);
      p = buf;
    }

  n = clib_unicode_get_utf8_char (p, &cp);
  if (n > n_left)
    n = 1;

  *n_cols = n == 1 ? 1 : clib_unicode_get_visible_len (cp);

  return n;
}

/* number of columns the last line of s takes, escape sequences are not counted */
static u32
st_line_col (u8 *s)
{
  u32 len = vec_len (s), start = len, col = 0;

  while (start > 0 && s[start - 1] != '\n')
    start--;

  for (u32 i = start, n, n_cols; i < len; i += n)
    {
      if (s[i] == 0x1b && i + 1 < len && s[i + 1] == '[')
	{
	  i += 2;
	  while (i < len && (s[i] < 0x40 || s[i] > 0x7e))
	    i++;
	  n = 0;
	  continue;
	}

      n = st_char (s + i, len - i, &n_cols);
      col += n_cols;
    }

  return col;
}

/* rendering of one object */
typedef struct
{
  styled_text_t *t;
  const styled_text_profile_t *profile;
  u8 *s;		      /* output */
  styled_text_style_t *stack; /* open styles, each merged with the ones around it */
  st_state_t zero;	      /* no style */
  st_state_t cur;	      /* what the terminal shows */
  st_state_t want;	      /* what the text at i is to be shown with */
  st_state_t pend_want;	      /* the same for the spaces kept back */
  u32 i;		      /* next byte of the text */
  u32 e;		      /* next formatting change */
  u32 col;
  u32 pending; /* spaces kept back for wrapping */
  u8 no_wrap;  /* the text at i is not to be wrapped */
} st_render_t;

/* the style of a formatting change, with its role looked up in the profile */
static styled_text_style_t
st_resolve (st_render_t *r, styled_text_style_t st)
{
  if (st.role == ST_R_NONE)
    return st;

  return st_merge (r->profile->role[st.role], st);
}

/* applies the formatting changes up to the current position */
static void
st_apply_changes (st_render_t *r)
{
  styled_text_fmt_chg_t *chg = r->t->fmt_chg;

  while (r->e < vec_len (chg) && chg[r->e].pos <= r->i)
    {
      styled_text_fmt_chg_t *c = chg + r->e++;
      styled_text_style_t top = {};
      u32 n = vec_len (r->stack);

      if (!c->end)
	{
	  if (n)
	    top = r->stack[n - 1];

	  vec_add1 (r->stack, st_merge (top, st_resolve (r, c->style)));
	}
      else if (n)
	vec_dec_len (r->stack, 1);

      n = vec_len (r->stack);
      top = n ? r->stack[n - 1] : (styled_text_style_t) {};
      r->want = st_state (top, r->t->output);
      r->no_wrap = top.wrap == ST_A_OFF;
    }
}

static void
st_set_state (st_render_t *r, st_state_t *state)
{
  if (r->t->output != ST_O_PLAIN)
    r->s = st_transition (r->s, &r->cur, state);
}

/* writes the character at the current position and moves to the next one */
static void
st_emit_char (st_render_t *r)
{
  u8 *text = r->t->string;
  u32 n_cols, n = st_char (text + r->i, vec_len (text) - r->i, &n_cols);

  st_set_state (r, &r->want);
  vec_add (r->s, text + r->i, n);
  r->col += n_cols;
  r->i += n;
}

/* spaces kept back for wrapping have the style they were written with */
static void
st_emit_pending (st_render_t *r)
{
  for (; r->pending; r->pending--)
    {
      st_set_state (r, &r->pend_want);
      vec_add1 (r->s, ' ');
      r->col++;
    }
}

/* a style does not run over the end of a line, it is opened again on the next one */
static void
st_new_line (st_render_t *r, u32 indent)
{
  st_set_state (r, &r->zero);
  r->s = format_newline (r->s, indent);
  r->col = indent;
}

/* appends the text of t to s, with the escape sequences for its formatting */
static u8 *
st_render (u8 *s, styled_text_t *t)
{
  st_state_t zero = st_state ((styled_text_style_t) {}, t->output);
  st_render_t r = {
    .t = t,
    .profile = t->profile ? t->profile : &styled_text_default_profile,
    .s = s,
    .zero = zero,
    .cur = zero,
    .want = zero,
    .col = st_line_col (s),
  };
  u8 *text = t->string;
  u32 len = vec_len (text), indent = r.col, line_indent = r.col;
  int at_line_start = 1;

  while (r.i < len)
    {
      u32 wlen = 0, wcols = 0;
      u8 c;

      st_apply_changes (&r);
      c = text[r.i];

      if (c == '\n')
	{
	  st_new_line (&r, indent);
	  line_indent = indent;
	  at_line_start = 1;
	  r.pending = 0;
	  r.i++;
	  continue;
	}

      if (t->width == 0 || r.no_wrap)
	{
	  st_emit_pending (&r);
	  st_emit_char (&r);
	  at_line_start = 0;
	  continue;
	}

      if (c == ' ')
	{
	  if (r.pending == 0)
	    r.pend_want = r.want;
	  r.pending++;
	  r.i++;
	  continue;
	}

      while (r.i + wlen < len && text[r.i + wlen] != ' ' && text[r.i + wlen] != '\n')
	{
	  u32 n_cols;

	  wlen += st_char (text + r.i + wlen, len - r.i - wlen, &n_cols);
	  wcols += n_cols;
	}

      if (r.col + r.pending + wcols > t->width && r.col > line_indent)
	st_new_line (&r, line_indent);
      else
	{
	  st_emit_pending (&r);

	  /* spaces at the start of a line are its indent, wrapped lines get it too */
	  if (at_line_start)
	    line_indent = r.col;
	}

      at_line_start = 0;
      r.pending = 0;

      for (u32 end = r.i + wlen; r.i < end;)
	{
	  st_apply_changes (&r);
	  st_emit_char (&r);
	}
    }

  st_emit_pending (&r);

  if (t->output != ST_O_PLAIN && !st_state_eq (&r.cur, &r.zero))
    r.s = format (r.s, "\x1b[0m");

  vec_free (r.stack);

  return r.s;
}

static void
st_add_chg (styled_text_t *t, u8 *s, u32 end, styled_text_style_t style)
{
  styled_text_fmt_chg_t c = {
    .pos = vec_len (s),
    .end = end,
    .style = style,
  };

  vec_add1 (t->fmt_chg, c);
}

/*
 * Appends src, every line it starts is indented by the given number of columns.
 * Empty lines are left empty.
 */
static void
st_append (styled_text_t *t, styled_text_t *src, u32 indent)
{
  u32 len = vec_len (src->string), n_chg = vec_len (src->fmt_chg), base, j = 0;
  i32 open = 0;

  for (u32 i = 0; i <= len; i++)
    {
      int starts_line =
	indent && i && i < len && src->string[i - 1] == '\n' && src->string[i] != '\n';

      /* styles which stop at the end of the previous line don't cover the indent */
      for (; j < n_chg && src->fmt_chg[j].pos == i; j++)
	{
	  styled_text_fmt_chg_t c = src->fmt_chg[j];

	  if (starts_line && c.end == 0)
	    break;

	  st_add_chg (t, t->string, c.end, c.style);
	  open += c.end ? -1 : 1;
	}

      if (starts_line)
	{
	  base = vec_len (t->string);
	  vec_resize (t->string, indent);
	  clib_memset (t->string + base, ' ', indent);
	}

      for (; j < n_chg && src->fmt_chg[j].pos == i; j++)
	{
	  styled_text_fmt_chg_t c = src->fmt_chg[j];

	  st_add_chg (t, t->string, c.end, c.style);
	  open += c.end ? -1 : 1;
	}

      if (i < len)
	vec_add1 (t->string, src->string[i]);
    }

  for (; open > 0; open--)
    st_add_chg (t, t->string, 1, (styled_text_style_t) {});
}

/*
 * A styled function adds to an object of its own, so whatever it does with
 * columns is relative to where it was called. Its lines are then indented to
 * that column.
 */
static void
st_add_fn (styled_text_t *t, styled_format_fn_t *fn, va_list *va)
{
  styled_text_t child = {
    .profile = t->profile,
    .output = t->output,
    .width = t->width,
  };
  u32 indent = st_line_col (t->string);

  fn (&child, va);
  st_append (t, &child, indent);
  styled_text_free (&child);
}

/* the first %T, %{ or %} of a format string, %%T is none of them */
static char *
st_find_directive (char *fmt)
{
  for (char *p = fmt; *p; p++)
    {
      if (*p != '%')
	continue;

      if (p[1] == 'T' || p[1] == '{' || p[1] == '}')
	return p;

      if (p[1] == '%')
	p++;
    }

  return 0;
}

/*
 * format () does not know %T, %{ and %}. The format string is cut at each of
 * them, the pieces in between go to format () with the same va_list, so the
 * arguments are used in order. The styled functions of %T get the va_list the
 * same way %U functions do. mark is the role of %{ %}, 0 where they can't be
 * used.
 */
static void
st_vadd (styled_text_t *t, const styled_text_role_t *mark, char *fmt, va_list *va)
{
  char *r = st_find_directive (fmt), *seg;
  u32 n_open = 0;
  u8 *copy;

  if (r == 0)
    {
      t->string = va_format (t->string, fmt, va);
      return;
    }

  copy = format (0, "%s%c", fmt, 0);
  seg = (char *) copy;
  r = seg + (r - fmt);

  while (r)
    {
      char directive = r[1];

      *r = 0;
      if (*seg)
	t->string = va_format (t->string, seg, va);

      if (directive == 'T')
	{
	  styled_format_fn_t *fn = va_arg (*va, styled_format_fn_t *);

	  st_add_fn (t, fn, va);
	}
      else if (directive == '{')
	{
	  ASSERT (mark);

	  if (mark)
	    {
	      styled_text_begin_role (t, *mark);
	      n_open++;
	    }
	}
      else
	{
	  /* a style opened outside of this format string is not ours to close */
	  ASSERT (n_open);

	  if (n_open)
	    {
	      styled_text_end (t);
	      n_open--;
	    }
	}

      seg = r + 2;
      r = st_find_directive (seg);
    }

  if (*seg)
    t->string = va_format (t->string, seg, va);

  for (; n_open; n_open--)
    styled_text_end (t);

  vec_free (copy);
}

__clib_export void
styled_text_add (styled_text_t *t, char *fmt, ...)
{
  va_list va;

  va_start (va, fmt);
  st_vadd (t, 0, fmt, &va);
  va_end (va);
}

__clib_export void
styled_text_begin (styled_text_t *t, styled_text_style_t style)
{
  ASSERT (style.role < ST_N_ROLES);
  st_add_chg (t, t->string, 0, style);
}

__clib_export void
styled_text_begin_role (styled_text_t *t, styled_text_role_t role)
{
  styled_text_begin (t, (styled_text_style_t) { .role = role });
}

__clib_export void
styled_text_end (styled_text_t *t)
{
  st_add_chg (t, t->string, 1, (styled_text_style_t) {});
}

__clib_export void
styled_text_add_styled (styled_text_t *t, styled_text_style_t style, char *fmt, ...)
{
  va_list va;

  styled_text_begin (t, style);

  va_start (va, fmt);
  st_vadd (t, 0, fmt, &va);
  va_end (va);

  styled_text_end (t);
}

__clib_export void
styled_text_add_role (styled_text_t *t, styled_text_role_t role, char *fmt, ...)
{
  va_list va;

  styled_text_begin_role (t, role);

  va_start (va, fmt);
  st_vadd (t, 0, fmt, &va);
  va_end (va);

  styled_text_end (t);
}

__clib_export void
styled_text_add_marked (styled_text_t *t, styled_text_role_t role, char *fmt, ...)
{
  va_list va;

  va_start (va, fmt);
  st_vadd (t, &role, fmt, &va);
  va_end (va);
}

__clib_export void
styled_text_append (styled_text_t *t, styled_text_t *src)
{
  ASSERT (t != src);
  st_append (t, src, 0);
}

__clib_export void
styled_text_set_output (styled_text_t *t, styled_text_output_t output)
{
  t->output = output;
}

__clib_export void
styled_text_free (styled_text_t *t)
{
  vec_free (t->string);
  vec_free (t->fmt_chg);
  *t = (styled_text_t) {};
}

__clib_export u8 *
format_styled_text (u8 *s, va_list *args)
{
  styled_text_t *t = va_arg (*args, styled_text_t *);

  return st_render (s, t);
}
