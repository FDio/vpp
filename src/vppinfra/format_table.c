/* SPDX-License-Identifier: MIT
 * Copyright (c) 2020 Damjan Marion
 */

#include <vppinfra/format.h>
#include <vppinfra/format_table.h>

static table_text_attr_t default_title = {
  .flags = TTAF_FG_COLOR_SET | TTAF_BOLD,
  .fg_color = TTAC_YELLOW,
  .align = TTAA_CENTER,
};

static table_text_attr_t default_body = {
  .align = TTAA_RIGHT,
};

static table_text_attr_t default_header_col = {
  .flags = TTAF_FG_COLOR_SET,
  .fg_color = TTAC_YELLOW,
  .align = TTAA_CENTER,
};

static table_text_attr_t default_header_row = {
  .flags = TTAF_FG_COLOR_SET | TTAF_BOLD,
  .fg_color = TTAC_GREEN,
  .align = TTAA_LEFT,
};

u8 *
format_text_cell (table_t *t, u8 *s, table_cell_t *c, table_text_attr_t *def,
		  int size)
{
  table_text_attr_t _a = {}, *a = &_a;

  if (c == 0)
    return format (s, t->no_ansi ? "" : "\x1b[0m");

  clib_memcpy (a, def, sizeof (table_text_attr_t));

  if (t->no_ansi == 0)
    {
      int *codes = 0;
      if (c->attr.flags & TTAF_FG_COLOR_SET)
	{
	  a->fg_color = c->attr.fg_color;
	  a->flags |= TTAF_FG_COLOR_SET;
	  a->flags |= c->attr.flags & TTAF_FG_COLOR_BRIGHT;
	}

      if (c->attr.flags & TTAF_BG_COLOR_SET)
	{
	  a->bg_color = c->attr.bg_color;
	  a->flags |= TTAF_BG_COLOR_SET;
	  a->flags |= c->attr.flags & TTAF_BG_COLOR_BRIGHT;
	}

      if (a->flags & TTAF_RESET)
	vec_add1 (codes, 0);

      if (a->flags & TTAF_BOLD)
	vec_add1 (codes, 1);

      if (a->flags & TTAF_DIM)
	vec_add1 (codes, 2);

      if (a->flags & TTAF_UNDERLINE)
	vec_add1 (codes, 4);

      if (a->flags & TTAF_FG_COLOR_SET)
	vec_add1 (codes,
		  (a->flags & TTAF_FG_COLOR_BRIGHT ? 90 : 30) + a->fg_color);

      if (a->flags & TTAF_BG_COLOR_SET)
	vec_add1 (codes,
		  (a->flags & TTAF_BG_COLOR_BRIGHT ? 100 : 40) + a->bg_color);

      if (codes)
	{
	  s = format (s, "\x1b[");
	  for (int i = 0; i < vec_len (codes); i++)
	    s = format (s, "%s%u", i ? ";" : "", codes[i]);
	  s = format (s, "m");
	  vec_free (codes);
	}
    }

  u8 *fmt = 0;
  table_text_attr_align_t align = c->attr.align;
  if (align == TTAA_DEFAULT)
    align = a->align;
  if (align == TTAA_LEFT)
    fmt = format (fmt, "%%-%uv%c", size, 0);
  else if (align == TTAA_CENTER)
    fmt = format (fmt, "%%=%uv%c", size, 0);
  else
    fmt = format (fmt, "%%%uv%c", size, 0);
  s = format (s, (char *) fmt, c->text);
  vec_free (fmt);
  return format (s, t->no_ansi ? "" : "\x1b[0m");
}

u8 *
format_table (u8 *s, va_list *args)
{
  table_t *t = va_arg (*args, table_t *);
  table_cell_t title_cell = { .text = t->title };
  int table_width = 0;
  u32 indent = format_get_indent (s);
  for (int i = 0; i < vec_len (t->row_sizes); i++)
    table_width += t->row_sizes[i];

  if (t->title)
    {
      table_text_attr_t *title_default;
      title_default =
	t->default_title.as_u32 ? &t->default_title : &default_title;
      /* fixup table width, in case title is larger than combined row sizes */
      table_width = vec_len (t->title) > table_width ? vec_len (t->title) : table_width;
      s = format_text_cell (t, s, &title_cell, title_default, table_width);
      s = format (s, "\n%U", format_white_space, indent);
    }

  for (int c = 0; c < vec_len (t->cells); c++)
    {
      table_text_attr_t *col_default;

      if (c < t->n_header_cols)
	col_default = t->default_header_col.as_u32 ? &t->default_header_col :
						     &default_header_col;
      else
	col_default =
	  t->default_body.as_u32 ? &t->default_body : &default_body;

      for (int r = 0; r < vec_len (t->cells[c]); r++)
	{
	  table_text_attr_t *row_default = col_default;
	  if (r)
	    s = format (s, " ");
	  if (r < t->n_header_rows && c >= t->n_header_cols)
	    row_default = t->default_header_row.as_u32 ?
			    &t->default_header_row :
			    &default_header_row;
	  s = format_text_cell (t, s, &t->cells[c][r], row_default,
				t->row_sizes[r]);
	}
      if (c + 1 < vec_len (t->cells))
	s = format (s, "\n%U", format_white_space, indent);
    }

  return s;
}

void
table_format_title (table_t *t, char *fmt, ...)
{
  va_list va;

  va_start (va, fmt);
  t->title = va_format (t->title, fmt, &va);
  va_end (va);
}

static table_cell_t *
table_get_cell (table_t *t, int c, int r)
{
  c += t->n_header_cols;
  r += t->n_header_rows;

  /* grow table if needed */
  vec_validate (t->cells, c);
  for (int i = 0; i < vec_len (t->cells); i++)
    vec_validate (t->cells[i], r);
  return &t->cells[c][r];
}

void
table_format_cell (table_t *t, int c, int r, char *fmt, ...)
{
  table_cell_t *cell = table_get_cell (t, c, r);
  va_list va;

  c += t->n_header_cols;
  r += t->n_header_rows;

  va_start (va, fmt);
  cell->text = va_format (t->cells[c][r].text, fmt, &va);
  va_end (va);

  vec_validate (t->row_sizes, r);
  t->row_sizes[r] = clib_max (t->row_sizes[r], vec_len (t->cells[c][r].text));
}

void
table_set_cell_align (table_t *t, int c, int r, table_text_attr_align_t a)
{
  table_cell_t *cell = table_get_cell (t, c, r);
  cell->attr.align = a;
}

void
table_set_cell_fg_color (table_t *t, int c, int r, table_text_attr_color_t v)
{
  table_cell_t *cell = table_get_cell (t, c, r);
  cell->attr.fg_color = v & 0x7;
  cell->attr.flags |= TTAF_FG_COLOR_SET;
  if (v & 8)
    cell->attr.flags |= TTAF_FG_COLOR_BRIGHT;
  else
    cell->attr.flags &= ~TTAF_FG_COLOR_BRIGHT;
}

void
table_set_cell_bg_color (table_t *t, int c, int r, table_text_attr_color_t v)
{
  table_cell_t *cell = table_get_cell (t, c, r);
  cell->attr.bg_color = v & 0x7;
  cell->attr.flags |= TTAF_BG_COLOR_SET;
  if (v & 8)
    cell->attr.flags |= TTAF_BG_COLOR_BRIGHT;
  else
    cell->attr.flags &= ~TTAF_BG_COLOR_BRIGHT;
}

void
table_free (table_t *t)
{
  for (int c = 0; c < vec_len (t->cells); c++)
    {
      for (int r = 0; r < vec_len (t->cells[c]); r++)
	vec_free (t->cells[c][r].text);
      vec_free (t->cells[c]);
    }
  vec_free (t->cells);
  vec_free (t->row_sizes);
  vec_free (t->title);
  clib_memset (t, 0, sizeof (table_t));
}

void
table_add_header_col (table_t *t, int n_strings, ...)
{
  va_list arg;
  int r, c = t->n_header_cols++;
  int n_rows;

  vec_insert (t->cells, 1, c);
  n_rows = clib_max (n_strings, 1);
  n_rows = clib_max (vec_len (t->row_sizes), n_rows);
  vec_validate (t->cells[c], n_rows - 1);

  va_start (arg, n_strings);
  for (r = 0; r < n_rows; r++)
    {
      if (n_strings-- > 0)
	table_format_cell (t, -1, r - t->n_header_rows, "%s",
			   va_arg (arg, char *));
    }
  va_end (arg);
}

void
table_add_header_row (table_t *t, int n_strings, ...)
{
  va_list arg;
  int c, r = t->n_header_rows++;

  vec_validate (t->cells, n_strings + t->n_header_cols - 1);

  va_start (arg, n_strings);
  for (c = t->n_header_cols; c < vec_len (t->cells); c++)
    {
      vec_insert (t->cells[c + t->n_header_cols], 1, r);
      if (n_strings-- > 0)
	table_format_cell (t, c, -1, "%s", va_arg (arg, char *));
    }
  va_end (arg);
}
