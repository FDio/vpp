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

static u8 *
table_format_spaces (u8 *s, int n_spaces)
{
  for (int i = 0; i < n_spaces; i++)
    s = format (s, " ");

  return s;
}

/* spaces on both sides of a cell which is to take size columns */
static void
table_cell_padding (table_cell_t *c, table_text_attr_t *def, int size, int *left_pad,
		    int *right_pad)
{
  table_text_attr_align_t align = c->attr.align;
  int visible_len = format_get_visible_length (c->text);

  *left_pad = *right_pad = 0;

  if (align == TTAA_DEFAULT)
    align = def->align;

  if (visible_len >= size)
    return;

  if (align == TTAA_LEFT)
    *right_pad = size - visible_len;
  else if (align == TTAA_CENTER)
    {
      *left_pad = (size - visible_len) / 2;
      *right_pad = size - visible_len - *left_pad;
    }
  else
    *left_pad = size - visible_len;
}

u8 *
format_text_cell (table_t *t, u8 *s, table_cell_t *c, table_text_attr_t *def,
		  int size)
{
  table_text_attr_t _a = {}, *a = &_a;
  int left_pad, right_pad;

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

  table_cell_padding (c, a, size, &left_pad, &right_pad);

  s = table_format_spaces (s, left_pad);
  s = format (s, "%v", c->text);
  s = table_format_spaces (s, right_pad);
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
      table_width = format_get_visible_length (t->title) > table_width ?
		      format_get_visible_length (t->title) :
		      table_width;
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

static void
table_apply_attr (styled_text_style_t *style, table_text_attr_t a)
{
  if (a.flags & TTAF_BOLD)
    style->bold = ST_A_ON;

  if (a.flags & TTAF_UNDERLINE)
    style->underline = ST_A_ON;

  if (a.flags & TTAF_FG_COLOR_SET)
    style->fg = ST_C_BLACK + (a.fg_color | (a.flags & TTAF_FG_COLOR_BRIGHT ? 8 : 0));

  if (a.flags & TTAF_BG_COLOR_SET)
    style->bg = ST_C_BLACK + (a.bg_color | (a.flags & TTAF_BG_COLOR_BRIGHT ? 8 : 0));
}

/*
 * own is what the user of the table set for this kind of cell, builtin is used
 * for the alignment when nothing was set. The colors of the builtin one are not
 * used, the role stands for them.
 */
static void
table_add_styled_cell (styled_text_t *st, table_cell_t *c, styled_text_role_t role,
		       table_text_attr_t *own, table_text_attr_t *builtin, int size)
{
  styled_text_style_t style = { .role = role };
  int left_pad, right_pad;

  if (own->as_u32)
    table_apply_attr (&style, *own);

  table_apply_attr (&style, c->attr);
  table_cell_padding (c, own->as_u32 ? own : builtin, size, &left_pad, &right_pad);

  styled_text_add_styled (st, style, "%U%v%U", format_white_space, left_pad, c->text,
			  format_white_space, right_pad);
}

__clib_export void
format_styled_table (styled_text_t *st, va_list *args)
{
  table_t *t = va_arg (*args, table_t *);
  int table_width = 0;

  for (int i = 0; i < vec_len (t->row_sizes); i++)
    table_width += t->row_sizes[i];

  styled_text_begin (st, (styled_text_style_t) { .wrap = ST_A_OFF });

  if (t->title)
    {
      table_cell_t title_cell = { .text = t->title };

      table_width = clib_max (format_get_visible_length (t->title), table_width);
      table_add_styled_cell (st, &title_cell, ST_R_TABLE_TITLE, &t->default_title, &default_title,
			     table_width);
      styled_text_add (st, "\n");
    }

  for (int c = 0; c < vec_len (t->cells); c++)
    {
      for (int r = 0; r < vec_len (t->cells[c]); r++)
	{
	  styled_text_role_t role = ST_R_TABLE_CELL;
	  table_text_attr_t *own = &t->default_body, *builtin = &default_body;

	  if (c < t->n_header_cols)
	    {
	      role = ST_R_TABLE_COL_HEADING;
	      own = &t->default_header_col;
	      builtin = &default_header_col;
	    }
	  else if (r < t->n_header_rows)
	    {
	      role = ST_R_TABLE_ROW_HEADING;
	      own = &t->default_header_row;
	      builtin = &default_header_row;
	    }

	  if (r)
	    styled_text_add (st, " ");

	  table_add_styled_cell (st, &t->cells[c][r], role, own, builtin, t->row_sizes[r]);
	}

      if (c + 1 < vec_len (t->cells))
	styled_text_add (st, "\n");
    }

  styled_text_end (st);
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
  t->row_sizes[r] = clib_max (t->row_sizes[r], format_get_visible_length (t->cells[c][r].text));
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
table_add_hdr_row (table_t *t, int n_strings, ...)
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
table_add_hdr_col (table_t *t, int n_strings, ...)
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
