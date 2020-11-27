/*
  Copyright (c) 2020 Damjan Marion

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef __table_h__
#define __table_h__

typedef enum
{
  TTAF_RESET = (1 << 0),
  TTAF_BOLD = (1 << 1),
  TTAF_DIM = (1 << 2),
  TTAF_UNDERLINE = (1 << 3),
  TTAF_FG_COLOR_SET = (1 << 4),
  TTAF_BG_COLOR_SET = (1 << 5),
  TTAF_FG_COLOR_BRIGHT = (1 << 6),
  TTAF_BG_COLOR_BRIGHT = (1 << 7),
} table_text_attr_flags_t;

typedef enum
{
  TTAC_BLACK = 0,
  TTAC_RED = 1,
  TTAC_GREEN = 2,
  TTAC_YELLOW = 3,
  TTAC_BLUE = 4,
  TTAC_MAGENTA = 5,
  TTAC_CYAN = 6,
  TTAC_WHITE = 7,
} table_text_attr_color_t;

typedef enum
{
  TTAA_DEFAULT = 0,
  TTAA_LEFT = 1,
  TTAA_RIGHT = 2,
  TTAA_CENTER = 3,
} table_text_attr_align_t;

typedef struct
{
  table_text_attr_flags_t flags : 16;
  table_text_attr_color_t fg_color : 4;
  table_text_attr_color_t bg_color : 4;
  table_text_attr_align_t align : 4;
} table_text_attr_t;

typedef struct
{
  table_text_attr_t attr;
  u8 *text;
} table_cell_t;

typedef struct
{
  u8 no_ansi : 1;
  u8 *title;
  table_cell_t **cells;
  int *row_sizes;
  int n_header_cols;
  int n_header_rows;
  int n_footer_cols;
} table_t;

format_function_t format_table;

void table_format_title (table_t *t, char *fmt, ...);
void table_format_cell (table_t *t, int c, int r, char *fmt, ...);
void table_set_cell_align (table_t *t, int c, int r,
			   table_text_attr_align_t a);
void table_set_cell_fg_color (table_t *t, int c, int r,
			      table_text_attr_color_t v);
void table_set_cell_bg_color (table_t *t, int c, int r,
			      table_text_attr_color_t v);
void table_free (table_t *t);
void table_add_header_col (table_t *t, int n_strings, ...);
void table_add_header_row (table_t *t, int n_strings, ...);

#endif
