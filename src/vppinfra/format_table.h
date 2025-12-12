/* SPDX-License-Identifier: MIT
 * Copyright (c) 2020 Damjan Marion
 */

#ifndef __format_table_h__
#define __format_table_h__

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
  TTAC_BRIGHT_BLACK = 8,
  TTAC_BRIGHT_RED = 9,
  TTAC_BRIGHT_GREEN = 10,
  TTAC_BRIGHT_YELLOW = 11,
  TTAC_BRIGHT_BLUE = 12,
  TTAC_BRIGHT_MAGENTA = 13,
  TTAC_BRIGHT_CYAN = 14,
  TTAC_BRIGHT_WHITE = 15,
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
  union
  {
    struct
    {
      table_text_attr_flags_t flags : 16;
      table_text_attr_color_t fg_color : 4;
      table_text_attr_color_t bg_color : 4;
      table_text_attr_align_t align : 4;
    };
    u32 as_u32;
  };
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
  table_text_attr_t default_title;
  table_text_attr_t default_body;
  table_text_attr_t default_header_col;
  table_text_attr_t default_header_row;
} table_t;

__clib_export format_function_t format_table;

__clib_export void table_format_title (table_t *t, char *fmt, ...);
__clib_export void table_format_cell (table_t *t, int c, int r, char *fmt,
				      ...);
__clib_export void table_set_cell_align (table_t *t, int c, int r,
					 table_text_attr_align_t a);
__clib_export void table_set_cell_fg_color (table_t *t, int c, int r,
					    table_text_attr_color_t v);
__clib_export void table_set_cell_bg_color (table_t *t, int c, int r,
					    table_text_attr_color_t v);
__clib_export void table_free (table_t *t);
__clib_export void table_add_header_col (table_t *t, int n_strings, ...);
__clib_export void table_add_header_row (table_t *t, int n_strings, ...);

#endif
