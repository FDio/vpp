/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vppinfra/format.h>

/* how a color value is to be read */
typedef enum
{
  ST_CK_INHERIT = 0,
  ST_CK_DEFAULT = 1,
  ST_CK_16 = 2,
  ST_CK_256 = 3,
  ST_CK_RGB = 4,
} styled_text_color_kind_t;

/* the base colors, styled_text_color256 () and styled_text_rgb () make the others */
typedef enum
{
  ST_C_INHERIT = 0, /* don't care, keeps the color of the enclosing style */
  /* the terminal's own color, as opposed to not touching the color */
  ST_C_DEFAULT = ST_CK_DEFAULT << 24,
  ST_C_BLACK = ST_CK_16 << 24,
  ST_C_RED,
  ST_C_GREEN,
  ST_C_YELLOW,
  ST_C_BLUE,
  ST_C_MAGENTA,
  ST_C_CYAN,
  ST_C_WHITE,
  ST_C_BRIGHT_BLACK,
  ST_C_BRIGHT_RED,
  ST_C_BRIGHT_GREEN,
  ST_C_BRIGHT_YELLOW,
  ST_C_BRIGHT_BLUE,
  ST_C_BRIGHT_MAGENTA,
  ST_C_BRIGHT_CYAN,
  ST_C_BRIGHT_WHITE,
  /* add the index to get a color of the 256 color palette in a static initializer */
  ST_C_256_BASE = ST_CK_256 << 24,
} styled_text_color_t;

/* the parts of a styled_text_color_t */
typedef union
{
  struct
  {
    union
    {
      u8 b, index; /* index in the palette, for the palette kinds */
    };
    u8 g, r;
    u8 kind; /* styled_text_color_kind_t */
  };
  u32 as_u32;
} styled_text_color_value_t;

STATIC_ASSERT_SIZEOF (styled_text_color_value_t, 4);

static_always_inline styled_text_color_t
styled_text_color256 (u8 n)
{
  return ST_C_256_BASE + n;
}

static_always_inline styled_text_color_t
styled_text_rgb (u8 r, u8 g, u8 b)
{
  styled_text_color_value_t v = { .r = r, .g = g, .b = b, .kind = ST_CK_RGB };

  return v.as_u32;
}

/* what a piece of text is, a profile says what it looks like */
typedef enum
{
  ST_R_NONE = 0,
  ST_R_VALUE,
  ST_R_HEADING,
  ST_R_SUCCESS,
  ST_R_WARNING,
  ST_R_ERROR,
  ST_R_TABLE_TITLE,
  ST_R_TABLE_COL_HEADING, /* heading of a column, above it */
  ST_R_TABLE_ROW_HEADING, /* heading of a row, on its left */
  ST_R_TABLE_CELL,
  ST_N_ROLES,
} styled_text_role_t;

typedef enum
{
  ST_A_INHERIT = 0, /* don't care, keeps what the enclosing style has */
  ST_A_ON,
  ST_A_OFF,
} styled_text_attr_t;

typedef struct
{
  styled_text_color_t fg, bg;
  styled_text_role_t role : 8;
  styled_text_attr_t bold : 2;
  styled_text_attr_t italic : 2;
  styled_text_attr_t underline : 2;
  styled_text_attr_t reverse : 2;
  /* ST_A_OFF: lines of this text are not broken to fit the width */
  styled_text_attr_t wrap : 2;
} styled_text_style_t;

typedef struct
{
  styled_text_style_t role[ST_N_ROLES]; /* the role member of these is not used */
} styled_text_profile_t;

extern const styled_text_profile_t styled_text_default_profile;

/* the most the output may use */
typedef enum
{
  ST_O_UNKNOWN = 0, /* no cap, every color is emitted as it was asked for */
  ST_O_PLAIN,	    /* no escape sequences at all */
  ST_O_16,	    /* 16 base colors */
  ST_O_256,	    /* 256 color palette */
} styled_text_output_t;

typedef struct
{
  u32 pos : 31;		     /* byte offset into styled_text_t.string */
  u32 end : 1;		     /* 0: style starts at pos, 1: the innermost open style stops at pos */
  styled_text_style_t style; /* not used when end is set */
} styled_text_fmt_chg_t;

typedef struct
{
  u8 *string;			  /* the text, read only for users, append with styled_text_add */
  styled_text_fmt_chg_t *fmt_chg; /* in order of pos */
  const styled_text_profile_t *profile; /* 0 = styled_text_default_profile */
  styled_text_output_t output;
  u16 width; /* wrap lines at spaces to this many columns, 0 = no wrapping */
} styled_text_t;

/* a format function which styles its output, %T of styled_text_add () */
typedef void (styled_format_fn_t) (styled_text_t *st, va_list *args);

/* appends formatted text, as format () with %T added */
void styled_text_add (styled_text_t *t, char *fmt, ...);
/* starts a style for the text added until the matching styled_text_end () */
void styled_text_begin (styled_text_t *t, styled_text_style_t style);
/* starts a role for the text added until the matching styled_text_end () */
void styled_text_begin_role (styled_text_t *t, styled_text_role_t role);
/* ends the innermost open style or role */
void styled_text_end (styled_text_t *t);
/* appends formatted text which has the style */
void styled_text_add_styled (styled_text_t *t, styled_text_style_t style, char *fmt, ...);
/* appends formatted text which has the role */
void styled_text_add_role (styled_text_t *t, styled_text_role_t role, char *fmt, ...);
/* appends formatted text, the parts between %{ and %} have the role */
void styled_text_add_marked (styled_text_t *t, styled_text_role_t role, char *fmt, ...);
/* appends the text of src together with its styles */
void styled_text_append (styled_text_t *t, styled_text_t *src);
/* limits the colors the rendered output may use */
void styled_text_set_output (styled_text_t *t, styled_text_output_t output);
/* frees the text and styles, the object is empty and can be used again */
void styled_text_free (styled_text_t *t);

/* %U with styled_text_t * */
format_function_t format_styled_text;
