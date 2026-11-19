/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vppinfra/format.h>
#include <vppinfra/format_table.h>
#include <vppinfra/styled_text.h>
#include <vppinfra/test/test.h>

/* escape sequences made visible, so a failure can be read */
static u8 *
visible (u8 *s)
{
  u8 *r = 0;

  for (u32 i = 0; i < vec_len (s); i++)
    {
      if (s[i] == 0x1b)
	r = format (r, "\\e");
      else if (s[i] == '\n')
	r = format (r, "\\n");
      else
	vec_add1 (r, s[i]);
    }

  return r;
}

static clib_error_t *
check (clib_error_t *err, u8 *got, char *expect, char *what)
{
  if (err == 0 && (vec_len (got) != strlen (expect) || memcmp (got, expect, vec_len (got)) != 0))
    {
      u8 *e = visible (format (0, "%s", expect)), *g = visible (got);

      err = clib_error_return (0, "%s: expected '%v' got '%v'", what, e, g);
      vec_free (e);
      vec_free (g);
    }

  vec_free (got);

  return err;
}

static u8 *
render (styled_text_t *t, styled_text_output_t output)
{
  styled_text_set_output (t, output);

  return format (0, "%U", format_styled_text, t);
}

static styled_format_fn_t styled_child;

static void
styled_child (styled_text_t *st, va_list *args __clib_unused)
{
  styled_text_begin (st, (styled_text_style_t) { .fg = ST_C_GREEN });
  styled_text_add (st, "child");
  styled_text_end (st);
}

/* a styled function that calls another one */
static styled_format_fn_t styled_parent;

static void
styled_parent (styled_text_t *st, va_list *args __clib_unused)
{
  styled_text_begin (st, (styled_text_style_t) { .bold = ST_A_ON });
  styled_text_add (st, "[%T]", styled_child);
  styled_text_end (st);
}

/* styled functions which add several lines, used at a column other than 0 */
static styled_format_fn_t styled_lines;

static void
styled_lines (styled_text_t *st, va_list *args __clib_unused)
{
  styled_text_add (st, "one\ntwo\n  three\n\nfour");
}

static styled_format_fn_t styled_nest;

static void
styled_nest (styled_text_t *st, va_list *args __clib_unused)
{
  styled_text_add (st, "in: %T\nafter", styled_lines);
}

static u8 *
format_two_lines (u8 *s, va_list *args __clib_unused)
{
  u32 indent = format_get_indent (s);

  s = format (s, "u1");
  s = format_newline (s, indent);

  return format (s, "u2");
}

static styled_format_fn_t styled_format_calls;

static void
styled_format_calls (styled_text_t *st, va_list *args __clib_unused)
{
  styled_text_add (st, "%U\nv: %U", format_two_lines, format_two_lines);
}

static styled_format_fn_t styled_line_ends;

static void
styled_line_ends (styled_text_t *st, va_list *args __clib_unused)
{
  /* the first style stops at the end of its line, the second goes over it */
  styled_text_add_marked (st, ST_R_VALUE, "%{a\n%}b %{c\nd%}");
}

/* arguments of its own */
static styled_format_fn_t styled_args;

static void
styled_args (styled_text_t *st, va_list *args)
{
  char *name = va_arg (*args, char *);
  u32 n = va_arg (*args, u32);

  styled_text_begin (st, (styled_text_style_t) { .fg = ST_C_RED });
  styled_text_add (st, "%s=%u", name, n);
  styled_text_end (st);
}

static format_function_t format_plain;

static u8 *
format_plain (u8 *s, va_list *args __clib_unused)
{
  return format (s, "plain");
}

/* a styled function that uses a format function */
static styled_format_fn_t styled_with_plain;

static void
styled_with_plain (styled_text_t *st, va_list *args __clib_unused)
{
  styled_text_begin (st, (styled_text_style_t) { .bold = ST_A_ON });
  styled_text_add (st, "<%U>", format_plain);
  styled_text_end (st);
}

static clib_error_t *
test_styled_text (clib_error_t *err)
{
  styled_text_t st = {};

  /* plain output has no escape sequences */
  styled_text_add (&st, "hello ");
  styled_text_begin (&st, (styled_text_style_t) { .fg = ST_C_RED, .bold = ST_A_ON });
  styled_text_add (&st, "world");
  styled_text_end (&st);
  err = check (err, render (&st, ST_O_PLAIN), "hello world", "plain");
  styled_text_free (&st);

  /* a single style */
  styled_text_begin (&st, (styled_text_style_t) { .fg = ST_C_GREEN });
  styled_text_add (&st, "ab");
  styled_text_end (&st);
  err = check (err, render (&st, ST_O_UNKNOWN), "\x1b[32mab\x1b[0m", "single style");
  styled_text_free (&st);

  /* nesting restores the enclosing style, and only changed attributes are emitted */
  styled_text_add (&st, "a");
  styled_text_begin (&st, (styled_text_style_t) { .bold = ST_A_ON });
  styled_text_add (&st, "b");
  styled_text_begin (&st, (styled_text_style_t) { .fg = ST_C_GREEN });
  styled_text_add (&st, "c");
  styled_text_end (&st);
  styled_text_add (&st, "d");
  styled_text_end (&st);
  styled_text_add (&st, "e");
  err = check (err, render (&st, ST_O_UNKNOWN), "a\x1b[1mb\x1b[32mc\x1b[39md\x1b[22me", "nesting");
  styled_text_free (&st);

  /* an attribute can be turned off inside a style that turned it on */
  styled_text_begin (&st, (styled_text_style_t) { .bold = ST_A_ON });
  styled_text_add (&st, "a");
  styled_text_begin (&st, (styled_text_style_t) { .bold = ST_A_OFF });
  styled_text_add (&st, "b");
  styled_text_end (&st);
  styled_text_add (&st, "c");
  styled_text_end (&st);
  err =
    check (err, render (&st, ST_O_UNKNOWN), "\x1b[1ma\x1b[22mb\x1b[1mc\x1b[0m", "attribute off");
  styled_text_free (&st);

  /* attributes before foreground before background */
  styled_text_begin (&st, (styled_text_style_t) { .bg = ST_C_BLUE, .bold = ST_A_ON });
  styled_text_add (&st, "x");
  styled_text_end (&st);
  err = check (err, render (&st, ST_O_UNKNOWN), "\x1b[1;44mx\x1b[0m", "bg and bold");
  styled_text_free (&st);

  /* the output is a cap on colors */
  styled_text_begin (&st, (styled_text_style_t) { .fg = styled_text_rgb (255, 0, 0) });
  styled_text_add (&st, "x");
  styled_text_end (&st);
  err = check (err, render (&st, ST_O_UNKNOWN), "\x1b[38;2;255;0;0mx\x1b[0m", "rgb");
  err = check (err, render (&st, ST_O_256), "\x1b[38;5;196mx\x1b[0m", "rgb capped to 256");
  err = check (err, render (&st, ST_O_16), "\x1b[91mx\x1b[0m", "rgb capped to 16");
  styled_text_free (&st);

  styled_text_begin (&st, (styled_text_style_t) { .fg = styled_text_color256 (196) });
  styled_text_add (&st, "x");
  styled_text_end (&st);
  err = check (err, render (&st, ST_O_UNKNOWN), "\x1b[38;5;196mx\x1b[0m", "256 colors");
  err = check (err, render (&st, ST_O_16), "\x1b[91mx\x1b[0m", "256 colors capped to 16");
  styled_text_free (&st);

  styled_text_begin (&st, (styled_text_style_t) { .fg = ST_C_GREEN });
  styled_text_add (&st, "x");
  styled_text_end (&st);
  err = check (err, render (&st, ST_O_256), "\x1b[32mx\x1b[0m", "16 colors under a larger cap");
  styled_text_free (&st);

  /* wrapping at spaces */
  styled_text_add (&st, "aaa bbb ccc ddd");
  st.width = 8;
  err = check (err, render (&st, ST_O_PLAIN), "aaa bbb\nccc ddd", "wrap");
  err = check (err, format (0, "  %U", format_styled_text, &st), "  aaa\n  bbb\n  ccc\n  ddd",
	       "wrap with indent");
  styled_text_free (&st);

  /* text which is not to be wrapped, between text which is */
  styled_text_add (&st, "aa bb ");
  styled_text_add_styled (&st, (styled_text_style_t) { .wrap = ST_A_OFF }, "cc dd  ee\n  ff gg");
  styled_text_add (&st, "\nhh ii");
  st.width = 4;
  err = check (err, render (&st, ST_O_PLAIN), "aa\nbb cc dd  ee\n  ff gg\nhh\nii", "no wrap");
  styled_text_free (&st);

  /* wrapping counts columns of UTF-8 characters, not bytes */
  styled_text_add (&st, "\xc3\xa9\xc3\xa9 \xc3\xa9\xc3\xa9\xc3\xa9");
  st.width = 6;
  err = check (err, render (&st, ST_O_PLAIN), "\xc3\xa9\xc3\xa9 \xc3\xa9\xc3\xa9\xc3\xa9",
	       "utf8 two byte characters");
  st.width = 5;
  err = check (err, render (&st, ST_O_PLAIN), "\xc3\xa9\xc3\xa9\n\xc3\xa9\xc3\xa9\xc3\xa9",
	       "utf8 wrap");
  styled_text_free (&st);

  /* wide characters take two columns */
  styled_text_add (&st, "\xe6\x97\xa5\xe6\x9c\xac \xe8\xaa\x9e ab");
  st.width = 7;
  err = check (err, render (&st, ST_O_PLAIN), "\xe6\x97\xa5\xe6\x9c\xac \xe8\xaa\x9e\nab",
	       "utf8 wide characters");
  styled_text_free (&st);

  /* combining characters take no column */
  styled_text_add (&st, "x\xcc\x81y\xcc\x81 ab");
  st.width = 5;
  err = check (err, render (&st, ST_O_PLAIN), "x\xcc\x81y\xcc\x81 ab", "utf8 combining");
  styled_text_free (&st);

  /* bytes which are not UTF-8 are a column each and are not changed */
  styled_text_add (&st, "\xff\xe6\x97 ab");
  st.width = 6;
  err = check (err, render (&st, ST_O_PLAIN), "\xff\xe6\x97 ab", "invalid utf8");
  styled_text_free (&st);

  /* styles around wide characters, and the column after them */
  styled_text_add_styled (&st, (styled_text_style_t) { .fg = ST_C_RED },
			  "\xe6\x97\xa5\xe6\x9c\xac");
  styled_text_add (&st, " ab cd");
  st.width = 8;
  err = check (err, render (&st, ST_O_16), "\x1b[31m\xe6\x97\xa5\xe6\x9c\xac\x1b[39m ab\ncd",
	       "utf8 styled");
  styled_text_free (&st);

  /* the column of the text already in the output counts UTF-8 as well */
  styled_text_add (&st, "ab cd");
  st.width = 6;
  err = check (err, format (0, "\xe6\x97\xa5 %U", format_styled_text, &st),
	       "\xe6\x97\xa5 ab\n   cd", "utf8 column of the output");
  styled_text_free (&st);

  /* a newline goes back to the indent the text started at */
  styled_text_add (&st, "a\nb");
  err = check (err, render (&st, ST_O_PLAIN), "a\nb", "newline");
  err = check (err, format (0, "  %U", format_styled_text, &st), "  a\n  b", "newline with indent");
  styled_text_free (&st);

  styled_text_add (&st, "x\n y z");
  err = check (err, format (0, "  %U", format_styled_text, &st), "  x\n   y z",
	       "indent after a newline");
  styled_text_free (&st);

  /* spaces at the start of a line are the indent of its wrapped lines */
  styled_text_add (&st, "head\n bbb ccc ddd");
  st.width = 8;
  err = check (err, render (&st, ST_O_PLAIN), "head\n bbb ccc\n ddd", "wrap after indent");
  styled_text_free (&st);

  /* escape sequences do not take columns */
  st.width = 8;
  styled_text_add (&st, "aaa ");
  styled_text_begin (&st, (styled_text_style_t) { .fg = ST_C_RED });
  styled_text_add (&st, "bbb ccc");
  styled_text_end (&st);
  styled_text_add (&st, " ddd");
  err = check (err, render (&st, ST_O_UNKNOWN), "aaa \x1b[31mbbb\x1b[39m\n\x1b[31mccc\x1b[39m ddd",
	       "wrap styled");
  styled_text_free (&st);

  /* a style is closed at the end of a line and opened again on the next one */
  styled_text_begin (&st, (styled_text_style_t) { .fg = ST_C_RED });
  styled_text_add (&st, "a\nb");
  styled_text_end (&st);
  err = check (err, render (&st, ST_O_UNKNOWN), "\x1b[31ma\x1b[39m\n\x1b[31mb\x1b[0m",
	       "style over a newline");
  err = check (err, format (0, "  %U", format_styled_text, &st),
	       "  \x1b[31ma\x1b[39m\n  \x1b[31mb\x1b[0m", "style over a newline with indent");
  styled_text_free (&st);

  /* text of one object into another */
  {
    styled_text_t inner = {};

    styled_text_begin (&inner, (styled_text_style_t) { .bold = ST_A_ON });
    styled_text_add (&inner, "in");
    styled_text_end (&inner);

    styled_text_add (&st, "x ");
    styled_text_append (&st, &inner);
    styled_text_add (&st, " y");
    err = check (err, render (&st, ST_O_UNKNOWN), "x \x1b[1min\x1b[22m y", "append");
    err = check (err, render (&st, ST_O_PLAIN), "x in y", "append plain");

    styled_text_free (&inner);
    styled_text_free (&st);
  }

  /* a styled function */
  styled_text_add (&st, "<%T>", styled_child);
  err = check (err, render (&st, ST_O_UNKNOWN), "<\x1b[32mchild\x1b[39m>", "styled function");
  err = check (err, render (&st, ST_O_PLAIN), "<child>", "styled function plain");
  styled_text_free (&st);

  styled_text_begin (&st, (styled_text_style_t) { .bold = ST_A_ON });
  styled_text_add (&st, "[%T]", styled_child);
  styled_text_end (&st);
  err = check (err, render (&st, ST_O_UNKNOWN), "\x1b[1m[\x1b[32mchild\x1b[39m]\x1b[0m",
	       "styled function in a style");
  styled_text_free (&st);

  /* %T at the start, at the end, and next to each other */
  styled_text_add (&st, "%T%T", styled_child, styled_child);
  err = check (err, render (&st, ST_O_UNKNOWN), "\x1b[32mchildchild\x1b[0m",
	       "consecutive styled functions");
  styled_text_free (&st);

  /* a styled function that calls a styled function */
  styled_text_add (&st, "<%T>", styled_parent);
  err = check (err, render (&st, ST_O_UNKNOWN), "<\x1b[1m[\x1b[32mchild\x1b[39m]\x1b[22m>",
	       "styled function nested");
  err = check (err, render (&st, ST_O_PLAIN), "<[child]>", "styled function nested plain");
  styled_text_free (&st);

  /* arguments are used in order, by the text around %T and by the function */
  styled_text_add (&st, "%s %T %u", "pre", styled_args, "x", 5u, 42u);
  err = check (err, render (&st, ST_O_UNKNOWN), "pre \x1b[31mx=5\x1b[39m 42", "arguments in order");
  err = check (err, render (&st, ST_O_PLAIN), "pre x=5 42", "arguments in order plain");
  styled_text_free (&st);

  /* format functions and styled functions in one string */
  styled_text_add (&st, "%U %T", format_plain, styled_child);
  err = check (err, render (&st, ST_O_UNKNOWN), "plain \x1b[32mchild\x1b[0m", "%U and %T");
  styled_text_free (&st);

  /* a styled function that uses a format function */
  styled_text_add (&st, "%T", styled_with_plain);
  err = check (err, render (&st, ST_O_UNKNOWN), "\x1b[1m<plain>\x1b[0m", "%U in a styled function");
  styled_text_free (&st);

  /* styled text in one call, with arguments and with a styled function inside */
  styled_text_add (&st, "<");
  styled_text_add_styled (&st, (styled_text_style_t) { .fg = ST_C_RED }, "%s=%u", "a", 3u);
  styled_text_add (&st, "> ");
  styled_text_add_styled (&st, (styled_text_style_t) { .bold = ST_A_ON }, "%T", styled_child);
  err = check (err, render (&st, ST_O_UNKNOWN), "<\x1b[31ma=3\x1b[39m> \x1b[1;32mchild\x1b[0m",
	       "styled add");
  err = check (err, render (&st, ST_O_PLAIN), "<a=3> child", "styled add plain");
  styled_text_free (&st);

  /* %%T is not a styled function */
  styled_text_add (&st, "100%%T %s", "x");
  err = check (err, render (&st, ST_O_PLAIN), "100%T x", "%%T");
  styled_text_free (&st);

  styled_text_add (&st, "100%%%T", styled_child);
  err = check (err, render (&st, ST_O_PLAIN), "100%child", "%%%T");
  styled_text_free (&st);

  /* a role looks the way the default profile says */
  styled_text_add_role (&st, ST_R_VALUE, "%u", 7u);
  styled_text_add (&st, " ");
  styled_text_begin_role (&st, ST_R_ERROR);
  styled_text_add (&st, "bad");
  styled_text_end (&st);
  err = check (err, render (&st, ST_O_UNKNOWN), "\x1b[38;5;153m7\x1b[39m \x1b[38;5;211mbad\x1b[0m",
	       "role");
  err = check (err, render (&st, ST_O_PLAIN), "7 bad", "role plain");
  styled_text_free (&st);

  /* %{ and %} are the same as the calls, arguments are used in order */
  styled_text_add_marked (&st, ST_R_VALUE, "%s %{%u%} b%{%s%}d %s", "a", 7u, "x", "z");
  {
    styled_text_t ref = {};
    u8 *want;

    styled_text_add (&ref, "a ");
    styled_text_add_role (&ref, ST_R_VALUE, "7");
    styled_text_add (&ref, " b");
    styled_text_add_role (&ref, ST_R_VALUE, "x");
    styled_text_add (&ref, "d z");

    want = render (&ref, ST_O_UNKNOWN);
    vec_add1 (want, 0);
    err = check (err, render (&st, ST_O_UNKNOWN), (char *) want, "%{ %}");
    err = check (err, render (&st, ST_O_PLAIN), "a 7 bxd z", "%{ %} plain");
    vec_free (want);
    styled_text_free (&ref);
  }
  styled_text_free (&st);

  /* a pair which is not closed ends with the call, an enclosing style stays */
  styled_text_begin_role (&st, ST_R_ERROR);
  styled_text_add_marked (&st, ST_R_SUCCESS, "%{a");
  styled_text_add (&st, "b");
  styled_text_end (&st);
  styled_text_add (&st, "c");
  err = check (err, render (&st, ST_O_16), "\x1b[32ma\x1b[37mb\x1b[39mc", "%{ not closed");
  styled_text_free (&st);

  /* lines of a styled function start at the column it is used at, at any depth */
  styled_text_add (&st, "head\nq: %T\ntail", styled_nest);
  err = check (err, render (&st, ST_O_PLAIN),
	       "head\nq: in: one\n       two\n         three\n\n       four\n   after\ntail",
	       "nested lines");
  err = check (err, format (0, "> %U", format_styled_text, &st),
	       "> head\n  q: in: one\n         two\n           three\n  \n         four\n"
	       "     after\n  tail",
	       "nested lines with indent");
  styled_text_free (&st);

  /* format functions of a styled function line up the same way */
  styled_text_add (&st, "p: %T", styled_format_calls);
  err = check (err, render (&st, ST_O_PLAIN), "p: u1\n   u2\n   v: u1\n      u2",
	       "%U in a nested function");
  styled_text_free (&st);

  /* the indent has only the styles which go over the line break */
  styled_text_add (&st, "-%T", styled_line_ends);
  err = check (err, render (&st, ST_O_UNKNOWN),
	       "-\x1b[38;5;153ma\x1b[39m\n b \x1b[38;5;153mc\x1b[39m\n"
	       "\x1b[38;5;153m d\x1b[0m",
	       "styles and indent");
  styled_text_free (&st);

  /* %T inside of a pair, %%{ and %%} are text */
  styled_text_add_marked (&st, ST_R_VALUE, "%{<%T>%} %%{%%}", styled_child);
  err = check (err, render (&st, ST_O_PLAIN), "<child> %{%}", "%T and %%{");
  styled_text_free (&st);

  /* the same text with another profile, a role it does not define changes nothing */
  {
    styled_text_profile_t profile = {
      .role = {
        [ST_R_VALUE] = {
          .fg = styled_text_rgb (255, 0, 0),
          .bold = ST_A_ON,
        },
      },
    };

    styled_text_add_role (&st, ST_R_VALUE, "v");
    styled_text_add_role (&st, ST_R_ERROR, "e");
    st.profile = &profile;
    err = check (err, render (&st, ST_O_16), "\x1b[1;91mv\x1b[22;39me", "profile");
    styled_text_free (&st);
  }

  /* members set next to a role go on top of what the profile says */
  styled_text_add_styled (&st,
			  (styled_text_style_t) {
			    .role = ST_R_VALUE,
			    .bold = ST_A_ON,
			  },
			  "x");
  err = check (err, render (&st, ST_O_UNKNOWN), "\x1b[1;38;5;153mx\x1b[0m", "role with a style");
  styled_text_free (&st);

  /* a table takes its styles from the profile of the text it is added to */
  {
    styled_text_profile_t profile = {
      .role = {
	[ST_R_TABLE_TITLE] = { .italic = ST_A_ON },
	[ST_R_TABLE_COL_HEADING] = { .underline = ST_A_ON },
	[ST_R_TABLE_ROW_HEADING] = { .fg = ST_C_YELLOW },
	[ST_R_TABLE_CELL] = { .fg = ST_C_GREEN },
	/* the roles of the text around a table are not used for it */
	[ST_R_HEADING] = { .reverse = ST_A_ON },
	[ST_R_VALUE] = { .fg = ST_C_RED },
      },
    };
    table_t table = {};

    table_add_hdr_row (&table, 2, "a", "bb");
    table_format_cell (&table, 0, 0, "%u", 1);
    table_format_cell (&table, 0, 1, "x");

    styled_text_add (&st, "%T", format_styled_table, &table);
    err = check (err, render (&st, ST_O_UNKNOWN),
		 "\x1b[1ma\x1b[22m \x1b[1mbb\x1b[22m\n"
		 "\x1b[38;5;153m1\x1b[39m \x1b[38;5;153m x\x1b[0m",
		 "table");
    err = check (err, render (&st, ST_O_PLAIN), "a bb\n1  x", "table plain");
    styled_text_free (&st);
    table.no_ansi = 1;
    err = check (err, format (0, "%U", format_table, &table), "a bb\n1  x",
		 "table plain, format_table");
    table.no_ansi = 0;

    /* lines start where the table does, text around it is wrapped, the table is not */
    styled_text_add (&st, "aaa bbb:\n  %T\ncc dd", format_styled_table, &table);
    st.width = 3;
    st.output = ST_O_PLAIN;
    err = check (err, format (0, " %U", format_styled_text, &st),
		 " aaa\n bbb:\n   a bb\n   1  x\n cc\n dd", "table in a text");
    styled_text_free (&st);

    table_set_cell_fg_color (&table, 0, 1, TTAC_BRIGHT_RED);
    styled_text_add (&st, "%T", format_styled_table, &table);
    st.profile = &profile;
    err = check (err, render (&st, ST_O_UNKNOWN),
		 "\x1b[4ma\x1b[24m \x1b[4mbb\x1b[24m\n"
		 "\x1b[32m1\x1b[39m \x1b[91m x\x1b[0m",
		 "table with a profile");
    styled_text_free (&st);

    table_free (&table);

    /* every part of a table has a role of its own */
    table_format_title (&table, "t");
    table_add_hdr_col (&table, 1, "");
    table_add_hdr_row (&table, 2, "k", "v");
    table_format_cell (&table, 0, -1, "r");
    table_format_cell (&table, 0, 0, "c");
    styled_text_add (&st, "%T", format_styled_table, &table);
    st.profile = &profile;
    err = check (err, render (&st, ST_O_UNKNOWN),
		 "\x1b[3mt \x1b[23m\n"
		 "\x1b[4mk\x1b[24m \x1b[4mv\x1b[24m\n"
		 "\x1b[33mr\x1b[39m \x1b[32mc\x1b[0m",
		 "table roles");
    styled_text_free (&st);
    table_free (&table);
  }

  /* a freed object is empty and usable */
  styled_text_add (&st, "x");
  styled_text_begin (&st, (styled_text_style_t) { .bold = ST_A_ON });
  styled_text_free (&st);
  if (err == 0 && (st.string || st.fmt_chg))
    err = clib_error_return (0, "free: object is not empty");
  styled_text_add (&st, "again");
  err = check (err, render (&st, ST_O_UNKNOWN), "again", "reuse");
  styled_text_free (&st);

  return err;
}

REGISTER_TEST (styled_text) = {
  .name = "styled_text",
  .fn = test_styled_text,
};
