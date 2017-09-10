/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

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

#include <vppinfra/format.h>

/* Call user's function to fill input buffer. */
uword
_unformat_fill_input (unformat_input_t * i)
{
  uword l, first_mark;

  if (i->index == UNFORMAT_END_OF_INPUT)
    return i->index;

  first_mark = l = vec_len (i->buffer);
  if (vec_len (i->buffer_marks) > 0)
    first_mark = i->buffer_marks[0];

  /* Re-use buffer when no marks. */
  if (first_mark > 0)
    vec_delete (i->buffer, first_mark, 0);

  i->index = vec_len (i->buffer);
  for (l = 0; l < vec_len (i->buffer_marks); l++)
    i->buffer_marks[l] -= first_mark;

  /* Call user's function to fill the buffer. */
  if (i->fill_buffer)
    i->index = i->fill_buffer (i);

  /* If input pointer is still beyond end of buffer even after
     fill then we've run out of input. */
  if (i->index >= vec_len (i->buffer))
    i->index = UNFORMAT_END_OF_INPUT;

  return i->index;
}

always_inline uword
is_white_space (uword c)
{
  switch (c)
    {
    case ' ':
    case '\t':
    case '\n':
    case '\r':
      return 1;

    default:
      return 0;
    }
}

/* Format function for dumping input stream. */
u8 *
format_unformat_error (u8 * s, va_list * va)
{
  unformat_input_t *i = va_arg (*va, unformat_input_t *);
  uword l = vec_len (i->buffer);

  /* Only show so much of the input buffer (it could be really large). */
  uword n_max = 30;

  if (i->index < l)
    {
      uword n = l - i->index;
      u8 *p, *p_end;

      p = i->buffer + i->index;
      p_end = p + (n > n_max ? n_max : n);

      /* Skip white space at end. */
      if (n <= n_max)
	{
	  while (p_end > p && is_white_space (p_end[-1]))
	    p_end--;
	}

      while (p < p_end)
	{
	  switch (*p)
	    {
	    case '\r':
	      vec_add (s, "\\r", 2);
	      break;
	    case '\n':
	      vec_add (s, "\\n", 2);
	      break;
	    case '\t':
	      vec_add (s, "\\t", 2);
	      break;
	    default:
	      vec_add1 (s, *p);
	      break;
	    }
	  p++;
	}

      if (n > n_max)
	vec_add (s, "...", 3);
    }

  return s;
}

/* Print everything: not just error context. */
u8 *
format_unformat_input (u8 * s, va_list * va)
{
  unformat_input_t *i = va_arg (*va, unformat_input_t *);
  uword l, n;

  if (i->index == UNFORMAT_END_OF_INPUT)
    s = format (s, "{END_OF_INPUT}");
  else
    {
      l = vec_len (i->buffer);
      n = l - i->index;
      if (n > 0)
	vec_add (s, i->buffer + i->index, n);
    }

  return s;
}

#if CLIB_DEBUG > 0
void
di (unformat_input_t * i)
{
  fformat (stderr, "%U\n", format_unformat_input, i);
}
#endif

/* Parse delimited vector string.  If string starts with { then string
   is delimited by balenced parenthesis.  Other string is delimited by
   white space.  {} were chosen since they are special to the shell. */
static uword
unformat_string (unformat_input_t * input,
		 uword delimiter_character,
		 uword format_character, va_list * va)
{
  u8 **string_return = va_arg (*va, u8 **);
  u8 *s = 0;
  word paren = 0;
  word is_paren_delimited = 0;
  word backslash = 0;
  uword c;

  switch (delimiter_character)
    {
    case '%':
    case ' ':
    case '\t':
      delimiter_character = 0;
      break;
    }

  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      word add_to_vector;

      /* Null return string means to skip over delimited input. */
      add_to_vector = string_return != 0;

      if (backslash)
	backslash = 0;
      else
	switch (c)
	  {
	  case '\\':
	    backslash = 1;
	    add_to_vector = 0;
	    break;

	  case '{':
	    if (paren == 0 && vec_len (s) == 0)
	      {
		is_paren_delimited = 1;
		add_to_vector = 0;
	      }
	    paren++;
	    break;

	  case '}':
	    paren--;
	    if (is_paren_delimited && paren == 0)
	      goto done;
	    break;

	  case ' ':
	  case '\t':
	  case '\n':
	  case '\r':
	    if (!is_paren_delimited)
	      {
		unformat_put_input (input);
		goto done;
	      }
	    break;

	  default:
	    if (!is_paren_delimited && c == delimiter_character)
	      {
		unformat_put_input (input);
		goto done;
	      }
	  }

      if (add_to_vector)
	vec_add1 (s, c);
    }

done:
  if (string_return)
    {
      /* Match the string { END-OF-INPUT as a single brace. */
      if (c == UNFORMAT_END_OF_INPUT && vec_len (s) == 0 && paren == 1)
	vec_add1 (s, '{');

      /* Don't match null string. */
      if (c == UNFORMAT_END_OF_INPUT && vec_len (s) == 0)
	return 0;

      /* Null terminate C string. */
      if (format_character == 's')
	vec_add1 (s, 0);

      *string_return = s;
    }
  else
    vec_free (s);		/* just to make sure */

  return 1;
}

uword
unformat_hex_string (unformat_input_t * input, va_list * va)
{
  u8 **hexstring_return = va_arg (*va, u8 **);
  u8 *s;
  uword n, d, c;

  n = 0;
  d = 0;
  s = 0;
  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      if (c >= '0' && c <= '9')
	d = 16 * d + c - '0';
      else if (c >= 'a' && c <= 'f')
	d = 16 * d + 10 + c - 'a';
      else if (c >= 'A' && c <= 'F')
	d = 16 * d + 10 + c - 'A';
      else
	{
	  unformat_put_input (input);
	  break;
	}
      n++;

      if (n == 2)
	{
	  vec_add1 (s, d);
	  n = d = 0;
	}
    }

  /* Hex string must have even number of digits. */
  if (n % 2)
    {
      vec_free (s);
      return 0;
    }
  /* Make sure something was processed. */
  else if (s == 0)
    {
      return 0;
    }

  *hexstring_return = s;
  return 1;
}

/* unformat (input "foo%U", unformat_eof) matches terminal foo only */
uword
unformat_eof (unformat_input_t * input, va_list * va)
{
  return unformat_check_input (input) == UNFORMAT_END_OF_INPUT;
}

/* Parse a token containing given set of characters. */
uword
unformat_token (unformat_input_t * input, va_list * va)
{
  u8 *token_chars = va_arg (*va, u8 *);
  u8 **string_return = va_arg (*va, u8 **);
  u8 *s, map[256];
  uword i, c;

  if (!token_chars)
    token_chars = (u8 *) "a-zA-Z0-9_";

  memset (map, 0, sizeof (map));
  for (s = token_chars; *s;)
    {
      /* Parse range. */
      if (s[0] < s[2] && s[1] == '-')
	{
	  for (i = s[0]; i <= s[2]; i++)
	    map[i] = 1;
	  s = s + 3;
	}
      else
	{
	  map[s[0]] = 1;
	  s = s + 1;
	}
    }

  s = 0;
  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      if (!map[c])
	{
	  unformat_put_input (input);
	  break;
	}

      vec_add1 (s, c);
    }

  if (vec_len (s) == 0)
    return 0;

  *string_return = s;
  return 1;
}

/* Unformat (parse) function which reads a %s string and converts it
   to and unformat_input_t. */
uword
unformat_input (unformat_input_t * i, va_list * args)
{
  unformat_input_t *sub_input = va_arg (*args, unformat_input_t *);
  u8 *s;

  if (unformat (i, "%v", &s))
    {
      unformat_init_vector (sub_input, s);
      return 1;
    }

  return 0;
}

/* Parse a line ending with \n and return it. */
uword
unformat_line (unformat_input_t * i, va_list * va)
{
  u8 *line = 0, **result = va_arg (*va, u8 **);
  uword c;

  while ((c = unformat_get_input (i)) != '\n' && c != UNFORMAT_END_OF_INPUT)
    {
      vec_add1 (line, c);
    }

  *result = line;
  return vec_len (line);
}

/* Parse a line ending with \n and return it as an unformat_input_t. */
uword
unformat_line_input (unformat_input_t * i, va_list * va)
{
  unformat_input_t *result = va_arg (*va, unformat_input_t *);
  u8 *line;
  if (!unformat_user (i, unformat_line, &line))
    return 0;
  unformat_init_vector (result, line);
  return 1;
}

/* Values for is_signed. */
#define UNFORMAT_INTEGER_SIGNED		1
#define UNFORMAT_INTEGER_UNSIGNED	0

static uword
unformat_integer (unformat_input_t * input,
		  va_list * va, uword base, uword is_signed, uword data_bytes)
{
  uword c, digit;
  uword value = 0;
  uword n_digits = 0;
  uword n_input = 0;
  uword sign = 0;

  /* We only support bases <= 64. */
  if (base < 2 || base > 64)
    goto error;

  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      switch (c)
	{
	case '-':
	  if (n_input == 0)
	    {
	      if (is_signed)
		{
		  sign = 1;
		  goto next_digit;
		}
	      else
		/* Leading sign for unsigned number. */
		goto error;
	    }
	  /* Sign after input (e.g. 100-200). */
	  goto put_input_done;

	case '+':
	  if (n_input > 0)
	    goto put_input_done;
	  sign = 0;
	  goto next_digit;

	case '0' ... '9':
	  digit = c - '0';
	  break;

	case 'a' ... 'z':
	  digit = 10 + (c - 'a');
	  break;

	case 'A' ... 'Z':
	  digit = 10 + (base >= 36 ? 26 : 0) + (c - 'A');
	  break;

	case '/':
	  digit = 62;
	  break;

	case '?':
	  digit = 63;
	  break;

	default:
	  goto put_input_done;
	}

      if (digit >= base)
	{
	put_input_done:
	  unformat_put_input (input);
	  goto done;
	}

      {
	uword new_value = base * value + digit;

	/* Check for overflow. */
	if (new_value < value)
	  goto error;
	value = new_value;
      }
      n_digits += 1;

    next_digit:
      n_input++;
    }

done:
  if (sign)
    value = -value;

  if (n_digits > 0)
    {
      void *v = va_arg (*va, void *);

      if (data_bytes == ~0)
	data_bytes = sizeof (int);

      switch (data_bytes)
	{
	case 1:
	  *(u8 *) v = value;
	  break;
	case 2:
	  *(u16 *) v = value;
	  break;
	case 4:
	  *(u32 *) v = value;
	  break;
	case 8:
	  *(u64 *) v = value;
	  break;
	default:
	  goto error;
	}

      return 1;
    }

error:
  return 0;
}

/* Return x 10^n */
static f64
times_power_of_ten (f64 x, int n)
{
  if (n >= 0)
    {
      static f64 t[8] = { 1e+0, 1e+1, 1e+2, 1e+3, 1e+4, 1e+5, 1e+6, 1e+7, };
      while (n >= 8)
	{
	  x *= 1e+8;
	  n -= 8;
	}
      return x * t[n];
    }
  else
    {
      static f64 t[8] = { 1e-0, 1e-1, 1e-2, 1e-3, 1e-4, 1e-5, 1e-6, 1e-7, };
      while (n <= -8)
	{
	  x *= 1e-8;
	  n += 8;
	}
      return x * t[-n];
    }

}

static uword
unformat_float (unformat_input_t * input, va_list * va)
{
  uword c;
  u64 values[3];
  uword n_digits[3], value_index = 0;
  uword signs[2], sign_index = 0;
  uword n_input = 0;

  memset (values, 0, sizeof (values));
  memset (n_digits, 0, sizeof (n_digits));
  memset (signs, 0, sizeof (signs));

  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      switch (c)
	{
	case '-':
	  if (value_index == 2 && n_digits[2] == 0)
	    /* sign of exponent: it's ok. */ ;

	  else if (value_index < 2 && n_digits[0] > 0)
	    {
	      /* 123- */
	      unformat_put_input (input);
	      goto done;
	    }

	  else if (n_input > 0)
	    goto error;

	  signs[sign_index++] = 1;
	  goto next_digit;

	case '+':
	  if (value_index == 2 && n_digits[2] == 0)
	    /* sign of exponent: it's ok. */ ;

	  else if (value_index < 2 && n_digits[0] > 0)
	    {
	      /* 123+ */
	      unformat_put_input (input);
	      goto done;
	    }

	  else if (n_input > 0)
	    goto error;
	  signs[sign_index++] = 0;
	  goto next_digit;

	case 'e':
	case 'E':
	  if (n_input == 0)
	    goto error;
	  value_index = 2;
	  sign_index = 1;
	  break;

	case '.':
	  if (value_index > 0)
	    goto error;
	  value_index = 1;
	  break;

	case '0' ... '9':
	  {
	    u64 tmp;

	    tmp = values[value_index] * 10 + c - '0';

	    /* Check for overflow. */
	    if (tmp < values[value_index])
	      goto error;
	    values[value_index] = tmp;
	    n_digits[value_index] += 1;
	  }
	  break;

	default:
	  unformat_put_input (input);
	  goto done;
	}

    next_digit:
      n_input++;
    }

done:
  {
    f64 f_values[2], *value_return;
    word expon;

    /* Must have either whole or fraction digits. */
    if (n_digits[0] + n_digits[1] <= 0)
      goto error;

    f_values[0] = values[0];
    if (signs[0])
      f_values[0] = -f_values[0];

    f_values[1] = values[1];
    f_values[1] = times_power_of_ten (f_values[1], -n_digits[1]);

    f_values[0] += f_values[1];

    expon = values[2];
    if (signs[1])
      expon = -expon;

    f_values[0] = times_power_of_ten (f_values[0], expon);

    value_return = va_arg (*va, f64 *);
    *value_return = f_values[0];
    return 1;
  }

error:
  return 0;
}

static const char *
match_input_with_format (unformat_input_t * input, const char *f)
{
  uword cf, ci;

  ASSERT (*f != 0);

  while (1)
    {
      cf = *f;
      if (cf == 0 || cf == '%' || cf == ' ')
	break;
      f++;

      ci = unformat_get_input (input);

      if (cf != ci)
	return 0;
    }
  return f;
}

static const char *
do_percent (unformat_input_t * input, va_list * va, const char *f)
{
  uword cf, n, data_bytes = ~0;

  cf = *f++;

  switch (cf)
    {
    default:
      break;

    case 'w':
      /* Word types. */
      cf = *f++;
      data_bytes = sizeof (uword);
      break;

    case 'l':
      cf = *f++;
      if (cf == 'l')
	{
	  cf = *f++;
	  data_bytes = sizeof (long long);
	}
      else
	{
	  data_bytes = sizeof (long);
	}
      break;

    case 'L':
      cf = *f++;
      data_bytes = sizeof (long long);
      break;
    }

  n = 0;
  switch (cf)
    {
    case 'D':
      data_bytes = va_arg (*va, int);
    case 'd':
      n = unformat_integer (input, va, 10,
			    UNFORMAT_INTEGER_SIGNED, data_bytes);
      break;

    case 'u':
      n = unformat_integer (input, va, 10,
			    UNFORMAT_INTEGER_UNSIGNED, data_bytes);
      break;

    case 'b':
      n = unformat_integer (input, va, 2,
			    UNFORMAT_INTEGER_UNSIGNED, data_bytes);
      break;

    case 'o':
      n = unformat_integer (input, va, 8,
			    UNFORMAT_INTEGER_UNSIGNED, data_bytes);
      break;

    case 'X':
      data_bytes = va_arg (*va, int);
    case 'x':
      n = unformat_integer (input, va, 16,
			    UNFORMAT_INTEGER_UNSIGNED, data_bytes);
      break;

    case 'f':
      n = unformat_float (input, va);
      break;

    case 's':
    case 'v':
      n = unformat_string (input, f[0], cf, va);
      break;

    case 'U':
      {
	unformat_function_t *f = va_arg (*va, unformat_function_t *);
	n = f (input, va);
      }
      break;

    case '=':
    case '|':
      {
	int *var = va_arg (*va, int *);
	uword val = va_arg (*va, int);

	if (cf == '|')
	  val |= *var;
	*var = val;
	n = 1;
      }
      break;
    }

  return n ? f : 0;
}

uword
unformat_skip_white_space (unformat_input_t * input)
{
  uword n = 0;
  uword c;

  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      if (!is_white_space (c))
	{
	  unformat_put_input (input);
	  break;
	}
      n++;
    }
  return n;
}

uword
va_unformat (unformat_input_t * input, const char *fmt, va_list * va)
{
  const char *f;
  uword input_matches_format;
  uword default_skip_input_white_space;
  uword n_input_white_space_skipped;
  uword last_non_white_space_match_percent;
  uword last_non_white_space_match_format;

  vec_add1_aligned (input->buffer_marks, input->index,
		    sizeof (input->buffer_marks[0]));

  f = fmt;
  default_skip_input_white_space = 1;
  input_matches_format = 0;
  last_non_white_space_match_percent = 0;
  last_non_white_space_match_format = 0;

  while (1)
    {
      char cf;
      uword is_percent, skip_input_white_space;

      cf = *f;
      is_percent = 0;

      /* Always skip input white space at start of format string.
         Otherwise use default skip value which can be changed by %_
         (see below). */
      skip_input_white_space = f == fmt || default_skip_input_white_space;

      /* Spaces in format request skipping input white space. */
      if (is_white_space (cf))
	{
	  skip_input_white_space = 1;

	  /* Multiple format spaces are equivalent to a single white
	     space. */
	  while (is_white_space (*++f))
	    ;
	}
      else if (cf == '%')
	{
	  /* %_ toggles whether or not to skip input white space. */
	  switch (*++f)
	    {
	    case '_':
	      default_skip_input_white_space =
		!default_skip_input_white_space;
	      f++;
	      /* For transition from skip to no-skip in middle of format
	         string, skip input white space.  For example, the following matches:
	         fmt = "%_%d.%d%_->%_%d.%d%_"
	         input "1.2 -> 3.4"
	         Without this the space after -> does not get skipped. */
	      if (!default_skip_input_white_space
		  && !(f == fmt + 2 || *f == 0))
		unformat_skip_white_space (input);
	      continue;

	      /* %% means match % */
	    case '%':
	      break;

	      /* % at end of format string. */
	    case 0:
	      goto parse_fail;

	    default:
	      is_percent = 1;
	      break;
	    }
	}

      n_input_white_space_skipped = 0;
      if (skip_input_white_space)
	n_input_white_space_skipped = unformat_skip_white_space (input);

      /* End of format string. */
      if (cf == 0)
	{
	  /* Force parse error when format string ends and input is
	     not white or at end.  As an example, this is to prevent
	     format "foo" from matching input "food".
	     The last_non_white_space_match_percent is to make
	     "foo %d" match input "foo 10,bletch" with %d matching 10. */
	  if (skip_input_white_space
	      && !last_non_white_space_match_percent
	      && !last_non_white_space_match_format
	      && n_input_white_space_skipped == 0
	      && input->index != UNFORMAT_END_OF_INPUT)
	    goto parse_fail;
	  break;
	}

      last_non_white_space_match_percent = is_percent;
      last_non_white_space_match_format = 0;

      /* Explicit spaces in format must match input white space. */
      if (cf == ' ' && !default_skip_input_white_space)
	{
	  if (n_input_white_space_skipped == 0)
	    goto parse_fail;
	}

      else if (is_percent)
	{
	  if (!(f = do_percent (input, va, f)))
	    goto parse_fail;
	}

      else
	{
	  const char *g = match_input_with_format (input, f);
	  if (!g)
	    goto parse_fail;
	  last_non_white_space_match_format = g > f;
	  f = g;
	}
    }

  input_matches_format = 1;
parse_fail:

  /* Rewind buffer marks. */
  {
    uword l = vec_len (input->buffer_marks);

    /* If we did not match back up buffer to last mark. */
    if (!input_matches_format)
      input->index = input->buffer_marks[l - 1];

    _vec_len (input->buffer_marks) = l - 1;
  }

  return input_matches_format;
}

uword
unformat (unformat_input_t * input, const char *fmt, ...)
{
  va_list va;
  uword result;
  va_start (va, fmt);
  result = va_unformat (input, fmt, &va);
  va_end (va);
  return result;
}

uword
unformat_user (unformat_input_t * input, unformat_function_t * func, ...)
{
  va_list va;
  uword result, l;

  /* Save place in input buffer in case parse fails. */
  l = vec_len (input->buffer_marks);
  vec_add1_aligned (input->buffer_marks, input->index,
		    sizeof (input->buffer_marks[0]));

  va_start (va, func);
  result = func (input, &va);
  va_end (va);

  if (!result && input->index != UNFORMAT_END_OF_INPUT)
    input->index = input->buffer_marks[l];

  _vec_len (input->buffer_marks) = l;

  return result;
}

/* Setup for unformat of Unix style command line. */
void
unformat_init_command_line (unformat_input_t * input, char *argv[])
{
  uword i;

  unformat_init (input, 0, 0);

  /* Concatenate argument strings with space in between. */
  for (i = 1; argv[i]; i++)
    {
      vec_add (input->buffer, argv[i], strlen (argv[i]));
      if (argv[i + 1])
	vec_add1 (input->buffer, ' ');
    }
}

void
unformat_init_string (unformat_input_t * input, char *string, int string_len)
{
  unformat_init (input, 0, 0);
  if (string_len > 0)
    vec_add (input->buffer, string, string_len);
}

void
unformat_init_vector (unformat_input_t * input, u8 * vector_string)
{
  unformat_init (input, 0, 0);
  input->buffer = vector_string;
}

#ifdef CLIB_UNIX

static uword
clib_file_fill_buffer (unformat_input_t * input)
{
  int fd = pointer_to_uword (input->fill_buffer_arg);
  uword l, n;

  l = vec_len (input->buffer);
  vec_resize (input->buffer, 4096);
  n = read (fd, input->buffer + l, 4096);
  if (n > 0)
    _vec_len (input->buffer) = l + n;

  if (n <= 0)
    return UNFORMAT_END_OF_INPUT;
  else
    return input->index;
}

void
unformat_init_clib_file (unformat_input_t * input, int file_descriptor)
{
  unformat_init (input, clib_file_fill_buffer,
		 uword_to_pointer (file_descriptor, void *));
}

/* Take input from Unix environment variable. */
uword
unformat_init_unix_env (unformat_input_t * input, char *var)
{
  char *val = getenv (var);
  if (val)
    unformat_init_string (input, val, strlen (val));
  return val != 0;
}

#endif /* CLIB_UNIX */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
