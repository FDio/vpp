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
/*------------------------------------------------------------------
 * format.c -- see notice below
 *
 * October 2003, Eliot Dresselhaus
 *
 * Modifications to this file Copyright (c) 2003 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

/*
  Copyright (c) 2001, 2002, 2003, 2006 Eliot Dresselhaus

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

#include <stdarg.h>		/* va_start, etc */

#ifdef CLIB_UNIX
#include <unistd.h>
#include <stdio.h>
#endif

#ifdef CLIB_STANDALONE
#include <vppinfra/standalone_stdio.h>
#endif

#include <vppinfra/mem.h>
#include <vppinfra/format.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/string.h>
#include <vppinfra/os.h>	/* os_puts */
#include <vppinfra/math.h>

typedef struct
{
  /* Output number in this base. */
  u8 base;

  /* Number of show of 64 bit number. */
  u8 n_bits;

  /* Signed or unsigned. */
  u8 is_signed;

  /* Output digits uppercase (not lowercase) %X versus %x. */
  u8 uppercase_digits;
} format_integer_options_t;

static u8 *format_integer (u8 * s, u64 number,
			   format_integer_options_t * options);
static u8 *format_float (u8 * s, f64 x, uword n_digits_to_print,
			 uword output_style);

typedef struct
{
  /* String justification: + => right, - => left, = => center. */
  uword justify;

  /* Width of string (before and after decimal point for numbers).
     0 => natural width. */
  uword width[2];

  /* Long => 'l', long long 'L', int 0. */
  uword how_long;

  /* Pad character.  Defaults to space. */
  uword pad_char;
} format_info_t;

static u8 *
justify (u8 * s, format_info_t * fi, uword s_len_orig)
{
  uword i0, l0, l1;

  i0 = s_len_orig;
  l0 = i0 + fi->width[0];
  l1 = vec_len (s);

  /* If width is zero user returned width. */
  if (l0 == i0)
    l0 = l1;

  if (l1 > l0)
    _vec_len (s) = l0;
  else if (l0 > l1)
    {
      uword n = l0 - l1;
      uword n_left = 0, n_right = 0;

      switch (fi->justify)
	{
	case '-':
	  n_right = n;
	  break;

	case '+':
	  n_left = n;
	  break;

	case '=':
	  n_right = n_left = n / 2;
	  if (n % 2)
	    n_left++;
	  break;
	}
      if (n_left > 0)
	{
	  vec_insert (s, n_left, i0);
	  memset (s + i0, fi->pad_char, n_left);
	  l1 = vec_len (s);
	}
      if (n_right > 0)
	{
	  vec_resize (s, n_right);
	  memset (s + l1, fi->pad_char, n_right);
	}
    }
  return s;
}

static const u8 *
do_percent (u8 ** _s, const u8 * fmt, va_list * va)
{
  u8 *s = *_s;
  uword c;

  const u8 *f = fmt;

  format_info_t fi = {
    .justify = '+',
    .width = {0},
    .pad_char = ' ',
    .how_long = 0,
  };

  uword i;

  ASSERT (f[0] == '%');

  switch (c = *++f)
    {
    case '%':
      /* %% => % */
      vec_add1 (s, c);
      f++;
      goto done;

    case '-':
    case '+':
    case '=':
      fi.justify = c;
      c = *++f;
      break;
    }

  /* Parse width0 . width1. */
  {
    uword is_first_digit = 1;

    fi.width[0] = fi.width[1] = 0;
    for (i = 0; i < 2; i++)
      {
	if (c == '0' && i == 0 && is_first_digit)
	  fi.pad_char = '0';
	is_first_digit = 0;
	if (c == '*')
	  {
	    fi.width[i] = va_arg (*va, int);
	    c = *++f;
	  }
	else
	  {
	    while (c >= '0' && c <= '9')
	      {
		fi.width[i] = 10 * fi.width[i] + (c - '0');
		c = *++f;
	      }
	  }
	if (c != '.')
	  break;
	c = *++f;
      }
  }

  /* Parse %l* and %L* */
  switch (c)
    {
    case 'w':
      /* word format. */
      fi.how_long = 'w';
      c = *++f;
      break;

    case 'L':
    case 'l':
      fi.how_long = c;
      c = *++f;
      if (c == 'l' && *f == 'l')
	{
	  fi.how_long = 'L';
	  c = *++f;
	}
      break;
    }

  /* Finally we are ready for format letter. */
  if (c != 0)
    {
      uword s_initial_len = vec_len (s);
      format_integer_options_t o = {
	.is_signed = 0,
	.base = 10,
	.n_bits = BITS (uword),
	.uppercase_digits = 0,
      };

      f++;

      switch (c)
	{
	default:
	  {
	    /* Try to give a helpful error message. */
	    vec_free (s);
	    s = format (s, "**** CLIB unknown format `%%%c' ****", c);
	    goto done;
	  }

	case 'c':
	  vec_add1 (s, va_arg (*va, int));
	  break;

	case 'p':
	  vec_add1 (s, '0');
	  vec_add1 (s, 'x');

	  o.is_signed = 0;
	  o.n_bits = BITS (uword *);
	  o.base = 16;
	  o.uppercase_digits = 0;

	  s = format_integer (s, pointer_to_uword (va_arg (*va, void *)), &o);
	  break;

	case 'x':
	case 'X':
	case 'u':
	case 'd':
	  {
	    u64 number;

	    o.base = 10;
	    if (c == 'x' || c == 'X')
	      o.base = 16;
	    o.is_signed = c == 'd';
	    o.uppercase_digits = c == 'X';

	    switch (fi.how_long)
	      {
	      case 'L':
		number = va_arg (*va, unsigned long long);
		o.n_bits = BITS (unsigned long long);
		break;

	      case 'l':
		number = va_arg (*va, long);
		o.n_bits = BITS (long);
		break;

	      case 'w':
		number = va_arg (*va, word);
		o.n_bits = BITS (uword);
		break;

	      default:
		number = va_arg (*va, int);
		o.n_bits = BITS (int);
		break;
	      }

	    s = format_integer (s, number, &o);
	  }
	  break;

	case 's':
	case 'S':
	  {
	    char *cstring = va_arg (*va, char *);
	    uword len;

	    if (!cstring)
	      {
		cstring = "(nil)";
		len = 5;
	      }
	    else if (fi.width[1] != 0)
	      len = clib_min (strlen (cstring), fi.width[1]);
	    else
	      len = strlen (cstring);

	    /* %S => format string as C identifier (replace _ with space). */
	    if (c == 'S')
	      {
		for (i = 0; i < len; i++)
		  vec_add1 (s, cstring[i] == '_' ? ' ' : cstring[i]);
	      }
	    else
	      vec_add (s, cstring, len);
	  }
	  break;

	case 'v':
	  {
	    u8 *v = va_arg (*va, u8 *);
	    uword len;

	    if (fi.width[1] != 0)
	      len = clib_min (vec_len (v), fi.width[1]);
	    else
	      len = vec_len (v);

	    vec_add (s, v, len);
	  }
	  break;

	case 'f':
	case 'g':
	case 'e':
	  /* Floating point. */
	  ASSERT (fi.how_long == 0 || fi.how_long == 'l');
	  s = format_float (s, va_arg (*va, double), fi.width[1], c);
	  break;

	case 'U':
	  /* User defined function. */
	  {
	    typedef u8 *(user_func_t) (u8 * s, va_list * args);
	    user_func_t *u = va_arg (*va, user_func_t *);

	    s = (*u) (s, va);
	  }
	  break;
	}

      s = justify (s, &fi, s_initial_len);
    }

done:
  *_s = s;
  return f;
}

u8 *
va_format (u8 * s, const char *fmt, va_list * va)
{
  const u8 *f = (u8 *) fmt, *g;
  u8 c;

  g = f;
  while (1)
    {
      c = *f;

      if (!c)
	break;

      if (c == '%')
	{
	  if (f > g)
	    vec_add (s, g, f - g);
	  f = g = do_percent (&s, f, va);
	}
      else
	{
	  f++;
	}
    }

  if (f > g)
    vec_add (s, g, f - g);

  return s;
}

u8 *
format (u8 * s, const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  s = va_format (s, fmt, &va);
  va_end (va);
  return s;
}

word
va_fformat (FILE * f, char *fmt, va_list * va)
{
  word ret;
  u8 *s;

  s = va_format (0, fmt, va);

#ifdef CLIB_UNIX
  if (f)
    {
      ret = fwrite (s, vec_len (s), 1, f);
    }
  else
#endif /* CLIB_UNIX */
    {
      ret = 0;
      os_puts (s, vec_len (s), /* is_error */ 0);
    }

  vec_free (s);
  return ret;
}

word
fformat (FILE * f, char *fmt, ...)
{
  va_list va;
  word ret;

  va_start (va, fmt);
  ret = va_fformat (f, fmt, &va);
  va_end (va);

  return (ret);
}

#ifdef CLIB_UNIX
void
fformat_append_cr (FILE * ofp, const char *fmt, ...)
{
  va_list va;

  va_start (va, fmt);
  (void) va_fformat (ofp, (char *) fmt, &va);
  va_end (va);
  fformat (ofp, "\n");
}

word
fdformat (int fd, char *fmt, ...)
{
  word ret;
  u8 *s;
  va_list va;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  ret = write (fd, s, vec_len (s));
  vec_free (s);
  return ret;
}
#endif

/* Format integral type. */
static u8 *
format_integer (u8 * s, u64 number, format_integer_options_t * options)
{
  u64 q;
  u32 r;
  u8 digit_buffer[128];
  u8 *d = digit_buffer + sizeof (digit_buffer);
  word c, base;

  if (options->is_signed && (i64) number < 0)
    {
      number = -number;
      vec_add1 (s, '-');
    }

  if (options->n_bits < BITS (number))
    number &= ((u64) 1 << options->n_bits) - 1;

  base = options->base;

  while (1)
    {
      q = number / base;
      r = number % base;

      if (r < 10 + 26 + 26)
	{
	  if (r < 10)
	    c = '0' + r;
	  else if (r < 10 + 26)
	    c = 'a' + (r - 10);
	  else
	    c = 'A' + (r - 10 - 26);

	  if (options->uppercase_digits
	      && base <= 10 + 26 && c >= 'a' && c <= 'z')
	    c += 'A' - 'a';

	  *--d = c;
	}
      else			/* will never happen, warning be gone */
	{
	  *--d = '?';
	}

      if (q == 0)
	break;

      number = q;
    }

  vec_add (s, d, digit_buffer + sizeof (digit_buffer) - d);
  return s;
}

/* Floating point formatting. */
/* Deconstruct IEEE 64 bit number into sign exponent and fraction. */
#define f64_down(f,sign,expon,fraction)				\
do {								\
  union { u64 u; f64 f; } _f64_down_tmp;			\
  _f64_down_tmp.f = (f);					\
  (sign) = (_f64_down_tmp.u >> 63);				\
  (expon) = ((_f64_down_tmp.u >> 52) & 0x7ff) - 1023;		\
  (fraction) = ((_f64_down_tmp.u << 12) >> 12) | ((u64) 1 << 52); \
} while (0)

/* Construct IEEE 64 bit number. */
static f64
f64_up (uword sign, word expon, u64 fraction)
{
  union
  {
    u64 u;
    f64 f;
  } tmp;

  tmp.u = (u64) ((sign) != 0) << 63;

  expon += 1023;
  if (expon > 1023)
    expon = 1023;
  if (expon < 0)
    expon = 0;
  tmp.u |= (u64) expon << 52;

  tmp.u |= fraction & (((u64) 1 << 52) - 1);

  return tmp.f;
}

/* Returns approximate precision of number given its exponent. */
static f64
f64_precision (int base2_expon)
{
  static int n_bits = 0;

  if (!n_bits)
    {
      /* Compute number of significant bits in floating point representation. */
      f64 one = 0;
      f64 small = 1;

      while (one != 1)
	{
	  small *= .5;
	  n_bits++;
	  one = 1 + small;
	}
    }

  return f64_up (0, base2_expon - n_bits, 0);
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

/* Write x = y * 10^expon with 1 < y < 10. */
static f64
normalize (f64 x, word * expon_return, f64 * prec_return)
{
  word expon2, expon10;
  CLIB_UNUSED (u64 fraction);
  CLIB_UNUSED (word sign);
  f64 prec;

  f64_down (x, sign, expon2, fraction);

  expon10 =
    .5 +
    expon2 * .301029995663981195213738894724493 /* Log (2) / Log (10) */ ;

  prec = f64_precision (expon2);
  x = times_power_of_ten (x, -expon10);
  prec = times_power_of_ten (prec, -expon10);

  while (x < 1)
    {
      x *= 10;
      prec *= 10;
      expon10--;
    }

  while (x > 10)
    {
      x *= .1;
      prec *= .1;
      expon10++;
    }

  if (x + prec >= 10)
    {
      x = 1;
      expon10++;
    }

  *expon_return = expon10;
  *prec_return = prec;

  return x;
}

static u8 *
add_some_zeros (u8 * s, uword n_zeros)
{
  while (n_zeros > 0)
    {
      vec_add1 (s, '0');
      n_zeros--;
    }
  return s;
}

/* Format a floating point number with the given number of fractional
   digits (e.g. 1.2345 with 2 fraction digits yields "1.23") and output style. */
static u8 *
format_float (u8 * s, f64 x, uword n_fraction_digits, uword output_style)
{
  f64 prec;
  word sign, expon, n_fraction_done, added_decimal_point;
  /* Position of decimal point relative to where we are. */
  word decimal_point;

  /* Default number of digits to print when its not specified. */
  if (n_fraction_digits == ~0)
    n_fraction_digits = 7;
  n_fraction_done = 0;
  decimal_point = 0;
  added_decimal_point = 0;
  sign = expon = 0;

  /* Special case: zero. */
  if (x == 0)
    {
    do_zero:
      vec_add1 (s, '0');
      goto done;
    }

  if (x < 0)
    {
      x = -x;
      sign = 1;
    }

  /* Check for not-a-number. */
  if (isnan (x))
    return format (s, "%cNaN", sign ? '-' : '+');

  /* Check for infinity. */
  if (isinf (x))
    return format (s, "%cinfinity", sign ? '-' : '+');

  x = normalize (x, &expon, &prec);

  /* Not enough digits to print anything: so just print 0 */
  if ((word) - expon > (word) n_fraction_digits
      && (output_style == 'f' || (output_style == 'g')))
    goto do_zero;

  if (sign)
    vec_add1 (s, '-');

  if (output_style == 'f'
      || (output_style == 'g' && expon > -10 && expon < 10))
    {
      if (expon < 0)
	{
	  /* Add decimal point and leading zeros. */
	  vec_add1 (s, '.');
	  n_fraction_done = clib_min (-(expon + 1), n_fraction_digits);
	  s = add_some_zeros (s, n_fraction_done);
	  decimal_point = -n_fraction_done;
	  added_decimal_point = 1;
	}
      else
	decimal_point = expon + 1;
    }
  else
    {
      /* Exponential output style. */
      decimal_point = 1;
      output_style = 'e';
    }

  while (1)
    {
      uword digit;

      /* Number is smaller than precision: call it zero. */
      if (x < prec)
	break;

      digit = x;
      x -= digit;
      if (x + prec >= 1)
	{
	  digit++;
	  x -= 1;
	}

      /* Round last printed digit. */
      if (decimal_point <= 0
	  && n_fraction_done + 1 == n_fraction_digits && digit < 9)
	digit += x >= .5;

      vec_add1 (s, '0' + digit);

      /* Move rightwards towards/away from decimal point. */
      decimal_point--;

      n_fraction_done += decimal_point < 0;
      if (decimal_point <= 0 && n_fraction_done >= n_fraction_digits)
	break;

      if (decimal_point == 0 && x != 0)
	{
	  vec_add1 (s, '.');
	  added_decimal_point = 1;
	}

      x *= 10;
      prec *= 10;
    }

done:
  if (decimal_point > 0)
    {
      s = add_some_zeros (s, decimal_point);
      decimal_point = 0;
    }

  if (n_fraction_done < n_fraction_digits)
    {
      if (!added_decimal_point)
	vec_add1 (s, '.');
      s = add_some_zeros (s, n_fraction_digits - n_fraction_done);
    }

  if (output_style == 'e')
    s = format (s, "e%wd", expon);

  return s;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
