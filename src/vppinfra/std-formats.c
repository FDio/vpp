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
#include <ctype.h>

/* Format vectors. */
u8 *
format_vec32 (u8 * s, va_list * va)
{
  u32 *v = va_arg (*va, u32 *);
  char *fmt = va_arg (*va, char *);
  uword i;
  for (i = 0; i < vec_len (v); i++)
    {
      if (i > 0)
	s = format (s, ", ");
      s = format (s, fmt, v[i]);
    }
  return s;
}

u8 *
format_vec_uword (u8 * s, va_list * va)
{
  uword *v = va_arg (*va, uword *);
  char *fmt = va_arg (*va, char *);
  uword i;
  for (i = 0; i < vec_len (v); i++)
    {
      if (i > 0)
	s = format (s, ", ");
      s = format (s, fmt, v[i]);
    }
  return s;
}

/* Ascii buffer and length. */
u8 *
format_ascii_bytes (u8 * s, va_list * va)
{
  u8 *v = va_arg (*va, u8 *);
  uword n_bytes = va_arg (*va, uword);
  vec_add (s, v, n_bytes);
  return s;
}

/* Format hex dump. */
u8 *
format_hex_bytes (u8 * s, va_list * va)
{
  u8 *bytes = va_arg (*va, u8 *);
  int n_bytes = va_arg (*va, int);
  uword i;

  /* Print short or long form depending on byte count. */
  uword short_form = n_bytes <= 32;
  u32 indent = format_get_indent (s);

  if (n_bytes == 0)
    return s;

  for (i = 0; i < n_bytes; i++)
    {
      if (!short_form && (i % 32) == 0)
	s = format (s, "%08x: ", i);

      s = format (s, "%02x", bytes[i]);

      if (!short_form && ((i + 1) % 32) == 0 && (i + 1) < n_bytes)
	s = format (s, "\n%U", format_white_space, indent);
    }

  return s;
}

u8 *
format_hex_bytes_no_wrap (u8 * s, va_list * va)
{
  u8 *bytes = va_arg (*va, u8 *);
  int n_bytes = va_arg (*va, int);
  uword i;

  if (n_bytes == 0)
    return s;

  for (i = 0; i < n_bytes; i++)
    s = format (s, "%02x", bytes[i]);

  return s;
}

/* Add variable number of spaces. */
u8 *
format_white_space (u8 * s, va_list * va)
{
  u32 n = va_arg (*va, u32);
  while (n-- > 0)
    vec_add1 (s, ' ');
  return s;
}

u8 *
format_duration (u8 *s, va_list *args)
{
  f64 t = va_arg (*args, f64);
  s = format (s, "");

  const f64 seconds_per_minute = 60;
  const f64 seconds_per_hour = 60 * seconds_per_minute;
  const f64 seconds_per_day = 24 * seconds_per_hour;
  uword days, hours, minutes, secs, msecs, usecs;

  days = t / seconds_per_day;
  t -= days * seconds_per_day;

  hours = t / seconds_per_hour;
  t -= hours * seconds_per_hour;

  minutes = t / seconds_per_minute;
  t -= minutes * seconds_per_minute;

  secs = t;
  t -= secs;

  msecs = 1e3 * t;

  usecs = 1e6 * t;
  usecs = usecs % 1000;

  if (days)
    s = format (s, "%ddays ", days);
  if (hours)
    s = format (s, "%dh ", hours);
  if (minutes)
    s = format (s, "%dmin ", minutes);
  if (secs)
    s = format (s, "%ds ", secs);
  if (msecs)
    s = format (s, "%dms ", msecs);
  if (usecs)
    s = format (s, "%dus", usecs);

  return (s);
}

u8 *
format_time_interval (u8 * s, va_list * args)
{
  u8 *fmt = va_arg (*args, u8 *);
  f64 t = va_arg (*args, f64);
  u8 *f;

  const f64 seconds_per_minute = 60;
  const f64 seconds_per_hour = 60 * seconds_per_minute;
  const f64 seconds_per_day = 24 * seconds_per_hour;
  uword days, hours, minutes, secs, msecs, usecs;

  days = t / seconds_per_day;
  t -= days * seconds_per_day;

  hours = t / seconds_per_hour;
  t -= hours * seconds_per_hour;

  minutes = t / seconds_per_minute;
  t -= minutes * seconds_per_minute;

  secs = t;
  t -= secs;

  msecs = 1e3 * t;
  usecs = 1e6 * t;

  for (f = fmt; *f; f++)
    {
      uword what, c;
      char *what_fmt = "%d";

      switch (c = *f)
	{
	default:
	  vec_add1 (s, c);
	  continue;

	case 'd':
	  what = days;
	  what_fmt = "%d";
	  break;
	case 'h':
	  what = hours;
	  what_fmt = "%02d";
	  break;
	case 'm':
	  what = minutes;
	  what_fmt = "%02d";
	  break;
	case 's':
	  what = secs;
	  what_fmt = "%02d";
	  break;
	case 'f':
	  what = msecs;
	  what_fmt = "%03d";
	  break;
	case 'u':
	  what = usecs;
	  what_fmt = "%06d";
	  break;
	}

      s = format (s, what_fmt, what);
    }

  return s;
}

/* Format base 10 e.g. 100, 100K, 100M, 100G */
__clib_export u8 *
format_base10 (u8 *s, va_list *va)
{
  uword size = va_arg (*va, uword);

  if (size < 1000)
    s = format (s, "%d", size);
  else if (size < 1000000)
    s = format (s, "%.2fK", (f64) size / 1000.);
  else if (size < 1000000000)
    s = format (s, "%.2fM", (f64) size / 1000000.);
  else
    s = format (s, "%.2fG", (f64) size / 1000000000.);

  return s;
}

/* Unparse memory size e.g. 100, 100k, 100m, 100g. */
__clib_export u8 *
format_memory_size (u8 * s, va_list * va)
{
  uword size = va_arg (*va, uword);
  uword l, u, log_u;

  l = size > 0 ? min_log2 (size) : 0;
  if (l < 10)
    log_u = 0;
  else if (l < 20)
    log_u = 10;
  else if (l < 30)
    log_u = 20;
  else
    log_u = 30;

  u = (uword) 1 << log_u;
  if (size & (u - 1))
    s = format (s, "%.2f", (f64) size / (f64) u);
  else
    s = format (s, "%d", size >> log_u);

  if (log_u != 0)
    s = format (s, "%c", " kmg"[log_u / 10]);

  return s;
}

/* Parse memory size e.g. 100, 100k, 100m, 100g. */
__clib_export uword
unformat_memory_size (unformat_input_t * input, va_list * va)
{
  uword amount, shift, c;
  uword *result = va_arg (*va, uword *);

  if (!unformat (input, "%wd%_", &amount))
    return 0;

  c = unformat_get_input (input);
  switch (c)
    {
    case 'k':
    case 'K':
      shift = 10;
      break;
    case 'm':
    case 'M':
      shift = 20;
      break;
    case 'g':
    case 'G':
      shift = 30;
      break;
    default:
      shift = 0;
      unformat_put_input (input);
      break;
    }

  *result = amount << shift;
  return 1;
}

/* Unparse memory page size e.g. 4K, 2M */
__clib_export u8 *
format_log2_page_size (u8 * s, va_list * va)
{
  clib_mem_page_sz_t log2_page_sz = va_arg (*va, clib_mem_page_sz_t);

  if (log2_page_sz == CLIB_MEM_PAGE_SZ_UNKNOWN)
    return format (s, "unknown");

  if (log2_page_sz == CLIB_MEM_PAGE_SZ_DEFAULT)
    return format (s, "default");

  if (log2_page_sz == CLIB_MEM_PAGE_SZ_DEFAULT_HUGE)
    return format (s, "default-hugepage");

  if (log2_page_sz >= 30)
    return format (s, "%uG", 1 << (log2_page_sz - 30));

  if (log2_page_sz >= 20)
    return format (s, "%uM", 1 << (log2_page_sz - 20));

  if (log2_page_sz >= 10)
    return format (s, "%uK", 1 << (log2_page_sz - 10));

  return format (s, "%u", 1 << log2_page_sz);
}

/* Parse memory page size e.g. 4K, 2M */
__clib_export uword
unformat_log2_page_size (unformat_input_t * input, va_list * va)
{
  uword amount;
  clib_mem_page_sz_t *result = va_arg (*va, clib_mem_page_sz_t *);

  if (unformat (input, "default-hugepage"))
    *result = CLIB_MEM_PAGE_SZ_DEFAULT_HUGE;
  else if (unformat (input, "default"))
    *result = CLIB_MEM_PAGE_SZ_DEFAULT;
  else if (unformat (input, "%wdk", &amount))
    *result = min_log2 (amount) + 10;
  else if (unformat (input, "%wdK", &amount))
    *result = min_log2 (amount) + 10;
  else if (unformat (input, "%wdm", &amount))
    *result = min_log2 (amount) + 20;
  else if (unformat (input, "%wdM", &amount))
    *result = min_log2 (amount) + 20;
  else if (unformat (input, "%wdg", &amount))
    *result = min_log2 (amount) + 30;
  else if (unformat (input, "%wdG", &amount))
    *result = min_log2 (amount) + 30;
  else
    return 0;
  return 1;
}

/* Format c identifier: e.g. a_name -> "a name".
   Works for both vector names and null terminated c strings. */
__clib_export u8 *
format_c_identifier (u8 * s, va_list * va)
{
  u8 *id = va_arg (*va, u8 *);
  uword i, l;

  l = ~0;
  if (clib_mem_is_vec (id))
    l = vec_len (id);

  if (id)
    for (i = 0; i < l && id[i] != 0; i++)
      {
	u8 c = id[i];

	if (c == '_')
	  c = ' ';
	vec_add1 (s, c);
      }

  return s;
}

__clib_export u8 *
format_hexdump (u8 * s, va_list * args)
{
  u8 *data = va_arg (*args, u8 *);
  uword len = va_arg (*args, uword);
  int i, index = 0;
  const int line_len = 16;
  u8 *line_hex = 0;
  u8 *line_str = 0;
  u32 indent = format_get_indent (s);

  if (!len)
    return s;

  for (i = 0; i < len; i++)
    {
      line_hex = format (line_hex, "%02x ", data[i]);
      line_str = format (line_str, "%c", isprint (data[i]) ? data[i] : '.');
      if (!((i + 1) % line_len))
	{
	  s = format (s, "%U%05x: %v[%v]",
		      format_white_space, index ? indent : 0,
		      index, line_hex, line_str);
	  if (i < len - 1)
	    s = format (s, "\n");
	  index = i + 1;
	  vec_reset_length (line_hex);
	  vec_reset_length (line_str);
	}
    }

  while (i++ % line_len)
    line_hex = format (line_hex, "   ");

  if (vec_len (line_hex))
    s = format (s, "%U%05x: %v[%v]",
		format_white_space, index ? indent : 0,
		index, line_hex, line_str);

  vec_free (line_hex);
  vec_free (line_str);

  return s;
}

__clib_export u8 *
format_u64_bitmap (u8 *s, va_list *args)
{
  u64 *bitmap = va_arg (*args, u64 *);
  int n_uword = va_arg (*args, int);
  u32 indent = format_get_indent (s);

  s = format (s, "%6s", "");

  for (int i = 60; i >= 0; i -= 4)
    s = format (s, "%5d", i);

  vec_add1 (s, '\n');

  for (int j = n_uword - 1; j >= 0; j--)
    {
      s = format (s, "%U0x%04x ", format_white_space, indent, j * 8);
      for (int i = 63; i >= 0; i--)
	{
	  vec_add1 (s, (1ULL << i) & bitmap[j] ? '1' : '.');
	  if (i % 4 == 0)
	    vec_add1 (s, ' ');
	}
      s = format (s, "0x%016lx", bitmap[j]);
      if (j)
	vec_add1 (s, '\n');
    }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
