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

#ifndef included_format_h
#define included_format_h

#include <stdarg.h>

#include <vppinfra/clib.h>	/* for CLIB_UNIX, etc. */
#include <vppinfra/vec.h>
#include <vppinfra/error.h>	/* for ASSERT */
#include <vppinfra/string.h>

typedef u8 *(format_function_t) (u8 * s, va_list * args);

u8 *va_format (u8 * s, const char *format, va_list * args);
u8 *format (u8 * s, const char *format, ...);

#ifdef CLIB_UNIX

#include <stdio.h>

#else /* ! CLIB_UNIX */

/* We're not Unix and have not stdio.h */
#define FILE void
#define stdin ((FILE *) 0)
#define stdout ((FILE *) 1)
#define stderr ((FILE *) 2)

#endif

word va_fformat (FILE * f, char *fmt, va_list * va);
word fformat (FILE * f, char *fmt, ...);
word fdformat (int fd, char *fmt, ...);

always_inline u32
format_get_indent (u8 * s)
{
  u32 indent = 0;
  u8 *nl;

  if (!s)
    return indent;

  nl = vec_end (s) - 1;
  while (nl >= s)
    {
      if (*nl-- == '\n')
	break;
      indent++;
    }
  return indent;
}

#define _(f) __clib_export u8 * f (u8 * s, va_list * va)

/* Standard user-defined formats. */
_(format_vec32);
_(format_vec_uword);
_(format_ascii_bytes);
_(format_hex_bytes);
_(format_hex_bytes_no_wrap);
_(format_white_space);
_(format_f64);
_(format_time_interval);
_ (format_duration);

#ifdef CLIB_UNIX
/* Unix specific formats. */
_(format_address_family);
_(format_network_address);
_(format_network_protocol);
_(format_network_port);
_(format_sockaddr);
_(format_timeval);
_(format_time_float);
_(format_signal);
_(format_ucontext_pc);
#endif

#undef _

/* Unformat. */

typedef struct _unformat_input_t
{
  /* Input buffer (vector). */
  u8 *buffer;

  /* Current index in input buffer. */
  uword index;

  /* Vector of buffer marks.  Used to delineate pieces of the buffer
     for error reporting and for parse recovery. */
  uword *buffer_marks;

  /* User's function to fill the buffer when its empty
     (and argument). */
    uword (*fill_buffer) (struct _unformat_input_t * i);

  /* Return values for fill buffer function which indicate whether not
     input has been exhausted. */
#define UNFORMAT_END_OF_INPUT (~0)
#define UNFORMAT_MORE_INPUT   0

  /* User controlled argument to fill buffer function. */
  void *fill_buffer_arg;
} unformat_input_t;

always_inline void
unformat_init (unformat_input_t * i,
	       uword (*fill_buffer) (unformat_input_t *),
	       void *fill_buffer_arg)
{
  clib_memset (i, 0, sizeof (i[0]));
  i->fill_buffer = fill_buffer;
  i->fill_buffer_arg = fill_buffer_arg;
}

always_inline void
unformat_free (unformat_input_t * i)
{
  vec_free (i->buffer);
  vec_free (i->buffer_marks);
  clib_memset (i, 0, sizeof (i[0]));
}

always_inline uword
unformat_check_input (unformat_input_t * i)
{
  /* Low level fill input function. */
  extern uword _unformat_fill_input (unformat_input_t * i);

  if (i->index >= vec_len (i->buffer) && i->index != UNFORMAT_END_OF_INPUT)
    _unformat_fill_input (i);

  return i->index;
}

/* Return true if input is exhausted */
always_inline uword
unformat_is_eof (unformat_input_t * input)
{
  return unformat_check_input (input) == UNFORMAT_END_OF_INPUT;
}

/* Return next element in input vector,
   possibly calling fill input to get more. */
always_inline uword
unformat_get_input (unformat_input_t * input)
{
  uword i = unformat_check_input (input);
  if (i < vec_len (input->buffer))
    {
      input->index = i + 1;
      i = input->buffer[i];
    }
  return i;
}

/* Back up input pointer by one. */
always_inline void
unformat_put_input (unformat_input_t * input)
{
  input->index -= 1;
}

/* Peek current input character without advancing. */
always_inline uword
unformat_peek_input (unformat_input_t * input)
{
  uword c = unformat_get_input (input);
  if (c != UNFORMAT_END_OF_INPUT)
    unformat_put_input (input);
  return c;
}

/* Skip current input line. */
always_inline void
unformat_skip_line (unformat_input_t * i)
{
  uword c;

  while ((c = unformat_get_input (i)) != UNFORMAT_END_OF_INPUT && c != '\n')
    ;
}

uword unformat_skip_white_space (unformat_input_t * input);

/* Unformat function. */
typedef uword (unformat_function_t) (unformat_input_t * input,
				     va_list * args);

/* External functions. */

/* General unformatting function with programmable input stream. */
uword unformat (unformat_input_t * i, const char *fmt, ...);

/* Call user defined parse function.
   unformat_user (i, f, ...) is equivalent to unformat (i, "%U", f, ...) */
uword unformat_user (unformat_input_t * input, unformat_function_t * func,
		     ...);

/* Alternate version which allows for extensions. */
uword va_unformat (unformat_input_t * i, const char *fmt, va_list * args);

/* Setup for unformat of Unix style command line. */
void unformat_init_command_line (unformat_input_t * input, char *argv[]);

/* Setup for unformat of given string. */
void unformat_init_string (unformat_input_t *input, const char *string,
			   int string_len);

always_inline void
unformat_init_cstring (unformat_input_t * input, char *string)
{
  unformat_init_string (input, string, strlen (string));
}

/* Setup for unformat of given vector string; vector will be freed by unformat_string. */
void unformat_init_vector (unformat_input_t * input, u8 * vector_string);

/* Format function for unformat input usable when an unformat error
   has occurred. */
u8 *format_unformat_error (u8 * s, va_list * va);

#define unformat_parse_error(input)						\
  clib_error_return (0, "parse error `%U'", format_unformat_error, input)

/* Print all input: not just error context. */
u8 *format_unformat_input (u8 * s, va_list * va);

/* Unformat (parse) function which reads a %s string and converts it
   to and unformat_input_t. */
unformat_function_t unformat_input;

/* Parse a line ending with \n and return it. */
unformat_function_t unformat_line;

/* Parse a line ending with \n and return it as an unformat_input_t. */
unformat_function_t unformat_line_input;

/* Parse a token containing given set of characters. */
unformat_function_t unformat_token;

/* Parses a hexstring into a vector of bytes. */
unformat_function_t unformat_hex_string;

/* Returns non-zero match if input is exhausted.
   Useful to ensure that the entire input matches with no trailing junk. */
unformat_function_t unformat_eof;

/* Parse memory size e.g. 100, 100k, 100m, 100g. */
unformat_function_t unformat_memory_size;

/* Format base 10 e.g. 100, 100K, 100M, 100G */
u8 *format_base10 (u8 *s, va_list *va);

/* Unparse memory size e.g. 100, 100k, 100m, 100g. */
u8 *format_memory_size (u8 * s, va_list * va);

/* Parse memory page size e.g. 4K, 2M */
unformat_function_t unformat_log2_page_size;

/* Unparse memory page size e.g. 4K, 2M */
u8 *format_log2_page_size (u8 * s, va_list * va);

/* Format c identifier: e.g. a_name -> "a name". */
u8 *format_c_identifier (u8 * s, va_list * va);

/* Format hexdump with both hex and printable chars - compatible with text2pcap */
u8 *format_hexdump (u8 * s, va_list * va);

/* Format bitmap of array of u64 numbers */
u8 *format_u64_bitmap (u8 *s, va_list *va);

/* Unix specific formats. */
#ifdef CLIB_UNIX
/* Setup input from Unix file. */
void unformat_init_clib_file (unformat_input_t * input, int file_descriptor);

/* Take input from Unix environment variable; returns
   1 if variable exists zero otherwise. */
uword unformat_init_unix_env (unformat_input_t * input, char *var);

/* Unformat unix group id (gid) specified as integer or string */
unformat_function_t unformat_unix_gid;
#endif /* CLIB_UNIX */

uword unformat_data_size (unformat_input_t * input, va_list * args);

/* Test code. */
int test_format_main (unformat_input_t * input);
int test_unformat_main (unformat_input_t * input);

/* This is not the right place for this, but putting it in vec.h
created circular dependency problems. */
int test_vec_main (unformat_input_t * input);

#endif /* included_format_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
