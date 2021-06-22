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

/* Error reporting. */
#include <stdarg.h>

#include <vppinfra/clib.h>	/* for HAVE_ERRNO */

#ifdef CLIB_LINUX_KERNEL
#include <linux/unistd.h>	/* for write */
#include <linux/kernel.h>	/* for printk */
#endif

#ifdef CLIB_UNIX
#include <unistd.h>		/* for write */
#include <stdio.h>		/* for printf */
#define HAVE_ERRNO
#endif

#ifdef CLIB_STANDALONE
#include <vppinfra/standalone_stdio.h>	/* for printf */
#endif

#include <vppinfra/string.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/os.h>	/* for os_panic/os_exit/os_puts */

typedef struct
{
  clib_error_handler_func_t *func;
  void *arg;
} clib_error_handler_t;

static clib_error_handler_t *handlers = 0;

__clib_export void
clib_error_register_handler (clib_error_handler_func_t func, void *arg)
{
  clib_error_handler_t h = {.func = func,.arg = arg, };
  vec_add1 (handlers, h);
}

static void
debugger (void)
{
  os_panic ();
}

static void
error_exit (int code)
{
  os_exit (code);
}

static u8 *
dispatch_message (u8 * msg)
{
  word i;

  if (!msg)
    return msg;

  for (i = 0; i < vec_len (handlers); i++)
    handlers[i].func (handlers[i].arg, msg, vec_len (msg));

  /* If no message handler is specified provide a default one. */
  if (vec_len (handlers) == 0)
    os_puts (msg, vec_len (msg), /* is_error */ 1);

  return msg;
}

__clib_export void
_clib_error (int how_to_die,
	     char *function_name, uword line_number, char *fmt, ...)
{
  u8 *msg = 0;
  va_list va;

  if (function_name)
    {
      msg = format (msg, "%s:", function_name);
      if (line_number > 0)
	msg = format (msg, "%wd:", line_number);
      msg = format (msg, " ");
    }

  va_start (va, fmt);
  msg = va_format (msg, fmt, &va);
  va_end (va);

#ifdef HAVE_ERRNO
  if (how_to_die & CLIB_ERROR_ERRNO_VALID)
    msg = format (msg, ": %s (errno %d)", strerror (errno), errno);
#endif

  if (vec_end (msg)[-1] != '\n')
    vec_add1 (msg, '\n');

  msg = dispatch_message (msg);

  vec_free (msg);

  if (how_to_die & CLIB_ERROR_ABORT)
    debugger ();
  if (how_to_die & CLIB_ERROR_FATAL)
    error_exit (1);
}

__clib_export clib_error_t *
_clib_error_return (clib_error_t * errors,
		    any code, uword flags, char *where, char *fmt, ...)
{
  clib_error_t *e;
  va_list va;

#ifdef HAVE_ERRNO
  /* Save errno since it may be re-set before we'll need it. */
  word errno_save = errno;
#endif

  va_start (va, fmt);
  vec_add2 (errors, e, 1);
  if (fmt)
    e->what = va_format (0, fmt, &va);

#ifdef HAVE_ERRNO
  if (flags & CLIB_ERROR_ERRNO_VALID)
    {
      if (e->what)
	e->what = format (e->what, ": ");
      e->what = format (e->what, "%s", strerror (errno_save));
    }
#endif

  e->where = (u8 *) where;
  e->code = code;
  e->flags = flags;
  va_end (va);
  return errors;
}

__clib_export void *
clib_error_free_vector (clib_error_t * errors)
{
  clib_error_t *e;
  vec_foreach (e, errors) vec_free (e->what);
  vec_free (errors);
  return 0;
}

__clib_export u8 *
format_clib_error (u8 * s, va_list * va)
{
  clib_error_t *errors = va_arg (*va, clib_error_t *);
  clib_error_t *e;

  vec_foreach (e, errors)
  {
    if (!e->what)
      continue;

    if (e->where)
      {
	u8 *where = 0;

	if (e > errors)
	  where = format (where, "from ");
	where = format (where, "%s", e->where);

	s = format (s, "%v: ", where);
	vec_free (where);
      }

    s = format (s, "%v", e->what);
    if ((vec_end (errors) - 1) != e)
      s = format (s, "\n");
  }

  return s;
}

__clib_export clib_error_t *
_clib_error_report (clib_error_t * errors)
{
  if (errors)
    {
      u8 *msg = format (0, "%U ", format_clib_error, errors);

      msg = dispatch_message (msg);
      vec_free (msg);

      if (errors->flags & CLIB_ERROR_ABORT)
	debugger ();
      if (errors->flags & CLIB_ERROR_FATAL)
	error_exit (1);

      clib_error_free (errors);
    }
  return 0;
}

#ifdef TEST

static error_t *
foo1 (int x)
{
  return error_return (0, "x is odd %d", x);
}

static error_t *
foo2 (int x)
{
  return error_return (0, "x is even %d", x);
}

static error_t *
foo (int x)
{
  error_t *e;
  if (x & 1)
    e = foo1 (x);
  else
    e = foo2 (x);
  if (e)
    return error_return (e, 0);
}

static void
error_handler (void *arg, char *msg, int msg_len)
{
  write (2, msg, msg_len);
}

int
main (int argc, char *argv[])
{
  error_t *e;

  register_error_handler (error_handler, 0);

  e = foo (getpid ());
  if (e)
    error_report (e);
  return 0;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
