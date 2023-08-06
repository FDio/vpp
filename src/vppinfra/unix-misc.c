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
  Copyright (c) 2005 Eliot Dresselhaus

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

#include <vppinfra/error.h>
#include <vppinfra/os.h>
#include <vppinfra/unix.h>
#include <vppinfra/format.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>		/* writev */
#include <fcntl.h>
#include <stdio.h>		/* for sprintf */
#include <limits.h>

__clib_export __thread uword __os_thread_index = 0;
__clib_export __thread uword __os_numa_index = 0;

clib_error_t *
clib_file_n_bytes (char *file, uword * result)
{
  struct stat s;

  if (stat (file, &s) < 0)
    return clib_error_return_unix (0, "stat `%s'", file);

  if (S_ISREG (s.st_mode))
    *result = s.st_size;
  else
    *result = 0;

  return /* no error */ 0;
}

clib_error_t *
clib_file_read_contents (char *file, u8 * result, uword n_bytes)
{
  int fd = -1;
  uword n_done, n_left;
  clib_error_t *error = 0;
  u8 *v = result;

  if ((fd = open (file, 0)) < 0)
    return clib_error_return_unix (0, "open `%s'", file);

  n_left = n_bytes;
  n_done = 0;
  while (n_left > 0)
    {
      int n_read;
      if ((n_read = read (fd, v + n_done, n_left)) < 0)
	{
	  error = clib_error_return_unix (0, "open `%s'", file);
	  goto done;
	}

      /* End of file. */
      if (n_read == 0)
	break;

      n_left -= n_read;
      n_done += n_read;
    }

  if (n_left > 0)
    {
      error =
	clib_error_return (0,
			   " `%s' expected to read %wd bytes; read only %wd",
			   file, n_bytes, n_bytes - n_left);
      goto done;
    }

done:
  close (fd);
  return error;
}

__clib_export clib_error_t *
clib_file_contents (char *file, u8 ** result)
{
  uword n_bytes;
  clib_error_t *error = 0;
  u8 *v;

  if ((error = clib_file_n_bytes (file, &n_bytes)))
    return error;

  v = 0;
  vec_resize (v, n_bytes);

  error = clib_file_read_contents (file, v, n_bytes);

  if (error)
    vec_free (v);
  else
    *result = v;

  return error;
}

__clib_export u8 *
clib_file_get_resolved_basename (char *fmt, ...)
{
  va_list va;
  char *p, buffer[PATH_MAX];
  u8 *link, *s = 0;
  int r;

  va_start (va, fmt);
  link = va_format (0, fmt, &va);
  va_end (va);
  vec_add1 (link, 0);

  r = readlink ((char *) link, buffer, sizeof (buffer) - 1);
  vec_free (link);

  if (r < 1)
    return 0;

  p = buffer + r - 1;
  while (p > buffer && p[-1] != '/')
    p--;

  while (p[0])
    vec_add1 (s, p++[0]);

  return s;
}

clib_error_t *
unix_proc_file_contents (char *file, u8 ** result)
{
  u8 *rv = 0;
  uword pos;
  int bytes, fd;

  /* Unfortunately, stat(/proc/XXX) returns zero... */
  fd = open (file, O_RDONLY);

  if (fd < 0)
    return clib_error_return_unix (0, "open `%s'", file);

  vec_validate (rv, 4095);
  pos = 0;
  while (1)
    {
      bytes = read (fd, rv + pos, 4096);
      if (bytes < 0)
	{
	  close (fd);
	  vec_free (rv);
	  return clib_error_return_unix (0, "read '%s'", file);
	}

      if (bytes == 0)
	{
	  vec_set_len (rv, pos);
	  break;
	}
      pos += bytes;
      vec_validate (rv, pos + 4095);
    }
  *result = rv;
  close (fd);
  return 0;
}

void os_panic (void) __attribute__ ((weak));

__clib_export void
os_panic (void)
{
  abort ();
}

void os_exit (int) __attribute__ ((weak));

void
os_exit (int code)
{
  exit (code);
}

void os_puts (u8 * string, uword string_length, uword is_error)
  __attribute__ ((weak));

void
os_puts (u8 * string, uword string_length, uword is_error)
{
  int cpu = os_get_thread_index ();
  int nthreads = os_get_nthreads ();
  char buf[64];
  int fd = is_error ? 2 : 1;
  struct iovec iovs[2];
  int n_iovs = 0;

  if (nthreads > 1)
    {
      snprintf (buf, sizeof (buf), "%d: ", cpu);

      iovs[n_iovs].iov_base = buf;
      iovs[n_iovs].iov_len = strlen (buf);
      n_iovs++;
    }

  iovs[n_iovs].iov_base = string;
  iovs[n_iovs].iov_len = string_length;
  n_iovs++;

  if (writev (fd, iovs, n_iovs) < 0)
    ;
}

__clib_export __clib_weak void
os_out_of_memory (void)
{
  os_panic ();
}

__clib_export __clib_weak uword
os_get_nthreads (void)
{
  return 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
