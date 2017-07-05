/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 * pci.c: Linux user space PCI bus management.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

clib_error_t *
foreach_directory_file (char *dir_name,
			clib_error_t * (*f) (void *arg, u8 * path_name,
					     u8 * file_name), void *arg,
			int scan_dirs)
{
  DIR *d;
  struct dirent *e;
  clib_error_t *error = 0;
  u8 *s, *t;

  d = opendir (dir_name);
  if (!d)
    {
      if (errno == ENOENT)
	return 0;
      return clib_error_return_unix (0, "open `%s'", dir_name);
    }

  s = t = 0;
  while (1)
    {
      e = readdir (d);
      if (!e)
	break;
      if (scan_dirs)
	{
	  if (e->d_type == DT_DIR
	      && (!strcmp (e->d_name, ".") || !strcmp (e->d_name, "..")))
	    continue;
	}
      else
	{
	  if (e->d_type == DT_DIR)
	    continue;
	}

      s = format (s, "%s/%s", dir_name, e->d_name);
      t = format (t, "%s", e->d_name);
      error = f (arg, s, t);
      _vec_len (s) = 0;
      _vec_len (t) = 0;

      if (error)
	break;
    }

  vec_free (s);
  closedir (d);

  return error;
}

clib_error_t *
vlib_sysfs_write (char *file_name, char *fmt, ...)
{
  u8 *s;
  int fd;
  clib_error_t *error = 0;

  fd = open (file_name, O_WRONLY);
  if (fd < 0)
    return clib_error_return_unix (0, "open `%s'", file_name);

  va_list va;
  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  if (write (fd, s, vec_len (s)) < 0)
    error = clib_error_return_unix (0, "write `%s'", file_name);

  vec_free (s);
  close (fd);
  return error;
}

clib_error_t *
vlib_sysfs_read (char *file_name, char *fmt, ...)
{
  unformat_input_t input;
  u8 *s = 0;
  int fd;
  ssize_t sz;
  uword result;

  fd = open (file_name, O_RDONLY);
  if (fd < 0)
    return clib_error_return_unix (0, "open `%s'", file_name);

  vec_validate (s, 4095);

  sz = read (fd, s, vec_len (s));
  if (sz < 0)
    {
      close (fd);
      vec_free (s);
      return clib_error_return_unix (0, "read `%s'", file_name);
    }

  _vec_len (s) = sz;
  unformat_init_vector (&input, s);

  va_list va;
  va_start (va, fmt);
  result = va_unformat (&input, fmt, &va);
  va_end (va);

  vec_free (s);
  close (fd);

  if (result == 0)
    return clib_error_return (0, "unformat error");

  return 0;
}

u8 *
vlib_sysfs_link_to_name (char *link)
{
  char *p, buffer[64];
  unformat_input_t in;
  u8 *s = 0;
  int r;

  r = readlink (link, buffer, sizeof (buffer) - 1);

  if (r < 0)
    return 0;

  buffer[r] = 0;
  p = strrchr (buffer, '/');

  if (!p)
    return 0;

  unformat_init_string (&in, p + 1, strlen (p + 1));
  if (unformat (&in, "%s", &s) != 1)
    clib_unix_warning ("no string?");
  unformat_free (&in);

  return s;
}

int
vlib_sysfs_get_free_hugepages (unsigned int numa_node, int page_size)
{
  struct stat sb;
  u8 *p = 0;
  int r = -1;

  p = format (p, "/sys/devices/system/node/node%u%c", numa_node, 0);

  if (stat ((char *) p, &sb) == 0)
    {
      if (S_ISDIR (sb.st_mode) == 0)
	goto done;
    }
  else if (numa_node == 0)
    {
      vec_reset_length (p);
      p = format (p, "/sys/kernel/mm%c", 0);
      if (stat ((char *) p, &sb) < 0 || S_ISDIR (sb.st_mode) == 0)
	goto done;
    }
  else
    goto done;

  _vec_len (p) -= 1;
  p = format (p, "/hugepages/hugepages-%ukB/free_hugepages%c", page_size, 0);
  vlib_sysfs_read ((char *) p, "%d", &r);

done:
  vec_free (p);
  return r;
}

clib_error_t *
unix_make_vpp_run_dir (void)
{
  int rv;

  rv = mkdir (VPP_RUN_DIR, 0755);
  if (rv && errno != EEXIST)
    return clib_error_return (0, "mkdir '%s' failed errno %d",
			      VPP_RUN_DIR, errno);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
