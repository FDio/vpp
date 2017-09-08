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
vlib_unix_recursive_mkdir (char *path)
{
  clib_error_t *error = 0;
  char *c = 0;
  int i = 0;

  while (path[i] != 0)
    {
      if (c && path[i] == '/')
	{
	  vec_add1 (c, 0);
	  if ((mkdir (c, 0755)) && (errno != EEXIST))
	    {
	      error = clib_error_return_unix (0, "mkdir '%s'", c);
	      goto done;
	    }
	  _vec_len (c)--;
	}
      vec_add1 (c, path[i]);
      i++;
    }

  if ((mkdir (path, 0755)) && (errno != EEXIST))
    {
      error = clib_error_return_unix (0, "mkdir '%s'", path);
      goto done;
    }

done:
  vec_free (c);

  return error;
}

clib_error_t *
vlib_unix_validate_runtime_file (unix_main_t * um,
				 const char *path, u8 ** full_path)
{
  u8 *fp = 0;
  char *last_slash = 0;

  if (path[0] == '\0')
    {
      return clib_error_return (0, "path is an empty string");
    }
  else if (strncmp (path, "../", 3) == 0 || strstr (path, "/../"))
    {
      return clib_error_return (0, "'..' not allowed in runtime path");
    }
  else if (path[0] == '/')
    {
      /* Absolute path. Has to start with runtime directory */
      if (strncmp ((char *) um->runtime_dir, path,
		   strlen ((char *) um->runtime_dir)))
	{
	  return clib_error_return (0,
				    "file %s is not in runtime directory %s",
				    path, um->runtime_dir);
	}
      fp = format (0, "%s%c", path, '\0');
    }
  else
    {
      /* Relative path, just append to runtime */
      fp = format (0, "%s/%s%c", um->runtime_dir, path, '\0');
    }

  /* We don't want to create a directory out of the last file */
  if ((last_slash = strrchr ((char *) fp, '/')) != NULL)
    *last_slash = '\0';

  clib_error_t *error = vlib_unix_recursive_mkdir ((char *) fp);

  if (last_slash != NULL)
    *last_slash = '/';

  if (error)
    vec_free (fp);

  *full_path = fp;
  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
