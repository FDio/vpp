/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vppinfra/clib.h>
#include <vppinfra/clib_error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

__clib_export clib_error_t *
clib_sysfs_write (char *file_name, char *fmt, ...)
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

__clib_export clib_error_t *
clib_sysfs_read (char *file_name, char *fmt, ...)
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

  vec_set_len (s, sz);
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


clib_error_t *
clib_sysfs_set_nr_hugepages (int numa_node, int log2_page_size, int nr)
{
  clib_error_t *error = 0;
  struct stat sb;
  u8 *p = 0;
  uword page_size;

  if (log2_page_size == 0)
    log2_page_size = min_log2 (clib_mem_get_default_hugepage_size ());

  page_size = 1ULL << (log2_page_size - 10);

  p = format (p, "/sys/devices/system/node/node%u%c", numa_node, 0);

  if (stat ((char *) p, &sb) == 0)
    {
      if (S_ISDIR (sb.st_mode) == 0)
	{
	  error = clib_error_return (0, "'%s' is not directory", p);
	  goto done;
	}
    }
  else if (numa_node == 0)
    {
      vec_reset_length (p);
      p = format (p, "/sys/kernel/mm%c", 0);
      if (stat ((char *) p, &sb) < 0 || S_ISDIR (sb.st_mode) == 0)
	{
	  error = clib_error_return (0, "'%s' does not exist or it is not "
				     "directory", p);
	  goto done;
	}
    }
  else
    {
      error = clib_error_return (0, "'%s' does not exist", p);
      goto done;
    }

  vec_dec_len (p, 1);
  p = format (p, "/hugepages/hugepages-%ukB/nr_hugepages%c", page_size, 0);
  clib_sysfs_write ((char *) p, "%d", nr);

done:
  vec_free (p);
  return error;
}


static clib_error_t *
clib_sysfs_get_xxx_hugepages (char *type, int numa_node,
			      int log2_page_size, int *val)
{
  clib_error_t *error = 0;
  struct stat sb;
  u8 *p = 0;

  uword page_size;

  if (log2_page_size == 0)
    log2_page_size = min_log2 (clib_mem_get_default_hugepage_size ());

  page_size = 1ULL << (log2_page_size - 10);


  p = format (p, "/sys/devices/system/node/node%u%c", numa_node, 0);

  if (stat ((char *) p, &sb) == 0)
    {
      if (S_ISDIR (sb.st_mode) == 0)
	{
	  error = clib_error_return (0, "'%s' is not directory", p);
	  goto done;
	}
    }
  else if (numa_node == 0)
    {
      vec_reset_length (p);
      p = format (p, "/sys/kernel/mm%c", 0);
      if (stat ((char *) p, &sb) < 0 || S_ISDIR (sb.st_mode) == 0)
	{
	  error = clib_error_return (0, "'%s' does not exist or it is not "
				     "directory", p);
	  goto done;
	}
    }
  else
    {
      error = clib_error_return (0, "'%s' does not exist", p);
      goto done;
    }

  vec_dec_len (p, 1);
  p = format (p, "/hugepages/hugepages-%ukB/%s_hugepages%c", page_size,
	      type, 0);
  error = clib_sysfs_read ((char *) p, "%d", val);

done:
  vec_free (p);
  return error;
}

clib_error_t *
clib_sysfs_get_free_hugepages (int numa_node, int log2_page_size, int *v)
{
  return clib_sysfs_get_xxx_hugepages ("free", numa_node, log2_page_size, v);
}

clib_error_t *
clib_sysfs_get_nr_hugepages (int numa_node, int log2_page_size, int *v)
{
  return clib_sysfs_get_xxx_hugepages ("nr", numa_node, log2_page_size, v);
}

clib_error_t *
clib_sysfs_get_surplus_hugepages (int numa_node, int log2_page_size, int *v)
{
  return clib_sysfs_get_xxx_hugepages ("surplus", numa_node, log2_page_size,
				       v);
}

clib_error_t *
clib_sysfs_prealloc_hugepages (int numa_node, int log2_page_size, int nr)
{
  clib_error_t *error = 0;
  int n, needed;
  uword page_size;

  if (log2_page_size == 0)
    log2_page_size = min_log2 (clib_mem_get_default_hugepage_size ());

  page_size = 1ULL << (log2_page_size - 10);

  error = clib_sysfs_get_free_hugepages (numa_node, log2_page_size, &n);
  if (error)
    return error;
  needed = nr - n;
  if (needed <= 0)
    return 0;

  error = clib_sysfs_get_nr_hugepages (numa_node, log2_page_size, &n);
  if (error)
    return error;
  clib_warning ("pre-allocating %u additional %uK hugepages on numa node %u",
		needed, page_size, numa_node);
  return clib_sysfs_set_nr_hugepages (numa_node, log2_page_size, n + needed);
}

__clib_export uword *
clib_sysfs_list_to_bitmap (char *filename)
{
  FILE *fp;
  uword *r = 0;

  fp = fopen (filename, "r");

  if (fp != NULL)
    {
      u8 *buffer = 0;
      vec_validate (buffer, 256 - 1);
      if (fgets ((char *) buffer, 256, fp))
	{
	  unformat_input_t in;
	  unformat_init_string (&in, (char *) buffer,
				strlen ((char *) buffer));
	  if (unformat (&in, "%U", unformat_bitmap_list, &r) != 1)
	    clib_warning ("unformat_bitmap_list failed");
	  unformat_free (&in);
	}
      vec_free (buffer);
      fclose (fp);
    }
  return r;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
