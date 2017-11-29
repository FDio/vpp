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

#include <vppinfra/maplog.h>

int
clib_maplog_init (clib_maplog_main_t * mm, char *file_basename,
		  u64 file_size_in_bytes, u32 record_size_in_bytes)
{
  int i, fd;
  int rv = 0;
  u8 zero = 0;
  u32 record_size_in_cache_lines;
  u64 file_size_in_records;

  /* Already initialized? */
  if (mm->flags & CLIB_MAPLOG_FLAG_INIT)
    return (-2);

  memset (mm, 0, sizeof (*mm));

  record_size_in_cache_lines =
    (record_size_in_bytes + CLIB_CACHE_LINE_BYTES -
     1) / CLIB_CACHE_LINE_BYTES;

  file_size_in_records = file_size_in_bytes
    / (record_size_in_cache_lines * CLIB_CACHE_LINE_BYTES);

  /* Round up file size in records to a power of 2, for speed... */
  mm->log2_file_size_in_records = max_log2 (file_size_in_records);
  file_size_in_records = 1ULL << (mm->log2_file_size_in_records);

  file_size_in_bytes = file_size_in_records * record_size_in_cache_lines
    * CLIB_CACHE_LINE_BYTES;

  mm->file_basename = format (0, "%s", file_basename);
  mm->file_size_in_records = file_size_in_records;
  mm->flags |= CLIB_MAPLOG_FLAG_INIT;
  mm->record_size_in_cachelines = record_size_in_cache_lines;

  /* Map two files */
  for (i = 0; i < 2; i++)
    {
      mm->filenames[i] = format (0, "%v_%d", mm->file_basename,
				 mm->current_file_index++);

      fd = open ((char *) mm->filenames[i], O_CREAT | O_RDWR | O_TRUNC, 0600);
      if (fd < 0)
	{
	  rv = -3;
	  goto fail;
	}

      if (lseek (fd, file_size_in_bytes - 1, SEEK_SET) == (off_t) - 1)
	{
	  rv = -4;
	  goto fail;
	}
      if (write (fd, &zero, 1) != 1)
	{
	  rv = -5;
	  goto fail;
	}

      mm->file_baseva[i] = mmap (0, file_size_in_bytes,
				 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      if (mm->file_baseva[i] == (u8 *) MAP_FAILED)
	{
	  clib_unix_warning ("mmap");
	  goto fail;
	}
      (void) close (fd);
    }
  return rv;

fail:
  if (fd)
    (void) close (fd);

  for (i = 0; i < 2; i++)
    {
      if (mm->file_baseva[i])
	(void) munmap ((u8 *) mm->file_baseva[i], file_size_in_bytes);
    }
  return rv;
}

u8 *
_clib_maplog_get_entry_slowpath (clib_maplog_main_t * mm, u64 my_record_index)
{
  int fd;
  u8 *rv;
  u8 zero = 0;
  u32 unmap_index = (mm->current_file_index) & 1;
  u64 file_size_in_bytes = mm->file_size_in_records
    * mm->record_size_in_cachelines * CLIB_CACHE_LINE_BYTES;

  (void) munmap ((u8 *) mm->file_baseva[unmap_index], file_size_in_bytes);
  vec_reset_length (mm->filenames[unmap_index]);

  mm->filenames[unmap_index] = format (mm->filenames[unmap_index],
				       "%v_%d", mm->file_basename,
				       mm->current_file_index++);

  fd = open ((char *) mm->filenames[unmap_index],
	     O_CREAT | O_RDWR | O_TRUNC, 0600);
  /* $$$ this is not real error recovery... */
  if (fd < 0)
    {
      clib_unix_warning ("creat");
      abort ();
    }

  if (lseek (fd, file_size_in_bytes - 1, SEEK_SET) == (off_t) - 1)
    {
      clib_unix_warning ("lseek");
      abort ();
    }
  if (write (fd, &zero, 1) != 1)
    {
      clib_unix_warning ("set-size write");
      abort ();
    }

  mm->file_baseva[unmap_index] =
    mmap (0, file_size_in_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mm->file_baseva[unmap_index] == (u8 *) MAP_FAILED)
    {
      clib_unix_warning ("mmap");
      abort ();
    }
  (void) close (fd);

  rv = (u8 *)
    mm->file_baseva[(my_record_index >> mm->log2_file_size_in_records) & 1] +
    (my_record_index & (mm->file_size_in_records - 1))
    * mm->record_size_in_cachelines * CLIB_CACHE_LINE_BYTES;

  return rv;
}

void
clib_maplog_close (clib_maplog_main_t * mm)
{
  int i;
  u64 file_size_in_bytes;

  if (!(mm->flags & CLIB_MAPLOG_FLAG_INIT))
    return;

  file_size_in_bytes =
    mm->file_size_in_records * mm->record_size_in_cachelines *
    CLIB_CACHE_LINE_BYTES;

  for (i = 0; i < 2; i++)
    {
      (void) munmap ((u8 *) mm->file_baseva[i], file_size_in_bytes);
      vec_free (mm->filenames[i]);
    }

  vec_free (mm->file_basename);
  memset (mm, 0, sizeof (*mm));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
