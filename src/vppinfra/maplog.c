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

/**
 * @brief Initialize a maplog object
 *
 * Compute record and file size parameters
 * Create and map two log segments to seed the process
 *
 * @param[in/out] a   init args structure
 * @return    0 => success, <0 => failure
 */
int
clib_maplog_init (clib_maplog_init_args_t * a)
{
  int i, fd;
  int rv = 0;
  u8 zero = 0;
  u32 record_size_in_cache_lines;
  u64 file_size_in_records;
  clib_maplog_main_t *mm;
  clib_maplog_header_t _h, *h = &_h;

  ASSERT (a && a->mm);
  mm = a->mm;

  /* Already initialized? */
  if (mm->flags & CLIB_MAPLOG_FLAG_INIT)
    return (-2);

  memset (mm, 0, sizeof (*mm));

  record_size_in_cache_lines =
    (a->record_size_in_bytes + CLIB_CACHE_LINE_BYTES -
     1) / CLIB_CACHE_LINE_BYTES;

  file_size_in_records = a->file_size_in_bytes
    / (record_size_in_cache_lines * CLIB_CACHE_LINE_BYTES);

  /* Round up file size in records to a power of 2, for speed... */
  mm->log2_file_size_in_records = max_log2 (file_size_in_records);
  file_size_in_records = 1ULL << (mm->log2_file_size_in_records);

  a->file_size_in_bytes = file_size_in_records * record_size_in_cache_lines
    * CLIB_CACHE_LINE_BYTES;

  mm->file_basename = format (0, "%s", a->file_basename);
  if (vec_len (mm->file_basename) > ARRAY_LEN (h->file_basename))
    {
      vec_free (mm->file_basename);
      return -11;
    }

  mm->file_size_in_records = file_size_in_records;
  mm->flags |= CLIB_MAPLOG_FLAG_INIT;
  mm->record_size_in_cachelines = record_size_in_cache_lines;

  /* Map two files */
  for (i = 0; i < 2; i++)
    {
      mm->filenames[i] = format (0, "%v_%d", mm->file_basename,
				 mm->current_file_index++);
      vec_add1 (mm->filenames[i], 0);

      fd = open ((char *) mm->filenames[i], O_CREAT | O_RDWR | O_TRUNC, 0600);
      if (fd < 0)
	{
	  rv = -3;
	  goto fail;
	}

      if (lseek (fd, a->file_size_in_bytes - 1, SEEK_SET) == (off_t) - 1)
	{
	  rv = -4;
	  goto fail;
	}
      if (write (fd, &zero, 1) != 1)
	{
	  rv = -5;
	  goto fail;
	}

      mm->file_baseva[i] = mmap (0, a->file_size_in_bytes,
				 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      if (mm->file_baseva[i] == (u8 *) MAP_FAILED)
	{
	  clib_unix_warning ("mmap");
	  goto fail;
	}
      (void) close (fd);
    }

  memset (h, 0, sizeof (*h));
  h->maplog_major_version = MAPLOG_MAJOR_VERSION;
  h->maplog_minor_version = MAPLOG_MINOR_VERSION;
  h->maplog_patch_version = MAPLOG_PATCH_VERSION;
  h->application_id = a->application_id;
  h->application_major_version = a->application_major_version;
  h->application_minor_version = a->application_minor_version;
  h->application_patch_version = a->application_patch_version;
  h->record_size_in_cachelines = record_size_in_cache_lines;
  h->cacheline_size = CLIB_CACHE_LINE_BYTES;
  h->file_size_in_records = file_size_in_records;
  h->number_of_records = ~0ULL;
  h->number_of_files = ~0ULL;
  memcpy (h->file_basename, mm->file_basename, vec_len (mm->file_basename));

  mm->header_filename = format (0, "%v_header", mm->file_basename);
  vec_add1 (mm->header_filename, 0);

  fd = open ((char *) mm->header_filename, O_CREAT | O_RDWR | O_TRUNC, 0600);
  if (fd < 0)
    {
      clib_unix_warning ("header create");
      rv = -6;
      goto fail;
    }
  rv = write (fd, h, sizeof (*h));
  if (rv != sizeof (*h))
    {
      clib_unix_warning ("header write");
      rv = -7;
      goto fail;
    }
  (void) close (fd);
  return 0;

fail:
  if (fd >= 0)
    (void) close (fd);

  for (i = 0; i < 2; i++)
    {
      if (mm->file_baseva[i])
	(void) munmap ((u8 *) mm->file_baseva[i], a->file_size_in_bytes);
      if (mm->filenames[i])
	(void) unlink ((char *) mm->filenames[i]);
      vec_free (mm->filenames[i]);
    }
  if (mm->header_filename)
    {
      (void) unlink ((char *) mm->header_filename);
      vec_free (mm->header_filename);
    }
  return rv;
}

/* slow path: unmap a full log segment, and replace it */

u8 *
_clib_maplog_get_entry_slowpath (clib_maplog_main_t * mm, u64 my_record_index)
{
  int fd;
  u8 *rv;
  u8 zero = 0;
  u32 unmap_index = (mm->current_file_index) & 1;
  u64 file_size_in_bytes = mm->file_size_in_records
    * mm->record_size_in_cachelines * CLIB_CACHE_LINE_BYTES;

  /*
   * Kill some time by calling format before we make the previous log
   * segment disappear. Obviously it won't do to call clib_maplog_get_entry(),
   * wait 100ms, and then fill in the log entry.
   */
  vec_reset_length (mm->filenames[unmap_index]);
  mm->filenames[unmap_index] = format (mm->filenames[unmap_index],
				       "%v_%d", mm->file_basename,
				       mm->current_file_index++);

  /* Unmap the previous (full) segment */
  (void) munmap ((u8 *) mm->file_baseva[unmap_index], file_size_in_bytes);

  /* Create a new segment */
  fd = open ((char *) mm->filenames[unmap_index],
	     O_CREAT | O_RDWR | O_TRUNC, 0600);

  /* This is not real error recovery... */
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

/**
 * @brief Close a mapped log, and update the log header file
 *
 * Unmap the current log segments.
 * Read the log header. Update the number of records, and number of files
 *
 * @param[in/out] mm	mapped log object
 */
void
clib_maplog_close (clib_maplog_main_t * mm)
{
  int i, rv;
  u64 file_size_in_bytes;
  int fd;
  clib_maplog_header_t _h, *h = &_h;

  if (!(mm->flags & CLIB_MAPLOG_FLAG_INIT))
    return;

  file_size_in_bytes =
    mm->file_size_in_records * mm->record_size_in_cachelines *
    CLIB_CACHE_LINE_BYTES;

  /* unmap current + next segments */
  for (i = 0; i < 2; i++)
    {
      (void) munmap ((u8 *) mm->file_baseva[i], file_size_in_bytes);
      vec_free (mm->filenames[i]);
    }

  /* Open the log header */
  fd = open ((char *) mm->header_filename, O_RDWR, 0600);
  if (fd < 0)
    {
      clib_unix_warning ("reopen maplog header");
      goto out;
    }

  /* Read the log */
  rv = read (fd, h, sizeof (*h));
  if (rv != sizeof (*h))
    {
      clib_unix_warning ("read maplog header");
      goto out;
    }
  /* Fix the header... */
  h->number_of_records = mm->next_record_index;
  h->number_of_files = mm->current_file_index;

  /* Back to the beginning of the log header... */
  if (lseek (fd, 0, SEEK_SET) < 0)
    {
      clib_unix_warning ("lseek to rewrite header");
      goto out;
    }
  /* Rewrite the log header */
  rv = write (fd, h, sizeof (*h));
  if (rv != sizeof (*h))
    clib_unix_warning ("rewrite header");

out:
  if (fd >= 0)
    (void) close (fd);

  vec_free (mm->file_basename);
  vec_free (mm->header_filename);
  memset (mm, 0, sizeof (*mm));
}

/**
 * @brief format a log header
 *
 * Usage: s = format (0, "%U", format_maplog_header, headerp, verbose);
 * @param [in] h clib_maplog_header_t pointer
 * @param [in] verbose self-explanatory
 */
u8 *
format_maplog_header (u8 * s, va_list * args)
{
  clib_maplog_header_t *h = va_arg (*args, clib_maplog_header_t *);
  int verbose = va_arg (*args, int);

  if (!verbose)
    goto brief;
  s = format (s, "basename %s ", h->file_basename);
  s = format (s, "log ver %d.%d.%d app id %u ver %d.%d.%d\n",
	      h->maplog_major_version,
	      h->maplog_minor_version,
	      h->maplog_patch_version,
	      h->application_id,
	      h->application_major_version,
	      h->application_minor_version, h->application_patch_version);
  s = format (s, "  records are %d %d-byte cachelines\n",
	      h->record_size_in_cachelines, h->cacheline_size);
  s = format (s, "  files are %lld records long, %lld files\n",
	      h->file_size_in_records, h->number_of_files);
  s = format (s, "  %lld records total\n", h->number_of_records);
  return s;

brief:
  s = format (s, "%s %lld records %lld files %lld records/file",
	      h->file_basename, h->number_of_records, h->number_of_files,
	      h->file_size_in_records);
  return s;
}

/**
 * @brief Process a complete maplog
 *
 * Reads the maplog header. Map and process all log segments in order.
 * Calls the callback function once per file with a record count.
 *
 * @param [in] file_basename Same basename supplied to clib_maplog_init
 * @param [in] fp_arg Callback function pointer
 */
int
clib_maplog_process (char *file_basename, void *fp_arg)
{
  clib_maplog_header_t _h, *h = &_h;
  int fd, rv = 0;
  u64 file_index;
  u64 file_size_in_bytes;
  u8 *header_filename, *this_filename = 0;
  u8 *file_baseva;
  void (*fp) (clib_maplog_header_t *, void *data, u64 count);
  u64 records_this_file, records_left;
  ASSERT (fp_arg);

  fp = fp_arg;

  header_filename = format (0, "%s_header%c", file_basename, 0);

  fd = open ((char *) header_filename, O_RDONLY, 0600);
  if (fd < 0)
    {
      clib_unix_warning ("open maplog header");
      rv = -1;
      goto out;
    }
  rv = read (fd, h, sizeof (*h));
  if (rv != sizeof (*h))
    {
      clib_unix_warning ("read maplog header");
      rv = -2;
      goto out;
    }
  (void) close (fd);

  file_size_in_bytes = h->file_size_in_records
    * h->record_size_in_cachelines * CLIB_CACHE_LINE_BYTES;

  records_left = h->number_of_records;

  for (file_index = 0; file_index < h->number_of_files; file_index++)
    {
      vec_reset_length (this_filename);
      this_filename = format (this_filename, "%s_%llu%c", file_basename,
			      file_index, 0);
      fd = open ((char *) this_filename, O_RDONLY, 0600);
      if (fd < 0)
	{
	  clib_unix_warning ("open maplog file");
	  rv = -3;
	  goto out;
	}

      file_baseva =
	mmap (0, file_size_in_bytes, PROT_READ, MAP_SHARED, fd, 0);
      (void) close (fd);
      if (file_baseva == (u8 *) MAP_FAILED)
	{
	  clib_unix_warning ("mmap");
	  rv = -4;
	  goto out;
	}

      records_this_file = (records_left > h->file_size_in_records) ?
	h->file_size_in_records : records_left;

      (*fp) (h, file_baseva, records_this_file);

      if (munmap (file_baseva, file_size_in_bytes) < 0)
	{
	  clib_warning ("munmap");
	  rv = -5;
	  /* but don't stop... */
	}
      records_left -= records_this_file;
      if (records_left == 0)
	break;
    }

out:
  if (fd > 0)
    (void) close (fd);

  vec_free (this_filename);
  vec_free (header_filename);
  return rv;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
