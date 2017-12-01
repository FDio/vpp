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

#ifndef __included_maplog_h__
#define __included_maplog_h__

/** @file
    @brief mmap-based thread-safe fixed-size record double-buffered logging.

   This scheme should be about as fast as practicable. By fiat, log
   records are rounded to a multiple of CLIB_CACHE_LINE_BYTES.
   Consumer code calls clib_maplog_get_entry(...) to obtain a pointer
   to a log entry.

   We use an atomic ticket-counter to dole out log entries. Whichever
   client thread crosses the double-buffer boundary is in charge of
   replacing the log segment which just filled.
*/

#include <vppinfra/clib.h>
#include <vppinfra/cache.h>
#include <vppinfra/format.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

/** Maplog log file header segment. In a separate file */

typedef struct
{
  u8 maplog_major_version;	/**< library major version number */
  u8 maplog_minor_version;	/**< library minor version number */
  u8 maplog_patch_version;	/**< library patch version number */
  u8 pad;
  u32 application_id;		/**< application identifier */
  u8 application_major_version;	/**< application major version number */
  u8 application_minor_version;	/**< application minor version number */
  u8 application_patch_version;	/**< application patch version number */
  u8 pad2;
  u32 record_size_in_cachelines; /**< record size in cache lines */
  u32 cacheline_size;		 /**< cache line size  */
  u64 file_size_in_records;	 /**< file size in records */
  u64 number_of_records;	 /**< number of records in entire log  */
  u64 number_of_files;		 /**< number of files in entire log  */
  u8 file_basename[256];	 /**< file basename  */
} clib_maplog_header_t;

#define MAPLOG_MAJOR_VERSION 1
#define MAPLOG_MINOR_VERSION 0
#define MAPLOG_PATCH_VERSION 0

/** Process-private main data structure */

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  /** rw cache line: atomic ticket-counter, file index */
  volatile u64 next_record_index;
  /** file size in records, rounded to a power of two */
  u64 file_size_in_records;
  u32 log2_file_size_in_records; /**< lg file size in records */
  volatile u32 current_file_index; /**< current file index */
  volatile u32 flags;		   /**< flags, currently just "init" or not  */

  /* read-mostly cache line: size parameters, file names, etc. */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  u32 record_size_in_cachelines; /**< record size in cache lines */

  /* double-buffered mmap'ed logfiles */
  volatile u8 *file_baseva[2];	/**< active segment base addresses */
  u8 *filenames[2];		/**< active segment file names  */
  /* vector not c-string */
  u8 *file_basename;		/**< basename, e.g. "/tmp/mylog" */
  u8 *header_filename;		/**< log header file name */
} clib_maplog_main_t;

/* flag bits */
#define CLIB_MAPLOG_FLAG_INIT 	(1<<0)

/** log initialization structure */
typedef struct
{
  clib_maplog_main_t *mm;	/**< pointer to the main structure */
  char *file_basename;		/**< file base name  */
  u64 file_size_in_bytes;	/**< file size in bytes */
  u32 record_size_in_bytes;	/**< record size in bytes */
  u32 application_id;		/**< application identifier */
  u8 application_major_version;	/**< applcation major version number */
  u8 application_minor_version;	/**< applcation minor version number */
  u8 application_patch_version;	/**< applcation patch version number */
} clib_maplog_init_args_t;

/* function prototypes */

int clib_maplog_init (clib_maplog_init_args_t * ap);
void clib_maplog_close (clib_maplog_main_t * mm);
int clib_maplog_process (char *file_basename, void *fp_arg);

format_function_t format_maplog_header;

u8 *_clib_maplog_get_entry_slowpath (clib_maplog_main_t * mm,
				     u64 my_record_index);

/**
 * @brief Obtain a log entry pointer
 *
 * Increments the atomic ticket counter, and returns a pointer to
 * the newly-allocated log entry. The slowpath function replaces
 * a full log segment with a new/fresh/empty log segment
 *
 * @param[in] mm   maplog object pointer
 * @return    pointer to the allocated log entry
 */
static inline void *
clib_maplog_get_entry (clib_maplog_main_t * mm)
{
  u64 my_record_index;
  u8 *rv;

  ASSERT (mm->flags & CLIB_MAPLOG_FLAG_INIT);

  my_record_index = __sync_fetch_and_add (&mm->next_record_index, 1);

  /* Time to unmap and create a new logfile? */
  if (PREDICT_FALSE ((my_record_index & (mm->file_size_in_records - 1)) == 0))
    {
      /* Yes, but not the very first time... (;-)... */
      if (my_record_index)
	return _clib_maplog_get_entry_slowpath (mm, my_record_index);
      /* FALLTHROUGH */
    }

  rv = (u8 *)
    mm->file_baseva[(my_record_index >> mm->log2_file_size_in_records) & 1] +
    (my_record_index & (mm->file_size_in_records - 1))
    * mm->record_size_in_cachelines * CLIB_CACHE_LINE_BYTES;

  return rv;
}

#endif /* __included_maplog_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
