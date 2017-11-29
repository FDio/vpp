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

/** \file

   mmap-based fixed-size record double-buffered logging
*/

#include <vppinfra/clib.h>
#include <vppinfra/cache.h>
#include <vppinfra/format.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

typedef struct
{
  /* rw: atomic ticket-counter, file index */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  volatile u64 next_record_index;
  u64 file_size_in_records; /**< power of two */
  u32 log2_file_size_in_records;
  volatile u32 current_file_index;
  volatile u32 flags;

  /* ro: size parameters */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  u32 record_size_in_cachelines;

  /* double-buffered mmap'ed logfiles */
  volatile u8 *file_baseva[2];
  u8 *filenames[2];
  /* vector not c-string */
  u8 *file_basename;
} clib_maplog_main_t;

int clib_maplog_init (clib_maplog_main_t * mm, char *file_basename,
		      u64 file_size, u32 record_size_in_bytes);

void clib_maplog_close (clib_maplog_main_t * mm);

#define CLIB_MAPLOG_FLAG_INIT 	(1<<0)

u8 *_clib_maplog_get_entry_slowpath (clib_maplog_main_t * mm,
				     u64 my_record_index);

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
