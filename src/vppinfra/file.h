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
/*
 * file.h: unix file handling
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

#ifndef included_clib_file_h
#define included_clib_file_h

#include <vppinfra/socket.h>
#include <vppinfra/pool.h>
#include <vppinfra/lock.h>
#include <termios.h>


struct clib_file;
typedef clib_error_t *(clib_file_function_t) (struct clib_file * f);

typedef struct clib_file
{
  /* Unix file descriptor from open/socket. */
  u32 file_descriptor;

  u16 flags;
#define UNIX_FILE_DATA_AVAILABLE_TO_WRITE (1 << 0)
#define UNIX_FILE_EVENT_EDGE_TRIGGERED   (1 << 1)

  u16 active : 1;
  u16 dont_close : 1;

  /* polling thread index */
  u32 polling_thread_index;

  u32 index;

  /* Data available for function's use. */
  u64 private_data;

  /* Functions to be called when read/write data becomes ready. */
  clib_file_function_t *read_function, *write_function, *error_function;

  /* Description */
  u8 *description;

  /* Stats */
  u64 read_events;
  u64 write_events;
  u64 error_events;
} clib_file_t;

typedef enum
{
  UNIX_FILE_UPDATE_ADD,
  UNIX_FILE_UPDATE_MODIFY,
  UNIX_FILE_UPDATE_DELETE,
} clib_file_update_type_t;

typedef struct
{
  /* Pool of files to poll for input/output. */
  clib_file_t **file_pool;
  clib_file_t **pending_free;

  u8 lock;

  void (*file_update) (clib_file_t * file,
		       clib_file_update_type_t update_type);

} clib_file_main_t;

always_inline clib_file_t *
clib_file_get (clib_file_main_t *fm, u32 file_index)
{
  if (pool_is_free_index (fm->file_pool, file_index))
    return 0;
  return *pool_elt_at_index (fm->file_pool, file_index);
}

always_inline uword
clib_file_add (clib_file_main_t *fm, clib_file_t *template)
{
  clib_file_t *f, **fp;
  u32 index;

  f = clib_mem_alloc_aligned (sizeof (clib_file_t), CLIB_CACHE_LINE_BYTES);

  CLIB_SPINLOCK_LOCK (fm->lock);
  pool_get (fm->file_pool, fp);
  index = fp - fm->file_pool;
  fp[0] = f;
  CLIB_SPINLOCK_UNLOCK (fm->lock);

  f[0] = template[0];
  f->read_events = 0;
  f->write_events = 0;
  f->error_events = 0;
  f->index = index;
  fm->file_update (f, UNIX_FILE_UPDATE_ADD);
  f->active = 1;
  return index;
}

always_inline void
clib_file_del (clib_file_main_t *fm, clib_file_t *f)
{
  fm->file_update (f, UNIX_FILE_UPDATE_DELETE);
  if (f->dont_close == 0)
    close ((int) f->file_descriptor);

  CLIB_SPINLOCK_LOCK (fm->lock);
  f->active = 0;
  vec_add1 (fm->pending_free, f);
  pool_put_index (fm->file_pool, f->index);
  CLIB_SPINLOCK_UNLOCK (fm->lock);
}

always_inline void
clib_file_del_by_index (clib_file_main_t *fm, uword index)
{
  clib_file_t *f = clib_file_get (fm, index);
  clib_file_del (fm, f);
}

always_inline void
clib_file_free_deleted (clib_file_main_t *fm, clib_thread_index_t thread_index)
{
  u32 n_keep = 0;

  if (vec_len (fm->pending_free) == 0)
    return;

  CLIB_SPINLOCK_LOCK (fm->lock);
  vec_foreach_pointer (f, fm->pending_free)
    {
      if (f->polling_thread_index == thread_index)
	{
	  vec_free (f->description);
	  clib_mem_free (f);
	}
      else
	fm->pending_free[n_keep++] = f;
    }
  vec_set_len (fm->pending_free, n_keep);
  CLIB_SPINLOCK_UNLOCK (fm->lock);
}

always_inline void
clib_file_set_polling_thread (clib_file_main_t *fm, uword index,
			      clib_thread_index_t thread_index)
{
  clib_file_t *f = clib_file_get (fm, index);
  fm->file_update (f, UNIX_FILE_UPDATE_DELETE);
  f->polling_thread_index = thread_index;
  fm->file_update (f, UNIX_FILE_UPDATE_ADD);
}

always_inline uword
clib_file_set_data_available_to_write (clib_file_main_t *fm,
				       u32 clib_file_index, uword is_available)
{
  clib_file_t *f = clib_file_get (fm, clib_file_index);
  uword was_available = (f->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE);
  if ((was_available != 0) != (is_available != 0))
    {
      f->flags ^= UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      fm->file_update (f, UNIX_FILE_UPDATE_MODIFY);
    }
  return was_available != 0;
}

always_inline clib_error_t *
clib_file_write (clib_file_t * f)
{
  f->write_events++;
  return f->write_function (f);
}

u8 *clib_file_get_resolved_basename (char *fmt, ...);

#endif /* included_clib_file_h */
