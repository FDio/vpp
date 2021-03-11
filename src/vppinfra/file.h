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
#include <termios.h>


struct clib_file;
typedef clib_error_t *(clib_file_function_t) (struct clib_file * f);

typedef struct clib_file
{
  /* Unix file descriptor from open/socket. */
  u32 file_descriptor;

  u32 flags;
#define UNIX_FILE_DATA_AVAILABLE_TO_WRITE (1 << 0)
#define UNIX_FILE_EVENT_EDGE_TRIGGERED   (1 << 1)
#define UNIX_FILE_ZOMBIE		  (1 << 2)

  /* polling thread index */
  u32 polling_thread_index;

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
  clib_file_t *file_pool;

  void (*file_update) (clib_file_t * file,
		       clib_file_update_type_t update_type);

} clib_file_main_t;

always_inline uword
clib_file_add (clib_file_main_t * um, clib_file_t * template)
{
  clib_file_t *f;
  pool_get (um->file_pool, f);
  f[0] = template[0];
  f->read_events = 0;
  f->write_events = 0;
  f->error_events = 0;
  um->file_update (f, UNIX_FILE_UPDATE_ADD);
  return f - um->file_pool;
}

always_inline void
clib_file_del (clib_file_main_t * um, clib_file_t * f)
{
  um->file_update (f, UNIX_FILE_UPDATE_DELETE);
  close (f->file_descriptor);
  f->file_descriptor = ~0;
  vec_free (f->description);
  pool_put (um->file_pool, f);
}

always_inline void
clib_file_del_by_index (clib_file_main_t * um, uword index)
{
  clib_file_t *uf;
  uf = pool_elt_at_index (um->file_pool, index);
  clib_file_del (um, uf);
}

always_inline void
clib_file_set_polling_thread (clib_file_main_t * um, uword index,
			      u32 thread_index)
{
  clib_file_t *f = pool_elt_at_index (um->file_pool, index);
  um->file_update (f, UNIX_FILE_UPDATE_DELETE);
  f->polling_thread_index = thread_index;
  um->file_update (f, UNIX_FILE_UPDATE_ADD);
}

always_inline uword
clib_file_set_data_available_to_write (clib_file_main_t * um,
				       u32 clib_file_index,
				       uword is_available)
{
  clib_file_t *uf = pool_elt_at_index (um->file_pool, clib_file_index);
  uword was_available = (uf->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE);
  if ((was_available != 0) != (is_available != 0))
    {
      uf->flags ^= UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      um->file_update (uf, UNIX_FILE_UPDATE_MODIFY);
    }
  return was_available != 0;
}

always_inline clib_file_t *
clib_file_get (clib_file_main_t * fm, u32 file_index)
{
  if (pool_is_free_index (fm->file_pool, file_index))
    return 0;
  return pool_elt_at_index (fm->file_pool, file_index);
}

always_inline clib_error_t *
clib_file_write (clib_file_t * f)
{
  f->write_events++;
  return f->write_function (f);
}

#endif /* included_clib_file_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
