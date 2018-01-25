/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_valloc_h
#define included_valloc_h
#include <vppinfra/clib.h>
#include <vppinfra/pool.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/lock.h>
#include <vppinfra/hash.h>

/** @file
    @brief Simple first-fit virtual space allocator
*/

typedef struct
{
  u32 next;			/**< next chunk pool index */
  u32 prev;			/**< previous chunk pool index */
  uword baseva;			/**< base VA for this chunk */
  uword size;			/**< size in bytes of this chunk */
  uword flags;			/**< flags (free/busy)  */
} clib_valloc_chunk_t;

#define CLIB_VALLOC_BUSY	(1<<0) /**< chunk is in use */

typedef struct
{
  clib_valloc_chunk_t *chunks;	/**< pool of virtual chunks  */
  uword *chunk_index_by_baseva;	/**< chunk by baseva hash */
  clib_spinlock_t lock;		/**< spinlock */
  uword flags;			/**< flags */
  u32 first_index;		/**< pool index of first chunk in list */
} clib_valloc_main_t;

#define CLIB_VALLOC_INITIALIZED	(1<<0) /**< object has been initialized */

/* doxygen tags in valloc.c */
void clib_valloc_init (clib_valloc_main_t * vam,
		       clib_valloc_chunk_t * template, int need_lock);
void
clib_valloc_add_chunk (clib_valloc_main_t * vam,
		       clib_valloc_chunk_t * template);

format_function_t format_valloc;

uword clib_valloc_free (clib_valloc_main_t * vam, uword baseva);
uword clib_valloc_alloc (clib_valloc_main_t * vam, uword size,
			 int os_out_of_memory_on_failure);

#endif /* included_valloc_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
