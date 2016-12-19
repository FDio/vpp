/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
  Copyright (c) 2012 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef included_clib_elf_self_h
#define included_clib_elf_self_h

#include <vppinfra/elf.h>
#include <vppinfra/hash.h>

#define CLIB_ELF_SECTION_DATA_ALIGN 32

#define CLIB_ELF_SECTION_ADD_PREFIX(n) "clib_elf_section_" n

/* Attribute used is so that static registrations work even if
   variable is not referenced. */
#define CLIB_ELF_SECTION(SECTION)					\
   __attribute__ ((used,						\
		   aligned (CLIB_ELF_SECTION_DATA_ALIGN),		\
		   section (CLIB_ELF_SECTION_ADD_PREFIX (SECTION))))

/* Given pointer to previous data A get next pointer.  EXTRA gives extra
   space beyond A + 1 used in object. */
#define clib_elf_section_data_next(a,extra)				\
  uword_to_pointer (round_pow2 (pointer_to_uword (a + 1) + (extra),	\
				CLIB_ELF_SECTION_DATA_ALIGN),		\
		    void *)

typedef struct
{
  void *lo, *hi;
} clib_elf_section_bounds_t;

typedef struct
{
  /* Vector of bounds for this section.  Multiple shared objects may have instances
     of the same sections. */
  clib_elf_section_bounds_t *bounds;

  /* Name of ELF section (e.g. .text). */
  u8 *name;
} clib_elf_section_t;

typedef struct
{
  /* Vector of sections. */
  clib_elf_section_t *sections;

  /* Hash map of name to section index. */
  uword *section_by_name;

  /* Unix path that we were exec()ed with. */
  char *exec_path;

  elf_main_t *elf_mains;
} clib_elf_main_t;

always_inline void
clib_elf_main_free (clib_elf_main_t * m)
{
  clib_elf_section_t *s;
  vec_foreach (s, m->sections)
  {
    vec_free (s->bounds);
    vec_free (s->name);
  }
  vec_free (m->sections);
  hash_free (m->section_by_name);

  {
    elf_main_t *em;
    vec_foreach (em, m->elf_mains)
    {
      elf_main_free (em);
    }
    vec_free (m->elf_mains);
  }
}

/* Call with exec_path equal to argv[0] from C main. */
void clib_elf_main_init (char *exec_path);

clib_elf_section_bounds_t *clib_elf_get_section_bounds (char *name);

typedef struct
{
  /* The symbol. */
  elf64_symbol_t symbol;

  /* elf_main_t where symbol came from. */
  u32 elf_main_index;

  /* Symbol table in elf_main_t where this symbol came from. */
  u32 symbol_table_index;
} clib_elf_symbol_t;

/* Returns 1 if found; otherwise zero. */
uword clib_elf_symbol_by_name (char *name, clib_elf_symbol_t * result);
uword clib_elf_symbol_by_address (uword address, clib_elf_symbol_t * result);

format_function_t format_clib_elf_symbol, format_clib_elf_symbol_with_address;

#endif /* included_clib_elf_self_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
