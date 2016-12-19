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
#include <vppinfra/elf_clib.h>

#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef struct
{
  char **path;
} path_search_t;

always_inline void
path_search_free (path_search_t * p)
{
  uword i;
  for (i = 0; i < vec_len (p->path); i++)
    vec_free (p->path[i]);
  vec_free (p->path);
}

static char **
split_string (char *string, u8 delimiter)
{
  char **result = 0;
  char *p, *start, *s;

  p = string;
  while (1)
    {
      start = p;
      while (*p != 0 && *p != delimiter)
	p++;
      s = 0;
      vec_add (s, start, p - start);
      vec_add1 (s, 0);
      vec_add1 (result, s);
      if (*p == 0)
	break;
      p++;
    }

  return result;
}

static int
file_exists_and_is_executable (char *dir, char *file)
{
  char *path = (char *) format (0, "%s/%s%c", dir, file, 0);
  struct stat s;
  uword yes;

  yes = (stat (path, &s) >= 0
	 && S_ISREG (s.st_mode)
	 && 0 != (s.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)));

  vec_free (path);

  return yes;
}

static char *
path_search (char *file)
{
  path_search_t ps;
  uword i;
  char *result;

  /* Relative or absolute path. */
  if (file[0] == '.' || file[0] == '/')
    return file;

  if (getenv ("PATH") == 0)
    return file;

  ps.path = split_string (getenv ("PATH"), ':');

  for (i = 0; i < vec_len (ps.path); i++)
    if (file_exists_and_is_executable (ps.path[i], file))
      break;

  result = 0;
  if (i < vec_len (ps.path))
    result = (char *) format (0, "%s/%s%c", ps.path[i], file);

  path_search_free (&ps);

  return result;
}

static clib_error_t *
clib_elf_parse_file (clib_elf_main_t * cem,
		     char *file_name, void *link_address)
{
  elf_main_t *em;
  elf_section_t *s;
  int fd;
  struct stat fd_stat;
  uword mmap_length = 0;
  void *data = 0;
  clib_error_t *error = 0;

  vec_add2 (cem->elf_mains, em, 1);

  fd = open (file_name, 0);
  if (fd < 0)
    {
      error = clib_error_return_unix (0, "open `%s'", file_name);
      goto done;
    }

  if (fstat (fd, &fd_stat) < 0)
    {
      error = clib_error_return_unix (0, "fstat `%s'", file_name);
      goto done;
    }
  mmap_length = fd_stat.st_size;

  data = mmap (0, mmap_length, PROT_READ, MAP_SHARED, fd, /* offset */ 0);
  if (~pointer_to_uword (data) == 0)
    {
      error = clib_error_return_unix (0, "mmap `%s'", file_name);
      goto done;
    }

  error = elf_parse (em, data, mmap_length);
  if (error)
    goto done;

  /* Look for CLIB special sections. */
  {
    char *section_name_start = CLIB_ELF_SECTION_ADD_PREFIX ();
    uword section_name_start_len = strlen (section_name_start);

    vec_foreach (s, em->sections)
    {
      u8 *name = elf_section_name (em, s);
      uword *p;
      clib_elf_section_t *vs;
      clib_elf_section_bounds_t *b;

      /* Section name must begin with CLIB_ELF_SECTION key. */
      if (memcmp (name, section_name_start, section_name_start_len))
	continue;

      name += section_name_start_len;
      p = hash_get_mem (cem->section_by_name, name);
      if (p)
	vs = vec_elt_at_index (cem->sections, p[0]);
      else
	{
	  name = format (0, "%s%c", name, 0);
	  if (!cem->section_by_name)
	    cem->section_by_name = hash_create_string (0, sizeof (uword));
	  hash_set_mem (cem->section_by_name, name, vec_len (cem->sections));
	  vec_add2 (cem->sections, vs, 1);
	  vs->name = name;
	}

      vec_add2 (vs->bounds, b, 1);
      b->lo = link_address + s->header.exec_address;
      b->hi = b->lo + s->header.file_size;
    }
  }

  /* Parse symbols for this file. */
  {
    elf_symbol_table_t *t;
    elf64_symbol_t *s;

    elf_parse_symbols (em);
    vec_foreach (t, em->symbol_tables)
    {
      vec_foreach (s, t->symbols)
      {
	s->value += pointer_to_uword (link_address);
      }
    }
  }

  /* No need to keep section contents around. */
  {
    elf_section_t *s;
    vec_foreach (s, em->sections)
    {
      if (s->header.type != ELF_SECTION_STRING_TABLE)
	vec_free (s->contents);
    }
  }

done:
  if (error)
    elf_main_free (em);
  if (fd >= 0)
    close (fd);
  if (data)
    munmap (data, mmap_length);
  return error;
}

#define __USE_GNU
#include <link.h>

static int
add_section (struct dl_phdr_info *info, size_t size, void *opaque)
{
  clib_elf_main_t *cem = opaque;
  clib_error_t *error;
  char *name = (char *) info->dlpi_name;
  void *addr = (void *) info->dlpi_addr;
  uword is_main;

  is_main = strlen (name) == 0;
  if (is_main)
    {
      static int done;

      /* Only do main program once. */
      if (done++)
	return 0;

      name = path_search (cem->exec_path);
      if (!name)
	{
	  clib_error ("failed to find %s on PATH", cem->exec_path);
	  return 0;
	}
      addr = 0;
    }

  error = clib_elf_parse_file (cem, name, addr);
  if (error)
    clib_error_report (error);

  if (is_main && name != cem->exec_path)
    vec_free (name);

  return 0;
}

static clib_elf_main_t clib_elf_main;

void
clib_elf_main_init (char *exec_path)
{
  clib_elf_main_t *cem = &clib_elf_main;

  cem->exec_path = exec_path;

  dl_iterate_phdr (add_section, cem);
}

clib_elf_section_bounds_t *
clib_elf_get_section_bounds (char *name)
{
  clib_elf_main_t *em = &clib_elf_main;
  uword *p = hash_get (em->section_by_name, name);
  return p ? vec_elt_at_index (em->sections, p[0])->bounds : 0;
}

static uword
symbol_by_address_or_name (char *by_name,
			   uword by_address, clib_elf_symbol_t * s)
{
  clib_elf_main_t *cem = &clib_elf_main;
  elf_main_t *em;

  vec_foreach (em, cem->elf_mains)
  {
    elf_symbol_table_t *t;
    s->elf_main_index = em - cem->elf_mains;
    vec_foreach (t, em->symbol_tables)
    {
      s->symbol_table_index = t - em->symbol_tables;
      if (by_name)
	{
	  uword *p = hash_get (t->symbol_by_name, by_name);
	  if (p)
	    {
	      s->symbol = vec_elt (t->symbols, p[0]);
	      return 1;
	    }
	}
      else
	{
	  elf64_symbol_t *x;
	  /* FIXME linear search. */
	  vec_foreach (x, t->symbols)
	  {
	    if (by_address >= x->value && by_address < x->value + x->size)
	      {
		s->symbol = x[0];
		return 1;
	      }
	  }
	}
    }
  }

  return 0;
}

uword
clib_elf_symbol_by_name (char *by_name, clib_elf_symbol_t * s)
{
  return symbol_by_address_or_name (by_name, /* by_address */ 0, s);
}

uword
clib_elf_symbol_by_address (uword by_address, clib_elf_symbol_t * s)
{
  return symbol_by_address_or_name ( /* by_name */ 0, by_address, s);
}

u8 *
format_clib_elf_symbol (u8 * s, va_list * args)
{
  clib_elf_main_t *cem = &clib_elf_main;
  clib_elf_symbol_t *sym = va_arg (*args, clib_elf_symbol_t *);
  elf_main_t *em;
  elf_symbol_table_t *t;

  if (!sym)
    /* Just print table headings. */
    return format (s, "%U", format_elf_symbol, 0, 0, 0);

  else
    {
      em = vec_elt_at_index (cem->elf_mains, sym->elf_main_index);
      t = vec_elt_at_index (em->symbol_tables, sym->symbol_table_index);
      return format (s, "%U", format_elf_symbol, em, t, &sym->symbol);
    }
}

u8 *
format_clib_elf_symbol_with_address (u8 * s, va_list * args)
{
  uword address = va_arg (*args, uword);
  clib_elf_main_t *cem = &clib_elf_main;
  clib_elf_symbol_t sym;
  elf_main_t *em;
  elf_symbol_table_t *t;

  if (clib_elf_symbol_by_address (address, &sym))
    {
      em = vec_elt_at_index (cem->elf_mains, sym.elf_main_index);
      t = vec_elt_at_index (em->symbol_tables, sym.symbol_table_index);
      s = format (s, "%s + 0x%wx",
		  elf_symbol_name (t, &sym.symbol),
		  address - sym.symbol.value);
    }
  else
    s = format (s, "0x%wx", address);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
