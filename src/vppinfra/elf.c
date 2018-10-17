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
#include <vppinfra/bitmap.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>
#include <vppinfra/elf.h>

always_inline void
elf_swap_first_header (elf_main_t * em, elf_first_header_t * h)
{
  h->architecture = elf_swap_u16 (em, h->architecture);
  h->file_type = elf_swap_u16 (em, h->file_type);
  h->file_version = elf_swap_u32 (em, h->file_version);
}

always_inline void
elf_swap_verneed (elf_dynamic_version_need_t * n)
{
#define _(t,f) n->f = clib_byte_swap_##t (n->f);
  foreach_elf_dynamic_version_need_field
#undef _
}

always_inline void
elf_swap_verneed_aux (elf_dynamic_version_need_aux_t * n)
{
#define _(t,f) n->f = clib_byte_swap_##t (n->f);
  foreach_elf_dynamic_version_need_aux_field
#undef _
}

clib_error_t *
elf_get_section_by_name (elf_main_t * em, char *section_name,
			 elf_section_t ** result)
{
  uword *p;

  p = hash_get_mem (em->section_by_name, section_name);
  if (!p)
    return clib_error_return (0, "no such section `%s'", section_name);

  *result = vec_elt_at_index (em->sections, p[0]);
  return 0;
}

elf_section_t *
elf_get_section_by_start_address_no_check (elf_main_t * em,
					   uword start_address)
{
  uword *p = hash_get (em->section_by_start_address, start_address);
  return p ? vec_elt_at_index (em->sections, p[0]) : 0;
}

clib_error_t *
elf_get_section_by_start_address (elf_main_t * em, uword start_address,
				  elf_section_t ** result)
{
  elf_section_t *s =
    elf_get_section_by_start_address_no_check (em, start_address);
  if (!s)
    return clib_error_return (0, "no section with address 0x%wx",
			      start_address);
  *result = s;
  return 0;
}

static u8 *
format_elf_section_type (u8 * s, va_list * args)
{
  elf_section_type_t type = va_arg (*args, elf_section_type_t);
  char *t = 0;

  switch (type)
    {
#define _(f,i) case ELF_SECTION_##f: t = #f; break;
      foreach_elf_section_type
#undef _
    }

  if (!t)
    s = format (s, "unknown 0x%x", type);
  else
    s = format (s, "%s", t);
  return s;
}

static u8 *
format_elf_section (u8 * s, va_list * args)
{
  elf_main_t *em = va_arg (*args, elf_main_t *);
  elf_section_t *es = va_arg (*args, elf_section_t *);
  elf64_section_header_t *h = &es->header;

  if (!h)
    return format (s, "%=40s%=10s%=20s%=8s%=16s%=16s%=16s",
		   "Name", "Index", "Type", "Size", "Align", "Address",
		   "File offset");

  s = format (s, "%-40s%10d%=20U%8Lx%16d%16Lx %Lx-%Lx",
	      elf_section_name (em, es),
	      es->index,
	      format_elf_section_type, h->type,
	      h->file_size,
	      h->align,
	      h->exec_address, h->file_offset, h->file_offset + h->file_size);

  if (h->flags != 0)
    {
#define _(f,i) \
  if (h->flags & ELF_SECTION_FLAG_##f) s = format (s, " %s", #f);
      foreach_elf_section_flag;
#undef _
    }

  return s;
}

static u8 *
format_elf_segment_type (u8 * s, va_list * args)
{
  elf_segment_type_t type = va_arg (*args, elf_segment_type_t);
  char *t = 0;

  switch (type)
    {
#define _(f,i) case ELF_SEGMENT_##f: t = #f; break;
      foreach_elf_segment_type
#undef _
    }

  if (!t)
    s = format (s, "unknown 0x%x", type);
  else
    s = format (s, "%s", t);
  return s;
}

static u8 *
format_elf_segment (u8 * s, va_list * args)
{
  elf_segment_t *es = va_arg (*args, elf_segment_t *);
  elf64_segment_header_t *h = &es->header;

  if (!h)
    return format (s, "%=16s%=16s%=16s%=16s",
		   "Type", "Virt. Address", "Phys. Address", "Size");

  s = format (s, "%=16U%16Lx%16Lx%16Lx%16Lx",
	      format_elf_segment_type, h->type,
	      h->virtual_address,
	      h->physical_address, h->memory_size, h->file_offset);

  if (h->flags != 0)
    {
#define _(f,i) \
  if (h->flags & ELF_SEGMENT_FLAG_##f) s = format (s, " %s", #f);
      foreach_elf_segment_flag;
#undef _
    }

  return s;
}

static u8 *
format_elf_symbol_binding_and_type (u8 * s, va_list * args)
{
  int bt = va_arg (*args, int);
  int b, t;
  char *type_string = 0;
  char *binding_string = 0;

  switch ((b = ((bt >> 4) & 0xf)))
    {
#define _(f,n) case n: binding_string = #f; break;
      foreach_elf_symbol_binding;
#undef _
    default:
      break;
    }

  switch ((t = ((bt >> 0) & 0xf)))
    {
#define _(f,n) case n: type_string = #f; break;
      foreach_elf_symbol_type;
#undef _
    default:
      break;
    }

  if (binding_string)
    s = format (s, "%s", binding_string);
  else
    s = format (s, "binding 0x%x", b);

  if (type_string)
    s = format (s, " %s", type_string);
  else
    s = format (s, " type 0x%x", t);

  return s;
}

static u8 *
format_elf_symbol_visibility (u8 * s, va_list * args)
{
  int visibility = va_arg (*args, int);
  char *t = 0;

  switch (visibility)
    {
#define _(f,n) case n: t = #f; break;
      foreach_elf_symbol_visibility
#undef _
    }

  if (t)
    return format (s, "%s", t);
  else
    return format (s, "unknown 0x%x", visibility);
}

static u8 *
format_elf_symbol_section_name (u8 * s, va_list * args)
{
  elf_main_t *em = va_arg (*args, elf_main_t *);
  int si = va_arg (*args, int);
  char *t = 0;

  if (si < vec_len (em->sections))
    {
      elf_section_t *es = vec_elt_at_index (em->sections, si);
      return format (s, "%s", elf_section_name (em, es));
    }

  if (si >= ELF_SYMBOL_SECTION_RESERVED_LO
      && si <= ELF_SYMBOL_SECTION_RESERVED_HI)
    {
      switch (si)
	{
#define _(f,n) case n: t = #f; break;
	  foreach_elf_symbol_reserved_section_index
#undef _
	default:
	  break;
	}
    }

  if (t)
    return format (s, "%s", t);
  else
    return format (s, "unknown 0x%x", si);
}

u8 *
format_elf_symbol (u8 * s, va_list * args)
{
  elf_main_t *em = va_arg (*args, elf_main_t *);
  elf_symbol_table_t *t = va_arg (*args, elf_symbol_table_t *);
  elf64_symbol_t *sym = va_arg (*args, elf64_symbol_t *);

  if (!sym)
    return format (s, "%=32s%=16s%=16s%=16s%=16s%=16s",
		   "Symbol", "Size", "Value", "Type", "Visibility",
		   "Section");

  s = format (s, "%-32s%16Ld%16Lx%=16U%=16U%U",
	      elf_symbol_name (t, sym),
	      sym->size, sym->value,
	      format_elf_symbol_binding_and_type, sym->binding_and_type,
	      format_elf_symbol_visibility, sym->visibility,
	      format_elf_symbol_section_name, em, sym->section_index);

  return s;
}

static u8 *
format_elf_relocation_type (u8 * s, va_list * args)
{
  elf_main_t *em = va_arg (*args, elf_main_t *);
  int type = va_arg (*args, int);
  char *t = 0;

  switch (em->first_header.architecture)
    {
#define _(f,i) [i] = #f,

    case ELF_ARCH_X86_64:
      {
	static char *tab[] = {
	  foreach_elf_x86_64_relocation_type
	};

#undef _
	if (type < ARRAY_LEN (tab))
	  t = tab[type];
	break;
      }

    default:
      break;
    }

  if (!t)
    s = format (s, "0x%02x", type);
  else
    s = format (s, "%s", t);

  return s;
}

static u8 *
format_elf_relocation (u8 * s, va_list * args)
{
  elf_main_t *em = va_arg (*args, elf_main_t *);
  elf_relocation_with_addend_t *r =
    va_arg (*args, elf_relocation_with_addend_t *);
  elf_symbol_table_t *t;
  elf64_symbol_t *sym;

  if (!r)
    return format (s, "%=16s%=16s%=16s", "Address", "Type", "Symbol");

  t = vec_elt_at_index (em->symbol_tables, 0);
  sym = vec_elt_at_index (t->symbols, r->symbol_and_type >> 32);

  s = format (s, "%16Lx%16U",
	      r->address,
	      format_elf_relocation_type, em, r->symbol_and_type & 0xff);

  if (sym->section_index != 0)
    {
      elf_section_t *es;
      es = vec_elt_at_index (em->sections, sym->section_index);
      s = format (s, " (section %s)", elf_section_name (em, es));
    }

  if (sym->name != 0)
    s = format (s, " %s", elf_symbol_name (t, sym));

  {
    i64 a = r->addend;
    if (a != 0)
      s = format (s, " %c 0x%Lx", a > 0 ? '+' : '-', a > 0 ? a : -a);
  }

  return s;
}

static u8 *
format_elf_dynamic_entry_type (u8 * s, va_list * args)
{
  u32 type = va_arg (*args, u32);
  char *t = 0;
  switch (type)
    {
#define _(f,n) case n: t = #f; break;
      foreach_elf_dynamic_entry_type;
#undef _
    default:
      break;
    }
  if (t)
    return format (s, "%s", t);
  else
    return format (s, "unknown 0x%x", type);
}

static u8 *
format_elf_dynamic_entry (u8 * s, va_list * args)
{
  elf_main_t *em = va_arg (*args, elf_main_t *);
  elf64_dynamic_entry_t *e = va_arg (*args, elf64_dynamic_entry_t *);

  if (!e)
    return format (s, "%=40s%=16s", "Type", "Data");

  s = format (s, "%=40U", format_elf_dynamic_entry_type, (u32) e->type);
  switch (e->type)
    {
    case ELF_DYNAMIC_ENTRY_NEEDED_LIBRARY:
    case ELF_DYNAMIC_ENTRY_RPATH:
    case ELF_DYNAMIC_ENTRY_RUN_PATH:
      s = format (s, "%s", em->dynamic_string_table + e->data);
      break;

    case ELF_DYNAMIC_ENTRY_INIT_FUNCTION:
    case ELF_DYNAMIC_ENTRY_FINI_FUNCTION:
    case ELF_DYNAMIC_ENTRY_SYMBOL_HASH:
    case ELF_DYNAMIC_ENTRY_GNU_HASH:
    case ELF_DYNAMIC_ENTRY_STRING_TABLE:
    case ELF_DYNAMIC_ENTRY_SYMBOL_TABLE:
    case ELF_DYNAMIC_ENTRY_PLT_GOT:
    case ELF_DYNAMIC_ENTRY_PLT_RELOCATION_ADDRESS:
    case ELF_DYNAMIC_ENTRY_RELA_ADDRESS:
    case ELF_DYNAMIC_ENTRY_VERSION_NEED:
    case ELF_DYNAMIC_ENTRY_VERSYM:
      {
	elf_section_t *es =
	  elf_get_section_by_start_address_no_check (em, e->data);
	if (es)
	  s = format (s, "section %s", elf_section_name (em, es));
	else
	  s = format (s, "0x%Lx", e->data);
	break;
      }

    default:
      s = format (s, "0x%Lx", e->data);
      break;
    }

  return s;
}

static u8 *
format_elf_architecture (u8 * s, va_list * args)
{
  int a = va_arg (*args, int);
  char *t;

  switch (a)
    {
#define _(f,n) case n: t = #f; break;
      foreach_elf_architecture;
#undef _
    default:
      return format (s, "unknown 0x%x", a);
    }

  return format (s, "%s", t);
}

static u8 *
format_elf_abi (u8 * s, va_list * args)
{
  int a = va_arg (*args, int);
  char *t;

  switch (a)
    {
#define _(f,n) case n: t = #f; break;
      foreach_elf_abi;
#undef _
    default:
      return format (s, "unknown 0x%x", a);
    }

  return format (s, "%s", t);
}

static u8 *
format_elf_file_class (u8 * s, va_list * args)
{
  int a = va_arg (*args, int);
  char *t;

  switch (a)
    {
#define _(f) case ELF_##f: t = #f; break;
      foreach_elf_file_class;
#undef _
    default:
      return format (s, "unknown 0x%x", a);
    }

  return format (s, "%s", t);
}

static u8 *
format_elf_file_type (u8 * s, va_list * args)
{
  int a = va_arg (*args, int);
  char *t;

  if (a >= ELF_ARCH_SPECIFIC_LO && a <= ELF_ARCH_SPECIFIC_HI)
    return format (s, "arch-specific 0x%x", a - ELF_ARCH_SPECIFIC_LO);

  if (a >= ELF_OS_SPECIFIC_LO && a <= ELF_OS_SPECIFIC_HI)
    return format (s, "os-specific 0x%x", a - ELF_OS_SPECIFIC_LO);

  switch (a)
    {
#define _(f,n) case n: t = #f; break;
      foreach_elf_file_type;
#undef _
    default:
      return format (s, "unknown 0x%x", a);
    }

  return format (s, "%s", t);
}

static u8 *
format_elf_data_encoding (u8 * s, va_list * args)
{
  int a = va_arg (*args, int);
  char *t;

  switch (a)
    {
#define _(f) case ELF_##f: t = #f; break;
      foreach_elf_data_encoding;
#undef _
    default:
      return format (s, "unknown 0x%x", a);
    }

  return format (s, "%s", t);
}

static int
elf_section_offset_compare (void *a1, void *a2)
{
  elf_section_t *s1 = a1;
  elf_section_t *s2 = a2;

  return ((i64) s1->header.file_offset - (i64) s2->header.file_offset);
}

static int
elf_segment_va_compare (void *a1, void *a2)
{
  elf_segment_t *s1 = a1;
  elf_segment_t *s2 = a2;

  return ((i64) s1->header.virtual_address -
	  (i64) s2->header.virtual_address);
}

u8 *
format_elf_main (u8 * s, va_list * args)
{
  elf_main_t *em = va_arg (*args, elf_main_t *);
  u32 verbose = va_arg (*args, u32);
  elf64_file_header_t *fh = &em->file_header;

  s =
    format (s,
	    "File header: machine: %U, file type/class %U/%U, data-encoding: %U, abi: %U version %d\n",
	    format_elf_architecture, em->first_header.architecture,
	    format_elf_file_type, em->first_header.file_type,
	    format_elf_file_class, em->first_header.file_class,
	    format_elf_data_encoding, em->first_header.data_encoding,
	    format_elf_abi, em->first_header.abi,
	    em->first_header.abi_version);

  s = format (s, "  entry 0x%Lx, arch-flags 0x%x",
	      em->file_header.entry_point, em->file_header.flags);

  if (em->interpreter)
    s = format (s, "\n  interpreter: %s", em->interpreter);

  {
    elf_section_t *h, *copy;

    copy = 0;
    vec_foreach (h, em->sections) if (h->header.type != ~0)
      vec_add1 (copy, h[0]);

    vec_sort_with_function (copy, elf_section_offset_compare);

    s = format (s, "\nSections %d at file offset 0x%Lx-0x%Lx:\n",
		fh->section_header_count,
		fh->section_header_file_offset,
		fh->section_header_file_offset +
		(u64) fh->section_header_count * fh->section_header_size);
    s = format (s, "%U\n", format_elf_section, em, 0);
    vec_foreach (h, copy) s = format (s, "%U\n", format_elf_section, em, h);

    vec_free (copy);
  }

  {
    elf_segment_t *h, *copy;

    copy = 0;
    vec_foreach (h, em->segments)
      if (h->header.type != ELF_SEGMENT_UNUSED && h->header.type != ~0)
      vec_add1 (copy, h[0]);

    /* Sort segments by address. */
    vec_sort_with_function (copy, elf_segment_va_compare);

    s = format (s, "\nSegments: %d at file offset 0x%Lx-0x%Lx:\n",
		fh->segment_header_count,
		fh->segment_header_file_offset,
		(u64) fh->segment_header_file_offset +
		(u64) fh->segment_header_count *
		(u64) fh->segment_header_size);

    s = format (s, "%U\n", format_elf_segment, 0);
    vec_foreach (h, copy) s = format (s, "%U\n", format_elf_segment, h);

    vec_free (copy);
  }

  if ((verbose & FORMAT_ELF_MAIN_SYMBOLS) && vec_len (em->symbol_tables) > 0)
    {
      elf_symbol_table_t *t;
      elf64_symbol_t *sym;
      elf_section_t *es;

      vec_foreach (t, em->symbol_tables)
      {
	es = vec_elt_at_index (em->sections, t->section_index);
	s =
	  format (s, "\nSymbols for section %s:\n",
		  elf_section_name (em, es));

	s = format (s, "%U\n", format_elf_symbol, em, 0, 0);
	vec_foreach (sym, t->symbols)
	  s = format (s, "%U\n", format_elf_symbol, em, t, sym);
      }
    }

  if ((verbose & FORMAT_ELF_MAIN_RELOCATIONS)
      && vec_len (em->relocation_tables) > 0)
    {
      elf_relocation_table_t *t;
      elf_relocation_with_addend_t *r;
      elf_section_t *es;

      vec_foreach (t, em->relocation_tables)
      {
	es = vec_elt_at_index (em->sections, t->section_index);
	r = t->relocations;
	s = format (s, "\nRelocations for section %s:\n",
		    elf_section_name (em, es));

	s = format (s, "%U\n", format_elf_relocation, em, 0);
	vec_foreach (r, t->relocations)
	{
	  s = format (s, "%U\n", format_elf_relocation, em, r);
	}
      }
    }

  if ((verbose & FORMAT_ELF_MAIN_DYNAMIC)
      && vec_len (em->dynamic_entries) > 0)
    {
      elf64_dynamic_entry_t *es, *e;
      s = format (s, "\nDynamic linker information:\n");
      es = vec_dup (em->dynamic_entries);
      s = format (s, "%U\n", format_elf_dynamic_entry, em, 0);
      vec_foreach (e, es)
	s = format (s, "%U\n", format_elf_dynamic_entry, em, e);
    }

  return s;
}

static void
elf_parse_segments (elf_main_t * em, void *data)
{
  void *d = data + em->file_header.segment_header_file_offset;
  uword n = em->file_header.segment_header_count;
  uword i;

  vec_resize (em->segments, n);

  for (i = 0; i < n; i++)
    {
      em->segments[i].index = i;

      if (em->first_header.file_class == ELF_64BIT)
	{
	  elf64_segment_header_t *h = d;
#define _(t,f) em->segments[i].header.f = elf_swap_##t (em, h->f);
	  foreach_elf64_segment_header
#undef _
	    d = (h + 1);
	}
      else
	{
	  elf32_segment_header_t *h = d;
#define _(t,f) em->segments[i].header.f = elf_swap_##t (em, h->f);
	  foreach_elf32_segment_header
#undef _
	    d = (h + 1);
	}
    }
}

static void
elf_parse_sections (elf_main_t * em, void *data)
{
  elf64_file_header_t *fh = &em->file_header;
  elf_section_t *s;
  void *d = data + fh->section_header_file_offset;
  uword n = fh->section_header_count;
  uword i;

  vec_resize (em->sections, n);

  for (i = 0; i < n; i++)
    {
      s = em->sections + i;

      s->index = i;

      if (em->first_header.file_class == ELF_64BIT)
	{
	  elf64_section_header_t *h = d;
#define _(t,f) em->sections[i].header.f = elf_swap_##t (em, h->f);
	  foreach_elf64_section_header
#undef _
	    d = (h + 1);
	}
      else
	{
	  elf32_section_header_t *h = d;
#define _(t,f) em->sections[i].header.f = elf_swap_##t (em, h->f);
	  foreach_elf32_section_header
#undef _
	    d = (h + 1);
	}

      if (s->header.type != ELF_SECTION_NO_BITS)
	vec_add (s->contents, data + s->header.file_offset,
		 s->header.file_size);
    }

  s = vec_elt_at_index (em->sections, fh->section_header_string_table_index);

  em->section_by_name
    = hash_create_string ( /* # elts */ vec_len (em->sections),
			  /* sizeof of value */ sizeof (uword));

  vec_foreach (s, em->sections)
  {
    hash_set_mem (em->section_by_name,
		  elf_section_name (em, s), s - em->sections);
    hash_set (em->section_by_start_address,
	      s->header.exec_address, s - em->sections);
  }
}

static void
add_symbol_table (elf_main_t * em, elf_section_t * s)
{
  elf_symbol_table_t *tab;
  elf32_symbol_t *sym32;
  elf64_symbol_t *sym64;
  uword i;

  if (s->header.type == ELF_SECTION_DYNAMIC_SYMBOL_TABLE)
    em->dynamic_symbol_table_index = vec_len (em->symbol_tables);

  vec_add2 (em->symbol_tables, tab, 1);

  tab->section_index = s->index;

  if (em->first_header.file_class == ELF_64BIT)
    {
      tab->symbols =
	elf_get_section_contents (em, s - em->sections,
				  sizeof (tab->symbols[0]));
      for (i = 0; i < vec_len (tab->symbols); i++)
	{
#define _(t,f) tab->symbols[i].f = elf_swap_##t (em, tab->symbols[i].f);
	  foreach_elf64_symbol_header;
#undef _
	}
    }
  else
    {
      sym32 =
	elf_get_section_contents (em, s - em->sections, sizeof (sym32[0]));
      vec_clone (tab->symbols, sym32);
      for (i = 0; i < vec_len (tab->symbols); i++)
	{
#define _(t,f) tab->symbols[i].f = elf_swap_##t (em, sym32[i].f);
	  foreach_elf32_symbol_header;
#undef _
	}
    }

  if (s->header.link == 0)
    return;

  tab->string_table =
    elf_get_section_contents (em, s->header.link,
			      sizeof (tab->string_table[0]));
  tab->symbol_by_name =
    hash_create_string ( /* # elts */ vec_len (tab->symbols),
			/* sizeof of value */ sizeof (uword));

  vec_foreach (sym64, tab->symbols)
  {
    if (sym64->name != 0)
      hash_set_mem (tab->symbol_by_name,
		    tab->string_table + sym64->name, sym64 - tab->symbols);
  }
}

static void
add_relocation_table (elf_main_t * em, elf_section_t * s)
{
  uword has_addend = s->header.type == ELF_SECTION_RELOCATION_ADD;
  elf_relocation_table_t *t;
  uword i;

  vec_add2 (em->relocation_tables, t, 1);
  t->section_index = s - em->sections;

  if (em->first_header.file_class == ELF_64BIT)
    {
      elf64_relocation_t *r, *rs;

      rs = elf_get_section_contents (em, t->section_index,
				     sizeof (rs[0]) +
				     has_addend * sizeof (rs->addend[0]));

      if (em->need_byte_swap)
	{
	  r = rs;
	  for (i = 0; i < vec_len (r); i++)
	    {
	      r->address = elf_swap_u64 (em, r->address);
	      r->symbol_and_type = elf_swap_u32 (em, r->symbol_and_type);
	      if (has_addend)
		r->addend[0] = elf_swap_u64 (em, r->addend[0]);
	      r = elf_relocation_next (r, s->header.type);
	    }
	}

      vec_resize (t->relocations, vec_len (rs));
      clib_memcpy (t->relocations, rs, vec_bytes (t->relocations));
      vec_free (rs);
    }
  else
    {
      elf_relocation_with_addend_t *r;
      elf32_relocation_t *r32, *r32s;

      r32s = elf_get_section_contents (em, t->section_index,
				       sizeof (r32s[0]) +
				       has_addend * sizeof (r32s->addend[0]));
      vec_resize (t->relocations, vec_len (r32s));

      r32 = r32s;
      vec_foreach (r, t->relocations)
      {
	r->address = elf_swap_u32 (em, r32->address);
	r->symbol_and_type = elf_swap_u32 (em, r->symbol_and_type);
	r->addend = has_addend ? elf_swap_u32 (em, r32->addend[0]) : 0;
	r32 = elf_relocation_next (r32, s->header.type);
      }

      vec_free (r32s);
    }
}

void
elf_parse_symbols (elf_main_t * em)
{
  elf_section_t *s;

  /* No need to parse symbols twice. */
  if (em->parsed_symbols)
    return;
  em->parsed_symbols = 1;

  vec_foreach (s, em->sections)
  {
    switch (s->header.type)
      {
      case ELF_SECTION_SYMBOL_TABLE:
      case ELF_SECTION_DYNAMIC_SYMBOL_TABLE:
	add_symbol_table (em, s);
	break;

      case ELF_SECTION_RELOCATION_ADD:
      case ELF_SECTION_RELOCATION:
	add_relocation_table (em, s);
	break;

      default:
	break;
      }
  }
}

void
elf_set_dynamic_entries (elf_main_t * em)
{
  uword i;

  /* Start address for sections may have changed. */
  {
    elf64_dynamic_entry_t *e;

    vec_foreach (e, em->dynamic_entries)
    {
      switch (e->type)
	{
	case ELF_DYNAMIC_ENTRY_INIT_FUNCTION:
	case ELF_DYNAMIC_ENTRY_FINI_FUNCTION:
	case ELF_DYNAMIC_ENTRY_SYMBOL_HASH:
	case ELF_DYNAMIC_ENTRY_GNU_HASH:
	case ELF_DYNAMIC_ENTRY_STRING_TABLE:
	case ELF_DYNAMIC_ENTRY_SYMBOL_TABLE:
	case ELF_DYNAMIC_ENTRY_PLT_GOT:
	case ELF_DYNAMIC_ENTRY_PLT_RELOCATION_ADDRESS:
	case ELF_DYNAMIC_ENTRY_RELA_ADDRESS:
	case ELF_DYNAMIC_ENTRY_VERSION_NEED:
	case ELF_DYNAMIC_ENTRY_VERSYM:
	  {
	    elf_section_t *es =
	      elf_get_section_by_start_address_no_check (em, e->data);
	    /* If section is not found just leave e->data alone. */
	    if (es)
	      e->data = es->header.exec_address;
	    break;
	  }

	default:
	  break;
	}
    }
  }

  if (em->first_header.file_class == ELF_64BIT)
    {
      elf64_dynamic_entry_t *e, *es;

      es = em->dynamic_entries;
      if (em->need_byte_swap)
	{
	  es = vec_dup (es);
	  vec_foreach (e, es)
	  {
	    e->type = elf_swap_u64 (em, e->type);
	    e->data = elf_swap_u64 (em, e->data);
	  }
	}

      elf_set_section_contents (em, em->dynamic_section_index, es,
				vec_bytes (es));
      if (es != em->dynamic_entries)
	vec_free (es);
    }
  else
    {
      elf32_dynamic_entry_t *es;

      vec_clone (es, em->dynamic_entries);
      if (em->need_byte_swap)
	{
	  for (i = 0; i < vec_len (es); i++)
	    {
	      es[i].type = elf_swap_u32 (em, em->dynamic_entries[i].type);
	      es[i].data = elf_swap_u32 (em, em->dynamic_entries[i].data);
	    }
	}

      elf_set_section_contents (em, em->dynamic_section_index, es,
				vec_bytes (es));
      vec_free (es);
    }
}

clib_error_t *
elf_parse (elf_main_t * em, void *data, uword data_bytes)
{
  elf_first_header_t *h = data;
  elf64_file_header_t *fh = &em->file_header;
  clib_error_t *error = 0;

  {
    char *save = em->file_name;
    clib_memset (em, 0, sizeof (em[0]));
    em->file_name = save;
  }

  em->first_header = h[0];
  em->need_byte_swap =
    CLIB_ARCH_IS_BIG_ENDIAN != (h->data_encoding ==
				ELF_TWOS_COMPLEMENT_BIG_ENDIAN);
  elf_swap_first_header (em, &em->first_header);

  if (!(h->magic[0] == 0x7f
	&& h->magic[1] == 'E' && h->magic[2] == 'L' && h->magic[3] == 'F'))
    return clib_error_return (0, "`%s': bad magic", em->file_name);

  if (h->file_class == ELF_64BIT)
    {
      elf64_file_header_t *h64 = (void *) (h + 1);
#define _(t,f) fh->f = elf_swap_##t (em, h64->f);
      foreach_elf64_file_header
#undef _
    }
  else
    {
      elf32_file_header_t *h32 = (void *) (h + 1);

#define _(t,f) fh->f = elf_swap_##t (em, h32->f);
      foreach_elf32_file_header
#undef _
    }

  elf_parse_segments (em, data);
  elf_parse_sections (em, data);

  /* Figure which sections are contained in each segment. */
  {
    elf_segment_t *g;
    elf_section_t *s;
    vec_foreach (g, em->segments)
    {
      u64 g_lo, g_hi;
      u64 s_lo, s_hi;

      if (g->header.memory_size == 0)
	continue;

      g_lo = g->header.virtual_address;
      g_hi = g_lo + g->header.memory_size;

      vec_foreach (s, em->sections)
      {
	s_lo = s->header.exec_address;
	s_hi = s_lo + s->header.file_size;

	if (s_lo >= g_lo && s_hi <= g_hi)
	  {
	    g->section_index_bitmap =
	      clib_bitmap_ori (g->section_index_bitmap, s->index);
	    s->segment_index_bitmap =
	      clib_bitmap_ori (s->segment_index_bitmap, g->index);
	  }
      }
    }
  }

  return error;
}

#ifdef CLIB_UNIX

static void
add_dynamic_entries (elf_main_t * em, elf_section_t * s)
{
  uword i;

  /* Can't have more than one dynamic section. */
  ASSERT (em->dynamic_section_index == 0);
  em->dynamic_section_index = s->index;

  if (em->first_header.file_class == ELF_64BIT)
    {
      elf64_dynamic_entry_t *e;

      e = elf_get_section_contents (em, s - em->sections, sizeof (e[0]));
      if (em->need_byte_swap)
	for (i = 0; i < vec_len (e); i++)
	  {
	    e[i].type = elf_swap_u64 (em, e[i].type);
	    e[i].data = elf_swap_u64 (em, e[i].data);
	  }

      em->dynamic_entries = e;
    }
  else
    {
      elf32_dynamic_entry_t *e;

      e = elf_get_section_contents (em, s - em->sections, sizeof (e[0]));
      vec_clone (em->dynamic_entries, e);
      if (em->need_byte_swap)
	for (i = 0; i < vec_len (e); i++)
	  {
	    em->dynamic_entries[i].type = elf_swap_u32 (em, e[i].type);
	    em->dynamic_entries[i].data = elf_swap_u32 (em, e[i].data);
	  }

      vec_free (e);
    }
}

static void
byte_swap_verneed (elf_main_t * em, elf_dynamic_version_need_union_t * vus)
{
  uword *entries_swapped = 0;
  uword i, j;

  for (i = 0; i < vec_len (vus); i++)
    {
      elf_dynamic_version_need_union_t *n = vec_elt_at_index (vus, i);
      elf_dynamic_version_need_union_t *a;

      if (clib_bitmap_get (entries_swapped, i))
	continue;

      elf_swap_verneed (&n->need);
      entries_swapped = clib_bitmap_set (entries_swapped, i, 1);

      if (n->need.first_aux_offset != 0)
	{
	  ASSERT (n->need.first_aux_offset % sizeof (n[0]) == 0);
	  j = i + (n->need.first_aux_offset / sizeof (n[0]));
	  while (1)
	    {
	      a = vec_elt_at_index (vus, j);
	      if (!clib_bitmap_get (entries_swapped, j))
		{
		  entries_swapped = clib_bitmap_set (entries_swapped, j, 1);
		  elf_swap_verneed_aux (&a->aux);
		}
	      if (a->aux.next_offset == 0)
		break;
	      ASSERT (a->aux.next_offset % sizeof (a->aux) == 0);
	      j += (a->aux.next_offset / sizeof (a->aux));
	    }
	}
    }

  clib_bitmap_free (entries_swapped);
}

static void set_dynamic_verneed (elf_main_t * em) __attribute__ ((unused));
static void
set_dynamic_verneed (elf_main_t * em)
{
  elf_dynamic_version_need_union_t *vus = em->verneed;

  if (em->need_byte_swap)
    {
      vus = vec_dup (vus);
      byte_swap_verneed (em, vus);
    }

  elf_set_section_contents (em, em->verneed_section_index, vus,
			    vec_bytes (vus));
  if (vus != em->verneed)
    vec_free (vus);
}

static void
set_symbol_table (elf_main_t * em, u32 table_index) __attribute__ ((unused));
static void
set_symbol_table (elf_main_t * em, u32 table_index)
{
  elf_symbol_table_t *tab = vec_elt_at_index (em->symbol_tables, table_index);

  if (em->first_header.file_class == ELF_64BIT)
    {
      elf64_symbol_t *s, *syms;

      syms = vec_dup (tab->symbols);
      vec_foreach (s, syms)
      {
#define _(t,f) s->f = elf_swap_##t (em, s->f);
	foreach_elf64_symbol_header;
#undef _
      }

      elf_set_section_contents (em, tab->section_index,
				syms, vec_bytes (syms));
    }
  else
    {
      elf32_symbol_t *syms;
      uword i;
      vec_clone (syms, tab->symbols);
      for (i = 0; i < vec_len (tab->symbols); i++)
	{
#define _(t,f) syms[i].f = elf_swap_##t (em, tab->symbols[i].f);
	  foreach_elf32_symbol_header;
#undef _
	}

      elf_set_section_contents (em, tab->section_index,
				syms, vec_bytes (syms));
    }
}

static char *
elf_find_interpreter (elf_main_t * em, void *data)
{
  elf_segment_t *g;
  elf_section_t *s;
  uword *p;

  vec_foreach (g, em->segments)
  {
    if (g->header.type == ELF_SEGMENT_INTERP)
      break;
  }

  if (g >= vec_end (em->segments))
    return 0;

  p = hash_get (em->section_by_start_address, g->header.virtual_address);
  if (!p)
    return 0;

  s = vec_elt_at_index (em->sections, p[0]);
  return (char *) vec_dup (s->contents);
}

static void *
elf_get_section_contents_with_starting_address (elf_main_t * em,
						uword start_address,
						uword elt_size,
						u32 * section_index_result)
{
  elf_section_t *s = 0;
  clib_error_t *error;

  error = elf_get_section_by_start_address (em, start_address, &s);
  if (error)
    {
      clib_error_report (error);
      return 0;
    }

  if (section_index_result)
    *section_index_result = s->index;

  return elf_get_section_contents (em, s->index, elt_size);
}

static void
elf_parse_dynamic (elf_main_t * em)
{
  elf_section_t *s;
  elf64_dynamic_entry_t *e;

  vec_foreach (s, em->sections)
  {
    switch (s->header.type)
      {
      case ELF_SECTION_DYNAMIC:
	add_dynamic_entries (em, s);
	break;

      default:
	break;
      }
  }

  em->dynamic_string_table_section_index = ~0;
  em->dynamic_string_table = 0;

  vec_foreach (e, em->dynamic_entries)
  {
    switch (e->type)
      {
      case ELF_DYNAMIC_ENTRY_STRING_TABLE:
	ASSERT (vec_len (em->dynamic_string_table) == 0);
	em->dynamic_string_table
	  =
	  elf_get_section_contents_with_starting_address (em, e->data,
							  sizeof (u8),
							  &em->
							  dynamic_string_table_section_index);
	break;

      case ELF_DYNAMIC_ENTRY_SYMBOL_TABLE:
	{
	  elf_section_t *s = 0;
	  clib_error_t *error;

	  error = elf_get_section_by_start_address (em, e->data, &s);
	  if (error)
	    {
	      clib_error_report (error);
	      return;
	    }

	  em->dynamic_symbol_table_section_index = s - em->sections;
	}
	break;

      case ELF_DYNAMIC_ENTRY_VERSYM:
	em->versym
	  =
	  elf_get_section_contents_with_starting_address (em, e->data,
							  sizeof (em->versym
								  [0]),
							  &em->
							  versym_section_index);
	if (em->need_byte_swap)
	  {
	    uword i;
	    for (i = 0; i < vec_len (em->versym); i++)
	      em->versym[i] = clib_byte_swap_u16 (em->versym[i]);
	  }
	break;

      case ELF_DYNAMIC_ENTRY_VERSION_NEED:
	em->verneed
	  =
	  elf_get_section_contents_with_starting_address (em, e->data,
							  sizeof (em->verneed
								  [0]),
							  &em->
							  verneed_section_index);
	if (em->need_byte_swap)
	  byte_swap_verneed (em, em->verneed);
	break;

      default:
	break;
      }
  }
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

clib_error_t *
elf_read_file (elf_main_t * em, char *file_name)
{
  int fd;
  struct stat fd_stat;
  uword mmap_length = 0;
  void *data = 0;
  clib_error_t *error = 0;

  elf_main_init (em);

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

  em->file_name = file_name;

  error = elf_parse (em, data, mmap_length);
  if (error)
    goto done;

  elf_parse_symbols (em);
  elf_parse_dynamic (em);

  em->interpreter = elf_find_interpreter (em, data);

  munmap (data, mmap_length);
  close (fd);

  return /* no error */ 0;

done:
  elf_main_free (em);
  if (fd >= 0)
    close (fd);
  if (data)
    munmap (data, mmap_length);
  return error;
}

typedef struct
{
  u8 *new_table;

  u8 *old_table;

  uword *hash;
} string_table_builder_t;

static u32
string_table_add_name (string_table_builder_t * b, u8 * n)
{
  uword *p, i, j, l;

  p = hash_get_mem (b->hash, n);
  if (p)
    return p[0];

  l = strlen ((char *) n);
  i = vec_len (b->new_table);
  vec_add (b->new_table, n, l + 1);

  for (j = 0; j <= l; j++)
    {
      if (j > 0)
	{
	  p = hash_get_mem (b->hash, n + j);

	  /* Sub-string already in table? */
	  if (p)
	    continue;
	}

      hash_set_mem (b->hash, n + j, i + j);
    }

  return i;
}

static u32 string_table_add_name_index (string_table_builder_t * b, u32 index)
  __attribute__ ((unused));
static u32
string_table_add_name_index (string_table_builder_t * b, u32 index)
{
  u8 *n = b->old_table + index;
  return string_table_add_name (b, n);
}

static void string_table_init (string_table_builder_t * b, u8 * old_table)
  __attribute__ ((unused));
static void
string_table_init (string_table_builder_t * b, u8 * old_table)
{
  clib_memset (b, 0, sizeof (b[0]));
  b->old_table = old_table;
  b->hash = hash_create_string (0, sizeof (uword));
}

static u8 *string_table_done (string_table_builder_t * b)
  __attribute__ ((unused));
static u8 *
string_table_done (string_table_builder_t * b)
{
  hash_free (b->hash);
  return b->new_table;
}

static void
layout_sections (elf_main_t * em)
{
  elf_section_t *s;
  u32 n_sections_with_changed_exec_address = 0;
  u32 *deferred_symbol_and_string_sections = 0;
  u32 n_deleted_sections = 0;
  /* note: rebuild is always zero. Intent lost in the sands of time */
#if 0
  int rebuild = 0;

  /* Re-build section string table (sections may have been deleted). */
  if (rebuild)
    {
      u8 *st = 0;

      vec_foreach (s, em->sections)
      {
	u8 *name;
	if (s->header.type == ~0)
	  continue;
	name = elf_section_name (em, s);
	s->header.name = vec_len (st);
	vec_add (st, name, strlen ((char *) name) + 1);
      }

      s =
	vec_elt_at_index (em->sections,
			  em->file_header.section_header_string_table_index);

      vec_free (s->contents);
      s->contents = st;
    }

  /* Re-build dynamic string table. */
  if (rebuild && em->dynamic_string_table_section_index != ~0)
    {
      string_table_builder_t b;

      string_table_init (&b, em->dynamic_string_table);

      /* Add all dynamic symbols. */
      {
	elf_symbol_table_t *symtab;
	elf64_symbol_t *sym;

	symtab =
	  vec_elt_at_index (em->symbol_tables,
			    em->dynamic_symbol_table_index);
	vec_foreach (sym, symtab->symbols)
	{
	  u8 *name = elf_symbol_name (symtab, sym);
	  sym->name = string_table_add_name (&b, name);
	}

	set_symbol_table (em, em->dynamic_symbol_table_index);
      }

      /* Add all dynamic entries. */
      {
	elf64_dynamic_entry_t *e;

	vec_foreach (e, em->dynamic_entries)
	{
	  switch (e->type)
	    {
	    case ELF_DYNAMIC_ENTRY_NEEDED_LIBRARY:
	    case ELF_DYNAMIC_ENTRY_RPATH:
	    case ELF_DYNAMIC_ENTRY_RUN_PATH:
	      e->data = string_table_add_name_index (&b, e->data);
	      break;
	    }
	}
      }

      /* Add all version needs. */
      if (vec_len (em->verneed) > 0)
	{
	  elf_dynamic_version_need_union_t *n, *a;

	  n = em->verneed;
	  while (1)
	    {
	      n->need.file_name_offset =
		string_table_add_name_index (&b, n->need.file_name_offset);

	      if (n->need.first_aux_offset != 0)
		{
		  a = n + n->need.first_aux_offset / sizeof (n[0]);
		  while (1)
		    {
		      a->aux.name =
			string_table_add_name_index (&b, a->aux.name);
		      if (a->aux.next_offset == 0)
			break;
		      a += a->aux.next_offset / sizeof (a[0]);
		    }
		}

	      if (n->need.next_offset == 0)
		break;

	      n += n->need.next_offset / sizeof (n[0]);
	    }

	  set_dynamic_verneed (em);
	}

      s =
	vec_elt_at_index (em->sections,
			  em->dynamic_string_table_section_index);

      vec_free (s->contents);
      s->contents = string_table_done (&b);
    }
#endif /* dead code */

  /* Figure file offsets and exec addresses for sections. */
  {
    u64 exec_address = 0, file_offset = 0;
    u64 file_size, align_size;

    vec_foreach (s, em->sections)
    {
      /* Ignore deleted and unused sections. */
      switch (s->header.type)
	{
	case ~0:
	  n_deleted_sections++;
	case ELF_SECTION_UNUSED:
	  continue;

	case ELF_SECTION_STRING_TABLE:
	case ELF_SECTION_SYMBOL_TABLE:
	  if (!(s->index == em->dynamic_string_table_section_index
		|| s->index ==
		em->file_header.section_header_string_table_index))
	    {
	      vec_add1 (deferred_symbol_and_string_sections, s->index);
	      continue;
	    }
	  break;

	default:
	  break;
	}

      exec_address = round_pow2_u64 (exec_address, s->header.align);

      /* Put sections we added at end of file. */
      if (s->header.file_offset == ~0)
	s->header.file_offset = file_offset;

      /* Follow gaps in original file. */
      if (s->header.exec_address > exec_address)
	{
	  exec_address = s->header.exec_address;
	  file_offset = s->header.file_offset;
	}

      if (s->header.flags & ELF_SECTION_FLAG_ALLOC)
	{
	  s->exec_address_change = exec_address - s->header.exec_address;
	  n_sections_with_changed_exec_address += s->exec_address_change != 0;
	  s->header.exec_address = exec_address;
	}

      if (s->header.type == ELF_SECTION_NO_BITS)
	file_size = s->header.file_size;
      else
	file_size = vec_len (s->contents);

      {
	u64 align;

	if (s + 1 >= vec_end (em->sections))
	  align = 16;
	else if (s[1].header.type == ELF_SECTION_NO_BITS)
	  align = 8;
	else
	  align = s[1].header.align;

	if (s->header.flags & ELF_SECTION_FLAG_ALLOC)
	  {
	    u64 v = round_pow2_u64 (exec_address + file_size, align);
	    align_size = v - exec_address;
	  }
	else
	  {
	    u64 v = round_pow2_u64 (file_offset + file_size, align);
	    align_size = v - file_offset;
	  }
      }

      s->header.file_offset = file_offset;
      s->header.file_size = file_size;
      s->align_size = align_size;

      if (s->header.type != ELF_SECTION_NO_BITS)
	file_offset += align_size;
      exec_address += align_size;
    }

    /* Section headers go after last section but before symbol/string
       tables. */
    {
      elf64_file_header_t *fh = &em->file_header;

      fh->section_header_file_offset = file_offset;
      fh->section_header_count = vec_len (em->sections) - n_deleted_sections;
      file_offset += (u64) fh->section_header_count * fh->section_header_size;
    }

    {
      int i;
      for (i = 0; i < vec_len (deferred_symbol_and_string_sections); i++)
	{
	  s =
	    vec_elt_at_index (em->sections,
			      deferred_symbol_and_string_sections[i]);

	  s->header.file_offset = file_offset;
	  s->header.file_size = vec_len (s->contents);

	  align_size = round_pow2 (vec_len (s->contents), 16);
	  s->align_size = align_size;
	  file_offset += align_size;
	}
      vec_free (deferred_symbol_and_string_sections);
    }
  }

  /* Update dynamic entries now that sections have been assigned
     possibly new addresses. */
#if 0
  if (rebuild)
    elf_set_dynamic_entries (em);
#endif

  /* Update segments for changed section addresses. */
  {
    elf_segment_t *g;
    uword si;

    vec_foreach (g, em->segments)
    {
      u64 s_lo, s_hi, f_lo = 0;
      u32 n_sections = 0;

      if (g->header.memory_size == 0)
	continue;

      s_lo = s_hi = 0;
	/* *INDENT-OFF* */
	clib_bitmap_foreach (si, g->section_index_bitmap, ({
	  u64 lo, hi;

	  s = vec_elt_at_index (em->sections, si);
	  lo = s->header.exec_address;
	  hi = lo + s->align_size;
	  if (n_sections == 0)
	    {
	      s_lo = lo;
	      s_hi = hi;
	      f_lo = s->header.file_offset;
	      n_sections++;
	    }
	  else
	    {
	      if (lo < s_lo)
		{
		  s_lo = lo;
		  f_lo = s->header.file_offset;
		}
	      if (hi > s_hi)
		s_hi = hi;
	    }
	}));
	/* *INDENT-ON* */

      if (n_sections == 0)
	continue;

      /* File offset zero includes ELF headers/segment headers.
         Don't change that. */
      if (g->header.file_offset == 0 && g->header.type == ELF_SEGMENT_LOAD)
	{
	  s_lo = g->header.virtual_address;
	  f_lo = g->header.file_offset;
	}

      g->header.virtual_address = s_lo;
      g->header.physical_address = s_lo;
      g->header.file_offset = f_lo;
      g->header.memory_size = s_hi - s_lo;
    }
  }
}

clib_error_t *
elf_write_file (elf_main_t * em, char *file_name)
{
  int fd;
  FILE *f;
  clib_error_t *error = 0;

  fd = open (file_name, O_CREAT | O_RDWR | O_TRUNC, 0755);
  if (fd < 0)
    return clib_error_return_unix (0, "open `%s'", file_name);

  f = fdopen (fd, "w");

  /* Section contents may have changed.  So, we need to update
     stuff to reflect this. */
  layout_sections (em);

  /* Write first header. */
  {
    elf_first_header_t h = em->first_header;

    elf_swap_first_header (em, &h);
    if (fwrite (&h, sizeof (h), 1, f) != 1)
      {
	error = clib_error_return_unix (0, "write first header");
	goto error;
      }
  }

  /* Write file header. */
  {
    elf64_file_header_t h = em->file_header;

    /* Segment headers are after first header. */
    h.segment_header_file_offset = sizeof (elf_first_header_t);
    if (em->first_header.file_class == ELF_64BIT)
      h.segment_header_file_offset += sizeof (elf64_file_header_t);
    else
      h.segment_header_file_offset += sizeof (elf32_file_header_t);

    if (em->first_header.file_class == ELF_64BIT)
      {
#define _(t,field) h.field = elf_swap_##t (em, h.field);
	foreach_elf64_file_header;
#undef _

	if (fwrite (&h, sizeof (h), 1, f) != 1)
	  {
	    error = clib_error_return_unix (0, "write file header");
	    goto error;
	  }
      }
    else
      {
	elf32_file_header_t h32;

#define _(t,field) h32.field = elf_swap_##t (em, h.field);
	foreach_elf32_file_header;
#undef _

	if (fwrite (&h32, sizeof (h32), 1, f) != 1)
	  {
	    error = clib_error_return_unix (0, "write file header");
	    goto error;
	  }
      }
  }

  /* Write segment headers. */
  {
    elf_segment_t *s;

    vec_foreach (s, em->segments)
    {
      elf64_segment_header_t h;

      if (s->header.type == ~0)
	continue;

      h = s->header;

      if (em->first_header.file_class == ELF_64BIT)
	{
#define _(t,field) h.field = elf_swap_##t (em, h.field);
	  foreach_elf64_segment_header;
#undef _

	  if (fwrite (&h, sizeof (h), 1, f) != 1)
	    {
	      error =
		clib_error_return_unix (0, "write segment header %U",
					format_elf_segment, em, s);
	      goto error;
	    }
	}
      else
	{
	  elf32_segment_header_t h32;

#define _(t,field) h32.field = elf_swap_##t (em, h.field);
	  foreach_elf32_segment_header;
#undef _

	  if (fwrite (&h32, sizeof (h32), 1, f) != 1)
	    {
	      error =
		clib_error_return_unix (0, "write segment header %U",
					format_elf_segment, em, s);
	      goto error;
	    }
	}
    }
  }

  /* Write contents for all sections. */
  {
    elf_section_t *s;

    vec_foreach (s, em->sections)
    {
      if (s->header.file_size == 0)
	continue;

      if (fseek (f, s->header.file_offset, SEEK_SET) < 0)
	{
	  fclose (f);
	  return clib_error_return_unix (0, "fseek 0x%Lx",
					 s->header.file_offset);
	}

      if (s->header.type == ELF_SECTION_NO_BITS)
	/* don't write for .bss sections */ ;
      else if (fwrite (s->contents, vec_len (s->contents), 1, f) != 1)
	{
	  error =
	    clib_error_return_unix (0, "write %s section contents",
				    elf_section_name (em, s));
	  goto error;
	}
    }

    /* Finally write section headers. */
    if (fseek (f, em->file_header.section_header_file_offset, SEEK_SET) < 0)
      {
	fclose (f);
	return clib_error_return_unix
	  (0, "fseek 0x%Lx", em->file_header.section_header_file_offset);
      }

    vec_foreach (s, em->sections)
    {
      elf64_section_header_t h;

      if (s->header.type == ~0)
	continue;

      h = s->header;

      if (em->first_header.file_class == ELF_64BIT)
	{
#define _(t,field) h.field = elf_swap_##t (em, h.field);
	  foreach_elf64_section_header;
#undef _

	  if (fwrite (&h, sizeof (h), 1, f) != 1)
	    {
	      error =
		clib_error_return_unix (0, "write %s section header",
					elf_section_name (em, s));
	      goto error;
	    }
	}
      else
	{
	  elf32_section_header_t h32;

#define _(t,field) h32.field = elf_swap_##t (em, h.field);
	  foreach_elf32_section_header;
#undef _

	  if (fwrite (&h32, sizeof (h32), 1, f) != 1)
	    {
	      error =
		clib_error_return_unix (0, "write %s section header",
					elf_section_name (em, s));
	      goto error;
	    }
	}
    }
  }

error:
  fclose (f);
  return error;
}

clib_error_t *
elf_delete_named_section (elf_main_t * em, char *section_name)
{
  elf_section_t *s = 0;
  clib_error_t *error;

  error = elf_get_section_by_name (em, section_name, &s);
  if (error)
    return error;

  s->header.type = ~0;

  return 0;
}

void
elf_create_section_with_contents (elf_main_t * em,
				  char *section_name,
				  elf64_section_header_t * header,
				  void *contents, uword n_content_bytes)
{
  elf_section_t *s, *sts;
  u8 *st, *c;
  uword *p, is_new_section;

  /* See if section already exists with given name.
     If so, just replace contents. */
  is_new_section = 0;
  if ((p = hash_get_mem (em->section_by_name, section_name)))
    {
      s = vec_elt_at_index (em->sections, p[0]);
      _vec_len (s->contents) = 0;
      c = s->contents;
    }
  else
    {
      vec_add2 (em->sections, s, 1);
      is_new_section = 1;
      c = 0;
    }

  sts =
    vec_elt_at_index (em->sections,
		      em->file_header.section_header_string_table_index);
  st = sts->contents;

  s->header = header[0];

  s->header.file_offset = ~0;
  s->header.file_size = n_content_bytes;
  s->index = s - em->sections;

  /* Add name to string table. */
  s->header.name = vec_len (st);
  vec_add (st, section_name, strlen (section_name));
  vec_add1 (st, 0);
  sts->contents = st;

  vec_resize (c, n_content_bytes);
  clib_memcpy (c, contents, n_content_bytes);
  s->contents = c;

  em->file_header.section_header_count += is_new_section
    && s->header.type != ~0;
}

uword
elf_delete_segment_with_type (elf_main_t * em,
			      elf_segment_type_t segment_type)
{
  uword n_deleted = 0;
  elf_segment_t *s;

  vec_foreach (s, em->segments) if (s->header.type == segment_type)
    {
      s->header.type = ~0;
      n_deleted += 1;
    }

  ASSERT (em->file_header.segment_header_count >= n_deleted);
  em->file_header.segment_header_count -= n_deleted;

  return n_deleted;
}

#endif /* CLIB_UNIX */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
