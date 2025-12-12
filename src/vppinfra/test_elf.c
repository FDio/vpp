/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

#include <vppinfra/elf.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef CLIB_UNIX
#error "unix only"
#endif

static clib_error_t *
elf_set_interpreter (elf_main_t * em, char *interp)
{
  elf_segment_t *g;
  elf_section_t *s;
  clib_error_t *error;

  vec_foreach (g, em->segments)
  {
    if (g->header.type == ELF_SEGMENT_INTERP)
      break;
  }

  if (g >= vec_end (em->segments))
    return clib_error_return (0, "interpreter not found");

  if (g->header.memory_size < 1 + strlen (interp))
    return clib_error_return (0,
			      "given interpreter does not fit; must be less than %d bytes (`%s' given)",
			      g->header.memory_size, interp);

  error =
    elf_get_section_by_start_address (em, g->header.virtual_address, &s);
  if (error)
    return error;

  /* Put in new null terminated string. */
  clib_memset (s->contents, 0, vec_len (s->contents));
  clib_memcpy (s->contents, interp, strlen (interp));

  return 0;
}

static void
delete_dynamic_rpath_entries_from_section (elf_main_t * em, elf_section_t * s)
{
  elf64_dynamic_entry_t *e;
  elf64_dynamic_entry_t *new_es = 0;

  vec_foreach (e, em->dynamic_entries)
  {
    switch (e->type)
      {
      case ELF_DYNAMIC_ENTRY_RPATH:
      case ELF_DYNAMIC_ENTRY_RUN_PATH:
	break;

      default:
	vec_add1 (new_es, e[0]);
	break;
      }
  }

  /* Pad so as to keep section size constant. */
  {
    elf64_dynamic_entry_t e_end;
    e_end.type = ELF_DYNAMIC_ENTRY_END;
    e_end.data = 0;
    while (vec_len (new_es) < vec_len (em->dynamic_entries))
      vec_add1 (new_es, e_end);
  }

  elf_set_dynamic_entries (em);
}

static void
elf_delete_dynamic_rpath_entries (elf_main_t * em)
{
  elf_section_t *s;

  vec_foreach (s, em->sections)
  {
    switch (s->header.type)
      {
      case ELF_SECTION_DYNAMIC:
	delete_dynamic_rpath_entries_from_section (em, s);
	break;

      default:
	break;
      }
  }
}

typedef struct
{
  elf_main_t elf_main;
  char *input_file;
  char *output_file;
  char *set_interpreter;
  int verbose;
} elf_test_main_t;

int
main (int argc, char *argv[])
{
  elf_test_main_t _tm, *tm = &_tm;
  elf_main_t *em = &tm->elf_main;
  unformat_input_t i;
  clib_error_t *error = 0;

  clib_memset (tm, 0, sizeof (tm[0]));

  unformat_init_command_line (&i, argv);
  while (unformat_check_input (&i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&i, "in %s", &tm->input_file))
	;
      else if (unformat (&i, "out %s", &tm->output_file))
	;
      else if (unformat (&i, "set-interpreter %s", &tm->set_interpreter))
	;
      else if (unformat (&i, "verbose"))
	tm->verbose = ~0;
      else if (unformat (&i, "verbose-symbols"))
	tm->verbose |= FORMAT_ELF_MAIN_SYMBOLS;
      else if (unformat (&i, "verbose-relocations"))
	tm->verbose |= FORMAT_ELF_MAIN_RELOCATIONS;
      else if (unformat (&i, "verbose-dynamic"))
	tm->verbose |= FORMAT_ELF_MAIN_DYNAMIC;
      else
	{
	  error = unformat_parse_error (&i);
	  goto done;
	}
    }

  if (!tm->input_file)
    {
      clib_warning ("No input file! Using test_bihash_template");
      tm->input_file = "test_bihash_template";
    }

  error = elf_read_file (em, tm->input_file);
  if (error)
    goto done;

  if (tm->set_interpreter)
    {
      clib_error_t *error = elf_set_interpreter (em, tm->set_interpreter);
      if (error)
	goto done;
      elf_delete_dynamic_rpath_entries (em);
    }

  if (tm->verbose)
    fformat (stdout, "%U", format_elf_main, em, tm->verbose);

  if (tm->output_file)
    error = elf_write_file (em, tm->output_file);

  elf_main_free (em);

done:
  if (error)
    {
      clib_error_report (error);
      return 1;
    }
  else
    return 0;
}
