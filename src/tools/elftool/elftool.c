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
  Copyright (c) 2008 Eliot Dresselhaus

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

#include <vppinfra/elf.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef CLIB_UNIX
#error "unix only"
#endif

typedef struct {
  elf_main_t elf_main;
  char * input_file;
  char * output_file;
  char * set_interpreter;
  char * set_rpath;
  int unset_rpath;
  int verbose;
  int quiet;
  int allow_elf_shared;
  /* for use in the optimized / simplified case */
  u64 file_size;
  u64 interpreter_offset;
  u64 rpath_offset;
} elf_tool_main_t;

static clib_error_t * elf_set_interpreter (elf_main_t * em, 
                                           elf_tool_main_t * tm)
{
  elf_segment_t * g;
  elf_section_t * s;
  clib_error_t * error;
  char * interp = tm->set_interpreter;

  switch (em->first_header.file_type)
    {
    case ELF_EXEC:
      break;

    case ELF_SHARED:
      if (tm->allow_elf_shared)
        break;
      /* Note flowthrough */
    default:
      return clib_error_return (0, "unacceptable file_type");    
    }

  vec_foreach (g, em->segments)
    {
      if (g->header.type == ELF_SEGMENT_INTERP)
	break;
    }

  if (g >= vec_end (em->segments))
    return clib_error_return (0, "interpreter not found");

  if (g->header.memory_size < 1 + strlen (interp))
    return clib_error_return (0, "given interpreter does not fit; must be less than %d bytes (`%s' given)",
			      g->header.memory_size, interp);

  error = elf_get_section_by_start_address (em, g->header.virtual_address, &s);
  if (error)
    return error;

  /* Put in new null terminated string. */
  clib_memset (s->contents, 0, vec_len (s->contents));
  clib_memcpy (s->contents, interp, strlen (interp));

  return 0;
}

static void
delete_rpath_for_section (elf_main_t * em, elf_section_t * s)
{
  elf64_dynamic_entry_t * e;
  elf64_dynamic_entry_t * new_es = 0;

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

  vec_free (em->dynamic_entries);
  em->dynamic_entries = new_es;

  elf_set_dynamic_entries (em);
}

static void delete_rpath (elf_main_t * em)
{
  elf_section_t * s;

  vec_foreach (s, em->sections)
    {
      switch (s->header.type)
	{
	case ELF_SECTION_DYNAMIC:
	  delete_rpath_for_section (em, s);
	  break;

	default:
	  break;
	}
    }
}

static clib_error_t *
set_rpath_for_section (elf_main_t * em, elf_section_t * s, char * new_rpath)
{
  elf64_dynamic_entry_t * e;
  char * old_rpath;
  int old_len, new_len = strlen (new_rpath);
  u8 * new_string_table = vec_dup (em->dynamic_string_table);

  vec_foreach (e, em->dynamic_entries)
    {
      switch (e->type)
	{
	case ELF_DYNAMIC_ENTRY_RPATH:
	case ELF_DYNAMIC_ENTRY_RUN_PATH:
	  old_rpath = (char *) new_string_table + e->data;
	  old_len = strlen (old_rpath);
	  if (old_len < new_len)
	    return clib_error_return (0, "rpath of `%s' does not fit (old rpath `%s')",
				      new_rpath, old_rpath);
	  strcpy (old_rpath, new_rpath);
	  break;

	default:
	  break;
	}
    }

  elf_set_section_contents (em, em->dynamic_string_table_section_index,
			    new_string_table,
			    vec_bytes (new_string_table));

  return 0;
}

static clib_error_t *
set_rpath (elf_main_t * em, char * rpath)
{
  clib_error_t * error = 0;
  elf_section_t * s;

  vec_foreach (s, em->sections)
    {
      switch (s->header.type)
	{
	case ELF_SECTION_DYNAMIC:
	  error = set_rpath_for_section (em, s, rpath);
	  if (error)
	    return error;
	  break;

	default:
	  break;
	}
    }

  return error;
}

static clib_error_t *
set_interpreter_rpath (elf_tool_main_t * tm)
{
  int ifd = -1, ofd = -1;
  struct stat fd_stat;
  u8 *idp = 0;                  /* warning be gone */
  u64 mmap_length = 0, i;
  u32 run_length;
  u8 in_run;
  u64 offset0 = 0, offset1 = 0;
  clib_error_t * error = 0;
  int fix_in_place = 0;

  if (!strcmp (tm->input_file, tm->output_file))
    fix_in_place = 1;

  ifd = open (tm->input_file, O_RDWR);
  if (ifd < 0)
    {
      error = clib_error_return_unix (0, "open `%s'", tm->input_file);
      goto done;
    }

  if (fstat (ifd, &fd_stat) < 0)
    {
      error = clib_error_return_unix (0, "fstat `%s'", tm->input_file);
      goto done;
    }

  if (!(fd_stat.st_mode & S_IFREG)) 
    {
      error = clib_error_return (0, "%s is not a regular file", tm->input_file);
      goto done;
    }

  mmap_length = fd_stat.st_size;
  if (mmap_length < 4)
    {
      error = clib_error_return (0, "%s too short", tm->input_file);
      goto done;
    }

  /* COW-mapping, since we intend to write the fixups */
  if (fix_in_place)
    idp = mmap (0, mmap_length, PROT_READ | PROT_WRITE, MAP_SHARED, 
              ifd, /* offset */ 0);
  else
    idp = mmap (0, mmap_length, PROT_READ | PROT_WRITE, MAP_PRIVATE, 
              ifd, /* offset */ 0);
  if (~pointer_to_uword (idp) == 0)
    {
      mmap_length = 0;
      error = clib_error_return_unix (0, "mmap `%s'", tm->input_file);
      goto done;
    }
  
  if (idp[0] != 0x7f || idp[1] != 'E' || idp[2] != 'L' || idp[3] != 'F')
    {
      error = clib_error_return (0, "not an ELF file '%s'", tm->input_file);
      goto done;
    }

  in_run = 0;
  run_length = 0;

  for (i = 0; i < mmap_length; i++)
    {
      if (idp[i] == '/')
        {
          if (in_run)
            run_length++;
          else
            {
              in_run = 1;
              run_length = 1;
            }
        }
      else
        {
          if (in_run && run_length >= 16)
            {
              if (offset0 == 0)
                  offset0 = (i - run_length);
              else if (offset1 == 0)
                {
                  offset1 = (i - run_length);
                  goto found_both;
                }
            }
          in_run = 0;
          run_length = 0;
        }
    }

  if (offset0 == 0)
    {
      error = clib_error_return (0, "no fixup markers in %s", 
                                 tm->input_file);
      goto done;
    }

 found_both:
  if (0)
    clib_warning ("offset0 %lld (0x%llx), offset1 %lld (0x%llx)", 
                  offset0, offset0, offset1, offset1);

  /* Executable file case */
  if (offset0 && offset1)
    {
      tm->interpreter_offset = offset0;
      tm->rpath_offset = offset1;
    }
  else /* shared library case */                         
    {
      tm->interpreter_offset = 0;
      tm->rpath_offset = offset0;
    }
  
  if (tm->interpreter_offset)
    clib_memcpy (&idp[tm->interpreter_offset], tm->set_interpreter, 
            strlen (tm->set_interpreter)+1);

  if (tm->rpath_offset)
    clib_memcpy (&idp[tm->rpath_offset], tm->set_rpath, 
            strlen (tm->set_rpath)+1);

  /* Write the output file... */
  if (fix_in_place == 0)
    {
      ofd = open (tm->output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
      if (ofd < 0)
        {
          error = clib_error_return_unix (0, "create `%s'", tm->output_file);
          goto done;
        }

      if (write (ofd, idp, mmap_length) != mmap_length)
        error = clib_error_return_unix (0, "write `%s'", tm->output_file);
    }

 done:
  if (mmap_length > 0 && idp)
    munmap (idp, mmap_length);
  if (ifd >= 0)
    close (ifd);
  if (ofd >= 0)
    close (ofd);
  return error;
}


int main (int argc, char * argv[])
{
  elf_tool_main_t _tm, * tm = &_tm;
  elf_main_t * em = &tm->elf_main;
  unformat_input_t i;
  clib_error_t * error = 0;

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
      else if (unformat (&i, "set-rpath %s", &tm->set_rpath))
	;
      else if (unformat (&i, "unset-rpath"))
	tm->unset_rpath = 1;
      else if (unformat (&i, "verbose"))
	tm->verbose = ~0;
      else if (unformat (&i, "verbose-symbols"))
	tm->verbose |= FORMAT_ELF_MAIN_SYMBOLS;
      else if (unformat (&i, "verbose-relocations"))
	tm->verbose |= FORMAT_ELF_MAIN_RELOCATIONS;
      else if (unformat (&i, "verbose-dynamic"))
	tm->verbose |= FORMAT_ELF_MAIN_DYNAMIC;
      else if (unformat (&i, "quiet"))
	tm->quiet = 1;
      else if (unformat (&i, "allow-elf-shared"))
        tm->allow_elf_shared = 1;
      else
	{
	  error = unformat_parse_error (&i);
	  goto done;
	}
    }

  if (! tm->input_file)
    {
      error = clib_error_return (0, "no input file");
      goto done;
    }

  /* Do the typical case a stone-simple way... */
  if (tm->quiet && tm->set_interpreter && tm->set_rpath && tm->output_file)
    {
      error = set_interpreter_rpath (tm);
      goto done;
    }

  error = elf_read_file (em, tm->input_file);

  if (error)
    goto done;

  if (tm->verbose)
    fformat (stdout, "%U", format_elf_main, em, tm->verbose);

  if (tm->set_interpreter)
    {
      error = elf_set_interpreter (em, tm);
      if (error)
	goto done;
    }

  if (tm->set_rpath)
    {
      error = set_rpath (em, tm->set_rpath);
      if (error)
	goto done;
    }

  if (tm->unset_rpath)
    delete_rpath (em);

  if (tm->output_file)
    error = elf_write_file (em, tm->output_file);

  elf_main_free (em);

 done:
  if (error)
    {
      if (tm->quiet == 0)
        clib_error_report (error);
      return 1;
    }
  else
    return 0;
}
