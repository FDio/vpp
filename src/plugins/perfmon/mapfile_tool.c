/*
 * mapfile_tool.c - skeleton vpp engine plug-in
 *
 * Copyright (c) 2018 Cisco Systems and/or affiliates
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
#include <stdio.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/unix.h>

typedef struct
{
  u8 *ifile;
  u8 *ofile;
  u8 *mapfile;
  u8 *table;
  FILE *ofp;
} mapfile_tool_main_t;

mapfile_tool_main_t mapfile_tool_main;

static char *top_boilerplate =
  "typedef struct {\n"
  "  u8 model;\n"
  "  u8 stepping;\n"
  "  u8 has_stepping;\n"
  "  char *filename;\n"
  "} file_by_model_and_stepping_t;\n\n"
  "static const file_by_model_and_stepping_t fms_table [] =\n"
  "{\n" " /* model, stepping, stepping valid, file */\n";

static char *bottom_boilerplate = "};\n";

static void
print_chunk (mapfile_tool_main_t * mtm, char *chunk)
{
  fformat (mtm->ofp, "%s", chunk);
}

static int
parse_mapfile (mapfile_tool_main_t * mtm)
{
  u8 *cp = mtm->mapfile;
  int i;
  char model[3];
  u8 *stepping = 0;
  u8 *filename = 0;
  int has_stepping;

  /* Skip header line */
  while (*cp && *cp != '\n')
    cp++;

  if (*cp == 0)
    {
      fformat (stderr, "mapfile broken or empty\n");
      return 1;
    }
  /* skip newline */
  cp++;

  /* GenuineIntel-6-55-[01234],V1.12,/SKX/skylakex_uncore_v1.12.json,uncore */
  /*    skip 15     ^ */

  /* Across payload lines... */
  while (1)
    {
      if (*cp == 0)
	return 0;

      for (i = 0; i < 15; i++)
	{
	  if (*cp == 0)
	    {
	    bad:
	      fformat (stderr, "mapfile broken\n");
	      return 1;
	    }
	  cp++;
	}
      /* should point at model */
      model[0] = *cp++;
      model[1] = *cp++;
      model[2] = 0;
      vec_reset_length (stepping);
      /* Stepping significant? */
      if (*cp == '-')
	{
	  cp += 2;
	  while (*cp != ']')
	    {
	      vec_add1 (stepping, *cp);
	      cp++;
	    }
	  cp++;
	}
      /* Skip dirname */
      while (*cp != '/')
	cp++;
      cp++;
      while (*cp != '/')
	*cp++;
      cp++;
      vec_reset_length (filename);
      while (*cp != ',')
	{
	  vec_add1 (filename, *cp);
	  cp++;
	}

      cp++;
      /* We only want ",core" entries */
      if (memcmp (cp, "core", 4))
	{
	  while (*cp && *cp != '\n')
	    cp++;
	  if (*cp)
	    cp++;
	  continue;
	}

      /* Skip to start of next line */
      while (*cp && *cp != '\n')
	cp++;
      if (*cp)
	cp++;

      has_stepping = 1;

      if (vec_len (stepping) == 0)
	{
	  vec_add1 (stepping, '0');
	  has_stepping = 0;
	}

      for (i = 0; i < vec_len (stepping); i++)
	{
	  mtm->table =
	    format (mtm->table, "  { 0x%s, 0x%c, %d, \"%v\" },\n",
		    model, stepping[i], has_stepping, filename);
	}
    }

  /* NOTREACHED */
  return -11;
}

static int
mapfile_main (unformat_input_t * input, mapfile_tool_main_t * mtm)
{
  u8 *mapfile;
  int rv;
  clib_error_t *error;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "in %s", &mtm->ifile))
	;
      else if (unformat (input, "out %s", &mtm->ofile))
	;
      else
	{
	  fformat (stderr, "unknown input '%U'\n", format_unformat_error,
		   input);
	usage:
	  fformat (stderr, "usage: mapfile_tool in <ifile> out <ofile>\n");
	  return 1;
	}
    }

  if (mtm->ifile == 0)
    {
      fformat (stderr, "input file not specified\n");
      goto usage;
    }

  if (mtm->ofile == 0)
    mtm->ofile = format (0, "perfmon_version.c%c", 0);

  mtm->ofp = fopen ((char *) mtm->ofile, "w");
  if (mtm->ofp == NULL)
    {
      fformat (stderr, "Couldn't create '%s'\n", mtm->ofile);
      return 1;
    }

  error = unix_proc_file_contents ((char *) mtm->ifile, &mapfile);

  if (error)
    {
      clib_error_free (error);
      fformat (stderr, "Failed to read mapfile from %s", mtm->ifile);
      return 1;
    }

  mtm->mapfile = mapfile;

  rv = parse_mapfile (mtm);
  if (rv)
    return rv;

  print_chunk (mtm, top_boilerplate);
  print_chunk (mtm, (char *) mtm->table);
  print_chunk (mtm, bottom_boilerplate);
  return 0;
}

int
main (int argc, char *argv[])
{
  unformat_input_t input;
  mapfile_tool_main_t *mtm = &mapfile_tool_main;
  int r;

  clib_mem_init (0, 128 << 20);

  unformat_init_command_line (&input, argv);
  r = mapfile_main (&input, mtm);
  unformat_free (&input);
  return r;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
