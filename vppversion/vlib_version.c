/*
 *------------------------------------------------------------------
 * vlib_version.c - generate a vlib version stamp
 * 
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/unix.h>

typedef struct {
  u8 * program;
  u8 * output_filename;
  u8 * git_branch;
  int ofd;
} version_main_t;

version_main_t version_main;

static char * fmt = 
"#include <vlib/vlib.h>"
"\n"
"static char * %s_version_string = \n\"%s\";\n"
"static char * %s_dir_string = \n\"%s\";\n"
"static char * %s_git_branch = \n\"%s\";\n"
"\n"
"static clib_error_t *\n"
"show_%s_version_command_fn (vlib_main_t * vm,\n"
"		 unformat_input_t * input,\n"
"		 vlib_cli_command_t * cmd)\n"
"{\n"
"  vlib_cli_output (vm, \"%%s\", %s_version_string);\n"
"  if (unformat (input, \"verbose\")){\n"
"     vlib_cli_output (vm, \"%%s\", %s_dir_string);\n"
"     vlib_cli_output (vm, \"%%s\", %s_git_branch);\n"
"  }\n"
"  return 0;\n"
"}\n"
"\n"
"VLIB_CLI_COMMAND (show_%s_version_command, static) = {\n"
"  .path = \"show version %s\",\n"
"  .short_help = \"show version information for %s\",\n"
"  .function = show_%s_version_command_fn,\n"
"};\n\n";

static char *api_fmt = 
"char * %s_api_get_build_directory (void) \n{\n  return \"%s\";\n}\n\n"
"char * %s_api_get_branch (void) \n{\n  return \"%s\";\n}\n"
"char * %s_api_get_build_date (void) \n{\n  return \"%s\";\n}";

clib_error_t * 
write_version_file (version_main_t *vm)
{
  u8 * pgm, * api_fns;
  u8 * vs;
  u8 * ts;
  u8 * ds;
  u8 * gb;
  u8 * hostname = 0;
  u8 * pathname = 0;
  struct passwd *passwd_file_entry;
  time_t now = time (0);
  clib_error_t * error = 0;

  /* kill the newline */
  ts = format (0, "%s", ctime (&now));
  ts[vec_len(ts)-1] = 0;

  vec_validate (hostname, 128);

  gethostname (hostname, vec_len (hostname)-1);
  hostname[128] = 0; /* jic */

  vec_validate (pathname, 256);
  { char *rv __attribute__((unused)) = 
      getcwd ((char *)pathname, vec_len(pathname) - 1);
  }

  passwd_file_entry = getpwuid(geteuid());

  vs = format (0, "%s built by %s on %s at %s%c",
               vm->program, passwd_file_entry->pw_name, hostname, ts, 0);

  ds = format (0, "in %s%c", pathname, 0);

  gb = format (0, "from git uber-branch %s%c", vm->git_branch, 0);

  pgm = format (0, fmt, 
                vm->program, vs, 
                vm->program, ds, 
                vm->program, gb,
                vm->program,
                vm->program,
                vm->program,
                vm->program,
                vm->program,
                vm->program,
                vm->program,
                vm->program);
  
  if (write (vm->ofd, pgm, vec_len (pgm)) != vec_len (pgm))
    error = clib_error_return_unix (0, "write error on %s", 
                                    vm->output_filename);

  api_fns = format (0, api_fmt, 
                    vm->program, pathname,
                    vm->program, vm->git_branch,
                    vm->program, ts);
                    
  if (write (vm->ofd, api_fns, vec_len (api_fns)) != vec_len (api_fns))
      error = clib_error_return_unix (0, "write error on %s", 
                                      vm->output_filename);

  return error;

}

clib_error_t * version_main_fn (unformat_input_t * input)
{
  version_main_t * vm = &version_main;
  u8 * fn, * pn, * bn;
  clib_error_t * error;

  vm->output_filename = format (0, "version.c");
  vm->program = "unknown";
  vm->git_branch = "unknown";
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat (input, "output-filename %s", &fn)
          || unformat (input, "-o %s", &fn))
        vm->output_filename = fn;
      else if (unformat (input, "program-name %s", &pn)
               || unformat (input, "-p %s", &pn))
        {
          vm->program = pn;
          vec_add1 (vm->program, 0);
        }
      else if (unformat (input, "git-branch %s", &bn)
               || unformat (input, "-b %s", &bn))
        {
          vm->git_branch = bn;
          vec_add1 (vm->git_branch, 0);
        }
      else
        return clib_error_return (0, "unknown args '%U'", 
                                  format_unformat_error, input);
    }
  vec_add1 (vm->output_filename, 0);

  vm->ofd = creat (vm->output_filename, 0666);
  if (vm->ofd < 0)
    return clib_error_return_unix (0, "couldn't create '%s'", 
                                   vm->output_filename);

  error = write_version_file (vm);
  close (vm->ofd);
  return error;
}


int main (int argc, char **argv)
{
  unformat_input_t _input, *input = &_input;
  clib_error_t * error;

  unformat_init_command_line (input, argv);
  error = version_main_fn (input);
  unformat_free (input);

  if (error)
    {
      clib_error_report (error);
      exit (1);
    }
  exit (0);
}
 
