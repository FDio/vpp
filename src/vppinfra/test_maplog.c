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

#include <vppinfra/maplog.h>

clib_maplog_main_t maplog_main;

typedef struct
{
  u64 serial_number;
  u64 junk[7];
} test_entry_t;

typedef enum
{
  TEST_NORMAL,
  TEST_CIRCULAR,
} test_type_t;

static void
process_maplog_records (clib_maplog_header_t * h,
			test_entry_t * e, u64 records_this_file)
{
  static int print_header;
  int i = 0;

  if (print_header == 0)
    {
      print_header = 1;
      fformat (stdout, "%U", format_maplog_header, h, 1 /* verbose */ );
    }

  while (records_this_file--)
    {
      /* Padding at the end of a damaged log? */
      if (e->serial_number == 0ULL)
	break;
      fformat (stdout, "%4lld ", e->serial_number);
      if (++i == 8)
	{
	  fformat (stdout, "\n");
	  i = 0;
	}
      e++;
    }
  fformat (stdout, "\n--------------\n");
}

int
test_maplog_main (unformat_input_t * input)
{
  clib_maplog_main_t *mm = &maplog_main;
  clib_maplog_init_args_t _a, *a = &_a;
  int rv;
  int i, limit;
  test_entry_t *t;
  int noclose = 0;
  test_type_t which = TEST_NORMAL;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "noclose"))
	noclose = 1;
      else if (unformat (input, "circular"))
	which = TEST_CIRCULAR;
      else
	clib_warning ("unknown input '%U'", format_unformat_error, input);
    }

  clib_memset (a, 0, sizeof (*a));
  a->mm = mm;
  a->file_basename = "/tmp/maplog_test";
  a->file_size_in_bytes = 4096;
  a->record_size_in_bytes = sizeof (test_entry_t);
  a->application_id = 1;
  a->application_major_version = 1;
  a->application_minor_version = 0;
  a->application_patch_version = 0;
  a->maplog_is_circular = (which == TEST_CIRCULAR) ? 1 : 0;

  rv = clib_maplog_init (a);

  if (rv)
    {
      clib_warning ("clib_maplog_init returned %d", rv);
      exit (1);
    }

  limit = (which == TEST_CIRCULAR) ? (64 + 2) : 64 * 5;

  for (i = 0; i < limit; i++)
    {
      t = clib_maplog_get_entry (mm);
      t->serial_number = i + 1;
    }

  if (noclose)
    clib_memset (mm, 0, sizeof (*mm));
  else
    clib_maplog_close (mm);

  clib_maplog_process ("/tmp/maplog_test", process_maplog_records);

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  clib_mem_init (0, 64ULL << 20);

  unformat_init_command_line (&i, argv);
  ret = test_maplog_main (&i);
  unformat_free (&i);

  return ret;
}
#endif /* CLIB_UNIX */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
