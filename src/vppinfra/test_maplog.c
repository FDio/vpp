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
      fformat (stdout, "%4lld ", e->serial_number);
      if (++i == 8)
	{
	  fformat (stdout, "\n");
	  i = 0;
	}
      e++;
    }
  fformat (stdout, "--------------\n");
}

int
test_maplog_main (unformat_input_t * input)
{
  clib_maplog_main_t *mm = &maplog_main;
  clib_maplog_init_args_t _a, *a = &_a;
  int rv;
  int i;
  test_entry_t *t;

  memset (a, 0, sizeof (*a));
  a->mm = mm;
  a->file_basename = "/tmp/maplog_test";
  a->file_size_in_bytes = 4096;
  a->record_size_in_bytes = sizeof (test_entry_t);
  a->application_id = 1;
  a->application_major_version = 1;
  a->application_minor_version = 0;
  a->application_patch_version = 0;

  rv = clib_maplog_init (a);

  if (rv)
    {
      clib_warning ("clib_maplog_init returned %d", rv);
      exit (1);
    }

  for (i = 0; i < 64 * 5; i++)
    {
      t = clib_maplog_get_entry (mm);
      t->serial_number = i;
    }

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
