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

int
test_maplog_main (unformat_input_t * input)
{
  clib_maplog_main_t *mm = &maplog_main;
  int rv;
  int i;
  test_entry_t *t;

  rv = clib_maplog_init (mm, "/tmp/maplog_test", 4096, sizeof (test_entry_t));

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
