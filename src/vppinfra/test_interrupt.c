/*
 * Copyright (c) 2021 Graphiant, Inc.
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

#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/random.h>
#include <vppinfra/time.h>
#include <vppinfra/interrupt.h>

#define MAX_INTS 2048

int debug = 0;

#define debug(format, args...)                                                \
  if (debug)                                                                  \
    {                                                                         \
      fformat (stdout, format, ##args);                                       \
    }

void
set_and_check_bits (void *interrupts, int num_ints)
{
  for (int step = 1; step < num_ints; step++)
    {
      int int_num = -1;
      int expected = 0;

      debug ("  Step of %d\n", step);
      for (int i = 0; i < num_ints; i += step)
	{
	  debug ("    Setting %d\n", i);
	  clib_interrupt_set (interrupts, i);
	}

      while ((int_num =
		clib_interrupt_get_next_and_clear (interrupts, int_num)) != -1)
	{
	  debug ("    Got %d, expecting %d\n", int_num, expected);
	  ASSERT (int_num == expected);
	  expected += step;
	}
      int_num = clib_interrupt_get_next_and_clear (interrupts, -1);
      ASSERT (int_num == -1);
    }
}

int
main (int argc, char *argv[])
{
  clib_mem_init (0, 3ULL << 30);

  debug = (argc > 1);

  void *interrupts = NULL;

  for (int num_ints = 0; num_ints < MAX_INTS; num_ints++)
    {
      clib_interrupt_resize (&interrupts, num_ints);
      debug ("Size now %d\n", num_ints);

      set_and_check_bits (interrupts, num_ints);
    }

  return 0;
}
