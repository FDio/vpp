/*
  Copyright (c) 2011 Cisco and/or its affiliates.

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

#include <vppinfra/mem.h>
#include <vppinfra/pool.h>

#ifdef __KERNEL__
#include <linux/unistd.h>
#else
#include <unistd.h>
#endif

int
main (int argc, char *argv[])
{
  int i;
  uword next;
  u32 *tp = 0;
  u32 *junk;

  for (i = 0; i < 70; i++)
    pool_get (tp, junk);

  (void) junk;			/* compiler warning */

  pool_put_index (tp, 1);
  pool_put_index (tp, 65);

  next = ~0;
  do
    {
      next = pool_next_index (tp, next);
      fformat (stdout, "next index %d\n", next);
    }
  while (next != ~0);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
