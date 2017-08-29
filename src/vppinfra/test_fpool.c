/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 *
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

#include <vppinfra/pool.h>

/* can be a very large size */
#define NELTS 1024

int
main (int argc, char *argv[])
{
  u32 *junk = 0;
  int i;
  u32 *tp = 0;
  u32 *indices = 0;

  clib_mem_init (0, 3ULL << 30);

  vec_validate (indices, NELTS - 1);
  _vec_len (indices) = 0;

  pool_init_fixed (tp, NELTS);

  for (i = 0; i < NELTS; i++)
    {
      pool_get (tp, junk);
      vec_add1 (indices, junk - tp);
      *junk = i;
    }

  for (i = 0; i < NELTS; i++)
    {
      junk = pool_elt_at_index (tp, indices[i]);
      ASSERT (*junk == i);
    }

  fformat (stdout, "%d pool elts before deletes\n", pool_elts (tp));

  pool_put_index (tp, indices[12]);
  pool_put_index (tp, indices[43]);

  fformat (stdout, "%d pool elts after deletes\n", pool_elts (tp));

  pool_validate (tp);

  pool_free (tp);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
