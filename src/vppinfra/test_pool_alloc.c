/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Yandex LLC.
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
  vec_set_len (indices, 0);

  /* zero size allocation is ok */
  pool_alloc (tp, 0);

  fformat (stdout, "%d pool elts of empty pool\n", pool_elts (tp));

  pool_validate (tp);

  pool_alloc (tp, NELTS);

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
