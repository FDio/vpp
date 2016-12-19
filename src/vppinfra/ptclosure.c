/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vppinfra/ptclosure.h>

u8 **
clib_ptclosure_alloc (int n)
{
  u8 **rv = 0;
  u8 *row;
  int i;

  ASSERT (n > 0);

  vec_validate (rv, n - 1);
  for (i = 0; i < n; i++)
    {
      row = 0;
      vec_validate (row, n - 1);

      rv[i] = row;
    }
  return rv;
}

void
clib_ptclosure_free (u8 ** ptc)
{
  u8 *row;
  int n = vec_len (ptc);
  int i;

  ASSERT (n > 0);

  for (i = 0; i < n; i++)
    {
      row = ptc[i];
      vec_free (row);
    }
  vec_free (ptc);
}

void
clib_ptclosure_copy (u8 ** dst, u8 ** src)
{
  int i, n;
  u8 *src_row, *dst_row;

  n = vec_len (dst);

  for (i = 0; i < vec_len (dst); i++)
    {
      src_row = src[i];
      dst_row = dst[i];
      clib_memcpy (dst_row, src_row, n);
    }
}

/*
 * compute the positive transitive closure
 * of a relation via Warshall's algorithm.
 *
 * Ref:
 * Warshall, Stephen (January 1962). "A theorem on Boolean matrices".
 * Journal of the ACM 9 (1): 11–12.
 *
 * foo[i][j] = 1 means that item i
 * "bears the relation" to item j.
 *
 * For example: "item i must be before item j"
 *
 * You could use a bitmap, but since the algorithm is
 * O(n**3) in the first place, large N is inadvisable...
 *
 */

u8 **
clib_ptclosure (u8 ** orig)
{
  int i, j, k;
  int n;
  u8 **prev, **cur;

  n = vec_len (orig);
  prev = clib_ptclosure_alloc (n);
  cur = clib_ptclosure_alloc (n);

  clib_ptclosure_copy (prev, orig);

  for (k = 0; k < n; k++)
    {
      for (i = 0; i < n; i++)
	{
	  for (j = 0; j < n; j++)
	    {
	      cur[i][j] = prev[i][j] || (prev[i][k] && prev[k][j]);
	    }
	}
      clib_ptclosure_copy (prev, cur);
    }
  clib_ptclosure_free (prev);
  return cur;
}



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
