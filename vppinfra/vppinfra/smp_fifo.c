/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
  Copyright (c) 2012 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <vppinfra/smp_fifo.h>
#include <vppinfra/mem.h>

clib_smp_fifo_t *
clib_smp_fifo_init (uword max_n_elts, uword n_bytes_per_elt)
{
  clib_smp_fifo_t *f;
  uword n_bytes_per_elt_cache_aligned;

  f = clib_mem_alloc_aligned (sizeof (f[0]), CLIB_CACHE_LINE_BYTES);

  memset (f, 0, sizeof (f[0]));

  max_n_elts = max_n_elts ? max_n_elts : 32;
  f->log2_max_n_elts = max_log2 (max_n_elts);
  f->max_n_elts_less_one = (1 << f->log2_max_n_elts) - 1;

  n_bytes_per_elt_cache_aligned =
    clib_smp_fifo_round_elt_bytes (n_bytes_per_elt);
  clib_exec_on_global_heap (
			     {
			     f->data =
			     clib_mem_alloc_aligned
			     (n_bytes_per_elt_cache_aligned <<
			      f->log2_max_n_elts, CLIB_CACHE_LINE_BYTES);}
  );

  /* Zero all data and mark all elements free. */
  {
    uword i;
    for (i = 0; i <= f->max_n_elts_less_one; i++)
      {
	void *d = clib_smp_fifo_elt_at_index (f, n_bytes_per_elt, i);
	clib_smp_fifo_data_footer_t *t;

	memset (d, 0, n_bytes_per_elt_cache_aligned);

	t = clib_smp_fifo_get_data_footer (d, n_bytes_per_elt);
	clib_smp_fifo_data_footer_set_state (t,
					     CLIB_SMP_FIFO_DATA_STATE_free);
      }
  }

  return f;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
