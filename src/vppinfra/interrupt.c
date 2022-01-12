
/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vppinfra/vec.h>
#include <vppinfra/interrupt.h>
#include <vppinfra/format.h>

__clib_export void
clib_interrupt_init (void **data, uword n_int)
{
  clib_interrupt_header_t *h;
  uword sz = sizeof (clib_interrupt_header_t);
  uword data_size = round_pow2 (n_int, CLIB_CACHE_LINE_BYTES * 8) / 8;

  sz += 2 * data_size;
  h = data[0] = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  clib_memset (data[0], 0, sz);
  h->n_int = n_int;
  h->n_uword_alloc = (data_size * 8) >> log2_uword_bits;
}

__clib_export void
clib_interrupt_resize (void **data, uword n_int)
{
  clib_interrupt_header_t *h = data[0];

  if (data[0] == 0)
    {
      clib_interrupt_init (data, n_int);
      return;
    }

  if (n_int < h->n_int)
    {
      uword *old_bmp, *old_abp, v;
      old_bmp = clib_interrupt_get_bitmap (data[0]);
      old_abp = clib_interrupt_get_atomic_bitmap (data[0]);
      for (uword i = 0; i < h->n_uword_alloc; i++)
	{
	  v = old_abp[i];
	  old_abp[i] = 0;
	  if (n_int > ((i + 1) * uword_bits))
	    old_bmp[i] |= v;
	  else if (n_int > (i * uword_bits))
	    old_bmp[i] = (old_bmp[i] | v) & pow2_mask (n_int - i * uword_bits);
	  else
	    old_bmp[i] = 0;
	}
    }
  else if (n_int > h->n_uword_alloc * uword_bits)
    {
      void *old = data[0];
      uword *old_bmp, *old_abp, *new_bmp;
      uword n_uwords = round_pow2 (h->n_int, uword_bits) / uword_bits;

      clib_interrupt_init (data, n_int);
      h = data[0];

      new_bmp = clib_interrupt_get_bitmap (data[0]);
      old_bmp = clib_interrupt_get_bitmap (old);
      old_abp = clib_interrupt_get_atomic_bitmap (old);

      for (uword i = 0; i < n_uwords; i++)
	new_bmp[i] = old_bmp[i] | old_abp[i];

      clib_mem_free (old);
    }
  h->n_int = n_int;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
