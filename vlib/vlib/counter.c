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
 * counter.c: simple and packet/byte counters
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>

void
vlib_clear_simple_counters (vlib_simple_counter_main_t * cm)
{
  uword i, j;
  u16 *my_minis;

  for (i = 0; i < vec_len (cm->minis); i++)
    {
      my_minis = cm->minis[i];

      for (j = 0; j < vec_len (my_minis); j++)
	{
	  cm->maxi[j] += my_minis[j];
	  my_minis[j] = 0;
	}
    }

  j = vec_len (cm->maxi);
  if (j > 0)
    vec_validate (cm->value_at_last_clear, j - 1);
  for (i = 0; i < j; i++)
    cm->value_at_last_clear[i] = cm->maxi[i];
}

void
vlib_clear_combined_counters (vlib_combined_counter_main_t * cm)
{
  uword i, j;
  vlib_mini_counter_t *my_minis;

  for (i = 0; i < vec_len (cm->minis); i++)
    {
      my_minis = cm->minis[i];

      for (j = 0; j < vec_len (my_minis); j++)
	{
	  cm->maxi[j].packets += my_minis[j].packets;
	  cm->maxi[j].bytes += my_minis[j].bytes;
	  my_minis[j].packets = 0;
	  my_minis[j].bytes = 0;
	}
    }

  j = vec_len (cm->maxi);
  if (j > 0)
    vec_validate (cm->value_at_last_clear, j - 1);

  for (i = 0; i < j; i++)
    {
      vlib_counter_t *c = vec_elt_at_index (cm->value_at_last_clear, i);

      c[0] = cm->maxi[i];
    }
}

void
vlib_validate_simple_counter (vlib_simple_counter_main_t * cm, u32 index)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;

  vec_validate (cm->minis, tm->n_vlib_mains - 1);
  for (i = 0; i < tm->n_vlib_mains; i++)
    vec_validate_aligned (cm->minis[i], index, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (cm->maxi, index, CLIB_CACHE_LINE_BYTES);
}

void
vlib_validate_combined_counter (vlib_combined_counter_main_t * cm, u32 index)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;

  vec_validate (cm->minis, tm->n_vlib_mains - 1);
  for (i = 0; i < tm->n_vlib_mains; i++)
    vec_validate_aligned (cm->minis[i], index, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (cm->maxi, index, CLIB_CACHE_LINE_BYTES);
}

void
serialize_vlib_simple_counter_main (serialize_main_t * m, va_list * va)
{
  clib_warning ("unimplemented");
}

void
unserialize_vlib_simple_counter_main (serialize_main_t * m, va_list * va)
{
  clib_warning ("unimplemented");
}

void
serialize_vlib_combined_counter_main (serialize_main_t * m, va_list * va)
{
  clib_warning ("unimplemented");
}

void
unserialize_vlib_combined_counter_main (serialize_main_t * m, va_list * va)
{
  clib_warning ("unimplemented");
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
