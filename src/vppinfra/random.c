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
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

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

#include <vppinfra/random.h>

/** \file Random number support
 */

/** \brief Default random seed for standalone version of library.
   Value can be overridden by platform code from e.g.
   machine's clock count register. */
u32 standalone_random_default_seed = 1;

/**
 * \brief Compute the X2 test statistic for a vector of counts.
 * Each value element corresponds to a histogram bucket.
 *
 * Typical use-case: test the hypothesis that a set of octets
 * are uniformly distributed (aka random).
 *
 * In a 1-dimensional use-case, the result should be compared
 * with the critical value from chi square tables with
 * vec_len(values) - 1 degrees of freedom.
 *
 * @param[in] values vector of histogram bucket values
 * @return    d - Pearson's X2 test statistic
 */

f64
clib_chisquare (u64 * values)
{
  u32 i, len;
  f64 d, delta_d, actual_frequency, expected_frequency;
  u64 n_observations = 0;

  len = vec_len (values);
  /*
   * Shut up coverity. Return a huge number which should always exceed
   * the X2 critical value.
   */
  if (len == 0)
    return (f64) 1e70;

  for (i = 0; i < len; i++)
    n_observations += values[i];

  expected_frequency = (1.0 / (f64) len) * (f64) n_observations;

  d = 0.0;

  for (i = 0; i < len; i++)
    {
      actual_frequency = ((f64) values[i]);
      delta_d = ((actual_frequency - expected_frequency)
		 * (actual_frequency - expected_frequency))
	/ expected_frequency;
      d += delta_d;
    }
  return d;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
