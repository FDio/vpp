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
  ------------------------------------------------------------------------------
  By Bob Jenkins, 1996, Public Domain
  MODIFIED:
  960327: Creation (addition of randinit, really)
  970719: use context, not global variables, for internal state
  980324: renamed seed to flag
  980605: recommend ISAAC_LOG2_SIZE=4 for noncryptography.
  010626: note this is public domain
  ------------------------------------------------------------------------------

  Modified for CLIB by Eliot Dresselhaus.
  Dear Bob, Thanks for all the great work. - Eliot

  modifications copyright (c) 2003 Eliot Dresselhaus

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

#ifndef included_random_isaac_h
#define included_random_isaac_h

#include <vppinfra/clib.h>	/* for u32/u64 */
#include <vppinfra/format.h>	/* for unformat_input_t */

/* Bob recommends 8 for crypto, 4 for simulations */
#define ISAAC_LOG2_SIZE   (4)
#define ISAAC_SIZE (1 << ISAAC_LOG2_SIZE)

typedef struct
{
  uword memory[ISAAC_SIZE];
  uword a, b, c;
} isaac_t;

void isaac (isaac_t * ctx, uword * results);
void isaac2 (isaac_t * ctx, uword * results);
void isaac_init (isaac_t * ctx, uword * results);

int test_isaac_main (unformat_input_t * input);

#endif /* included_random_isaac_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
