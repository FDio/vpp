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
  Copyright (c) 2001-2005 Eliot Dresselhaus

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

#ifndef included_clib_smp_h
#define included_clib_smp_h

#include <vppinfra/cache.h>
#include <vppinfra/os.h>	/* for os_panic */

#define clib_smp_compare_and_swap(addr,new,old) __sync_val_compare_and_swap(addr,old,new)
#define clib_smp_swap(addr,new) __sync_lock_test_and_set(addr,new)
#define clib_smp_atomic_add(addr,increment) __sync_fetch_and_add(addr,increment)

#if defined (i386) || defined (__x86_64__)
#define clib_smp_pause() do { asm volatile ("pause"); } while (0)
#endif

#ifndef clib_smp_pause
#define clib_smp_pause() do { } while (0)
#endif

#ifdef CLIB_UNIX
#include <sched.h>

always_inline void
os_sched_yield (void)
{
  sched_yield ();
}
#else
always_inline void
os_sched_yield (void)
{
  clib_smp_pause ();
}
#endif


#endif /* included_clib_smp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
