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
 * error.h: drop/punt error packets
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

#ifndef included_vlib_error_h
#define included_vlib_error_h

#include <vppinfra/format.h>

typedef u16 vlib_error_t;

enum vl_counter_severity_e
{
  VL_COUNTER_SEVERITY_ERROR,
  VL_COUNTER_SEVERITY_WARN,
  VL_COUNTER_SEVERITY_INFO,
};

typedef struct
{
  char *name;
  char *desc;
  enum vl_counter_severity_e severity;
} vl_counter_t;

typedef struct
{
  /* Error counters. */
  u64 *counters;

  /* Counter values as of last counter clear. */
  u64 *counters_last_clear;

  /* Counter structures in heap. Heap index
     indexes counter vector. */
  vl_counter_t *counters_heap;
} vlib_error_main_t;

/* Per node error registration. */
void vlib_register_errors (struct vlib_main_t *vm,
			   u32 node_index,
			   u32 n_errors, char *error_strings[],
			   vl_counter_t counters[]);

unformat_function_t unformat_vlib_error;

#endif /* included_vlib_error_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
