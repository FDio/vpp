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
 * trace.h: VLIB trace buffer.
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

#ifndef included_vlib_trace_h
#define included_vlib_trace_h

#include <vppinfra/pool.h>

typedef struct
{
  /* CPU time stamp trace was made. */
  u64 time;

  /* Node which generated this trace. */
  u32 node_index;

  /* Number of data words in this trace. */
  u32 n_data;

  /* Trace data follows. */
  u8 data[0];
} vlib_trace_header_t;

typedef struct
{
  /* Current number of traces in buffer. */
  u32 count;

  /* Max. number of traces to be added to buffer. */
  u32 limit;
} vlib_trace_node_t;

typedef struct
{
  /* Pool of trace buffers. */
  vlib_trace_header_t **trace_buffer_pool;

  u32 last_main_loop_count;
  u32 filter_node_index;
  u32 filter_flag;
#define FILTER_FLAG_NONE    0
#define FILTER_FLAG_INCLUDE 1
#define FILTER_FLAG_EXCLUDE 2
  u32 filter_count;

  /* set on trace add, cleared on clear trace */
  u32 trace_active_hint;

  /* Per node trace counts. */
  vlib_trace_node_t *nodes;

  /* verbosity */
  int verbose;
} vlib_trace_main_t;

#endif /* included_vlib_trace_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
