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

/* Callback type for post-processing the vlib trace buffer */
struct vlib_main_t;
struct vlib_trace_main_t;
typedef void (vlib_trace_buffer_callback_t) (struct vlib_main_t *,
					     struct vlib_trace_main_t *);

/* Callback type for alternate handling of vlib_add_trace internals */
struct vlib_node_runtime_t;
struct vlib_buffer_t;
typedef void *(vlib_add_trace_callback_t) (struct vlib_main_t *,
					   struct vlib_node_runtime_t * r,
					   struct vlib_buffer_t * b,
					   u32 n_data_bytes);

typedef int (vlib_is_packet_traced_fn_t) (vlib_buffer_t *b,
					  u32 classify_table_index, int func);
typedef struct vlib_trace_filter_function_registration
{
  const char *name;
  const char *description;
  int priority;
  vlib_is_packet_traced_fn_t *function;
  struct vlib_trace_filter_function_registration *next;
} vlib_trace_filter_function_registration_t;

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
#define FILTER_FLAG_POST_MORTEM 3
  u32 filter_count;

  /* set on trace add, cleared on clear trace */
  u32 trace_enable;

  /* Per node trace counts. */
  vlib_trace_node_t *nodes;

  /* verbosity */
  int verbose;

  /* a callback to enable customized consumption of the trace buffer content */
  vlib_trace_buffer_callback_t *trace_buffer_callback;

  /* a callback to enable customized addition of a new trace */
  vlib_add_trace_callback_t *add_trace_callback;

  vlib_is_packet_traced_fn_t *current_trace_filter_function;

} vlib_trace_main_t;

format_function_t format_vlib_trace;
typedef struct
{
  vlib_trace_filter_function_registration_t *trace_filter_registration;
} vlib_trace_filter_main_t;

extern vlib_trace_filter_main_t vlib_trace_filter_main;
#define VLIB_REGISTER_TRACE_FILTER_FUNCTION(x, ...)                           \
  __VA_ARGS__ vlib_trace_filter_function_registration_t                       \
    __vlib_trace_filter_function_##x;                                         \
  static void __clib_constructor                                              \
    __vlib_trace_filter_function_registration_##x (void)                      \
  {                                                                           \
    vlib_trace_filter_main_t *tfm = &vlib_trace_filter_main;                  \
    __vlib_trace_filter_function_##x.next = tfm->trace_filter_registration;   \
    tfm->trace_filter_registration = &__vlib_trace_filter_function_##x;       \
  }                                                                           \
  __VA_ARGS__ vlib_trace_filter_function_registration_t                       \
    __vlib_trace_filter_function_##x

vlib_is_packet_traced_fn_t *
vlib_is_packet_traced_function_from_name (const char *name);
vlib_is_packet_traced_fn_t *vlib_is_packet_traced_default_function ();
void trace_apply_filter (struct vlib_main_t *vm);
int trace_time_cmp (void *a1, void *a2);
void vlib_trace_stop_and_clear (void);
int vlib_enable_disable_pkt_trace_filter (int enable) __attribute__ ((weak));
void trace_update_capture_options (u32 add, u32 node_index,
				   u32 filter, u8 verbose);
void trace_filter_set (u32 node_index, u32 flag, u32 count);
void clear_trace_buffer (void);
void vlib_set_trace_filter_function (vlib_is_packet_traced_fn_t *x);
uword unformat_vlib_trace_filter_function (unformat_input_t *input,
					   va_list *args);

#endif /* included_vlib_trace_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
