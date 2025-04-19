/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef _ELOG_ACL_TRACE_H_
#define _ELOG_ACL_TRACE_H_


/* use like: elog_acl_cond_trace_X1(am, (x < 0), "foobar: %d", "i4", int32_value); */

#define elog_acl_cond_trace_X1(am, trace_cond, acl_elog_trace_format_label,   \
			       acl_elog_trace_format_args, acl_elog_val1)     \
  do                                                                          \
    {                                                                         \
      if (trace_cond)                                                         \
	{                                                                     \
	  CLIB_UNUSED (struct {                                               \
	    u8 available_space[18 - sizeof (acl_elog_val1)];                  \
	  } * static_check);                                                  \
	  clib_thread_index_t thread_index = os_get_thread_index ();          \
	  vlib_worker_thread_t *w = vlib_worker_threads + thread_index;       \
	  ELOG_TYPE_DECLARE (e) = {                                           \
	    .format = "(%02d) " acl_elog_trace_format_label,                  \
	    .format_args = "i2" acl_elog_trace_format_args,                   \
	  };                                                                  \
	  CLIB_PACKED (struct {                                               \
	    u16 thread;                                                       \
	    typeof (acl_elog_val1) val1;                                      \
	  }) *                                                                \
	    ed;                                                               \
	  ed =                                                                \
	    ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);  \
	  ed->thread = thread_index;                                          \
	  ed->val1 = acl_elog_val1;                                           \
	}                                                                     \
    }                                                                         \
  while (0)

/* use like: elog_acl_cond_trace_X2(am, (x<0), "foobar: %d some u64: %lu", "i4i8", int32_value, int64_value); */

#define elog_acl_cond_trace_X2(am, trace_cond, acl_elog_trace_format_label,   \
			       acl_elog_trace_format_args, acl_elog_val1,     \
			       acl_elog_val2)                                 \
  do                                                                          \
    {                                                                         \
      if (trace_cond)                                                         \
	{                                                                     \
	  CLIB_UNUSED (struct {                                               \
	    u8 available_space[18 - sizeof (acl_elog_val1) -                  \
			       sizeof (acl_elog_val2)];                       \
	  } * static_check);                                                  \
	  clib_thread_index_t thread_index = os_get_thread_index ();          \
	  vlib_worker_thread_t *w = vlib_worker_threads + thread_index;       \
	  ELOG_TYPE_DECLARE (e) = {                                           \
	    .format = "(%02d) " acl_elog_trace_format_label,                  \
	    .format_args = "i2" acl_elog_trace_format_args,                   \
	  };                                                                  \
	  CLIB_PACKED (struct {                                               \
	    u16 thread;                                                       \
	    typeof (acl_elog_val1) val1;                                      \
	    typeof (acl_elog_val2) val2;                                      \
	  }) *                                                                \
	    ed;                                                               \
	  ed =                                                                \
	    ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);  \
	  ed->thread = thread_index;                                          \
	  ed->val1 = acl_elog_val1;                                           \
	  ed->val2 = acl_elog_val2;                                           \
	}                                                                     \
    }                                                                         \
  while (0)

/* use like: elog_acl_cond_trace_X3(am, (x<0), "foobar: %d some u64 %lu baz: %d", "i4i8i4", int32_value, u64_value, int_value); */

#define elog_acl_cond_trace_X3(am, trace_cond, acl_elog_trace_format_label,   \
			       acl_elog_trace_format_args, acl_elog_val1,     \
			       acl_elog_val2, acl_elog_val3)                  \
  do                                                                          \
    {                                                                         \
      if (trace_cond)                                                         \
	{                                                                     \
	  CLIB_UNUSED (struct {                                               \
	    u8 available_space[18 - sizeof (acl_elog_val1) -                  \
			       sizeof (acl_elog_val2) -                       \
			       sizeof (acl_elog_val3)];                       \
	  } * static_check);                                                  \
	  clib_thread_index_t thread_index = os_get_thread_index ();          \
	  vlib_worker_thread_t *w = vlib_worker_threads + thread_index;       \
	  ELOG_TYPE_DECLARE (e) = {                                           \
	    .format = "(%02d) " acl_elog_trace_format_label,                  \
	    .format_args = "i2" acl_elog_trace_format_args,                   \
	  };                                                                  \
	  CLIB_PACKED (struct {                                               \
	    u16 thread;                                                       \
	    typeof (acl_elog_val1) val1;                                      \
	    typeof (acl_elog_val2) val2;                                      \
	    typeof (acl_elog_val3) val3;                                      \
	  }) *                                                                \
	    ed;                                                               \
	  ed =                                                                \
	    ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);  \
	  ed->thread = thread_index;                                          \
	  ed->val1 = acl_elog_val1;                                           \
	  ed->val2 = acl_elog_val2;                                           \
	  ed->val3 = acl_elog_val3;                                           \
	}                                                                     \
    }                                                                         \
  while (0)

/* use like: elog_acl_cond_trace_X4(am, (x<0), "foobar: %d some int %d baz: %d bar: %d", "i4i4i4i4", int32_value, int32_value2, int_value, int_value); */

#define elog_acl_cond_trace_X4(am, trace_cond, acl_elog_trace_format_label,   \
			       acl_elog_trace_format_args, acl_elog_val1,     \
			       acl_elog_val2, acl_elog_val3, acl_elog_val4)   \
  do                                                                          \
    {                                                                         \
      if (trace_cond)                                                         \
	{                                                                     \
	  CLIB_UNUSED (struct {                                               \
	    u8 available_space[18 - sizeof (acl_elog_val1) -                  \
			       sizeof (acl_elog_val2) -                       \
			       sizeof (acl_elog_val3) -                       \
			       sizeof (acl_elog_val4)];                       \
	  } * static_check);                                                  \
	  clib_thread_index_t thread_index = os_get_thread_index ();          \
	  vlib_worker_thread_t *w = vlib_worker_threads + thread_index;       \
	  ELOG_TYPE_DECLARE (e) = {                                           \
	    .format = "(%02d) " acl_elog_trace_format_label,                  \
	    .format_args = "i2" acl_elog_trace_format_args,                   \
	  };                                                                  \
	  CLIB_PACKED (struct {                                               \
	    u16 thread;                                                       \
	    typeof (acl_elog_val1) val1;                                      \
	    typeof (acl_elog_val2) val2;                                      \
	    typeof (acl_elog_val3) val3;                                      \
	    typeof (acl_elog_val4) val4;                                      \
	  }) *                                                                \
	    ed;                                                               \
	  ed =                                                                \
	    ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);  \
	  ed->thread = thread_index;                                          \
	  ed->val1 = acl_elog_val1;                                           \
	  ed->val2 = acl_elog_val2;                                           \
	  ed->val3 = acl_elog_val3;                                           \
	  ed->val4 = acl_elog_val4;                                           \
	}                                                                     \
    }                                                                         \
  while (0)

#endif
