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
/**
 * @file
 * @brief NAT port/address allocation lib
 */
#ifndef included_nat_log_h__
#define included_nat_log_h__

#include <vppinfra/elog.h>

#include <nat/lib/nat_types.api_types.h>

#define nat_elog(_pm, _level, _str)                                           \
  do                                                                          \
    {                                                                         \
      if (PREDICT_FALSE (_pm->log_level >= _level))                           \
	{                                                                     \
	  ELOG_TYPE_DECLARE (e) = {                                           \
	    .format = "nat-msg " _str,                                        \
	    .format_args = "",                                                \
	  };                                                                  \
	  ELOG_DATA (&vlib_global_main.elog_main, e);                         \
	}                                                                     \
    }                                                                         \
  while (0);

#define nat_elog_addr(_pm, _level, _str, _addr)                               \
  do                                                                          \
    {                                                                         \
      if (PREDICT_FALSE (_pm->log_level >= _level))                           \
	{                                                                     \
	  ELOG_TYPE_DECLARE (e) = {                                           \
	    .format = "nat-msg " _str " %d.%d.%d.%d",                         \
	    .format_args = "i1i1i1i1",                                        \
	  };                                                                  \
	  CLIB_PACKED (struct {                                               \
	    u8 oct1;                                                          \
	    u8 oct2;                                                          \
	    u8 oct3;                                                          \
	    u8 oct4;                                                          \
	  }) *                                                                \
	    ed;                                                               \
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);                    \
	  ed->oct4 = _addr >> 24;                                             \
	  ed->oct3 = _addr >> 16;                                             \
	  ed->oct2 = _addr >> 8;                                              \
	  ed->oct1 = _addr;                                                   \
	}                                                                     \
    }                                                                         \
  while (0);

#define nat_elog_debug_handoff(_pm, _str, _tid, _fib, _src, _dst)             \
  do                                                                          \
    {                                                                         \
      if (PREDICT_FALSE (_pm->log_level >= NAT_LOG_DEBUG))                    \
	{                                                                     \
	  ELOG_TYPE_DECLARE (e) = {                                           \
	    .format = "nat-msg " _str " ip src: %d.%d.%d.%d dst: %d.%d.%d.%d" \
		      " tid from: %d to: %d fib: %d",                         \
	    .format_args = "i1i1i1i1i1i1i1i1i4i4i4",                          \
	  };                                                                  \
	  CLIB_PACKED (struct {                                               \
	    u8 src_oct1;                                                      \
	    u8 src_oct2;                                                      \
	    u8 src_oct3;                                                      \
	    u8 src_oct4;                                                      \
	    u8 dst_oct1;                                                      \
	    u8 dst_oct2;                                                      \
	    u8 dst_oct3;                                                      \
	    u8 dst_oct4;                                                      \
	    u32 ftid;                                                         \
	    u32 ttid;                                                         \
	    u32 fib;                                                          \
	  }) *                                                                \
	    ed;                                                               \
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);                    \
	  ed->src_oct1 = _src >> 24;                                          \
	  ed->src_oct2 = _src >> 16;                                          \
	  ed->src_oct3 = _src >> 8;                                           \
	  ed->src_oct4 = _src;                                                \
	  ed->dst_oct1 = _dst >> 24;                                          \
	  ed->dst_oct2 = _dst >> 16;                                          \
	  ed->dst_oct3 = _dst >> 8;                                           \
	  ed->dst_oct4 = _dst;                                                \
	  ed->ftid = vlib_get_thread_index ();                                \
	  ed->ttid = _tid;                                                    \
	  ed->fib = _fib;                                                     \
	}                                                                     \
    }                                                                         \
  while (0);

#define nat_elog_debug_handoff_v2(_pm, _str, _prt, _fib, _src, _dst)          \
  do                                                                          \
    {                                                                         \
      if (PREDICT_FALSE (_pm->log_level >= NAT_LOG_DEBUG))                    \
	{                                                                     \
	  ELOG_TYPE_DECLARE (e) = {                                           \
	    .format =                                                         \
	      "nat-msg " _str " ip_src:%d.%d.%d.%d ip_dst:%d.%d.%d.%d"        \
	      " tid:%d prt:%d fib:%d",                                        \
	    .format_args = "i1i1i1i1i1i1i1i1i4i4i4",                          \
	  };                                                                  \
	  CLIB_PACKED (struct {                                               \
	    u8 src_oct1;                                                      \
	    u8 src_oct2;                                                      \
	    u8 src_oct3;                                                      \
	    u8 src_oct4;                                                      \
	    u8 dst_oct1;                                                      \
	    u8 dst_oct2;                                                      \
	    u8 dst_oct3;                                                      \
	    u8 dst_oct4;                                                      \
	    u32 tid;                                                          \
	    u32 prt;                                                          \
	    u32 fib;                                                          \
	  }) *                                                                \
	    ed;                                                               \
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);                    \
	  ed->src_oct1 = _src >> 24;                                          \
	  ed->src_oct2 = _src >> 16;                                          \
	  ed->src_oct3 = _src >> 8;                                           \
	  ed->src_oct4 = _src;                                                \
	  ed->dst_oct1 = _dst >> 24;                                          \
	  ed->dst_oct2 = _dst >> 16;                                          \
	  ed->dst_oct3 = _dst >> 8;                                           \
	  ed->dst_oct4 = _dst;                                                \
	  ed->tid = vlib_get_thread_index ();                                 \
	  ed->prt = _prt;                                                     \
	  ed->fib = _fib;                                                     \
	}                                                                     \
    }                                                                         \
  while (0);

#define nat_elog_X1(_pm, _level, _fmt, _arg, _val1)                           \
  do                                                                          \
    {                                                                         \
      if (PREDICT_FALSE (_pm->log_level >= _level))                           \
	{                                                                     \
	  ELOG_TYPE_DECLARE (e) = {                                           \
	    .format = "nat-msg " _fmt,                                        \
	    .format_args = _arg,                                              \
	  };                                                                  \
	  CLIB_PACKED (struct { typeof (_val1) val1; }) * ed;                 \
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);                    \
	  ed->val1 = _val1;                                                   \
	}                                                                     \
    }                                                                         \
  while (0);

#define nat_elog_notice(_pm, nat_elog_str)                                    \
  nat_elog (_pm, NAT_LOG_INFO, "[notice] " nat_elog_str)
#define nat_elog_warn(_pm, nat_elog_str)                                      \
  nat_elog (_pm, NAT_LOG_WARNING, "[warning] " nat_elog_str)
#define nat_elog_err(_pm, nat_elog_str)                                       \
  nat_elog (_pm, NAT_LOG_ERROR, "[error] " nat_elog_str)
#define nat_elog_debug(_pm, nat_elog_str)                                     \
  nat_elog (_pm, NAT_LOG_DEBUG, "[debug] " nat_elog_str)
#define nat_elog_info(_pm, nat_elog_str)                                      \
  nat_elog (_pm, NAT_LOG_INFO, "[info] " nat_elog_str)

#define nat_elog_notice_X1(_pm, nat_elog_fmt_str, nat_elog_fmt_arg,           \
			   nat_elog_val1)                                     \
  nat_elog_X1 (_pm, NAT_LOG_NOTICE, "[notice] " nat_elog_fmt_str,             \
	       nat_elog_fmt_arg, nat_elog_val1)
#define nat_elog_warn_X1(_pm, nat_elog_fmt_str, nat_elog_fmt_arg,             \
			 nat_elog_val1)                                       \
  nat_elog_X1 (_pm, NAT_LOG_WARNING, "[warning] " nat_elog_fmt_str,           \
	       nat_elog_fmt_arg, nat_elog_val1)
#define nat_elog_err_X1(_pm, nat_elog_fmt_str, nat_elog_fmt_arg,              \
			nat_elog_val1)                                        \
  nat_elog_X1 (_pm, NAT_LOG_ERROR, "[error] " nat_elog_fmt_str,               \
	       nat_elog_fmt_arg, nat_elog_val1)
#define nat_elog_debug_X1(_pm, nat_elog_fmt_str, nat_elog_fmt_arg,            \
			  nat_elog_val1)                                      \
  nat_elog_X1 (_pm, NAT_LOG_DEBUG, "[debug] " nat_elog_fmt_str,               \
	       nat_elog_fmt_arg, nat_elog_val1)
#define nat_elog_info_X1(_pm, nat_elog_fmt_str, nat_elog_fmt_arg,             \
			 nat_elog_val1)                                       \
  nat_elog_X1 (_pm, NAT_LOG_INFO, "[info] " nat_elog_fmt_str,                 \
	       nat_elog_fmt_arg, nat_elog_val1)

#endif /* included_nat_lib_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
