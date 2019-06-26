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

#ifndef included_vlib_log_h
#define included_vlib_log_h

#include <vppinfra/types.h>

#define foreach_vlib_log_level \
  _(0, EMERG, emerg) \
  _(1, ALERT, alert) \
  _(2, CRIT, crit) \
  _(3, ERR, err) \
  _(4, WARNING, warn) \
  _(5, NOTICE, notice) \
  _(6, INFO, info) \
  _(7, DEBUG, debug) \
  _(8, DISABLED, disabled)

typedef enum
{
#define _(n,uc,lc) VLIB_LOG_LEVEL_##uc = n,
  foreach_vlib_log_level
#undef _
} vlib_log_level_t;

typedef struct
{
  vlib_log_level_t level;
  vlib_log_class_t class;
  f64 timestamp;
  u8 *string;
} vlib_log_entry_t;

typedef struct
{
  u32 index;
  u8 *name;
  // level of log messages kept for this subclass
  vlib_log_level_t level;
  // level of log messages sent to syslog for this subclass
  vlib_log_level_t syslog_level;
  // flag saying whether this subclass is logged to syslog
  f64 last_event_timestamp;
  int last_sec_count;
  int is_throttling;
  int rate_limit;
} vlib_log_subclass_data_t;

typedef struct
{
  u32 index;
  u8 *name;
  vlib_log_subclass_data_t *subclasses;
} vlib_log_class_data_t;

typedef struct
{
  vlib_log_entry_t *entries;
  vlib_log_class_data_t *classes;
  int size, next, count;

  /* our own log class */
  vlib_log_class_t log_class;

  int default_rate_limit;
  int default_log_level;
  int default_syslog_log_level;
  int unthrottle_time;
  u32 indent;

  /* time zero */
  struct timeval time_zero_timeval;
  f64 time_zero;

} vlib_log_main_t;

extern vlib_log_main_t log_main;

vlib_log_class_t vlib_log_register_class (char *vlass, char *subclass);
u32 vlib_log_get_indent ();
void vlib_log (vlib_log_level_t level, vlib_log_class_t class, char *fmt,
	       ...);
int last_log_entry ();
u8 *format_vlib_log_class (u8 * s, va_list * args);

#define vlib_log_emerg(...) vlib_log(VLIB_LOG_LEVEL_EMERG, __VA_ARGS__)
#define vlib_log_alert(...) vlib_log(VLIB_LOG_LEVEL_ALERT, __VA_ARGS__)
#define vlib_log_crit(...) vlib_log(VLIB_LOG_LEVEL_CRIT, __VA_ARGS__)
#define vlib_log_err(...) vlib_log(VLIB_LOG_LEVEL_ERR, __VA_ARGS__)
#define vlib_log_warn(...) vlib_log(VLIB_LOG_LEVEL_WARNING, __VA_ARGS__)
#define vlib_log_notice(...) vlib_log(VLIB_LOG_LEVEL_NOTICE, __VA_ARGS__)
#define vlib_log_info(...) vlib_log(VLIB_LOG_LEVEL_INFO, __VA_ARGS__)
#define vlib_log_debug(...) vlib_log(VLIB_LOG_LEVEL_DEBUG, __VA_ARGS__)

#endif /* included_vlib_log_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
