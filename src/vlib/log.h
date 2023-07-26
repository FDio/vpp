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

#include <sys/time.h>
#include <vppinfra/types.h>

#define foreach_vlib_log_level	\
  _(EMERG, emerg)		\
  _(ALERT, alert)		\
  _(CRIT, crit)			\
  _(ERR, error)			\
  _(WARNING, warn)		\
  _(NOTICE, notice)		\
  _(INFO, info)			\
  _(DEBUG, debug)		\
  _(DISABLED, disabled)

typedef enum
{
  VLIB_LOG_LEVEL_UNKNOWN = 0,
#define _(uc,lc) VLIB_LOG_LEVEL_##uc,
  foreach_vlib_log_level
#undef _
    VLIB_LOG_N_LEVELS,
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
  vlib_log_level_t level;
  vlib_log_level_t syslog_level;
  int rate_limit;
  char *name;
} vlib_log_class_config_t;


typedef struct vlib_log_registration
{
  char *class_name;
  char *subclass_name;
  vlib_log_class_t class;
  vlib_log_level_t default_level;
  vlib_log_level_t default_syslog_level;

  /* next */
  struct vlib_log_registration *next;
} vlib_log_class_registration_t;

typedef struct
{
  vlib_log_entry_t *entries;
  vlib_log_class_data_t *classes;
  int size, next, count;

  int default_rate_limit;
  int default_log_level;
  int default_syslog_log_level;
  int unthrottle_time;
  u32 max_class_name_length;

  /* time zero */
  struct timeval time_zero_timeval;
  f64 time_zero;

  /* config */
  vlib_log_class_config_t *configs;
  uword *config_index_by_name;
  int add_to_elog;

  /* registrations */
  vlib_log_class_registration_t *registrations;
} vlib_log_main_t;

extern vlib_log_main_t log_main;

clib_error_t *vlib_log_init (struct vlib_main_t *vm);
vlib_log_class_t vlib_log_register_class (char *vlass, char *subclass);
vlib_log_class_t
vlib_log_register_class_rate_limit (char *class, char *subclass,
				    u32 rate_limit);
void vlib_log (vlib_log_level_t level, vlib_log_class_t class, char *fmt,
	       ...);
int last_log_entry ();
u8 *format_vlib_log_class (u8 * s, va_list * args);
u8 *format_vlib_log_level (u8 * s, va_list * args);

#define vlib_log_emerg(...) vlib_log(VLIB_LOG_LEVEL_EMERG, __VA_ARGS__)
#define vlib_log_alert(...) vlib_log(VLIB_LOG_LEVEL_ALERT, __VA_ARGS__)
#define vlib_log_crit(...) vlib_log(VLIB_LOG_LEVEL_CRIT, __VA_ARGS__)
#define vlib_log_err(...) vlib_log(VLIB_LOG_LEVEL_ERR, __VA_ARGS__)
#define vlib_log_warn(...) vlib_log(VLIB_LOG_LEVEL_WARNING, __VA_ARGS__)
#define vlib_log_notice(...) vlib_log(VLIB_LOG_LEVEL_NOTICE, __VA_ARGS__)
#define vlib_log_info(...) vlib_log(VLIB_LOG_LEVEL_INFO, __VA_ARGS__)
#define vlib_log_debug(...) vlib_log(VLIB_LOG_LEVEL_DEBUG, __VA_ARGS__)

#define VLIB_REGISTER_LOG_CLASS(x,...) \
__VA_ARGS__ vlib_log_class_registration_t x; \
static void __clib_constructor			\
__vlib_add_log_registration_##x (void)		\
  {						\
    vlib_log_main_t * lm = &log_main;		\
    x.next = lm->registrations;			\
    x.class = ~0;				\
    lm->registrations = &x;			\
  }						\
__VA_ARGS__  vlib_log_class_registration_t x

static_always_inline vlib_log_class_data_t *
vlib_log_get_class_data (vlib_log_class_t ci)
{
  vlib_log_main_t *lm = &log_main;
  return vec_elt_at_index (lm->classes, (ci >> 16));
}

static_always_inline vlib_log_subclass_data_t *
vlib_log_get_subclass_data (vlib_log_class_t ci)
{
  vlib_log_class_data_t *c = vlib_log_get_class_data (ci);
  return vec_elt_at_index (c->subclasses, (ci & 0xffff));
}

static_always_inline int
vlib_log_is_enabled (vlib_log_level_t level, vlib_log_class_t class)
{
  vlib_log_subclass_data_t *sc = vlib_log_get_subclass_data (class);

  if (level <= sc->level && sc->level != VLIB_LOG_LEVEL_DISABLED)
    return 1;

  if (level <= sc->syslog_level && sc->syslog_level != VLIB_LOG_LEVEL_DISABLED)
    return 1;

  return 0;
}

#endif /* included_vlib_log_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
