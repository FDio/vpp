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

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vlib/log.h>
#include <syslog.h>

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

vlib_log_main_t log_main = {
  .default_log_level = VLIB_LOG_LEVEL_NOTICE,
  .default_syslog_log_level = VLIB_LOG_LEVEL_WARNING,
  .unthrottle_time = 3,
  .size = 512,
  .default_rate_limit = 50,
};

static int
last_log_entry ()
{
  vlib_log_main_t *lm = &log_main;
  int i;

  i = lm->next - lm->count;

  if (i < 0)
    i += lm->size;
  return i;
}

static vlib_log_class_data_t *
get_class_data (vlib_log_class_t ci)
{
  vlib_log_main_t *lm = &log_main;
  return vec_elt_at_index (lm->classes, (ci >> 16));
}

static vlib_log_subclass_data_t *
get_subclass_data (vlib_log_class_t ci)
{
  vlib_log_class_data_t *c = get_class_data (ci);
  return vec_elt_at_index (c->subclasses, (ci & 0xffff));
}

static int
vlib_log_level_to_syslog_priority (vlib_log_level_t level)
{
  switch (level)
    {
#define LOG_DISABLED LOG_DEBUG
#define _(n,uc,lc) \
    case VLIB_LOG_LEVEL_##uc:\
      return LOG_##uc;
      foreach_vlib_log_level
#undef _
#undef LOG_DISABLED
    }
  return LOG_DEBUG;
}

u8 *
format_vlib_log_class (u8 * s, va_list * args)
{
  vlib_log_class_t ci = va_arg (*args, vlib_log_class_t);
  vlib_log_class_data_t *c = get_class_data (ci);
  vlib_log_subclass_data_t *sc = get_subclass_data (ci);

  if (sc->name)
    return format (s, "%v/%v", c->name, sc->name);
  else
    return format (s, "%v", c->name, 0);
}


void
vlib_log (vlib_log_level_t level, vlib_log_class_t class, char *fmt, ...)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_log_main_t *lm = &log_main;
  vlib_log_entry_t *e;
  vlib_log_subclass_data_t *sc = get_subclass_data (class);
  va_list va;
  f64 t = vlib_time_now (vm);
  f64 delta = t - sc->last_event_timestamp;
  u8 *s = 0;
  bool use_formatted_log_entry = true;

  vec_validate (lm->entries, lm->size);
  /* make sure we are running on the main thread to avoid use in dataplane
     code, for dataplane logging consider use of event-logger */
  ASSERT (vlib_get_thread_index () == 0);

  if (level > sc->level)
    {
      use_formatted_log_entry = false;
      goto syslog;
    }

  if ((delta > lm->unthrottle_time) ||
      (sc->is_throttling == 0 && (delta > 1)))
    {
      sc->last_event_timestamp = t;
      sc->last_sec_count = 0;
      sc->is_throttling = 0;
    }
  else
    {
      sc->last_sec_count++;
      if (sc->last_sec_count > sc->rate_limit)
	return;
      else if (sc->last_sec_count == sc->rate_limit)
	{
	  vec_reset_length (s);
	  s = format (0, "--- message(s) throttled ---");
	  sc->is_throttling = 1;
	}
    }

  if (s == 0)
    {
      va_start (va, fmt);
      s = va_format (s, fmt, &va);
      va_end (va);
    }

  e = vec_elt_at_index (lm->entries, lm->next);
  vec_free (e->string);
  e->level = level;
  e->class = class;
  e->string = s;
  e->timestamp = t;

  lm->next = (lm->next + 1) % lm->size;
  if (lm->size > lm->count)
    lm->count++;

syslog:
  if (sc->syslog_level != VLIB_LOG_LEVEL_DISABLED &&
      level <= sc->syslog_level)
    {
      u8 *tmp = format (NULL, "%U", format_vlib_log_class, class);
      if (use_formatted_log_entry)
	{
	  syslog (vlib_log_level_to_syslog_priority (level), "%.*s: %.*s",
		  (int) vec_len (tmp), tmp,
		  (int) (vec_len (s) -
			 (vec_c_string_is_terminated (s) ? 1 : 0)), s);
	}
      else
	{
	  tmp = format (tmp, ": ");
	  va_start (va, fmt);
	  tmp = va_format (tmp, fmt, &va);
	  va_end (va);
	  syslog (vlib_log_level_to_syslog_priority (level), "%.*s",
		  (int) (vec_len (tmp) -
			 (vec_c_string_is_terminated (tmp) ? 1 : 0)), tmp);
	}
      vec_free (tmp);
    }

}

vlib_log_class_t
vlib_log_register_class (char *class, char *subclass)
{
  vlib_log_main_t *lm = &log_main;
  vlib_log_class_data_t *c = NULL;
  vlib_log_subclass_data_t *s;
  vlib_log_class_data_t *tmp;
  vec_foreach (tmp, lm->classes)
  {
    if (vec_len (tmp->name) != strlen (class))
      continue;
    if (!memcmp (class, tmp->name, vec_len (tmp->name)))
      {
	c = tmp;
	break;
      }
  }
  if (!c)
    {
      vec_add2 (lm->classes, c, 1);
      c->index = c - lm->classes;
      c->name = format (0, "%s", class);
    }

  vec_add2 (c->subclasses, s, 1);
  s->index = s - c->subclasses;
  s->name = subclass ? format (0, "%s", subclass) : 0;
  s->rate_limit = lm->default_rate_limit;
  s->level = lm->default_log_level;
  s->syslog_level = lm->default_syslog_log_level;
  return (c->index << 16) | (s->index);
}

u8 *
format_vlib_log_level (u8 * s, va_list * args)
{
  vlib_log_level_t i = va_arg (*args, vlib_log_level_t);
  char *t = 0;

  switch (i)
    {
#define _(v,uc,lc) case VLIB_LOG_LEVEL_##uc: t = #lc; break;
      foreach_vlib_log_level
#undef _
    default:
      return format (s, "unknown");
    }
  return format (s, "%s", t);
}

u32
vlib_log_get_indent ()
{
  return log_main.indent;
}

static clib_error_t *
vlib_log_init (vlib_main_t * vm)
{
  vlib_log_main_t *lm = &log_main;

  gettimeofday (&lm->time_zero_timeval, 0);
  lm->time_zero = vlib_time_now (vm);

  vec_validate (lm->entries, lm->size);
  lm->log_class = vlib_log_register_class ("log", 0);
  u8 *tmp = format (NULL, "%U %-10U %-10U ", format_time_float, 0, (f64) 0,
		    format_white_space, 255, format_white_space, 255);
  log_main.indent = vec_len (tmp);
  vec_free (tmp);
  return 0;
}

VLIB_INIT_FUNCTION (vlib_log_init);


static clib_error_t *
show_log (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vlib_log_main_t *lm = &log_main;
  vlib_log_entry_t *e;
  int i = last_log_entry ();
  int count = lm->count;
  f64 time_offset;

  time_offset = (f64) lm->time_zero_timeval.tv_sec
    + (((f64) lm->time_zero_timeval.tv_usec) * 1e-6) - lm->time_zero;

  while (count--)
    {
      e = vec_elt_at_index (lm->entries, i);
      vlib_cli_output (vm, "%U %-10U %-10U %v",
		       format_time_float, 0, e->timestamp + time_offset,
		       format_vlib_log_level, e->level,
		       format_vlib_log_class, e->class, e->string);
      i = (i + 1) % lm->size;
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_log, static) = {
  .path = "show logging",
  .short_help = "show logging",
  .function = show_log,
};
/* *INDENT-ON* */

static clib_error_t *
show_log_config (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vlib_log_main_t *lm = &log_main;
  vlib_log_class_data_t *c;
  vlib_log_subclass_data_t *sc;

  vlib_cli_output (vm, "%-20s %u entries", "Buffer Size:", lm->size);
  vlib_cli_output (vm, "Defaults:\n");
  vlib_cli_output (vm, "%-20s %U", "  Log Level:",
		   format_vlib_log_level, lm->default_log_level);
  vlib_cli_output (vm, "%-20s %U", "  Syslog Log Level:",
		   format_vlib_log_level, lm->default_syslog_log_level);
  vlib_cli_output (vm, "%-20s %u msgs/sec", "  Rate Limit:",
		   lm->default_rate_limit);
  vlib_cli_output (vm, "\n");
  vlib_cli_output (vm, "%-22s %-14s %-14s %s",
		   "Class/Subclass", "Level", "Syslog Level", "Rate Limit");


  u8 *defstr = format (0, "default");
  vec_foreach (c, lm->classes)
  {
    vlib_cli_output (vm, "%v", c->name);
    vec_foreach (sc, c->subclasses)
    {
      vlib_cli_output (vm, "  %-20v %-14U %-14U %d",
		       sc->name ? sc->name : defstr,
		       format_vlib_log_level, sc->level,
		       format_vlib_log_level, sc->syslog_level,
		       sc->rate_limit);
    }
  }
  vec_free (defstr);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_log_config, static) = {
  .path = "show logging configuration",
  .short_help = "show logging configuration",
  .function = show_log_config,
};
/* *INDENT-ON* */

static clib_error_t *
clear_log (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vlib_log_main_t *lm = &log_main;
  vlib_log_entry_t *e;
  int i = last_log_entry ();
  int count = lm->count;

  while (count--)
    {
      e = vec_elt_at_index (lm->entries, i);
      vec_free (e->string);
      i = (i + 1) % lm->size;
    }

  lm->count = 0;
  lm->next = 0;
  vlib_log_info (lm->log_class, "log cleared");
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_clear_log, static) = {
  .path = "clear logging",
  .short_help = "clear logging",
  .function = clear_log,
};
/* *INDENT-ON* */

static uword
unformat_vlib_log_level (unformat_input_t * input, va_list * args)
{
  vlib_log_level_t *level = va_arg (*args, vlib_log_level_t *);
  u8 *level_str = NULL;
  uword rv = 1;
  if (unformat (input, "%s", &level_str))
    {
#define _(v, uc, lc)                                   \
  const char __##uc[] = #lc;                           \
  if (!strcmp ((const char *) level_str, __##uc))	\
    {                                                  \
      *level = VLIB_LOG_LEVEL_##uc;                 \
      rv = 1;                                          \
      goto done;                                       \
    }
      foreach_vlib_log_level;
      rv = 0;
#undef _
    }
done:
  vec_free (level_str);
  return rv;
}

static uword
unformat_vlib_log_class (unformat_input_t * input, va_list * args)
{
  vlib_log_class_data_t **class = va_arg (*args, vlib_log_class_data_t **);
  uword rv = 0;
  u8 *class_str = NULL;
  vlib_log_main_t *lm = &log_main;
  if (unformat (input, "%v", &class_str))
    {
      vlib_log_class_data_t *cdata;
      vec_foreach (cdata, lm->classes)
      {
	if (vec_is_equal (cdata->name, class_str))
	  {
	    *class = cdata;
	    rv = 1;
	    break;
	  }
      }
    }
  vec_free (class_str);
  return rv;
}

static clib_error_t *
set_log_class (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *rv = NULL;
  int rate_limit;
  bool set_rate_limit = false;
  bool set_level = false;
  bool set_syslog_level = false;
  vlib_log_level_t level;
  vlib_log_level_t syslog_level;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  vlib_log_class_data_t *class = NULL;
  if (!unformat (line_input, "%U", unformat_vlib_log_class, &class))
    {
      return clib_error_return (0, "unknown log class `%U'",
				format_unformat_error, line_input);
    }
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "rate-limit %d", &rate_limit))
	{
	  set_rate_limit = true;
	}
      else
	if (unformat
	    (line_input, "level %U", unformat_vlib_log_level, &level))
	{
	  set_level = true;
	}
      else
	if (unformat
	    (line_input, "syslog-level %U", unformat_vlib_log_level,
	     &syslog_level))
	{
	  set_syslog_level = true;
	}
      else
	{
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, line_input);
	}
    }

  if (set_level)
    {
      vlib_log_subclass_data_t *subclass;
      vec_foreach (subclass, class->subclasses)
      {
	subclass->level = level;
      }
    }
  if (set_syslog_level)
    {
      vlib_log_subclass_data_t *subclass;
      vec_foreach (subclass, class->subclasses)
      {
	subclass->syslog_level = syslog_level;
      }
    }
  if (set_rate_limit)
    {
      vlib_log_subclass_data_t *subclass;
      vec_foreach (subclass, class->subclasses)
      {
	subclass->rate_limit = rate_limit;
      }
    }

  return rv;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_set_log, static) = {
  .path = "set logging class",
  .short_help = "set loggging class <class> [rate-limit <int>] "
    "[level <level>] [syslog-level <level>]",
  .function = set_log_class,
};
/* *INDENT-ON* */

static clib_error_t *
set_log_unth_time (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *rv = NULL;
  int unthrottle_time;
  vlib_log_main_t *lm = &log_main;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d", &unthrottle_time))
	lm->unthrottle_time = unthrottle_time;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }

  return rv;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_set_log_params, static) = {
  .path = "set logging unthrottle-time",
  .short_help = "set logging unthrottle-time <int>",
  .function = set_log_unth_time,
};
/* *INDENT-ON* */

static clib_error_t *
set_log_size (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *rv = NULL;
  int size;
  vlib_log_main_t *lm = &log_main;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d", &size))
	{
	  lm->size = size;
	  vec_validate (lm->entries, lm->size);
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }

  return rv;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_set_log_size, static) = {
  .path = "set logging size",
  .short_help = "set logging size <int>",
  .function = set_log_size,
};
/* *INDENT-ON* */

static uword
unformat_vlib_log_subclass (unformat_input_t * input, va_list * args)
{
  vlib_log_class_data_t *class = va_arg (*args, vlib_log_class_data_t *);
  vlib_log_subclass_data_t **subclass =
    va_arg (*args, vlib_log_subclass_data_t **);
  uword rv = 0;
  u8 *subclass_str = NULL;
  if (unformat (input, "%v", &subclass_str))
    {
      vlib_log_subclass_data_t *scdata;
      vec_foreach (scdata, class->subclasses)
      {
	if (vec_is_equal (scdata->name, subclass_str))
	  {
	    rv = 1;
	    *subclass = scdata;
	    break;
	  }
      }
    }
  vec_free (subclass_str);
  return rv;
}

static clib_error_t *
test_log_class_subclass (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  vlib_log_class_data_t *class = NULL;
  vlib_log_subclass_data_t *subclass = NULL;
  vlib_log_level_t level;
  if (unformat (line_input, "%U", unformat_vlib_log_level, &level))
    {
      if (unformat (line_input, "%U", unformat_vlib_log_class, &class))
	{
	  if (unformat
	      (line_input, "%U", unformat_vlib_log_subclass, class,
	       &subclass))
	    {
	      vlib_log (level,
			(class->index << 16) | (subclass->index), "%U",
			format_unformat_input, line_input);
	    }
	  else
	    {
	      return clib_error_return (0,
					"unknown log subclass near beginning of `%U'",
					format_unformat_error, line_input);
	    }
	}
      else
	{
	  return clib_error_return (0,
				    "unknown log class near beginning of `%U'",
				    format_unformat_error, line_input);
	}
    }
  else
    {
      return clib_error_return (0, "unknown log level near beginning of `%U'",
				format_unformat_error, line_input);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_test_log, static) = {
  .path = "test log",
  .short_help = "test log <level> <class> <subclass> <message>",
  .function = test_log_class_subclass,
};
/* *INDENT-ON* */

static clib_error_t *
log_config (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_log_main_t *lm = &log_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "size %d", &lm->size))
	vec_validate (lm->entries, lm->size);
      else if (unformat (input, "unthrottle-time %d", &lm->unthrottle_time))
	;
      else if (unformat (input, "default-log-level %U",
			 unformat_vlib_log_level, &lm->default_log_level))
	;
      else if (unformat (input, "default-syslog-log-level %U",
			 unformat_vlib_log_level,
			 &lm->default_syslog_log_level))
	;
      else
	{
	  return unformat_parse_error (input);
	}
    }

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (log_config, "logging");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
