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
#include <vlib/unix/unix.h>
#include <syslog.h>
#include <vppinfra/elog.h>

vlib_log_main_t log_main = {
  .default_log_level = VLIB_LOG_LEVEL_NOTICE,
  .default_syslog_log_level = VLIB_LOG_LEVEL_WARNING,
  .unthrottle_time = 3,
  .size = 512,
  .add_to_elog = 1,
  .default_rate_limit = 50,
};

/* *INDENT-OFF* */
VLIB_REGISTER_LOG_CLASS (log_log, static) = {
  .class_name = "log",
};
/* *INDENT-ON* */

static const int colors[] = {
  [VLIB_LOG_LEVEL_EMERG] = 1,	/* red */
  [VLIB_LOG_LEVEL_ALERT] = 1,	/* red */
  [VLIB_LOG_LEVEL_CRIT] = 1,	/* red */
  [VLIB_LOG_LEVEL_ERR] = 1,	/* red */
  [VLIB_LOG_LEVEL_WARNING] = 3,	/* yellow */
  [VLIB_LOG_LEVEL_NOTICE] = 2,	/* green */
  [VLIB_LOG_LEVEL_INFO] = 4,	/* blue */
  [VLIB_LOG_LEVEL_DEBUG] = 6,	/* cyan */
};

static const int log_level_to_syslog_priority[] = {
  [VLIB_LOG_LEVEL_EMERG] = LOG_EMERG,
  [VLIB_LOG_LEVEL_ALERT] = LOG_ALERT,
  [VLIB_LOG_LEVEL_CRIT] = LOG_CRIT,
  [VLIB_LOG_LEVEL_ERR] = LOG_ERR,
  [VLIB_LOG_LEVEL_WARNING] = LOG_WARNING,
  [VLIB_LOG_LEVEL_NOTICE] = LOG_NOTICE,
  [VLIB_LOG_LEVEL_INFO] = LOG_INFO,
  [VLIB_LOG_LEVEL_DEBUG] = LOG_DEBUG,
  [VLIB_LOG_LEVEL_DISABLED] = LOG_DEBUG,
};

int
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

u8 *
format_indent (u8 * s, va_list * args)
{
  u8 *v = va_arg (*args, u8 *);
  u32 indent = va_arg (*args, u32);
  u8 *c;

  /* *INDENT-OFF* */
  vec_foreach (c, v)
    {
      vec_add (s, c, 1);
      if (c[0] == '\n')
	for (u32 i = 0; i < indent; i++)
	  vec_add1 (s, (u8) ' ');
    }
  /* *INDENT-ON* */
  return s;
}

static int
log_level_is_enabled (vlib_log_level_t level, vlib_log_level_t configured)
{
  if (configured == VLIB_LOG_LEVEL_DISABLED)
    return 0;
  if (level > configured)
    return 0;
  return 1;
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
  int log_enabled = log_level_is_enabled (level, sc->level);
  int syslog_enabled = log_level_is_enabled (level, sc->syslog_level);
  u8 *s = 0;

  /* make sure we are running on the main thread to avoid use in dataplane
     code, for dataplane logging consider use of event-logger */
  ASSERT (vlib_get_thread_index () == 0);

  if ((log_enabled || syslog_enabled) == 0)
    return;

  vec_validate (lm->entries, lm->size);

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
	  s = format (s, "--- message(s) throttled ---");
	  sc->is_throttling = 1;
	}
    }

  if (s == 0)
    {
      va_start (va, fmt);
      s = va_format (s, fmt, &va);
      va_end (va);
    }

  if (syslog_enabled)
    {
      u8 *l = 0;
      if (unix_main.flags & (UNIX_FLAG_INTERACTIVE | UNIX_FLAG_NOSYSLOG))
	{
	  int indent = 0;
	  int with_colors = (unix_main.flags & UNIX_FLAG_NOCOLOR) == 0;
	  u8 *fmt;
	  if (with_colors)
	    {
	      l = format (l, "\x1b[%um", 90 + colors[level]);
	      indent = vec_len (l);
	    }
	  fmt = format (0, "%%-%uU [%%-6U]: ", lm->max_class_name_length);
	  vec_terminate_c_string (fmt);
	  l = format (l, (char *) fmt, format_vlib_log_class, class,
		      format_vlib_log_level, level);
	  vec_free (fmt);
	  indent = vec_len (l) - indent;
	  if (with_colors)
	    l = format (l, "\x1b[0m");
	  l = format (l, "%U", format_indent, s, indent);
	  fformat (stderr, "%v\n", l);
	  fflush (stderr);
	}
      else
	{
	  l = format (l, "%U", format_vlib_log_class, class);
	  int prio = log_level_to_syslog_priority[level];
	  int is_term = vec_c_string_is_terminated (l) ? 1 : 0;

	  syslog (prio, "%.*s: %.*s", (int) vec_len (l), l,
		  (int) vec_len (s) - is_term, s);
	}
      vec_free (l);
    }

  if (log_enabled)
    {
      e = vec_elt_at_index (lm->entries, lm->next);
      vec_free (e->string);
      e->level = level;
      e->class = class;
      e->string = s;
      e->timestamp = t;
      s = 0;

      if (lm->add_to_elog)
	{
          /* *INDENT-OFF* */
          ELOG_TYPE_DECLARE(ee) =
            {
             .format = "log-%s: %s",
             .format_args = "t4T4",
             .n_enum_strings = 9,
             .enum_strings = {
                "emerg",
                "alert",
                "crit",
                "err",
                "warn",
                "notice",
                "info",
                "debug",
                "disabled",
                },
            };
          struct {
            u32 log_level;
            u32 string_index;
          } *ed;
          /* *INDENT-ON* */
	  ed = ELOG_DATA (&vlib_global_main.elog_main, ee);
	  ed->log_level = level;
	  ed->string_index =
	    elog_string (&vlib_global_main.elog_main, "%v", e->string);
	}

      lm->next = (lm->next + 1) % lm->size;
      if (lm->size > lm->count)
	lm->count++;
    }

  vec_free (s);
}

static vlib_log_class_t
vlib_log_register_class_internal (char *class, char *subclass, u32 limit)
{
  vlib_log_main_t *lm = &log_main;
  vlib_log_class_data_t *c = NULL;
  vlib_log_subclass_data_t *s;
  vlib_log_class_data_t *tmp;
  vlib_log_class_config_t *cc = 0, *scc = 0;
  uword *p;
  u8 *str;
  u32 length = 0;

  if ((p = hash_get_mem (lm->config_index_by_name, class)))
    cc = vec_elt_at_index (lm->configs, p[0]);

  str = format (0, "%s/%s%c", class, subclass, 0);
  if ((p = hash_get_mem (lm->config_index_by_name, (char *) str)))
    scc = vec_elt_at_index (lm->configs, p[0]);
  vec_free (str);

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
  length = vec_len (c->name);

  vec_add2 (c->subclasses, s, 1);
  s->index = s - c->subclasses;
  s->name = subclass ? format (0, "%s", subclass) : 0;

  if (scc && scc->rate_limit != ~0)
    s->rate_limit = scc->rate_limit;
  else if (cc && cc->rate_limit != ~0)
    s->rate_limit = cc->rate_limit;
  else if (limit)
    s->rate_limit = limit;
  else
    s->rate_limit = lm->default_rate_limit;

  if (scc && scc->level != ~0)
    s->level = scc->level;
  else if (cc && cc->level != ~0)
    s->level = cc->level;
  else
    s->level = lm->default_log_level;

  if (scc && scc->syslog_level != ~0)
    s->syslog_level = scc->syslog_level;
  else if (cc && cc->syslog_level != ~0)
    s->syslog_level = cc->syslog_level;
  else
    s->syslog_level = lm->default_syslog_log_level;

  if (subclass)
    length += 1 + vec_len (s->name);
  if (length > lm->max_class_name_length)
    lm->max_class_name_length = length;
  return (c->index << 16) | (s->index);
}

vlib_log_class_t
vlib_log_register_class (char *class, char *subclass)
{
  return vlib_log_register_class_internal (class, subclass,
					   0 /* default rate limit */ );
}

vlib_log_class_t
vlib_log_register_class_rate_limit (char *class, char *subclass, u32 limit)
{
  return vlib_log_register_class_internal (class, subclass, limit);
}


u8 *
format_vlib_log_level (u8 * s, va_list * args)
{
  vlib_log_level_t i = va_arg (*args, vlib_log_level_t);
  char *t = 0;

  switch (i)
    {
#define _(uc,lc) case VLIB_LOG_LEVEL_##uc: t = #lc; break;
      foreach_vlib_log_level
#undef _
    default:
      return format (s, "unknown");
    }
  return format (s, "%s", t);
}

static clib_error_t *
vlib_log_init (vlib_main_t * vm)
{
  vlib_log_main_t *lm = &log_main;
  vlib_log_class_registration_t *r = lm->registrations;

  gettimeofday (&lm->time_zero_timeval, 0);
  lm->time_zero = vlib_time_now (vm);

  vec_validate (lm->entries, lm->size);

  while (r)
    {
      r->class = vlib_log_register_class (r->class_name, r->subclass_name);
      if (r->default_level)
	get_subclass_data (r->class)->level = r->default_level;
      if (r->default_syslog_level)
	get_subclass_data (r->class)->syslog_level = r->default_syslog_level;
      r = r->next;
    }

  r = lm->registrations;
  while (r)
    {
      vlib_log_debug (r->class, "initialized");
      r = r->next;
    }
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
      vlib_cli_output (vm, "%U %-10U %-14U %v",
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
  vlib_log_info (log_log.class, "log cleared");
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
#define _(uc, lc)                                      \
  const char __##uc[] = #lc;                           \
  if (!strcmp ((const char *) level_str, __##uc))      \
    {                                                  \
      *level = VLIB_LOG_LEVEL_##uc;                    \
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
  .short_help = "set logging class <class> [rate-limit <int>] "
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
log_config_class (vlib_main_t * vm, char *name, unformat_input_t * input)
{
  vlib_log_main_t *lm = &log_main;
  vlib_log_class_config_t *cc, tmp;
  uword *p;

  if (lm->config_index_by_name == 0)
    lm->config_index_by_name = hash_create_string (0, sizeof (uword));

  p = hash_get_mem (lm->config_index_by_name, name);

  if (p)
    return clib_error_return (0, "logging class '%s' already configured",
			      name);

  clib_memset_u8 (&tmp, 0xff, sizeof (vlib_log_class_config_t));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "level %U", unformat_vlib_log_level, &tmp.level))
	;
      else if (unformat (input, "syslog-level %U", unformat_vlib_log_level,
			 &tmp.syslog_level))
	;
      else if (unformat (input, "rate-limit %u", &tmp.rate_limit))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  vec_add2 (lm->configs, cc, 1);
  clib_memcpy_fast (cc, &tmp, sizeof (vlib_log_class_config_t));
  cc->name = name;
  hash_set_mem (lm->config_index_by_name, name, cc - lm->configs);
  return 0;
}

static clib_error_t *
log_config (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_log_main_t *lm = &log_main;
  unformat_input_t sub_input;
  u8 *class = 0;

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
      else if (unformat (input, "add-to-elog"))
	lm->add_to_elog = 1;
      else if (unformat (input, "class %s %U", &class,
			 unformat_vlib_cli_sub_input, &sub_input))
	{
	  clib_error_t *err;
	  err = log_config_class (vm, (char *) class, &sub_input);
	  class = 0;
	  unformat_free (&sub_input);
	  if (err)
	    return err;
	}
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
