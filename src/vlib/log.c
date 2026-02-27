/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
  .default_kmsg_log_level = VLIB_LOG_LEVEL_DISABLED,
  .unthrottle_time = 3,
  .size = 512,
  .add_to_elog = 0,
  .default_rate_limit = 50,
};

VLIB_REGISTER_LOG_CLASS (log_log, static) = {
  .class_name = "log",
};

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
u8 *
format_vlib_log_class (u8 * s, va_list * args)
{
  vlib_log_class_t ci = va_arg (*args, vlib_log_class_t);
  vlib_log_class_data_t *c = vlib_log_get_class_data (ci);
  vlib_log_subclass_data_t *sc = vlib_log_get_subclass_data (ci);

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

  vec_foreach (c, v)
    {
      vec_add (s, c, 1);
      if (c[0] == '\n')
	for (u32 i = 0; i < indent; i++)
	  vec_add1 (s, (u8) ' ');
    }
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

static void
log_size_validate (vlib_log_main_t *lm)
{
  if (vec_len (lm->entries) < lm->size)
    {
      CLIB_SPINLOCK_LOCK (lm->lock);
      vec_validate (lm->entries, lm->size);
      CLIB_SPINLOCK_UNLOCK (lm->lock);
    }
}

void
vlib_log_va (vlib_log_level_t level, vlib_log_class_t class, char *fmt,
	     va_list *va)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_log_main_t *lm = &log_main;
  vlib_log_entry_t *e;
  vlib_log_subclass_data_t *sc = vlib_log_get_subclass_data (class);
  f64 t = vlib_time_now (vm);
  f64 delta = t - sc->last_event_timestamp;
  int log_enabled = log_level_is_enabled (level, sc->level);
  int syslog_enabled = log_level_is_enabled (level, sc->syslog_level);
  int kmsg_enabled = log_level_is_enabled (level, sc->kmsg_level);
  u8 *s = 0;

  if ((log_enabled || syslog_enabled || kmsg_enabled) == 0)
    return;

  log_size_validate (lm);

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
      s = va_format (s, fmt, va);
    }

  if ((syslog_enabled || kmsg_enabled) &&
      (unix_main.flags & (UNIX_FLAG_INTERACTIVE | UNIX_FLAG_NOSYSLOG)))
    {
      u8 *l = 0;
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
      l = format (l, (char *) fmt, format_vlib_log_class, class, format_vlib_log_level, level);
      vec_free (fmt);
      indent = vec_len (l) - indent;
      if (with_colors)
	l = format (l, "\x1b[0m");
      l = format (l, "%U", format_indent, s, indent);
      fformat (stderr, "%v\n", l);
      fflush (stderr);
      vec_free (l);
    }
  else
    {
      u8 *l = 0;
      l = format (l, "%U", format_vlib_log_class, class);
      int is_term = s && vec_c_string_is_terminated (s) ? 1 : 0;
      const char *log_class = l ? (const char *) l : "";
      const char *log_msg = s ? (const char *) s : "";
      int log_class_len = l ? (int) vec_len (l) : 0;
      int log_msg_len = s ? (int) (vec_len (s) - is_term) : 0;
      if (syslog_enabled)
	{
	  int prio = log_level_to_syslog_priority[level];
	  syslog (prio, "%.*s: %.*s", log_class_len, log_class, log_msg_len, log_msg);
	}
      if (kmsg_enabled && lm->kmsg_filp)
	{
	  fprintf (lm->kmsg_filp, "%.*s: %.*s\n", log_class_len, log_class, log_msg_len, log_msg);
	}
      vec_free (l);
    }

  if (log_enabled)
    {
      vlib_worker_thread_t *w = vlib_worker_threads + vm->thread_index;

      CLIB_SPINLOCK_LOCK (lm->lock);
      e = vec_elt_at_index (lm->entries, lm->next);
      lm->next = (lm->next + 1) % lm->size;
      if (lm->size > lm->count)
	lm->count++;
      e->level = level;
      e->class = class;
      e->timestamp = t;
      e->thread_index = vm->thread_index;
      CLIB_SWAP (e->string, s);
      CLIB_SPINLOCK_UNLOCK (lm->lock);

      vec_free (s);

      if (lm->add_to_elog)
	{
	  ELOG_TYPE_DECLARE(ee) =
            {
             .format = "log-%s: %s",
             .format_args = "t4T4",
             .n_enum_strings = VLIB_LOG_N_LEVELS,
             .enum_strings = {
                "unknown",
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
	  struct
	  {
	    u32 log_level;
	    u32 string_index;
	  } * ed;
	  ed = ELOG_TRACK_DATA (vlib_get_elog_main (), ee, w->elog_track);
	  ed->log_level = level;
	  ed->string_index =
	    elog_string (vlib_get_elog_main (), "%v%c", e->string, 0);
	}
    }

  vec_free (s);
}

void
vlib_log (vlib_log_level_t level, vlib_log_class_t class, char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  vlib_log_va (level, class, fmt, &va);
  va_end (va);
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

  if (scc && scc->kmsg_level != ~0)
    s->kmsg_level = scc->kmsg_level;
  else if (cc && cc->kmsg_level != ~0)
    s->kmsg_level = cc->kmsg_level;
  else
    s->kmsg_level = lm->default_kmsg_log_level;

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

clib_error_t *
vlib_log_init (vlib_main_t *vm)
{
  vlib_log_main_t *lm = &log_main;
  vlib_log_class_registration_t *r = lm->registrations;

  gettimeofday (&lm->time_zero_timeval, 0);
  lm->time_zero = vlib_time_now (vm);

  log_size_validate (lm);

  lm->kmsg_filp = fopen ("/dev/kmsg", "w");
  if (lm->kmsg_filp)
    setbuf (lm->kmsg_filp, NULL); // unbuffered

  while (r)
    {
      r->class = vlib_log_register_class (r->class_name, r->subclass_name);
      if (r->default_level)
	vlib_log_get_subclass_data (r->class)->level = r->default_level;
      if (r->default_syslog_level)
	vlib_log_get_subclass_data (r->class)->syslog_level =
	  r->default_syslog_level;
      if (r->default_kmsg_level)
	vlib_log_get_subclass_data (r->class)->kmsg_level = r->default_kmsg_level;
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

static clib_error_t *
show_log (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vlib_log_main_t *lm = &log_main;
  vlib_log_entry_t *e, *entries;
  int i = last_log_entry ();
  int count;
  f64 time_offset;

  time_offset = (f64) lm->time_zero_timeval.tv_sec
    + (((f64) lm->time_zero_timeval.tv_usec) * 1e-6) - lm->time_zero;

  CLIB_SPINLOCK_LOCK (lm->lock);
  count = lm->count;
  entries = vec_dup (lm->entries);
  CLIB_SPINLOCK_UNLOCK (lm->lock);

  while (count--)
    {
      e = vec_elt_at_index (entries, i);
      vlib_cli_output (vm, "%U %-10U %-14U %v", format_time_float, NULL,
		       e->timestamp + time_offset, format_vlib_log_level,
		       e->level, format_vlib_log_class, e->class, e->string);
      i = (i + 1) % lm->size;
    }

  vec_free (entries);

  return error;
}

VLIB_CLI_COMMAND (cli_show_log, static) = {
  .path = "show logging",
  .short_help = "show logging",
  .function = show_log,
};

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
  vlib_cli_output (vm, "%-20s %U", "  Kmsg Log Level:", format_vlib_log_level,
		   lm->default_kmsg_log_level);
  vlib_cli_output (vm, "%-20s %u msgs/sec", "  Rate Limit:",
		   lm->default_rate_limit);
  vlib_cli_output (vm, "\n");
  vlib_cli_output (vm, "%-22s %-14s %-14s %-14s %s", "Class/Subclass", "Level", "Syslog Level",
		   "Kmsg Log Level", "Rate Limit");

  u8 *defstr = format (0, "default");
  vec_foreach (c, lm->classes)
  {
    vlib_cli_output (vm, "%v", c->name);
    vec_foreach (sc, c->subclasses)
    {
	vlib_cli_output (vm, "  %-20v %-14U %-14U %-14U %d", sc->name ? sc->name : defstr,
			 format_vlib_log_level, sc->level, format_vlib_log_level, sc->syslog_level,
			 format_vlib_log_level, sc->kmsg_level, sc->rate_limit);
    }
  }
  vec_free (defstr);

  return error;
}

VLIB_CLI_COMMAND (cli_show_log_config, static) = {
  .path = "show logging configuration",
  .short_help = "show logging configuration",
  .function = show_log_config,
};

static clib_error_t *
clear_log (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vlib_log_main_t *lm = &log_main;
  vlib_log_entry_t *e;
  int i = last_log_entry ();
  int count;

  CLIB_SPINLOCK_LOCK (lm->lock);
  count = lm->count;
  while (count--)
    {
      e = vec_elt_at_index (lm->entries, i);
      vec_free (e->string);
      i = (i + 1) % lm->size;
    }

  lm->count = 0;
  lm->next = 0;
  CLIB_SPINLOCK_UNLOCK (lm->lock);

  vlib_log_info (log_log.class, "log cleared");
  return error;
}

VLIB_CLI_COMMAND (cli_clear_log, static) = {
  .path = "clear logging",
  .short_help = "clear logging",
  .function = clear_log,
};

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
  bool set_kmsg_level = false;
  vlib_log_level_t level;
  vlib_log_level_t syslog_level;
  vlib_log_level_t kmsg_level;

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
      else if (unformat (line_input, "kmsg-level %U", unformat_vlib_log_level, &kmsg_level))
	{
	  set_kmsg_level = true;
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
  if (set_kmsg_level)
    {
      vlib_log_subclass_data_t *subclass;
      vec_foreach (subclass, class->subclasses)
      {
	subclass->kmsg_level = kmsg_level;
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

VLIB_CLI_COMMAND (cli_set_log, static) = {
  .path = "set logging class",
  .short_help = "set logging class <class> [rate-limit <int>] "
		"[level <level>] [syslog-level <level>] [kmsg-level <level>]",
  .function = set_log_class,
};

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

VLIB_CLI_COMMAND (cli_set_log_params, static) = {
  .path = "set logging unthrottle-time",
  .short_help = "set logging unthrottle-time <int>",
  .function = set_log_unth_time,
};

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
	  log_size_validate (lm);
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }

  return rv;
}

VLIB_CLI_COMMAND (cli_set_log_size, static) = {
  .path = "set logging size",
  .short_help = "set logging size <int>",
  .function = set_log_size,
};

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

VLIB_CLI_COMMAND (cli_test_log, static) = {
  .path = "test log",
  .short_help = "test log <level> <class> <subclass> <message>",
  .function = test_log_class_subclass,
};

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
      else if (unformat (input, "kmsg-level %U", unformat_vlib_log_level, &tmp.kmsg_level))
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
	log_size_validate (lm);
      else if (unformat (input, "unthrottle-time %d", &lm->unthrottle_time))
	;
      else if (unformat (input, "default-log-level %U",
			 unformat_vlib_log_level, &lm->default_log_level))
	;
      else if (unformat (input, "default-syslog-log-level %U",
			 unformat_vlib_log_level,
			 &lm->default_syslog_log_level))
	;
      else if (unformat (input, "default-kmsg-log-level %U", unformat_vlib_log_level,
			 &lm->default_kmsg_log_level))
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
