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

#include <vlib/vlib.h>
#include <vlib/log.h>

#define VLIB_LOG_SIZE 50
#define VLIB_LOG_RATE_LIMIT 10
#define VLIB_LOG_UNTHROTTLE_TIME 3
#define VLIB_LOG_DEFAULT_SEVERITY 7

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
  vlib_log_level_t level;
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
} vlib_log_main_t;

vlib_log_main_t log_main;


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

void
vlib_log (vlib_log_level_t level, vlib_log_class_t class, char *fmt, ...)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_log_main_t *lm = &log_main;
  vlib_log_entry_t *e;
  vlib_log_subclass_data_t *sc = get_subclass_data (class);
  //vlib_log_class_data_t *c = get_class_data (class);
  va_list va;
  f64 t = vlib_time_now (vm);
  f64 delta = t - sc->last_event_timestamp;
  u8 *s = 0;

  if ((delta > VLIB_LOG_UNTHROTTLE_TIME) ||
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
}

vlib_log_class_t
vlib_log_register_class (char *class, char *subclass)
{
  vlib_log_main_t *lm = &log_main;
  vlib_log_class_data_t *c;
  vlib_log_subclass_data_t *s;
  vec_add2 (lm->classes, c, 1);
  c->index = c - lm->classes;
  c->name = format (0, "%s", class);

  vec_add2 (c->subclasses, s, 1);
  s->index = s - c->subclasses;
  s->name = subclass ? format (0, "%s", subclass) : 0;
  s->rate_limit = VLIB_LOG_RATE_LIMIT;
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

u8 *
format_vlib_log_class (u8 * s, va_list * args)
{
  vlib_log_class_t ci = va_arg (*args, vlib_log_class_t);
  vlib_log_class_data_t *c = get_class_data (ci);
  vlib_log_subclass_data_t *sc = get_subclass_data (ci);;

  if (sc->name)
    return format (s, "%v/%v", c->name, sc->name);
  else
    return format (s, "%v", c->name, 0);
}

static clib_error_t *
show_log (vlib_main_t * vm,
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
      vlib_cli_output (vm, "%U %-10U %-10U %v (%d)",
		       format_time_float, 0, e->timestamp,
		       format_vlib_log_level, e->level,
		       format_vlib_log_class, e->class, e->string, i);
      i = (i + 1) % lm->size;
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_log, static) = {
  .path = "show log",
  .short_help = "show log",
  .function = show_log,
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
  .path = "clear log",
  .short_help = "clear log",
  .function = clear_log,
};
/* *INDENT-ON* */

static clib_error_t *
set_log_class (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  // TODO
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_set_log, static) = {
  .path = "set log class",
  .short_help = "set log class <class> [rate-limit <int>] "
    "[severity <severity>]",
  .function = set_log_class,
};
/* *INDENT-ON* */

static clib_error_t *
vlib_log_init (vlib_main_t * vm)
{
  vlib_log_main_t *lm = &log_main;
  vlib_log_class_t c1, c2;
  lm->size = VLIB_LOG_SIZE;
  vec_validate (lm->entries, lm->size);
  lm->log_class = vlib_log_register_class ("log", 0);
  c1 = vlib_log_register_class ("foo", 0);
  c2 = vlib_log_register_class ("foo", "bar");
  vlib_log_info (c1, "initialized");
  for (int i = 0; i < 15; i++)
    vlib_log_info (c2, "initialized %u", i);
  sleep (1);
  for (int i = 0; i < 15; i++)
    vlib_log_info (c2, "init2 %u", i);
  sleep (3);
  for (int i = 0; i < 15; i++)
    vlib_log_info (c2, "init3 %u", i);
  return 0;
}

VLIB_INIT_FUNCTION (vlib_log_init);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
