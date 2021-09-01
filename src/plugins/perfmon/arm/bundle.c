/*
 * Copyright (c) 2021 Arm and/or its affiliates.
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

#include <perfmon/perfmon.h>

VLIB_REGISTER_LOG_CLASS (if_default_log, static) = {
  .class_name = "perfmon",
};

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (if_default_log.class, fmt, __VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (if_default_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...) vlib_log_err (if_default_log.class, fmt, __VA_ARGS__)

clib_error_t *
bundle_event_support (vlib_main_t *vm, perfmon_bundle_t *b)
{
  clib_error_t *err = 0;
  clib_bitmap_alloc (b->event_disabled, b->n_events);
  for (int i = 0; i < b->n_events; i++)
    {
      perfmon_event_t *e = b->src->events + b->events[i];
      if (!e->implemented)
	{
	  log_debug (
	    "bundle \'%s\': perf event %s is not implemented on this CPU",
	    b->name, e->name);
	  clib_bitmap_set (b->event_disabled, i, 1);
	}
    }
  // if no events are implemented, fail and do not register bundle
  if (clib_bitmap_count_set_bits (b->event_disabled) == b->n_events)
    {
      err = clib_error_create (
	"no events in this bundle are supported by the CPU");
      return err;
    }

  clib_bitmap_alloc (b->column_disabled, b->n_columns);

  return err;
}

void
set_column_events (perfmon_bundle_t *b, u8 column, int event, ...)
{
  va_list args;
  va_start (args, event);
  do
    {
      if (clib_bitmap_get (b->event_disabled, event))
	{
	  clib_bitmap_set (b->column_disabled, column, 1);
	  return;
	}
    }
  while ((event = va_arg (args, int)) != -1); // sentinel value -1
  va_end (args);
}