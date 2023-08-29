/*
 * Copyright (c) 2022 Arm and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vppinfra/linux/sysfs.h>
#include <perfmon/perfmon.h>
#include <perfmon/arm/events.h>
#include <perfmon/arm/dispatch_wrapper.h>
#include <linux/perf_event.h>
#include <dirent.h>

VLIB_REGISTER_LOG_CLASS (if_default_log, static) = {
  .class_name = "perfmon",
};

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (if_default_log.class, fmt, __VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (if_default_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...) vlib_log_err (if_default_log.class, fmt, __VA_ARGS__)

/*
 * config1 = 2 : user access enabled and always 32-bit
 * config1 = 3 : user access enabled and always 64-bit
 *
 * Since there is no discovery into whether 64b counters are supported
 * or not, first attempt to request 64b counters, then fall back to
 * 32b if perf_event_open returns EOPNOTSUPP
 */
static perfmon_event_t events[] = {
#define _(event, n, desc)                                                     \
  [ARMV8_PMUV3_##n] = {                                                       \
    .type = PERF_TYPE_RAW,                                                    \
    .config = event,                                                          \
    .config1 = 3,                                                             \
    .name = #n,                                                               \
    .description = desc,                                                      \
    .exclude_kernel = 1,                                                      \
  },
  foreach_perf_arm_event
#undef _
};

u8 *
format_arm_config (u8 *s, va_list *args)
{
  u64 config = va_arg (*args, u64);

  s = format (s, "event=0x%02x", config & 0xff);

  return s;
}

static clib_error_t *
arm_init (vlib_main_t *vm, perfmon_source_t *src)
{
  clib_error_t *err;

  /*
    check /proc/sys/kernel/perf_user_access flag to check if userspace
    access to perf counters is enabled (disabled by default)
    - if this file doesn't exist, we are on an unsupported kernel ver
    - if the file exists and is 0, user access needs to be granted
      with 'sudo sysctl kernel/perf_user_access=1'
  */
  u32 perf_user_access_enabled;
  char *path = "/proc/sys/kernel/perf_user_access";
  err = clib_sysfs_read (path, "%u", &perf_user_access_enabled);
  if (err)
    {
      if (err->code == ENOENT) /* No such file or directory */
	{
	  return clib_error_create (
	    "linux kernel version is unsupported, please upgrade to v5.17+ "
	    "- user access to perf counters is not possible");
	}
      return clib_error_return_unix (0, "failed to read: %s", path);
    }

  if (perf_user_access_enabled == 1)
    log_debug ("user access to perf counters is enabled in %s", path);
  else
    {
      return clib_error_create (
	"user access to perf counters is not enabled: run"
	" \'sudo sysctl kernel/perf_user_access=1\'");
    }

  /*
    perfmon/arm/events.h has up to 0xFF/256 possible PMUv3 event codes
    supported - create a bitmap to store whether each event is
    implemented or not
  */
  uword *bitmap = NULL;
  clib_bitmap_alloc (bitmap, 256);

  struct dirent *dir_entry;
  const char *event_path =
    "/sys/bus/event_source/devices/armv8_pmuv3_0/events";
  DIR *event_dir = opendir (event_path);

  if (event_dir == NULL)
    {
      err =
	clib_error_return_unix (0, "error listing directory: %s", event_path);
      log_err ("%U", format_clib_error, err);
      return err;
    }

  while ((dir_entry = readdir (event_dir)) != NULL)
    {
      if (dir_entry->d_name[0] != '.')
	{
	  u8 *s = NULL;
	  u8 *tmpstr = NULL;
	  unformat_input_t input;
	  u32 config;

	  s = format (s, "%s/%s%c", event_path, dir_entry->d_name, 0);
	  err = clib_sysfs_read ((char *) s, "%s", &tmpstr);
	  if (err)
	    {
	      log_err ("%U", format_clib_error, err);
	      continue;
	    }
	  unformat_init_vector (&input, tmpstr);
	  if (unformat (&input, "event=0x%x", &config))
	    {
	      /* it's possible to have have event codes up to 0xFFFF */
	      if (config < 0xFF) /* perfmon supports < 0xFF */
		{
		  clib_bitmap_set (bitmap, config, 1);
		}
	      log_debug ("found supported event in sysfs: %s \'%s\' 0x%x",
			 dir_entry->d_name, tmpstr, config);
	    }
	  else
	    {
	      err = clib_error_create ("error parsing event: %s %s",
				       dir_entry->d_name, tmpstr);
	      log_err ("%U", format_clib_error, err);
	      continue;
	    }
	}
    }
  closedir (event_dir);

  for (int i = 0; i < ARRAY_LEN (events); i++)
    {
      if (clib_bitmap_get (bitmap, events[i].config))
	events[i].implemented = 1;
    }
  clib_bitmap_free (bitmap);

  return 0;
}

u8
arm_bundle_supported (perfmon_bundle_t *b)
{
  clib_bitmap_alloc (b->event_disabled, b->n_events);
  for (u32 i = 0; i < b->n_events; i++)
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

  /* if no events are implemented, fail and do not register bundle */
  if (clib_bitmap_count_set_bits (b->event_disabled) == b->n_events)
    {
      return 0;
    }

  /* disable columns that use unimplemented events */
  clib_bitmap_alloc (b->column_disabled, b->n_columns);
  if (b->column_events)
    {
      u32 disabled_event;
      /* iterate through set bits */
      clib_bitmap_foreach (disabled_event, b->event_disabled)
	{
	  for (u32 j = 0; j < b->n_columns; j++)
	    {
	      if (clib_bitmap_get (b->column_disabled, j))
		continue;
	      if (GET_BIT (b->column_events[j], disabled_event))
		{
		  clib_bitmap_set (b->column_disabled, j, 1);
		  log_debug (
		    "bundle \'%s\': disabling column %d as event unsupported",
		    b->name, j);
		}
	    }
	}
    }

  return 1;
}

PERFMON_REGISTER_SOURCE (arm) = {
  .name = "arm",
  .description = "Arm PMU events",
  .events = events,
  .n_events = ARRAY_LEN (events),
  .init_fn = arm_init,
  .format_config = format_arm_config,
  .bundle_support = arm_bundle_supported,
  .config_dispatch_wrapper = arm_config_dispatch_wrapper,
};
