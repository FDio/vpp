/*
 * Copyright (c) 2022 Intel and/or its affiliates.
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

#include <ctype.h>
#include <vnet/vnet.h>
#include <vppinfra/linux/sysfs.h>
#include <perfmon/perf_events.h>

VLIB_REGISTER_LOG_CLASS (perfmon_perf_events_log, static) = {
  .class_name = "perfmon",
  .subclass_name = "perf_events",
};

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (perfmon_perf_events_log.class, fmt, __VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (perfmon_perf_events_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)                                                     \
  vlib_log_err (perfmon_perf_events_log.class, fmt, __VA_ARGS__)

perf_event_main_t perf_event_main;

static perf_event_source_t *
add_event_sources (perf_e_event_source_t t, char *name, int *socket_by_cpu_id);

perf_event_t *
perf_query_event (const char *event_name)
{
  uword *p;
  perf_event_main_t *pem = &perf_event_main;

  if (!pem->event_by_name)
    return NULL;

  p = hash_get_mem (pem->event_by_name, event_name);
  if (!p)
    {
      log_err ("event %s not found", event_name);
      return 0;
    }

  return (perf_event_t *) p[0];
}

perf_event_source_t *
perf_query_event_sources (perf_event_t *event)
{
  perf_event_main_t *pem = &perf_event_main;
  perf_event_source_t *p, **pp;

  pp = (perf_event_source_t **) hash_get_mem (pem->event_source_by_name,
					      event->source_name);

  if (!pp)
    {
      /* we do a lazy create for CPU, SOFTWARE and friends */
      if (event->source != PERF_SOURCE_OTHER)
	{
	  if (!(p = add_event_sources (event->source, event->source_name, 0)))
	    return 0;

	  hash_set_mem (pem->event_source_by_name, event->source_name, p);
	  return p;
	}

      /* otherwise we just couldn't find it */
      return 0;
    }

  return pp[0];
}

static u8
check_uarch_supported (perf_uarch_features_t *uarch_features,
		       u32 n_uarch_features)
{
  perf_uarch_features_t *puf = NULL;
  u8 f = 0;

  for (; f < n_uarch_features; f++)
    {
      puf = &uarch_features[f];

      if (puf->check_feature () != puf->expected_result)
	break;
    }

  /* all the features passed for the current uarch */
  return n_uarch_features == f;
}

static int *
build_numa_by_cpu_id ()
{
  clib_bitmap_t *cpumask = 0;
  clib_error_t *err = 0;
  u8 *s = 0;
  u32 j;
  int numa = -1;
  int *numa_by_cpu_id = 0;

  while ((numa = vlib_mem_get_next_numa_node (numa)) != -1)
    {
      s = format (s, "/sys/devices/system/node/node%u/cpulist%c", numa, 0);
      if ((err = clib_sysfs_read ((char *) s, "%U", unformat_bitmap_list,
				  &cpumask)) ||
	  !cpumask)
	goto done;

      clib_bitmap_foreach (j, cpumask)
	{
	  vec_validate_init_empty (numa_by_cpu_id, j, -1);
	  numa_by_cpu_id[j] = numa;
	}
      clib_bitmap_free (cpumask);
      vec_reset_length (s);
    }

done:
  clib_error_free (err);
  return numa_by_cpu_id;
}

static perf_event_source_t *
add_event_sources (perf_e_event_source_t t, char *name, int *socket_by_cpu_id)
{
  const char *sysfs_path = "/sys/bus/event_source/devices";
  clib_error_t *err = 0;
  clib_bitmap_t *cpumask = 0;
  u8 *s = 0;
  int i = 0, j;
  u32 perf_type;
  perf_event_source_t *sources = 0, *source = 0;

  /*
   * event source can be per cpu pmu or per uncore pmu
   * we let the kernel detect and enumerate them for us.
   */

  s = format (s, "%s/%s/type%c", sysfs_path, name, 0);
  if (!(err = clib_sysfs_read ((char *) s, "%u", &perf_type)))
    {
      for (int i = 0; i < vlib_get_n_threads (); i++)
	{
	  vlib_worker_thread_t *w = vlib_worker_threads + i;
	  vec_add2 (sources, source, 1);
	  source->type = perf_type;
	  source->cpu = w->cpu_id;
	  source->pid = w->lwp;
	  source->name = (char *) format (0, "%s (%u)%c", w->name, i, 0);
	  log_debug ("added event source %s", source->name);
	}
    }
  else // multiple pmus
    {
      clib_error_free (err);
      vec_reset_length (s);

      while (1)
	{
	  s = format (s, "%s/uncore_%s_%u/type%c", sysfs_path, name, i, 0);
	  if ((err = clib_sysfs_read ((char *) s, "%u", &perf_type)))
	    break;
	  vec_reset_length (s);

	  s = format (s, "%s/uncore_%s_%u/cpumask%c", sysfs_path, name, i, 0);
	  if ((err = clib_sysfs_read ((char *) s, "%U", unformat_bitmap_list,
				      &cpumask)))
	    break;
	  vec_reset_length (s);

	  clib_bitmap_foreach (j, cpumask)
	    {
	      vec_add2 (sources, source, 1);
	      source->type = perf_type;
	      source->cpu = j;
	      source->pid = -1;
	      source->name = (char *) format (0, "%s%u/%u%c", name,
					      socket_by_cpu_id[j], i, 0);
	      log_debug ("added event source %s", source->name);
	    }
	  i++;
	};
    }

  clib_error_free (err);
  clib_bitmap_free (cpumask);
  vec_free (s);

  return sources;
}

uword
unformat_perf_event_source (unformat_input_t *input, va_list *args)
{
  perf_event_main_t *pem = &perf_event_main;
  perf_event_source_t **es = va_arg (*args, perf_event_source_t **);
  u8 **str = va_arg (*args, u8 **);
  uword *p;

  if (unformat (input, "source %s", str) == 0)
    return 0;

  p = hash_get_mem (pem->event_source_by_name, *str);

  if (p)
    es[0] = (perf_event_source_t *) p[0];

  return p ? 1 : 0;
}

u8 *
format_perf_event (u8 *s, va_list *args)
{
  perf_event_t *event = va_arg (*args, perf_event_t *);
  int verbose = va_arg (*args, int);

  char *counter_types[PERF_COUNTER_TYPE_MAX] = { "GENERAL", "FIXED",
						 "PSEUDO" };

  if (verbose)
    {
      s = format (s, "%-15s : %s\n", "name", event->name);
      s = format (s, "%-15s : %s\n", "description", event->description);
      s = format (s, "%-15s : ", "perf config");
      if (event->format_config)
	s = format (s, "%U\n", event->format_config, event->config);
      else
	s = format (s, "0x%x\n", event->config);

      s = format (s, "%-15s : %s\n", "source", event->source_name);
      s = format (s, "%-15s : 0x%02x\n", "counter mask", event->pmc_mask);
      s = format (s, "%-15s : %s\n", "counter type",
		  counter_types[event->counter_type]);
    }
  else
    {
      if (event == 0)
	return format (s, "%-10s%-70s", "Source", "Name");

      s = format (s, "%-10s%-70s", event->source_name, event->name);
    }

  return s;
}

u8 *
format_perf_source (u8 *s, va_list *args)
{
  u8 *source_name = va_arg (*args, u8 *);
  perf_event_source_t *sources = va_arg (*args, perf_event_source_t *);
  int verbose = va_arg (*args, int);
  struct
  {
    perf_e_event_source_t e;
    char *t;
  } _source_names[] = { { PERF_SOURCE_SOFTWARE, "software" },
			{ PERF_SOURCE_CPU, "cpu" },
			{ PERF_SOURCE_OTHER, "other" } };

  if (verbose)
    {
      s = format (s, "%-15s : %s\n", "source", source_name);
      for (int i = 0; i < vec_len (sources); i++)
	{
	  int e = 0;
	  s = format (s, "%-15s : %s\n", "name", sources[i].name);
	  for (; e < ARRAY_LEN (_source_names); e++)
	    if (_source_names[e].e == sources[i].type)
	      {
		s = format (s, "%-15s : %s\n", "type", _source_names[e].t);
		break;
	      }

	  if (ARRAY_LEN (_source_names) == e)
	    s = format (s, "%-15s : %d\n", "type", sources[i].type);
	}
    }
  else
    {
      if (source_name == 0)
	return format (s, "%-20s%s", "Source", "Instance Count");

      s = format (s, "%-20s%d", source_name, vec_len (sources));
    }

  return s;
}

static int
event_sort_cmp (void *a1, void *a2)
{
  perf_event_t **e1 = a1;
  perf_event_t **e2 = a2;

  if (clib_strcmp ((*e1)->source_name, (*e2)->source_name) == 0)
    return (*e1)->config > (*e2)->config;
  else
    {
      u32 l0 = strlen ((*e1)->source_name);
      u32 l1 = strlen ((*e2)->source_name);
      u32 len = clib_min (l0, l1);

      for (u32 i = 0; i < len; i++)
	if ((*e1)->source_name[i] != (*e2)->source_name[i])
	  return (*e1)->source_name[i] > (*e2)->source_name[i];

      return 0;
    }

  return 0;
}

static clib_error_t *
show_perf_events_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  char *sn = 0, *default_source = "cpu";
  perf_event_main_t *pem = &perf_event_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  perf_event_t **ve = 0, *e = 0;
  perf_event_source_t *es = 0;
  u8 *source_name = 0;
  int verbose = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else if (unformat (line_input, "%U", unformat_perf_event_source, &es,
			     &source_name))
	    {
	      if (!es)
		return clib_error_return (
		  0, "please specify a valid event source");
	    }
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, line_input);
	}
      unformat_free (line_input);
    }

  u8 *key;
  sn = default_source;
  if (source_name)
    sn = (char *) source_name;

  hash_foreach_mem (key, e, pem->event_by_name, {
    if (clib_strcmp (sn, e->source_name) == 0)
      vec_add (ve, &e, 1);
  });

  vec_sort_with_function (ve, event_sort_cmp);

  if (!verbose)
    vlib_cli_output (vm, "%U", format_perf_event, 0, 0);

  for (int i = 0; i < vec_len (ve); i++)
    vlib_cli_output (vm, "%U", format_perf_event, ve[i], verbose);

  vec_free (ve);
  vec_free (source_name);

  return 0;
}

VLIB_CLI_COMMAND (show_perf_events_command, static) = {
  .path = "show perf events",
  .short_help = "show perf events [verbose] source [source]",
  .function = show_perf_events_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_perf_sources_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  perf_event_main_t *pem = &perf_event_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  perf_event_source_t *s = 0;
  int verbose = 0;
  char *key;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, line_input);
	}
      unformat_free (line_input);
    }

  if (!verbose)
    vlib_cli_output (vm, "%U", format_perf_source, 0, 0, 0);

  hash_foreach_mem (key, s, pem->event_source_by_name, {
    vlib_cli_output (vm, "%U", format_perf_source, key, s, verbose);
  });

  return 0;
}

VLIB_CLI_COMMAND (show_perf_sources_command, static) = {
  .path = "show perf sources",
  .short_help = "show perf sources",
  .function = show_perf_sources_command_fn,
  .is_mp_safe = 1,
};

clib_error_t *
perf_event_init (vlib_main_t *vm)
{
  perf_event_main_t *pem = &perf_event_main;
  perf_events_registration_t *events = pem->events_registrations;
  perf_event_source_t *event_sources = 0, **pevent_sources = 0;
  int *numa_by_cpu_id = build_numa_by_cpu_id ();

  if (!numa_by_cpu_id)
    return clib_error_return (0, "failed to discover numa topology");

  pem->event_by_name = hash_create_string (0, sizeof (uword));
  pem->event_source_by_name = hash_create_string (0, sizeof (uword));

  while (events)
    {
      /* check these events may only be supported on a specific uarch */
      if (!check_uarch_supported (events->uarch_features,
				  events->n_uarch_features))
	{
	  events = events->next_events;
	  continue;
	}

      for (int i = 0; i < events->n_events; i++)
	{
	  char *event_name = events->events[i].name;

	  if (hash_get_mem (pem->event_by_name, event_name) != 0)
	    {
	      log_debug ("skipping duplicate event name '%s'", event_name);
	      continue;
	    }

	  pevent_sources = (perf_event_source_t **) hash_get_mem (
	    pem->event_source_by_name, &events->events[i].source_name);

	  /* add event sources we can interogate at startup */
	  if (!pevent_sources && events->events[i].source == PERF_SOURCE_OTHER)
	    {
	      event_sources = add_event_sources (events->events[i].source,
						 events->events[i].source_name,
						 numa_by_cpu_id);

	      hash_set_mem (pem->event_source_by_name,
			    events->events[i].source_name, event_sources);
	    }

	  hash_set_mem (pem->event_by_name, event_name, &events->events[i]);
	  log_debug ("event '%s' registered", event_name);
	}

      events = events->next_events;
    }

  vec_free (numa_by_cpu_id);

  return 0;
}

/* VLIB_INIT_FUNCTION (perf_event_init); */
