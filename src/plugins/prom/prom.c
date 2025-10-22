/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <prom/prom.h>
#include <vpp-api/client/stat_client.h>
#include <vlib/stats/stats.h>
#include <ctype.h>

static prom_main_t prom_main;

static u8 *
make_stat_name (char *name)
{
  prom_main_t *pm = &prom_main;
  char *p = name;

  while (*p)
    {
      if (!isalnum (*p))
	*p = '_';
      p++;
    }

  /* Reuse vector, instead of always allocating, when building a name. */
  vec_reset_length (pm->name_scratch_pad);
  pm->name_scratch_pad =
    format (pm->name_scratch_pad, "%v%s", pm->stat_name_prefix, name);
  return pm->name_scratch_pad;
}

static u8 *
dump_counter_vector_simple (stat_segment_data_t *res, u8 *s, u8 used_only)
{
  u8 need_header = 1;
  int j, k;
  u8 *name;

  name = make_stat_name (res->name);

  for (k = 0; k < vec_len (res->simple_counter_vec); k++)
    for (j = 0; j < vec_len (res->simple_counter_vec[k]); j++)
      {
	if (used_only && !res->simple_counter_vec[k][j])
	  continue;
	if (need_header)
	  {
	    s = format (s, "# TYPE %v counter\n", name);
	    need_header = 0;
	  }
	s = format (s, "%v{thread=\"%d\",interface=\"%d\"} %lld\n", name, k, j,
		    res->simple_counter_vec[k][j]);
      }

  return s;
}

static u8 *
dump_counter_vector_combined (stat_segment_data_t *res, u8 *s, u8 used_only)
{
  u8 need_header = 1;
  int j, k;
  u8 *name;

  name = make_stat_name (res->name);

  for (k = 0; k < vec_len (res->simple_counter_vec); k++)
    for (j = 0; j < vec_len (res->combined_counter_vec[k]); j++)
      {
	if (used_only && !res->combined_counter_vec[k][j].packets)
	  continue;
	if (need_header)
	  {
	    s = format (s, "# TYPE %v_packets counter\n", name);
	    s = format (s, "# TYPE %v_bytes counter\n", name);
	    need_header = 0;
	  }
	s = format (s, "%v_packets{thread=\"%d\",interface=\"%d\"} %lld\n",
		    name, k, j, res->combined_counter_vec[k][j].packets);
	s = format (s, "%v_bytes{thread=\"%d\",interface=\"%d\"} %lld\n", name,
		    k, j, res->combined_counter_vec[k][j].bytes);
      }

  return s;
}

static u8 *
dump_scalar_index (stat_segment_data_t *res, u8 *s, u8 used_only)
{
  u8 *name;

  if (used_only && !res->scalar_value)
    return s;

  name = make_stat_name (res->name);

  s = format (s, "# TYPE %v counter\n", name);
  s = format (s, "%v %.2f\n", name, res->scalar_value);

  return s;
}

static u8 *
dump_name_vector (stat_segment_data_t *res, u8 *s, u8 used_only)
{
  u8 *name;
  int k;

  name = make_stat_name (res->name);

  s = format (s, "# TYPE %v_info gauge\n", name);
  for (k = 0; k < vec_len (res->name_vector); k++)
    s = format (s, "%v_info{index=\"%d\",name=\"%s\"} 1\n", name, k,
		res->name_vector[k]);

  return s;
}

static u8 *
scrape_stats_segment (u8 *s, u8 **patterns, u8 used_only)
{
  stat_segment_data_t *res;
  static u32 *stats = 0;
  int i;

  stats = stat_segment_ls (patterns);

retry:
  res = stat_segment_dump (stats);
  if (res == 0)
    { /* Memory layout has changed */
      if (stats)
	vec_free (stats);
      stats = stat_segment_ls (patterns);
      goto retry;
    }

  for (i = 0; i < vec_len (res); i++)
    {
      switch (res[i].type)
	{
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  s = dump_counter_vector_simple (&res[i], s, used_only);
	  break;

	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  s = dump_counter_vector_combined (&res[i], s, used_only);
	  break;

	case STAT_DIR_TYPE_SCALAR_INDEX:
	case STAT_DIR_TYPE_GAUGE:
	  s = dump_scalar_index (&res[i], s, used_only);
	  break;

	case STAT_DIR_TYPE_NAME_VECTOR:
	  s = dump_name_vector (&res[i], s, used_only);
	  break;

	case STAT_DIR_TYPE_EMPTY:
	case STAT_DIR_TYPE_RING_BUFFER:
	case STAT_DIR_TYPE_HISTOGRAM_LOG2:
	  break;

	default:
	  clib_warning ("Unknown value %d\n", res[i].type);
	  ;
	}
    }
  stat_segment_data_free (res);
  vec_free (stats);

  return s;
}

static void
send_data_to_hss (hss_session_handle_t sh)
{
  hss_url_handler_args_t args = {};
  prom_main_t *pm = &prom_main;

  args.sh = sh;
  args.data = vec_dup (pm->stats);
  args.data_len = vec_len (pm->stats);
  args.ct = HTTP_CONTENT_TEXT_PLAIN;
  args.sc = HTTP_STATUS_OK;
  args.free_vec_data = 1;

  pm->send_data (&args);
}

static void
send_data_to_hss_rpc (void *rpc_args)
{
  send_data_to_hss (*(hss_session_handle_t *) rpc_args);
}

static uword
prom_scraper_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		      vlib_frame_t *f)
{
  uword *event_data = 0, event_type, *sh_as_uword;
  prom_main_t *pm = &prom_main;
  hss_session_handle_t sh;
  f64 timeout = 10000.0;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, (uword **) &event_data);
      switch (event_type)
	{
	case ~0:
	  /* timeout, do nothing */
	  break;
	case PROM_SCRAPER_EVT_RUN:
	  vec_reset_length (pm->stats);
	  pm->stats = scrape_stats_segment (pm->stats, pm->stats_patterns,
					    pm->used_only);
	  vec_foreach (sh_as_uword, event_data)
	    {
	      sh.as_u64 = (u64) *sh_as_uword;
	      session_send_rpc_evt_to_thread_force (
		sh.thread_index, send_data_to_hss_rpc, sh_as_uword);
	    }
	  pm->last_scrape = vlib_time_now (vm);
	  break;
	default:
	  clib_warning ("unexpected event %u", event_type);
	  break;
	}

      vec_reset_length (event_data);
    }
  return 0;
}

VLIB_REGISTER_NODE (prom_scraper_process_node) = {
  .function = prom_scraper_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "prom-scraper-process",
  .state = VLIB_NODE_STATE_DISABLED,
};

static void
prom_scraper_process_enable (vlib_main_t *vm)
{
  prom_main_t *pm = &prom_main;
  vlib_node_t *n;

  vlib_node_set_state (vm, prom_scraper_process_node.index,
		       VLIB_NODE_STATE_POLLING);
  n = vlib_get_node (vm, prom_scraper_process_node.index);
  vlib_start_process (vm, n->runtime_index);

  pm->scraper_node_index = n->index;
}

static void
signal_run_to_scraper (uword *args)
{
  prom_main_t *pm = &prom_main;
  ASSERT (vlib_get_thread_index () == 0);
  vlib_process_signal_event (pm->vm, pm->scraper_node_index,
			     PROM_SCRAPER_EVT_RUN, *args);
}

hss_url_handler_rc_t
prom_stats_dump (hss_url_handler_args_t *args)
{
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);
  prom_main_t *pm = &prom_main;

  /* If we've recently scraped stats, return data */
  if ((now - pm->last_scrape) < pm->min_scrape_interval)
    {
      send_data_to_hss (args->sh);
      return HSS_URL_HANDLER_ASYNC;
    }

  if (vm->thread_index != 0)
    vl_api_rpc_call_main_thread (signal_run_to_scraper, (u8 *) &args->sh,
				 sizeof (args->sh));
  else
    signal_run_to_scraper (&args->sh.as_u64);

  return HSS_URL_HANDLER_ASYNC;
}

void
prom_stat_patterns_add (u8 **patterns)
{
  prom_main_t *pm = &prom_main;

  u8 **pattern, **existing;
  u8 found;
  u32 len;

  vec_foreach (pattern, patterns)
    {
      found = 0;
      len = vec_len (*pattern);
      if (len == 0)
	continue;
      vec_foreach (existing, pm->stats_patterns)
	{
	  if (vec_len (*existing) != len)
	    continue;
	  if (!memcmp (*existing, *pattern, len - 1))
	    {
	      found = 1;
	      break;
	    }
	}
      if (!found)
	vec_add1 (pm->stats_patterns, *pattern);
    }
}

void
prom_stat_patterns_free (void)
{
  prom_main_t *pm = &prom_main;
  u8 **pattern;

  vec_foreach (pattern, pm->stats_patterns)
    vec_free (*pattern);
  vec_free (pm->stats_patterns);
}

void
prom_stat_patterns_set (u8 **patterns)
{
  prom_stat_patterns_free ();
  prom_stat_patterns_add (patterns);
}

u8 **
prom_stat_patterns_get (void)
{
  return prom_main.stats_patterns;
}

void
prom_stat_name_prefix_set (u8 *prefix)
{
  prom_main_t *pm = &prom_main;

  vec_free (pm->stat_name_prefix);
  pm->stat_name_prefix = prefix;
}

void
prom_report_used_only (u8 used_only)
{
  prom_main_t *pm = &prom_main;

  pm->used_only = used_only;
}

static void
prom_stat_segment_client_init (void)
{
  stat_client_main_t *scm = &stat_client_main;
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  uword size;

  size = sm->memory_size ? sm->memory_size : STAT_SEGMENT_DEFAULT_SIZE;
  scm->memory_size = size;
  scm->shared_header = sm->shared_header;
  scm->directory_vector =
    stat_segment_adjust (scm, (void *) scm->shared_header->directory_vector);
}

clib_error_t *
prom_enable (vlib_main_t *vm)
{
  prom_main_t *pm = &prom_main;

  pm->register_url = vlib_get_plugin_symbol ("http_static_plugin.so",
					     "hss_register_url_handler");
  if (pm->register_url == 0)
    return clib_error_return (0, "http_static_plugin.so not loaded");

  pm->send_data =
    vlib_get_plugin_symbol ("http_static_plugin.so", "hss_session_send_data");
  pm->register_url (prom_stats_dump, "stats.prom", HTTP_REQ_GET);

  pm->is_enabled = 1;
  pm->vm = vm;
  if (!pm->stat_name_prefix)
    pm->stat_name_prefix = format (0, "vpp");

  prom_scraper_process_enable (vm);
  prom_stat_segment_client_init ();

  return 0;
}

static clib_error_t *
prom_init (vlib_main_t *vm)
{
  prom_main_t *pm = &prom_main;

  pm->is_enabled = 0;
  pm->min_scrape_interval = 1;
  pm->used_only = 0;
  pm->stat_name_prefix = 0;

  return 0;
}

prom_main_t *
prom_get_main (void)
{
  return &prom_main;
}

VLIB_INIT_FUNCTION (prom_init) = {
  .runs_after = VLIB_INITS ("hss_main_init"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Prometheus Stats Exporter",
  .default_disabled = 0,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
