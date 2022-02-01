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
#include <ctype.h>

static prom_main_t prom_main;

static char *
prom_string (char *s)
{
  char *p = s;
  while (*p)
    {
      if (!isalnum (*p))
	*p = '_';
      p++;
    }
  return s;
}

static void
scrape_stats_segment (u8 *s, u8 **patterns)
{
  stat_segment_data_t *res;
  static u32 *stats = 0;
  int i, j, k;

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
	  format (s, "# TYPE %s counter\n", prom_string (res[i].name));
	  for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
	    for (j = 0; j < vec_len (res[i].simple_counter_vec[k]); j++)
	      format (s, "%s{thread=\"%d\",interface=\"%d\"} %lld\n",
		      prom_string (res[i].name), k, j,
		      res[i].simple_counter_vec[k][j]);
	  break;

	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  format (s, "# TYPE %s_packets counter\n", prom_string (res[i].name));
	  format (s, "# TYPE %s_bytes counter\n", prom_string (res[i].name));
	  for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
	    for (j = 0; j < vec_len (res[i].combined_counter_vec[k]); j++)
	      {
		format (s, "%s_packets{thread=\"%d\",interface=\"%d\"} %lld\n",
			prom_string (res[i].name), k, j,
			res[i].combined_counter_vec[k][j].packets);
		format (s, "%s_bytes{thread=\"%d\",interface=\"%d\"} %lld\n",
			prom_string (res[i].name), k, j,
			res[i].combined_counter_vec[k][j].bytes);
	      }
	  break;
	case STAT_DIR_TYPE_ERROR_INDEX:
	  for (j = 0; j < vec_len (res[i].error_vector); j++)
	    {
	      format (s, "# TYPE %s counter\n", prom_string (res[i].name));
	      format (s, "%s{thread=\"%d\"} %lld\n", prom_string (res[i].name),
		      j, res[i].error_vector[j]);
	    }
	  break;

	case STAT_DIR_TYPE_SCALAR_INDEX:
	  format (s, "# TYPE %s counter\n", prom_string (res[i].name));
	  format (s, "%s %.2f\n", prom_string (res[i].name),
		  res[i].scalar_value);
	  break;

	case STAT_DIR_TYPE_NAME_VECTOR:
	  format (s, "# TYPE %s_info gauge\n", prom_string (res[i].name));
	  for (k = 0; k < vec_len (res[i].name_vector); k++)
	    if (res[i].name_vector[k])
	      format (s, "%s_info{index=\"%d\",name=\"%s\"} 1\n",
		      prom_string (res[i].name), k, res[i].name_vector[k]);
	  break;

	case STAT_DIR_TYPE_EMPTY:
	  break;

	default:
	  fformat (stderr, "Unknown value %d\n", res[i].type);
	  ;
	}
    }
  stat_segment_data_free (res);
}

typedef struct prom_rpc_args_
{
  hss_session_handle_t session_handle;
  u8 *data;
  uword data_len;
} prom_rpc_args_t;

static void
send_data_to_hss (void *rpc_args)
{
  hss_session_handle_t *sh = (hss_session_handle_t *) rpc_args;
  prom_main_t *pm = &prom_main;

  pm->send_data (*sh, pm->stats, vec_len (pm->stats), HTTP_STATUS_OK);
}

static uword
prom_scraper_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		      vlib_frame_t *f)
{
  uword *event_data = 0, event_type;
  prom_main_t *pm = &prom_main;
  hss_session_handle_t sh;
  f64 timeout = 1.0;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, (uword **) &event_data);
      sh.as_u64 = event_data[0];
      switch (event_type)
	{
	case ~0:
	  /* timeout, do nothing */
	  break;
	case PROM_SCRAPER_EVT_RUN:
	  vec_free (pm->stats);
	  scrape_stats_segment (pm->stats, 0);
	  session_send_rpc_evt_to_thread_force (sh.thread_index,
						send_data_to_hss, &sh);
	  pm->latest_scrape = vlib_time_now (vm);
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
start_scraper_process (vlib_main_t *vm)
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
signal_evt_to_scraper (uword *code)
{
  prom_main_t *pm = &prom_main;
  ASSERT (vlib_get_thread_index () == 0);
  vlib_process_signal_event (pm->vm, pm->scraper_node_index, *code, 0);
}

int
prom_stats_dump (http_req_method_t reqtype, u8 *request, hss_session_t *hs)
{
  uword code;

  if (vlib_get_thread_index () != 0)
    vl_api_rpc_call_main_thread (signal_evt_to_scraper, (u8 *) &code,
				 sizeof (code));
  else
    signal_evt_to_scraper (&code);

  return 0;
}

static clib_error_t *
prom_command_fn (vlib_main_t *vm, unformat_input_t *input,
		 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  prom_main_t *pm = &prom_main;

  if (!unformat_user (input, unformat_line_input, line_input))
    goto no_input;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	;
      else
	{
	  unformat_free (line_input);
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, line_input);
	}
    }

  unformat_free (line_input);

no_input:

  pm->register_url = vlib_get_plugin_symbol ("http_static_plugin.so",
					     "hss_register_url_handler");
  pm->send_data =
    vlib_get_plugin_symbol ("http_static_plugin.so", "hss_session_send_data");
  pm->register_url (prom_stats_dump, "stats.prom", HTTP_REQ_GET);

  pm->is_enabled = 1;
  pm->vm = vm;

  start_scraper_process (vm);

  return 0;
}

VLIB_CLI_COMMAND (prom_enable_command, static) = {
  .path = "prom",
  .short_help = "prom [enable]",
  .function = prom_command_fn,
};

static clib_error_t *
prom_init (vlib_main_t *vm)
{
  prom_main_t *pm = &prom_main;

  pm->is_enabled = 0;

  return 0;
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
