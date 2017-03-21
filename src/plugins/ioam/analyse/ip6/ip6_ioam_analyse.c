/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <ioam/analyse/ioam_analyse.h>
#include <ioam/export-common/ioam_export.h>
#include <ioam/analyse/ip6/ip6_ioam_analyse.h>
#include <ioam/analyse/ioam_summary_export.h>
#include <vnet/ip/ip.h>
#include <ioam/ipfixcollector/ipfixcollector.h>

extern ioam_export_main_t ioam_export_main;
static clib_error_t *
ioam_analyse_enable_disable (vlib_main_t * vm,
			     int is_add, int is_export, int remote_listen)
{
  ipfix_client_add_del_t ipfix_reg;
  clib_error_t *rv = 0;

  ipfix_reg.client_name = format (0, "ip6-hbh-analyse-remote");
  ipfix_reg.client_node = analyse_node_remote.index;
  ipfix_reg.ipfix_setid = IPFIX_IOAM_EXPORT_ID;

  if (is_export)
    {
      rv = ioam_flow_create (!is_add);
      if (rv)
	goto ret;
    }

  if (is_add)
    {
      ip6_ioam_analyse_register_handlers ();
      if (remote_listen)
	{
	  ipfix_reg.del = 0;
	  ipfix_collector_reg_setid (vm, &ipfix_reg);
	}
      else
	{
	  ioam_export_set_next_node (&ioam_export_main,
				     (u8 *) "ip6-hbh-analyse-local");
	}
    }
  else
    {
      ip6_ioam_analyse_unregister_handlers ();
      if (remote_listen)
	{
	  ipfix_reg.del = 1;
	  ipfix_collector_reg_setid (vm, &ipfix_reg);
	}
      else
	ioam_export_reset_next_node (&ioam_export_main);
    }

ret:
  vec_free (ipfix_reg.client_name);
  return rv;
}

static clib_error_t *
set_ioam_analyse_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  int is_export = 0;
  int is_add = 1;
  int remote_listen = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "export-ipfix-collector"))
	is_export = 1;
      else if (unformat (input, "disable"))
	is_add = 0;
      else if (unformat (input, "listen-ipfix"))
	remote_listen = 1;
      else
	break;
    }

  return (ioam_analyse_enable_disable (vm, is_add, is_export, remote_listen));
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ioam_analyse_command, static) = {
  .path = "set ioam analyse",
  .short_help = "set ioam analyse [export-ipfix-collector] [disable] [listen-ipfix]",
  .function = set_ioam_analyse_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_ioam_analyse_cmd_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  ip6_ioam_analyser_main_t *am = &ioam_analyser_main;
  ioam_analyser_data_t *record = NULL;
  u8 i;
  u8 *s = 0;

  vec_reset_length (s);
  s = format (0, "iOAM Analyse Information: \n");
  vec_foreach_index (i, am->aggregated_data)
  {
    record = am->aggregated_data + i;
    if (record->is_free)
      continue;

    s = format (s, "Flow Number: %u\n", i);
    s = print_analyse_flow (s, record);
    s = format (s, "\n");
  }
  vlib_cli_output (vm, "%v", s);

  vec_free (s);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_show_ioam_ipfix_cmd, static) = {
  .path = "show ioam analyse ",
  .short_help = "show ioam analyser information",
  .function = show_ioam_analyse_cmd_fn,
};
/* *INDENT-ON* */

static clib_error_t *
ioam_analyse_init (vlib_main_t * vm)
{
  ip6_ioam_analyser_main_t *am = &ioam_analyser_main;
  u16 i;

  vec_validate_aligned (am->aggregated_data, 50, CLIB_CACHE_LINE_BYTES);
  vec_foreach_index (i, am->aggregated_data)
  {
    ioam_analyse_init_data (am->aggregated_data + i);
  }

  return 0;
}

VLIB_INIT_FUNCTION (ioam_analyse_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
