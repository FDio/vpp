/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/base/tcp-check/tcp_check.h>

static clib_error_t *
sfdp_tcp_check_show_sessions_command_fn (vlib_main_t *vm,
					 unformat_input_t *input,
					 vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tcp_check_main_t *vtcm = &sfdp_tcp;
  sfdp_session_t *session;
  sfdp_tcp_check_session_state_t *tcp_session;
  sfdp_tenant_t *tenant;
  u32 session_index;
  sfdp_tenant_id_t tenant_id = ~0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "tenant %d", &tenant_id))
	    ;
	  else
	    {
	      err = unformat_parse_error (line_input);
	      break;
	    }
	}
      unformat_free (line_input);
    }

  if (!err)
    {
      table_t session_table_ = {}, *session_table = &session_table_;
      u32 n = 0;
      table_add_header_col (session_table, 8, "id", "tenant", "index", "type",
			    "context", "ingress", "egress", "flags");
      sfdp_foreach_session (sfdp, session_index, session)
      {
	tenant = sfdp_tenant_at_index (sfdp, session->tenant_idx);
	if (tenant_id != ~0 && tenant_id != tenant->tenant_id)
	  continue;
	if (session->proto != IP_PROTOCOL_TCP)
	  continue;
	tcp_session = vec_elt_at_index (vtcm->state, session_index);
	n = sfdp_table_format_insert_tcp_check_session (
	  session_table, n, sfdp, session_index, session, tcp_session);
      }
      vlib_cli_output (vm, "%U", format_table, session_table);
      table_free (session_table);
    }

  return err;
}

VLIB_CLI_COMMAND (show_sfdp_tcp_check_sessions_command, static) = {
  .path = "show sfdp tcp session-table",
  .short_help = "show sfdp tcp session-table [tenant <tenant-id>]",
  .function = sfdp_tcp_check_show_sessions_command_fn,
};