/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/service.h>

/*
 * add CLI:
 * sfdp tenant <add/del> <tenant-id>
 *
 * it creates entry in the tenant pool. Default service chains in both
 * directions is "sfdp-drop"
 *
 *
 * add CLI:
 * set sfdp services tenant <tenant-id> (SERVICE_NAME)+ <forward|reverse>
 *
 * configure tenant with a service chain for a given direction (forward or
 * reverse)
 *
 */

static clib_error_t *
sfdp_tenant_add_del_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  sfdp_main_t *sfdp = &sfdp_main;
  u8 is_del = 0;
  sfdp_tenant_id_t tenant_id = ~0;
  u32 context_id = ~0;
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add %d", &tenant_id))
	is_del = 0;
      else if (unformat (line_input, "del %d", &tenant_id))
	is_del = 1;
      else if (unformat (line_input, "context %d", &context_id))
	;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  if (tenant_id == ~0)
    {
      err = clib_error_return (0, "missing tenant id");
      goto done;
    }
  if (context_id == ~0)
    context_id = tenant_id;
  err = sfdp_tenant_add_del (sfdp, tenant_id, context_id, is_del);
done:
  unformat_free (line_input);
  return err;
}

static clib_error_t *
sfdp_set_services_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tenant_id_t tenant_id = ~0;
  sfdp_bitmap_t bitmap = 0;
  u8 direction = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &tenant_id))
	;
      else if (unformat_user (line_input, unformat_sfdp_service_bitmap,
			      &bitmap))
	;
      else if (unformat (line_input, "forward"))
	direction = SFDP_FLOW_FORWARD;
      else if (unformat (line_input, "reverse"))
	direction = SFDP_FLOW_REVERSE;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  if (tenant_id == ~0)
    {
      err = clib_error_return (0, "missing tenant id");
      goto done;
    }
  if (direction == (u8) ~0)
    {
      err = clib_error_return (0, "missing direction");
      goto done;
    }
  sfdp_set_services (sfdp, tenant_id, bitmap, direction);
done:
  unformat_free (line_input);
  return err;
}

static_always_inline u32
table_format_insert_sfdp_service (table_t *t,
				  sfdp_service_registration_t *service, u32 n)
{
  table_format_cell (t, n, 0, "%s", service->node_name);
  table_set_cell_align (t, n, 0, TTAA_LEFT);
  table_format_cell (t, n, 1, "%u", *(service->index_in_bitmap));
  table_set_cell_align (t, n, 1, TTAA_CENTER);
  table_format_cell (t, n, 2, "%s", (service->is_terminal) ? "T" : "");
  table_set_cell_align (t, n, 1, TTAA_CENTER);
  return n + 1;
}

static clib_error_t *
sfdp_show_services_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  sfdp_service_main_t *vsm = &sfdp_service_main;
  sfdp_service_registration_t ***services_for_scope;

  vec_foreach (services_for_scope, vsm->services_per_scope_index)
    {
      table_t service_table_ = {}, *service_table = &service_table_;
      u32 scope_index = services_for_scope - vsm->services_per_scope_index;
      sfdp_service_registration_t **service;
      table_format_title (service_table,
			  "Registered SFDP services for scope '%s'",
			  vsm->scope_names[scope_index]);
      table_add_header_col (service_table, 3, "Node name", "Index",
			    "Terminal");

      u32 n = 0;
      vec_foreach (service, *services_for_scope)
	{
	  n = table_format_insert_sfdp_service (service_table, *service, n);
	}
      vlib_cli_output (vm, "%U", format_table, service_table);
      vlib_cli_output (vm, "%u / 64 registered services", n);
      table_free (service_table);
    }
  return 0;
}

static clib_error_t *
sfdp_set_timeout_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tenant_id_t tenant_id = ~0;
  u32 timeout_idx = ~0;
  u32 timeout_val = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &tenant_id))
	;
      else if (unformat (line_input, "%U %d", unformat_sfdp_timeout_name,
			 &timeout_idx, &timeout_val))
	;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  if (tenant_id == ~0)
    {
      err = clib_error_return (0, "missing tenant id");
      goto done;
    }
  if (timeout_idx == ~0)
    {
      err = clib_error_return (0, "missing timeout");
      goto done;
    }

  err = sfdp_set_timeout (sfdp, tenant_id, timeout_idx, timeout_val);
done:
  unformat_free (line_input);
  return err;
}

static clib_error_t *
sfdp_set_sp_node_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tenant_id_t tenant_id = ~0;
  u32 sp_idx = ~0;
  u32 node_index = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &tenant_id))
	;
      else if (unformat (line_input, "node %U", unformat_vlib_node, vm,
			 &node_index))
	;
      else if (unformat (line_input, "%U", unformat_sfdp_sp_node, &sp_idx))
	;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  if (tenant_id == ~0)
    {
      err = clib_error_return (0, "missing tenant id");
      goto done;
    }
  if (node_index == ~0)
    {
      err = clib_error_return (0, "missing node");
      goto done;
    }
  if (sp_idx == ~0)
    {
      err = clib_error_return (0, "missing slow-path");
      goto done;
    }

  err = sfdp_set_sp_node (sfdp, tenant_id, sp_idx, node_index);
done:
  unformat_free (line_input);
  return err;
}

static clib_error_t *
sfdp_set_icmp_error_node_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tenant_id_t tenant_id = ~0;
  u32 node_index = ~0;
  u8 ip46 = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %d", &tenant_id))
	;
      else if (unformat (line_input, "node %U", unformat_vlib_node, vm,
			 &node_index))
	;
      else if (unformat (line_input, "ip4"))
	ip46 = 1;
      else if (unformat (line_input, "ip6"))
	ip46 = 2;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  if (tenant_id == ~0)
    {
      err = clib_error_return (0, "missing tenant id");
      goto done;
    }
  if (node_index == ~0)
    {
      err = clib_error_return (0, "missing node");
      goto done;
    }
  if (ip46 == 0)
    {
      err = clib_error_return (0, "missing adress family");
      goto done;
    }

  err = sfdp_set_icmp_error_node (sfdp, tenant_id, ip46 - 1, node_index);

done:
  unformat_free (line_input);
  return err;
}

static clib_error_t *
sfdp_show_sessions_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_session_t *session;
  u32 session_index;
  sfdp_tenant_t *tenant;
  sfdp_tenant_id_t tenant_id = ~0;
  u32 max_output_value = 20;
  bool is_show_all = false;
  f64 now = vlib_time_now (vm);

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "tenant %u", &tenant_id))
	    ;
	  else if (unformat (line_input, "max %u", &max_output_value))
	    ;
	  else if (unformat (line_input, "unsafe-show-all"))
	    is_show_all = true;
	  else
	    {
	      err = unformat_parse_error (line_input);
	      break;
	    }
	}
      unformat_free (line_input);
    }

  if (!is_show_all && max_output_value == 0)
    err = clib_error_return (0, "Please specify a positive integer for max");

  if (!err)
    {
      table_t session_table_ = {}, *session_table = &session_table_;
      u32 n = 0;
      sfdp_table_format_add_header_col (session_table);
      sfdp_foreach_session (sfdp, session_index, session)
      {
	tenant = sfdp_tenant_at_index (sfdp, session->tenant_idx);
	if (tenant_id != ~0 && tenant_id != tenant->tenant_id)
	  continue;
	n = sfdp_table_format_insert_session (session_table, n, session_index,
					      session, tenant->tenant_id, now);

	if (!is_show_all && n >= max_output_value)
	  break;
      }
      vlib_cli_output (vm, "%U", format_table, session_table);
      if (n < pool_elts (sfdp->sessions))
	{
	  vlib_cli_output (vm, "Only %u sessions displayed, %u ignored", n,
			   pool_elts (sfdp->sessions) - n);
	}

      table_free (session_table);
    }

  return err;
}

static clib_error_t *
sfdp_show_session_detail_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  sfdp_main_t *sfdp = &sfdp_main;
  clib_bihash_kv_8_8_t kv = { 0 };
  f64 now = vlib_time_now (vm);
  u32 session_index;
  u64 session_id;
  if (unformat_user (input, unformat_line_input, line_input))
    {
      if (unformat_check_input (line_input) == UNFORMAT_END_OF_INPUT ||
	  unformat (line_input, "0x%X", sizeof (session_id), &session_id) == 0)
	err = unformat_parse_error (line_input);
      unformat_free (line_input);
    }
  else
    err = clib_error_return (0, "No session id provided");

  if (!err)
    {
      kv.key = session_id;
      if (!clib_bihash_search_inline_8_8 (&sfdp->session_index_by_id, &kv))
	{
	  session_index = sfdp_session_index_from_lookup (kv.value);
	  vlib_cli_output (vm, "%U", format_sfdp_session_detail, session_index,
			   now);
	}
      else
	{
	  err =
	    clib_error_return (0, "Session id 0x%llx not found", session_id);
	}
    }
  return err;
}

static clib_error_t *
sfdp_kill_session_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  sfdp_main_t *sfdp = &sfdp_main;
  u32 session_index = ~0;
  bool is_all = false;
  bool has_index = false;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "all"))
	is_all = true;
      else if (unformat (line_input, "index %u", &session_index) ||
	       unformat (line_input, "0x%x", &session_index) ||
	       unformat (line_input, "%u", &session_index))
	has_index = true;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (is_all && has_index)
    {
      err = clib_error_return (0, "Use either a session index or all");
      goto done;
    }
  if (!is_all && !has_index)
    {
      err = clib_error_return (0, "Missing session index or all");
      goto done;
    }

  err = sfdp_kill_session (sfdp, session_index, is_all);

done:
  unformat_free (line_input);
  return err;
}

static clib_error_t *
sfdp_show_tenant_detail_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tenant_t *tenant;
  sfdp_tenant_id_t tenant_id = ~0;
  sfdp_tenant_index_t tenant_idx;
  u8 detail = 0;
  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "%d detail", &tenant_id))
	    detail = 1;
	  else if (unformat (line_input, "%d", &tenant_id))
	    ;
	  else
	    {
	      err = unformat_parse_error (line_input);
	      break;
	    }
	}
      unformat_free (line_input);
    }
  if (err)
    return err;

  pool_foreach_index (tenant_idx, sfdp->tenants)
    {
      tenant = sfdp_tenant_at_index (sfdp, tenant_idx);

      if (tenant_id != ~0 && tenant->tenant_id != tenant_id)
	continue;

      vlib_cli_output (vm, "Tenant %d", tenant->tenant_id);
      vlib_cli_output (vm, "  %U", format_sfdp_tenant, sfdp, tenant_idx,
		       tenant);
      if (detail)
	vlib_cli_output (vm, "  %U", format_sfdp_tenant_extra, sfdp,
			 tenant_idx, tenant);
    }

  return err;
}

static clib_error_t *
sfdp_show_sfdp_status_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  sfdp_main_t *sfdp = &sfdp_main;
  u64 max_sessions = sfdp_num_sessions ();
  u64 free_sessions = sfdp_remaining_sessions_in_pool ();
  u64 active_sessions = sfdp_real_active_sessions ();
  f64 active_percent = (((f64) (100)) * active_sessions) / max_sessions;

  vlib_cli_output (vm, "sfdp status:\n");
  vlib_cli_output (vm, "  max sessions: %lu\n", max_sessions);
  vlib_cli_output (vm, "  active sessions: %lu (%.2f%%)\n", active_sessions,
		   active_percent);
  vlib_cli_output (vm, "  free sessions: %lu\n", free_sessions);
  vlib_cli_output (vm, "  eviction sessions margin: %u\n",
		   sfdp->eviction_sessions_margin);
  vlib_cli_output (vm, "  max sessions cache per thread: %lu\n",
		   sfdp_num_sessions_cache_per_thread ());
  vlib_cli_output (vm, "  max tenants: %llu\n", 1ULL << sfdp->log2_tenants);

  // iterate over all threads
  sfdp_per_thread_data_t *ptd;
  vec_foreach (ptd, sfdp->per_thread_data)
    {
      u32 index = ptd - sfdp->per_thread_data;
      vlib_cli_output (vm, "    [%u] active sessions: %lu\n", index,
		       ptd->n_sessions);
      vlib_cli_output (vm, "    [%u] cached sessions: %lu\n", index,
		       vec_len (ptd->session_freelist));
    }

  return NULL;
}

VLIB_CLI_COMMAND (sfdp_tenant_add_del_command, static) = {
  .path = "sfdp tenant",
  .short_help = "sfdp tenant <add|del> <tenant-id> context <context-id>",
  .function = sfdp_tenant_add_del_command_fn,
};

VLIB_CLI_COMMAND (sfdp_set_services_command, static) = {
  .path = "set sfdp services",
  .short_help = "set sfdp services tenant <tenant-id>"
		" [SERVICE_NAME]+ <forward|reverse>",
  .function = sfdp_set_services_command_fn,
};

VLIB_CLI_COMMAND (sfdp_show_services_command, static) = {
  .path = "show sfdp services",
  .short_help = "show sfdp services",
  .function = sfdp_show_services_fn,
};

VLIB_CLI_COMMAND (show_sfdp_sessions_command, static) = {
  .path = "show sfdp session-table",
  .short_help = "show sfdp session-table [tenant <tenant-id>] "
		"[max <max_value>] [unsafe-show-all]",
  .function = sfdp_show_sessions_command_fn,
};

VLIB_CLI_COMMAND (show_sfdp_detail_command, static) = {
  .path = "show sfdp session-detail",
  .short_help = "show sfdp session-detail 0x<session-id>",
  .function = sfdp_show_session_detail_command_fn,
};

VLIB_CLI_COMMAND (sfdp_kill_session_command, static) = {
  .path = "kill sfdp session",
  .short_help = "kill sfdp session index <index>|all",
  .function = sfdp_kill_session_command_fn,
};

VLIB_CLI_COMMAND (show_sfdp_tenant, static) = {
  .path = "show sfdp tenant",
  .short_help = "show sfdp tenant [<tenant-id> [detail]]",
  .function = sfdp_show_tenant_detail_command_fn,
};

VLIB_CLI_COMMAND (sfdp_show_sfdp_status_command, static) = {
  .path = "show sfdp status",
  .short_help = "show sfdp status",
  .function = sfdp_show_sfdp_status_command_fn,
};

VLIB_CLI_COMMAND (sfdp_set_timeout_command, static) = {
  .path = "set sfdp timeout",
  .short_help = "set sfdp timeout tenant <tenant-id>"
		" <timeout-name> <timeout-value>",
  .function = sfdp_set_timeout_command_fn
};

VLIB_CLI_COMMAND (sfdp_set_sp_node_command, static) = {
  .path = "set sfdp sp-node",
  .short_help = "set sfdp sp-node tenant <tenant-id>"
		" <sp-name> node <node-name>",
  .function = sfdp_set_sp_node_command_fn
};

VLIB_CLI_COMMAND (sfdp_set_icmp_error_node_command, static) = {
  .path = "set sfdp icmp-error-node",
  .short_help = "set sfdp icmp-error-node tenant <tenant-id>"
		" <ip4|ip6> node <node-name>",
  .function = sfdp_set_icmp_error_node_command_fn
};
