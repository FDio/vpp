/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/stats/stats.h>
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/session_stats/session_stats.h>

extern void sfdp_session_stats_periodic_export_enable (vlib_main_t *vm, f64 interval);
extern void sfdp_session_stats_periodic_export_disable (vlib_main_t *vm);
extern void sfdp_session_stats_export_now (vlib_main_t *vm);

static clib_error_t *
sfdp_session_stats_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_session_t *session;
  uword session_index;
  u64 session_id_filter = 0;
  i32 tenant_filter = -1;
  u32 count = 0;
  u32 max_entries = 100;
  u8 verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "session 0x%X", sizeof (session_id_filter), &session_id_filter))
	;
      else if (unformat (input, "tenant %d", &tenant_filter))
	;
      else if (unformat (input, "max %u", &max_entries))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  vlib_cli_output (vm, "SFDP Session Statistics:");
  vlib_cli_output (vm, "  Ring buffer: %s (size: %u)",
		   ssm->ring_buffer_enabled ? "enabled" : "disabled", ssm->ring_buffer_size);
  vlib_cli_output (vm, "  Periodic export: %s (interval: %.1f sec)",
		   ssm->periodic_export_enabled ? "enabled" : "disabled", ssm->export_interval);
  vlib_cli_output (vm, "  Total exports: %lu", ssm->total_exports);
  vlib_cli_output (vm, "");

  vlib_cli_output (vm, "%-18s %-6s %-10s %-12s %-12s %-12s %-12s", "Session", "Proto", "Tenant",
		   "Pkts(fwd)", "Pkts(rev)", "Bytes(fwd)", "Bytes(rev)");
  vlib_cli_output (vm, "------------------ ------ ---------- ------------ "
		       "------------ ------------ ------------");

  sfdp_foreach_session (sfdp, session_index, session)
  {
    sfdp_session_stats_entry_t *stats;

    /* Apply filters */
    if (session_id_filter != 0 && session->session_id != session_id_filter)
      continue;
    if (tenant_filter >= 0 && session->tenant_idx != (u32) tenant_filter)
      continue;

    /* Check bounds */
    if (session_index >= vec_len (ssm->stats))
      continue;

    stats = vec_elt_at_index (ssm->stats, session_index);

    /* Skip sessions with no traffic unless verbose */
    if (!verbose && stats->packets[SFDP_FLOW_FORWARD] == 0 &&
	stats->packets[SFDP_FLOW_REVERSE] == 0)
      continue;

    u64 sid_net = clib_host_to_net_u64 (session->session_id);
    vlib_cli_output (vm, "0x%U %-6u %-10d %-12lu %-12lu %-12lu %-12lu", format_hex_bytes, &sid_net,
		     sizeof (sid_net), session->proto, session->tenant_idx,
		     stats->packets[SFDP_FLOW_FORWARD], stats->packets[SFDP_FLOW_REVERSE],
		     stats->bytes[SFDP_FLOW_FORWARD], stats->bytes[SFDP_FLOW_REVERSE]);

    if (verbose && (stats->first_seen > 0 || stats->last_seen > 0))
      {
	vlib_cli_output (vm, "           First seen: %.6f, Last seen: %.6f", stats->first_seen,
			 stats->last_seen);
      }

    count++;
    if (count >= max_entries)
      {
	vlib_cli_output (vm, "... (truncated at %u entries)", max_entries);
	break;
      }
  }

  if (count == 0)
    vlib_cli_output (vm, "  (no sessions with traffic)");

  return 0;
}

VLIB_CLI_COMMAND (sfdp_session_stats_show_command, static) = {
  .path = "show sfdp session stats",
  .short_help = "show sfdp session stats [session <hex-id>] [tenant <idx>] "
		"[max <n>] [verbose]",
  .function = sfdp_session_stats_show_command_fn,
};

static clib_error_t *
sfdp_session_stats_ring_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  u8 enable = 1;
  u32 ring_size = SFDP_SESSION_STATS_DEFAULT_RING_SIZE;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "size %u", &ring_size))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (enable)
    {
      rv = sfdp_session_stats_ring_init (vm, ring_size);
      if (rv < 0)
	return clib_error_return (0, "failed to initialize ring buffer");
      vlib_cli_output (vm, "Ring buffer enabled (size: %u)", ring_size);
    }
  else
    {
      if (ssm->ring_buffer_enabled)
	{
	  vlib_stats_remove_entry (ssm->ring_buffer_index);
	  ssm->ring_buffer_index = CLIB_U32_MAX;
	  ssm->ring_buffer_size = 0;
	  ssm->ring_buffer_enabled = 0;
	}
      vlib_cli_output (vm, "Ring buffer disabled");
    }

  return 0;
}

VLIB_CLI_COMMAND (sfdp_session_stats_ring_command, static) = {
  .path = "sfdp session stats ring",
  .short_help = "sfdp session stats ring <enable|disable> [size <n>]",
  .function = sfdp_session_stats_ring_command_fn,
};

static clib_error_t *
sfdp_session_stats_periodic_command_fn (vlib_main_t *vm, unformat_input_t *input,
					vlib_cli_command_t *cmd)
{
  u8 enable = 1;
  f64 interval = 30.0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "interval %f", &interval))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (enable)
    {
      sfdp_session_stats_periodic_export_enable (vm, interval);
      vlib_cli_output (vm, "Periodic export enabled (interval: %.1f sec)", interval);
    }
  else
    {
      sfdp_session_stats_periodic_export_disable (vm);
      vlib_cli_output (vm, "Periodic export disabled");
    }

  return 0;
}

VLIB_CLI_COMMAND (sfdp_session_stats_periodic_command, static) = {
  .path = "sfdp session stats periodic",
  .short_help = "sfdp session stats periodic <enable|disable> "
		"[interval <seconds>]",
  .function = sfdp_session_stats_periodic_command_fn,
};

static clib_error_t *
sfdp_session_stats_export_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;

  if (!ssm->ring_buffer_enabled)
    return clib_error_return (0, "ring buffer not enabled");

  sfdp_session_stats_export_now (vm);
  vlib_cli_output (vm, "Export triggered");

  return 0;
}

VLIB_CLI_COMMAND (sfdp_session_stats_export_command, static) = {
  .path = "sfdp session stats export",
  .short_help = "sfdp session stats export",
  .function = sfdp_session_stats_export_command_fn,
};

static clib_error_t *
sfdp_session_stats_clear_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  u64 session_id = 0;
  u32 cleared = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "session 0x%X", sizeof (session_id), &session_id))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (session_id == 0)
    {
      /* Clear all */
      for (u32 i = 0; i < vec_len (ssm->stats); i++)
	{
	  sfdp_session_stats_entry_t *s = vec_elt_at_index (ssm->stats, i);
	  clib_memset (s, 0, sizeof (*s));
	  cleared++;
	}
      vlib_cli_output (vm, "Cleared %u session stats", cleared);
    }
  else
    {
      /* Clear specific session */
      sfdp_main_t *sfdp = &sfdp_main;
      sfdp_session_t *session;
      uword session_index;

      sfdp_foreach_session (sfdp, session_index, session)
      {
	if (session->session_id == session_id && session_index < vec_len (ssm->stats))
	  {
	    sfdp_session_stats_entry_t *s = vec_elt_at_index (ssm->stats, session_index);
	    clib_memset (s, 0, sizeof (*s));
	    vlib_cli_output (vm, "Cleared stats for session 0x%llx", session_id);
	    return 0;
	  }
      }
      return clib_error_return (0, "session 0x%llx not found", session_id);
    }

  return 0;
}

VLIB_CLI_COMMAND (sfdp_session_stats_clear_command, static) = {
  .path = "clear sfdp session stats",
  .short_help = "clear sfdp session stats [session <hex-id>]",
  .function = sfdp_session_stats_clear_command_fn,
};

static clib_error_t *
sfdp_session_stats_custom_data_command_fn (vlib_main_t *vm, unformat_input_t *input,
					   vlib_cli_command_t *cmd)
{
  u32 tenant_id = ~0;
  u64 value = 0;
  u8 is_clear = 0;
  u8 has_value = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tenant %u", &tenant_id))
	;
      else if (unformat (input, "value %llu", &value))
	has_value = 1;
      else if (unformat (input, "clear"))
	is_clear = 1;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (is_clear)
    {
      int rv = sfdp_session_stats_clear_custom_api_data (tenant_id);
      if (rv < 0)
	return clib_error_return (0, "failed to clear custom data");
      if (tenant_id == SFDP_SESSION_STATS_ALL_TENANTS)
	vlib_cli_output (vm, "Cleared custom data for all tenants");
      else
	vlib_cli_output (vm, "Cleared custom data for tenant %u", tenant_id);
      return 0;
    }

  if (tenant_id == (u32) ~0)
    return clib_error_return (0, "please specify tenant <id>");
  if (!has_value)
    return clib_error_return (0, "please specify value <n> or clear");

  int rv = sfdp_session_stats_set_custom_api_data (tenant_id, value);
  if (rv < 0)
    return clib_error_return (0, "failed to set custom data");

  vlib_cli_output (vm, "Set custom data for tenant %u to %llu", tenant_id, value);
  return 0;
}

VLIB_CLI_COMMAND (sfdp_session_stats_custom_data_command, static) = {
  .path = "sfdp session stats custom-data",
  .short_help = "sfdp session stats custom-data [tenant <id>] [value <n>] [clear]",
  .function = sfdp_session_stats_custom_data_command_fn,
};

static clib_error_t *
sfdp_session_stats_custom_data_name_command_fn (vlib_main_t *vm, unformat_input_t *input,
						vlib_cli_command_t *cmd)
{
  /* TODO - implement safer handling of custom data label name */
  u8 *name = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &name))
	;
      else
	{
	  vec_free (name);
	  return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
	}
    }

  if (!name || vec_len (name) == 0)
    return clib_error_return (0, "please specify name <string>");

  int rv = sfdp_session_stats_set_custom_api_data_name (name, vec_len (name));

  if (rv == 0)
    vlib_cli_output (vm, "Custom data field name set to %s", name);

  vec_free (name);

  if (rv == -1)
    return clib_error_return (0, "name too long (max %u characters)",
			      SFDP_SESSION_STATS_CUSTOM_API_DATA_NAME_MAX_LEN);
  if (rv == -2)
    return clib_error_return (0, "cannot change name after ring buffer is enabled");
  if (rv < 0)
    return clib_error_return (0, "failed to set custom data name");

  return 0;
}

VLIB_CLI_COMMAND (sfdp_session_stats_custom_data_name_command, static) = {
  .path = "sfdp session stats custom-data-name",
  .short_help = "sfdp session stats custom-data-name name <string>",
  .function = sfdp_session_stats_custom_data_name_command_fn,
};
