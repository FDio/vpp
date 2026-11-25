/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <ssh/ssh.h>
#include <vppinfra/format_table.h>

static const cli_column_t ssh_host_columns[] = {
  { "address", "Address" },
  { "port", "Port" },
  { "file", "File" },
  { "public", "Public" },
  { "fingerprint", "Fingerprint" },
  {},
};

static const cli_column_t ssh_users_columns[] = {
  { "user", "User" },
  { "type", "Type" },
  { "fingerprint", "Fingerprint" },
  {},
};

static const cli_column_t ssh_sessions_columns[] = {
  { "id", "ID" },	{ "user", "User" }, { "peer", "Peer" },
  { "state", "State" }, { "age", "Age" },   {},
};

static const char *
ssh_session_state (ssh_session_t *s)
{
  if (s->shell)
    return "shell";

  if (s->authenticated)
    return "auth";

  return "login";
}

static void
ssh_table_align_left (table_t *t, int row, int first_col, int n_cols)
{
  for (int c = first_col; c < n_cols; c++)
    table_set_cell_align (t, row, c, TTAA_LEFT);
}

static clib_error_t *
ssh_host_json (cli_ctx_t *ctx)
{
  ssh_main_t *sm = &ssh_main;
  clib_json_text_t j;

  clib_json_init (&j);
  clib_json_add_object (&j, 0);
  clib_json_add_string (&j, "address", "%v", sm->address);
  clib_json_add_number (&j, "port", sm->port);
  clib_json_add_string (&j, "file", "%v", sm->host_key_file);
  clib_json_add_string (&j, "public", "%v", sm->host_key_public);
  clib_json_add_string (&j, "fingerprint", "%v", sm->host_key_fingerprint);
  clib_json_parent (&j);

  return cli_emit_object (ctx, &j, ssh_host_columns);
}

static void
ssh_host_text (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ssh_main_t *sm = &ssh_main;
  table_t t = { .no_ansi = ctx->plain_text_only };

  table_add_hdr_col (&t, 0);
  table_format_cell (&t, 0, -1, "file");
  table_format_cell (&t, 0, 0, "%v", sm->host_key_file);
  table_format_cell (&t, 1, -1, "public");
  table_format_cell (&t, 1, 0, "%v", sm->host_key_public);
  table_format_cell (&t, 2, -1, "fingerprint");
  table_format_cell (&t, 2, 0, "%v", sm->host_key_fingerprint);
  for (int row = 0; row < 3; row++)
    ssh_table_align_left (&t, row, -1, 1);

  vlib_cli_output (vm, "listening on %v port %u\n", sm->address, sm->port);
  vlib_cli_output (vm, "Host key:\n  %U", format_table, &t);
  table_free (&t);
}

static clib_error_t *
ssh_users_json (cli_ctx_t *ctx)
{
  ssh_main_t *sm = &ssh_main;
  clib_json_text_t j;
  ssh_user_t *u;
  ssh_key *k;

  clib_json_init (&j);
  clib_json_add_array (&j, 0);
  vec_foreach (u, sm->users)
    vec_foreach (k, u->keys)
      {
	u8 *fp = ssh_key_format_fingerprint (*k);

	clib_json_add_object (&j, 0);
	clib_json_add_string (&j, "user", "%s", u->name);
	clib_json_add_string (&j, "type", "%s", ssh_key_type_to_char (ssh_key_type (*k)));
	clib_json_add_string (&j, "fingerprint", "%v", fp);
	clib_json_parent (&j);
	vec_free (fp);
      }
  clib_json_parent (&j);

  return cli_emit_table (ctx, &j, ssh_users_columns);
}

static void
ssh_users_text (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ssh_main_t *sm = &ssh_main;
  table_t t = { .no_ansi = ctx->plain_text_only };
  ssh_user_t *u;
  ssh_key *k;
  int row = 0;

  table_add_hdr_col (&t, 0);
  vec_foreach (u, sm->users)
    vec_foreach (k, u->keys)
      {
	u8 *fp = ssh_key_format_fingerprint (*k);

	if (k == u->keys)
	  table_format_cell (&t, row, -1, "%s", u->name);
	table_format_cell (&t, row, 0, "%s", ssh_key_type_to_char (ssh_key_type (*k)));
	table_format_cell (&t, row, 1, "%v", fp);
	ssh_table_align_left (&t, row++, -1, 2);
	vec_free (fp);
      }

  vlib_cli_output (vm, "Users:\n  %U", format_table, &t);
  table_free (&t);
}

static clib_error_t *
ssh_sessions_json (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ssh_main_t *sm = &ssh_main;
  f64 now = vlib_time_now (vm);
  clib_json_text_t j;
  ssh_session_t *s;

  clib_json_init (&j);
  clib_json_add_array (&j, 0);
  pool_foreach (s, sm->sessions)
    {
      u32 age = now - s->start_time;

      clib_json_add_object (&j, 0);
      clib_json_add_number (&j, "id", s->index);
      clib_json_add_string (&j, "user", "%s", s->user ? s->user->name : "");
      clib_json_add_string (&j, "peer", "%s", s->peer);
      clib_json_add_string (&j, "state", "%s", ssh_session_state (s));
      clib_json_add_number (&j, "age", age);
      clib_json_parent (&j);
    }
  clib_json_parent (&j);

  return cli_emit_table (ctx, &j, ssh_sessions_columns);
}

static void
ssh_sessions_text (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ssh_main_t *sm = &ssh_main;
  table_t t = { .no_ansi = ctx->plain_text_only };
  f64 now = vlib_time_now (vm);
  ssh_session_t *s;
  int row = 0;

  if (pool_elts (sm->sessions) == 0)
    {
      vlib_cli_output (vm, "no sessions");
      return;
    }

  table_add_hdr_row (&t, 5, "ID", "User", "Peer", "State", "Age");
  pool_foreach (s, sm->sessions)
    {
      u32 age = now - s->start_time;

      table_format_cell (&t, row, 0, "%u", s->index);
      table_format_cell (&t, row, 1, "%s", s->user ? s->user->name : "-");
      table_format_cell (&t, row, 2, "%s", s->peer);
      table_format_cell (&t, row, 3, "%s", ssh_session_state (s));
      table_format_cell (&t, row, 4, "%us", age);
      ssh_table_align_left (&t, row++, 0, 5);
    }

  vlib_cli_output (vm, "Sessions:\n  %U", format_table, &t);
  table_free (&t);
}

static clib_error_t *
show_ssh_server_host_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  if (ssh_main.bind == 0)
    return clib_error_return (0, "ssh is not configured");

  if (cli_is_structured (ctx))
    return ssh_host_json (ctx);

  ssh_host_text (vm, ctx);

  return 0;
}

VLIB_CLI_COMMAND (show_ssh_server_host_command, static) = {
  .path = "show ssh-server host",
  .short_help = "Show the address, the port and the host key of the ssh server",
  .handler = show_ssh_server_host_command_fn,
  .is_structured = 1,
};

static clib_error_t *
show_ssh_server_users_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  if (ssh_main.bind == 0)
    return clib_error_return (0, "ssh is not configured");

  if (cli_is_structured (ctx))
    return ssh_users_json (ctx);

  ssh_users_text (vm, ctx);

  return 0;
}

VLIB_CLI_COMMAND (show_ssh_server_users_command, static) = {
  .path = "show ssh-server users",
  .short_help = "Show the users of the ssh server and the fingerprints of their keys",
  .handler = show_ssh_server_users_command_fn,
  .is_structured = 1,
};

static clib_error_t *
show_ssh_server_sessions_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  if (ssh_main.bind == 0)
    return clib_error_return (0, "ssh is not configured");

  if (cli_is_structured (ctx))
    return ssh_sessions_json (vm, ctx);

  ssh_sessions_text (vm, ctx);

  return 0;
}

VLIB_CLI_COMMAND (show_ssh_server_sessions_command, static) = {
  .path = "show ssh-server sessions",
  .short_help = "Show the sessions of the ssh server",
  .handler = show_ssh_server_sessions_command_fn,
  .is_structured = 1,
};

static clib_error_t *
show_ssh_server_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  if (ssh_main.bind == 0)
    {
      vlib_cli_output (vm, "ssh is not configured");
      return 0;
    }

  ssh_host_text (vm, ctx);
  vlib_cli_output (vm, "");
  ssh_users_text (vm, ctx);
  vlib_cli_output (vm, "");
  ssh_sessions_text (vm, ctx);

  return 0;
}

VLIB_CLI_COMMAND (show_ssh_server_command, static) = {
  .path = "show ssh-server",
  .short_help = "Show the ssh server, see also: show ssh-server host|users|sessions",
  .handler = show_ssh_server_command_fn,
};
