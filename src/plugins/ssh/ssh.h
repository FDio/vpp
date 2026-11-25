/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vlib/vlib.h>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

typedef struct
{
  char *name;
  ssh_key *keys;
} ssh_user_t;

typedef struct
{
  ssh_session session;
  ssh_event event;
  ssh_channel channel;
  struct ssh_server_callbacks_struct server_cb;
  struct ssh_channel_callbacks_struct channel_cb;
  ssh_user_t *user;
  u8 *name;
  u8 *peer;
  u8 *to_ssh;
  u8 *to_cli;
  f64 start_time;
  f64 close_time;
  u32 index;
  u32 ssh_file_index;
  u32 pump_file_index;
  u32 cli_session;
  int pump_fd;
  u16 width;
  u16 height;
  u8 ansi;
  u8 pty;
  u8 kex_done;
  u8 authenticated;
  u8 shell;
  u8 closing;
  u8 n_auth_tries;
} ssh_session_t;

typedef struct
{
  ssh_user_t *users;
  ssh_session_t *sessions;
  ssh_bind bind;
  u32 process_node_index;
  u8 *address;
  u32 port;
  u8 *host_key_file;
  u8 *host_key_public;
  u8 *host_key_fingerprint;
} ssh_main_t;

extern ssh_main_t ssh_main;
extern vlib_log_class_registration_t ssh_plugin_log;

#define log_debug(f, ...) vlib_log_debug (ssh_plugin_log.class, f, ##__VA_ARGS__)
#define log_info(f, ...)  vlib_log_info (ssh_plugin_log.class, f, ##__VA_ARGS__)
#define log_warn(f, ...)  vlib_log_warn (ssh_plugin_log.class, f, ##__VA_ARGS__)
#define log_err(f, ...)	  vlib_log_err (ssh_plugin_log.class, f, ##__VA_ARGS__)

/* The public key as in an authorized_keys file, without the comment, and its SHA256 fingerprint */
u8 *ssh_key_format_public (ssh_key pubkey);
u8 *ssh_key_format_fingerprint (ssh_key pubkey);

/* Adds a public key of a user, the user is created with the first one */
clib_error_t *ssh_user_add_key (char *name, char *type, char *b64);

/* Starts to listen, address is 0 for localhost, host_key is the file with the private key */
clib_error_t *ssh_listen (char *address, u32 port, char *host_key);
