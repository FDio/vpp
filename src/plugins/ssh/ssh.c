/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <ssh/ssh.h>
#include <vlib/file.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <sys/socket.h>
#include <sys/stat.h>

#define SSH_MAX_SESSIONS       16
#define SSH_MAX_AUTH_TRIES     5
#define SSH_AUTH_TIMEOUT       60.0
#define SSH_CLOSE_TIMEOUT      5.0
#define SSH_MAX_PENDING_TO_SSH (16 << 20)
#define SSH_MAX_PENDING_TO_CLI (1 << 20)

VLIB_REGISTER_LOG_CLASS (ssh_plugin_log) = {
  .class_name = "ssh",
};

ssh_main_t ssh_main;

static ssh_user_t *
ssh_find_user (const char *name)
{
  ssh_main_t *sm = &ssh_main;
  ssh_user_t *u;

  vec_foreach (u, sm->users)
    if (strcmp (u->name, name) == 0)
      return u;

  return 0;
}

static void
ssh_session_free (ssh_session_t *s)
{
  ssh_main_t *sm = &ssh_main;
  clib_file_main_t *fm = &file_main;

  if (s->pump_file_index != ~0)
    clib_file_del_by_index (fm, s->pump_file_index);

  if (s->pump_fd >= 0)
    close (s->pump_fd);

  if (s->ssh_file_index != ~0)
    clib_file_del_by_index (fm, s->ssh_file_index);

  if (s->event)
    {
      ssh_event_remove_session (s->event, s->session);
      ssh_event_free (s->event);
    }

  ssh_disconnect (s->session);
  ssh_free (s->session);

  log_info ("session from %s closed", s->peer);

  vec_free (s->to_ssh);
  vec_free (s->to_cli);
  vec_free (s->name);
  vec_free (s->peer);
  pool_put (sm->sessions, s);
}

/* libssh sends what it has buffered when the socket is writable */
static void
ssh_session_update_poll (ssh_session_t *s)
{
  clib_file_main_t *fm = &file_main;
  int pending = ssh_get_poll_flags (s->session) & SSH_WRITE_PENDING;

  clib_file_set_data_available_to_write (fm, s->ssh_file_index, pending != 0);
}

static void
ssh_session_run (ssh_session_t *s)
{
  int rv = SSH_OK;

  if (!s->kex_done)
    {
      rv = ssh_handle_key_exchange (s->session);
      if (rv == SSH_AGAIN)
	{
	  ssh_session_update_poll (s);
	  return;
	}

      if (rv != SSH_OK)
	{
	  log_warn ("key exchange with %s failed: %s", s->peer, ssh_get_error (s->session));
	  ssh_session_free (s);
	  return;
	}

      s->event = ssh_event_new ();
      if (s->event == 0 || ssh_event_add_session (s->event, s->session) != SSH_OK)
	{
	  log_err ("unable to poll the session from %s", s->peer);
	  ssh_session_free (s);
	  return;
	}

      log_debug ("key exchange with %s done", s->peer);
      s->kex_done = 1;
    }

  rv = ssh_event_dopoll (s->event, 0);

  if (rv == SSH_ERROR || s->closing ||
      (ssh_get_status (s->session) & (SSH_CLOSED | SSH_CLOSED_ERROR)))
    {
      ssh_session_free (s);
      return;
    }

  ssh_session_update_poll (s);
}

static void
ssh_flush_to_ssh (ssh_session_t *s)
{
  while (vec_len (s->to_ssh))
    {
      int n = ssh_channel_write (s->channel, s->to_ssh, vec_len (s->to_ssh));

      if (n < 0)
	{
	  s->closing = 1;
	  return;
	}

      if (n == 0)
	break;

      vec_delete (s->to_ssh, n, 0);
    }

  if (vec_len (s->to_ssh) > SSH_MAX_PENDING_TO_SSH)
    s->closing = 1;
}

/* The CLI has ended, or the client does not read, tell the client and let it close the channel */
static void
ssh_session_close_channel (ssh_session_t *s, f64 now)
{
  clib_file_main_t *fm = &file_main;

  if (s->pump_file_index != ~0)
    {
      clib_file_del_by_index (fm, s->pump_file_index);
      s->pump_file_index = ~0;
    }

  if (s->pump_fd >= 0)
    {
      close (s->pump_fd);
      s->pump_fd = -1;
    }

  if (s->channel == 0 || s->close_time != 0)
    {
      s->closing = 1;
      return;
    }

  ssh_flush_to_ssh (s);
  ssh_channel_send_eof (s->channel);
  ssh_channel_close (s->channel);
  s->close_time = now;
}

static clib_error_t *
ssh_pump_read_ready (clib_file_t *f)
{
  ssh_main_t *sm = &ssh_main;
  ssh_session_t *s = pool_elt_at_index (sm->sessions, f->private_data);
  u8 buf[4096];
  ssize_t n = read (f->file_descriptor, buf, sizeof (buf));

  if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR))
    {
      ssh_session_close_channel (s, vlib_time_now (vlib_get_main ()));
      ssh_session_update_poll (s);
      if (s->closing)
	ssh_session_free (s);
      return 0;
    }

  if (n < 0)
    return 0;

  vec_add (s->to_ssh, buf, n);
  ssh_flush_to_ssh (s);

  if (s->closing)
    ssh_session_free (s);
  else
    ssh_session_update_poll (s);

  return 0;
}

static clib_error_t *
ssh_pump_write_ready (clib_file_t *f)
{
  ssh_main_t *sm = &ssh_main;
  clib_file_main_t *fm = &file_main;
  ssh_session_t *s = pool_elt_at_index (sm->sessions, f->private_data);
  ssize_t n = write (f->file_descriptor, s->to_cli, vec_len (s->to_cli));

  if (n < 0 && errno != EAGAIN && errno != EINTR)
    {
      ssh_session_free (s);
      return 0;
    }

  if (n > 0)
    vec_delete (s->to_cli, n, 0);

  if (vec_len (s->to_cli) == 0)
    clib_file_set_data_available_to_write (fm, f->index, 0);

  return 0;
}

static clib_error_t *
ssh_pump_error_detected (clib_file_t *f)
{
  ssh_main_t *sm = &ssh_main;

  ssh_session_free (pool_elt_at_index (sm->sessions, f->private_data));

  return 0;
}

static int
ssh_auth_pubkey (ssh_session session, const char *user, struct ssh_key_struct *pubkey,
		 char signature_state, void *userdata)
{
  ssh_session_t *s = userdata;
  ssh_user_t *u = ssh_find_user (user);
  ssh_key *k;

  if (u == 0 || signature_state == SSH_PUBLICKEY_STATE_WRONG)
    goto denied;

  vec_foreach (k, u->keys)
    if (ssh_key_cmp (*k, pubkey, SSH_KEY_CMP_PUBLIC) == 0)
      {
	log_debug ("key of user %s from %s is %s", u->name, s->peer,
		   signature_state == SSH_PUBLICKEY_STATE_VALID ? "valid" : "acceptable");

	/* the state is none when the client only asks if the key would be accepted */
	if (signature_state == SSH_PUBLICKEY_STATE_VALID)
	  {
	    s->authenticated = 1;
	    s->user = u;
	    log_info ("user %s from %s authenticated", u->name, s->peer);
	  }

	return SSH_AUTH_SUCCESS;
      }

denied:
  log_warn ("authentication of user %s from %s denied", user, s->peer);

  if (++s->n_auth_tries >= SSH_MAX_AUTH_TRIES)
    {
      log_warn ("too many failed attempts from %s", s->peer);
      s->closing = 1;
    }

  return SSH_AUTH_DENIED;
}

static int
ssh_channel_pty_request (ssh_session session, ssh_channel channel, const char *term, int width,
			 int height, int pxwidth, int pxheight, void *userdata)
{
  ssh_session_t *s = userdata;

  if (!s->authenticated)
    return SSH_ERROR;

  s->pty = 1;
  s->width = clib_min (width, 0xffff);
  s->height = clib_min (height, 0xffff);
  s->ansi = term && term[0] && strcmp (term, "dumb") != 0;

  return SSH_OK;
}

static int
ssh_channel_pty_window_change (ssh_session session, ssh_channel channel, int width, int height,
			       int pxwidth, int pxheight, void *userdata)
{
  ssh_session_t *s = userdata;

  s->width = clib_min (width, 0xffff);
  s->height = clib_min (height, 0xffff);

  if (s->shell)
    vlib_unix_cli_set_session_size (s->cli_session, s->width, s->height);

  return SSH_OK;
}

static int
ssh_channel_shell_request (ssh_session session, ssh_channel channel, void *userdata)
{
  ssh_session_t *s = userdata;
  clib_file_main_t *fm = &file_main;
  clib_file_t t = {
    .read_function = ssh_pump_read_ready,
    .write_function = ssh_pump_write_ready,
    .error_function = ssh_pump_error_detected,
    .private_data = s->index,
  };
  int fds[2];

  if (!s->authenticated || !s->pty || s->shell)
    return SSH_ERROR;

  if (socketpair (AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds) < 0)
    {
      log_err ("unable to create a socket pair: %s", strerror (errno));
      return SSH_ERROR;
    }

  s->pump_fd = fds[1];
  t.file_descriptor = fds[1];
  t.description = format (0, "%s", s->name);
  s->pump_file_index = clib_file_add (fm, &t);

  s->cli_session =
    vlib_unix_cli_add_session ((char *) s->name, fds[0], s->width, s->height, s->ansi);
  s->shell = 1;
  log_info ("user %s from %s has a shell, terminal %ux%u", s->user->name, s->peer, s->width,
	    s->height);

  return SSH_OK;
}

static int
ssh_channel_data (ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr,
		  void *userdata)
{
  ssh_session_t *s = userdata;
  clib_file_main_t *fm = &file_main;
  ssize_t n = 0;

  if (s->pump_fd < 0)
    return len;

  if (vec_len (s->to_cli) == 0)
    {
      n = write (s->pump_fd, data, len);
      if (n < 0 && errno != EAGAIN && errno != EINTR)
	{
	  s->closing = 1;
	  return len;
	}

      if (n < 0)
	n = 0;
    }

  if (n < len)
    {
      vec_add (s->to_cli, (u8 *) data + n, len - n);
      if (vec_len (s->to_cli) > SSH_MAX_PENDING_TO_CLI)
	s->closing = 1;
      else
	clib_file_set_data_available_to_write (fm, s->pump_file_index, 1);
    }

  return len;
}

static int
ssh_channel_write_wontblock (ssh_session session, ssh_channel channel, uint32_t bytes,
			     void *userdata)
{
  ssh_session_t *s = userdata;

  ssh_flush_to_ssh (s);

  return 0;
}

static void
ssh_channel_closed (ssh_session session, ssh_channel channel, void *userdata)
{
  ssh_session_t *s = userdata;

  s->closing = 1;
}

static void
ssh_channel_eof (ssh_session session, ssh_channel channel, void *userdata)
{
  ssh_session_t *s = userdata;

  s->closing = 1;
}

static ssh_channel
ssh_open_session_channel (ssh_session session, void *userdata)
{
  ssh_session_t *s = userdata;

  if (!s->authenticated || s->channel)
    return 0;

  s->channel = ssh_channel_new (session);
  if (s->channel == 0)
    return 0;

  s->channel_cb = (struct ssh_channel_callbacks_struct) {
    .userdata = s,
    .channel_data_function = ssh_channel_data,
    .channel_eof_function = ssh_channel_eof,
    .channel_close_function = ssh_channel_closed,
    .channel_pty_request_function = ssh_channel_pty_request,
    .channel_pty_window_change_function = ssh_channel_pty_window_change,
    .channel_shell_request_function = ssh_channel_shell_request,
    .channel_write_wontblock_function = ssh_channel_write_wontblock,
  };
  ssh_callbacks_init (&s->channel_cb);
  ssh_set_channel_callbacks (s->channel, &s->channel_cb);

  return s->channel;
}

static clib_error_t *
ssh_file_ready (clib_file_t *f)
{
  ssh_main_t *sm = &ssh_main;

  ssh_session_run (pool_elt_at_index (sm->sessions, f->private_data));

  return 0;
}

static clib_error_t *
ssh_file_error_detected (clib_file_t *f)
{
  ssh_main_t *sm = &ssh_main;

  ssh_session_free (pool_elt_at_index (sm->sessions, f->private_data));

  return 0;
}

static clib_error_t *
ssh_listen_read_ready (clib_file_t *f)
{
  ssh_main_t *sm = &ssh_main;
  vlib_main_t *vm = vlib_get_main ();
  clib_file_main_t *fm = &file_main;
  struct sockaddr_storage ss = {};
  socklen_t len = sizeof (ss);
  ssh_session_t *s;
  ssh_session session = ssh_new ();
  clib_file_t t = {
    .read_function = ssh_file_ready,
    .write_function = ssh_file_ready,
    .error_function = ssh_file_error_detected,
  };

  if (session == 0)
    return 0;

  if (ssh_bind_accept (sm->bind, session) != SSH_OK)
    {
      ssh_free (session);
      return 0;
    }

  if (pool_elts (sm->sessions) >= SSH_MAX_SESSIONS)
    {
      log_warn ("too many sessions, connection refused");
      ssh_disconnect (session);
      ssh_free (session);
      return 0;
    }

  pool_get_zero (sm->sessions, s);
  s->index = s - sm->sessions;
  s->session = session;
  s->pump_fd = -1;
  s->pump_file_index = ~0;
  s->start_time = vlib_time_now (vm);
  s->server_cb = (struct ssh_server_callbacks_struct) {
    .userdata = s,
    .auth_pubkey_function = ssh_auth_pubkey,
    .channel_open_request_session_function = ssh_open_session_channel,
  };

  if (getpeername (ssh_get_fd (session), (struct sockaddr *) &ss, &len) == 0)
    s->peer = format (0, "%U%c", format_sockaddr, &ss, 0);
  else
    s->peer = format (0, "unknown%c", 0);

  ssh_callbacks_init (&s->server_cb);
  ssh_set_server_callbacks (session, &s->server_cb);
  ssh_set_auth_methods (session, SSH_AUTH_METHOD_PUBLICKEY);
  ssh_set_blocking (session, 0);

  t.file_descriptor = ssh_get_fd (session);
  t.private_data = s->index;
  t.description = format (0, "ssh %s", s->peer);
  s->ssh_file_index = clib_file_add (fm, &t);

  log_debug ("connection from %s", s->peer);
  vlib_process_signal_event (vm, sm->process_node_index, 1, 0);

  ssh_session_run (s);

  return 0;
}

/* Sessions which do not get anywhere are closed, a client must not keep a slot for ever */
static uword
ssh_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  ssh_main_t *sm = &ssh_main;
  uword *event_data = 0;
  u32 *expired = 0, *e, i;

  while (1)
    {
      f64 now;

      if (pool_elts (sm->sessions))
	vlib_process_wait_for_event_or_clock (vm, 1.0);
      else
	vlib_process_wait_for_event (vm);

      vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      now = vlib_time_now (vm);

      pool_foreach_index (i, sm->sessions)
	{
	  ssh_session_t *s = pool_elt_at_index (sm->sessions, i);

	  if ((!s->shell && now - s->start_time > SSH_AUTH_TIMEOUT) ||
	      (s->close_time != 0 && now - s->close_time > SSH_CLOSE_TIMEOUT))
	    {
	      log_info ("session from %s timed out", s->peer);
	      vec_add1 (expired, i);
	    }
	}

      vec_foreach (e, expired)
	ssh_session_free (pool_elt_at_index (sm->sessions, *e));

      vec_reset_length (expired);
    }

  return 0;
}

VLIB_REGISTER_NODE (ssh_process_node) = {
  .function = ssh_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ssh-process",
};

clib_error_t *
ssh_user_add_key (char *name, char *type, char *b64)
{
  ssh_main_t *sm = &ssh_main;
  enum ssh_keytypes_e kt = ssh_key_type_from_name (type);
  ssh_user_t *u = ssh_find_user (name);
  ssh_key key = 0;

  if (kt == SSH_KEYTYPE_UNKNOWN || ssh_pki_import_pubkey_base64 (b64, kt, &key) != SSH_OK)
    return clib_error_return (0, "ssh: user %s has an invalid key '%s %s'", name, type, b64);

  if (u == 0)
    {
      vec_add2 (sm->users, u, 1);
      u->name = (char *) format (0, "%s%c", name, 0);
    }

  vec_add1 (u->keys, key);

  return 0;
}

u8 *
ssh_key_format_public (ssh_key pubkey)
{
  u8 *s = 0;
  char *b64 = 0;

  if (ssh_pki_export_pubkey_base64 (pubkey, &b64) != SSH_OK)
    return 0;

  s = format (0, "%s %s", ssh_key_type_to_char (ssh_key_type (pubkey)), b64);
  ssh_string_free_char (b64);

  return s;
}

u8 *
ssh_key_format_fingerprint (ssh_key pubkey)
{
  u8 *s = 0;
  unsigned char *hash = 0;
  size_t len = 0;
  char *fp;

  if (ssh_get_publickey_hash (pubkey, SSH_PUBLICKEY_HASH_SHA256, &hash, &len) != SSH_OK)
    return 0;

  fp = ssh_get_fingerprint_hash (SSH_PUBLICKEY_HASH_SHA256, hash, len);
  if (fp)
    {
      s = format (0, "%s", fp);
      ssh_string_free_char (fp);
    }

  ssh_clean_pubkey_hash (&hash);

  return s;
}

static u8 *
ssh_host_key_hint (char *path)
{
  char *slash = strrchr (path, '/');
  u8 *dir, *s;

  if (slash == 0)
    return format (0, "ssh-keygen -t ed25519 -N '' -f %s", path);

  dir = format (0, "%s", path);
  vec_set_len (dir, slash == path ? 1 : slash - path);
  s = format (0, "mkdir -p %v && ssh-keygen -t ed25519 -N '' -f %s", dir, path);
  vec_free (dir);

  return s;
}

clib_error_t *
ssh_listen (char *address, u32 port, char *host_key)
{
  ssh_main_t *sm = &ssh_main;
  struct stat st;
  ssh_key key = 0, pubkey = 0;
  int fd;

  if (address == 0)
    address = "127.0.0.1";

  if (stat (host_key, &st) < 0)
    return clib_error_return (0,
			      "ssh: host key %s: %s\nCreate it with: %v\nor set host-key in the "
			      "ssh section to the key to use",
			      host_key, strerror (errno), ssh_host_key_hint (host_key));

  if (st.st_mode & (S_IRWXG | S_IRWXO))
    return clib_error_return (0, "ssh: host key %s can be accessed by others\nRun: chmod 600 %s",
			      host_key, host_key);

  if (ssh_pki_import_privkey_file (host_key, 0, 0, 0, &key) != SSH_OK)
    return clib_error_return (0,
			      "ssh: unable to load host key %s, it must be an OpenSSH private key "
			      "without a passphrase\nCreate it with: %v\nor set host-key in the "
			      "ssh section to the key to use",
			      host_key, ssh_host_key_hint (host_key));

  ssh_init ();

  if (ssh_pki_export_privkey_to_pubkey (key, &pubkey) == SSH_OK)
    {
      sm->host_key_public = ssh_key_format_public (pubkey);
      sm->host_key_fingerprint = ssh_key_format_fingerprint (pubkey);
      ssh_key_free (pubkey);
    }

  sm->bind = ssh_bind_new ();
  if (sm->bind == 0)
    return clib_error_return (0, "ssh: unable to create the listener");

  ssh_bind_options_set (sm->bind, SSH_BIND_OPTIONS_BINDADDR, address);
  ssh_bind_options_set (sm->bind, SSH_BIND_OPTIONS_BINDPORT, &port);
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 10, 0)
  {
    int no = 0;

    ssh_bind_options_set (sm->bind, SSH_BIND_OPTIONS_PROCESS_CONFIG, &no);
  }
#endif

  /* the listener owns the key */
  ssh_bind_options_set (sm->bind, SSH_BIND_OPTIONS_IMPORT_KEY, key);

  if (ssh_bind_listen (sm->bind) != SSH_OK)
    return clib_error_return (0, "ssh: unable to listen on %s port %u: %s", address, port,
			      ssh_get_error (sm->bind));

  ssh_bind_set_blocking (sm->bind, 0);
  fd = ssh_bind_get_fd (sm->bind);
  sm->process_node_index = ssh_process_node.index;
  sm->address = format (0, "%s", address);
  sm->port = port;
  sm->host_key_file = format (0, "%s", host_key);

  clib_file_add (&file_main, &(clib_file_t) {
			       .read_function = ssh_listen_read_ready,
			       .file_descriptor = fd,
			       .description = format (0, "ssh listener"),
			     });

  log_info ("listening on %s port %u, host key %v", address, port, sm->host_key_fingerprint);

  return 0;
}

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "ssh server",
};
