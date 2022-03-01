/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

#define STAT_SEGMENT_SOCKET_FILENAME "stats.sock"

static clib_error_t *
statseg_config (vlib_main_t *vm, unformat_input_t *input)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  sm->update_interval = 10.0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "socket-name %s", &sm->socket_name))
	;
      /* DEPRECATE: default (does nothing) */
      else if (unformat (input, "default"))
	;
      else if (unformat (input, "size %U", unformat_memory_size,
			 &sm->memory_size))
	;
      else if (unformat (input, "page-size %U", unformat_log2_page_size,
			 &sm->log2_page_sz))
	;
      else if (unformat (input, "per-node-counters on"))
	sm->node_counters_enabled = 1;
      else if (unformat (input, "per-node-counters off"))
	sm->node_counters_enabled = 0;
      else if (unformat (input, "update-interval %f", &sm->update_interval))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  /*
   * NULL-terminate socket name string
   * clib_socket_init()->socket_config() use C str*
   */
  if (vec_len (sm->socket_name))
    vec_terminate_c_string (sm->socket_name);

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (statseg_config, "statseg");

/*
 * Accept connection on the socket and exchange the fd for the shared
 * memory segment.
 */
static clib_error_t *
stats_socket_accept_ready (clib_file_t *uf)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  clib_error_t *err;
  clib_socket_t client = { 0 };

  err = clib_socket_accept (sm->socket, &client);
  if (err)
    {
      clib_error_report (err);
      return err;
    }

  /* Send the fd across and close */
  err = clib_socket_sendmsg (&client, 0, 0, &sm->memfd, 1);
  if (err)
    clib_error_report (err);
  clib_socket_close (&client);

  return 0;
}

static clib_error_t *
stats_segment_socket_init (void)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  clib_error_t *error;
  clib_socket_t *s = clib_mem_alloc (sizeof (clib_socket_t));

  memset (s, 0, sizeof (clib_socket_t));
  s->config = (char *) sm->socket_name;
  s->flags = CLIB_SOCKET_F_IS_SERVER | CLIB_SOCKET_F_SEQPACKET |
	     CLIB_SOCKET_F_ALLOW_GROUP_WRITE | CLIB_SOCKET_F_PASSCRED;

  if ((error = clib_socket_init (s)))
    return error;

  clib_file_t template = { 0 };
  template.read_function = stats_socket_accept_ready;
  template.file_descriptor = s->fd;
  template.description = format (0, "stats segment listener %s", s->config);
  clib_file_add (&file_main, &template);

  sm->socket = s;

  return 0;
}

static clib_error_t *
stats_segment_socket_exit (vlib_main_t *vm)
{
  /*
   * cleanup the listener socket on exit.
   */
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  unlink ((char *) sm->socket_name);
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (stats_segment_socket_exit);

static clib_error_t *
statseg_init (vlib_main_t *vm)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);

  /* set default socket file name when statseg config stanza is empty. */
  if (!vec_len (sm->socket_name))
    sm->socket_name = format (0, "%s/%s%c", vlib_unix_get_runtime_dir (),
			      STAT_SEGMENT_SOCKET_FILENAME, 0);
  return stats_segment_socket_init ();
}

VLIB_INIT_FUNCTION (statseg_init) = {
  .runs_after = VLIB_INITS ("unix_input_init", "linux_epoll_input_init"),
};
