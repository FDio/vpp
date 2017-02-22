/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * pg_cli.c: packet generator cli
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <sys/stat.h>

#include <vnet/vnet.h>
#include <vnet/pg/pg.h>

#ifdef CLIB_UNIX
#include <vnet/unix/pcap.h>
#endif

/* Root of all packet generator cli commands. */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_pg_command, static) = {
  .path = "packet-generator",
  .short_help = "Packet generator commands",
};
/* *INDENT-ON* */

void
pg_enable_disable (u32 stream_index, int is_enable)
{
  pg_main_t *pg = &pg_main;
  pg_stream_t *s;

  if (stream_index == ~0)
    {
      /* No stream specified: enable/disable all streams. */
      /* *INDENT-OFF* */
        pool_foreach (s, pg->streams, ({
            pg_stream_enable_disable (pg, s, is_enable);
        }));
	/* *INDENT-ON* */
    }
  else
    {
      /* enable/disable specified stream. */
      s = pool_elt_at_index (pg->streams, stream_index);
      pg_stream_enable_disable (pg, s, is_enable);
    }
}

clib_error_t *
pg_capture (pg_capture_args_t * a)
{
  pg_main_t *pg = &pg_main;
  pg_interface_t *pi;

  if (a->is_enabled == 1)
    {
      struct stat sb;
      if (stat ((char *) a->pcap_file_name, &sb) != -1)
	return clib_error_return (0, "Cannot create pcap file");
    }

  pi = pool_elt_at_index (pg->interfaces, a->dev_instance);
  vec_free (pi->pcap_file_name);
  memset (&pi->pcap_main, 0, sizeof (pi->pcap_main));

  if (a->is_enabled == 0)
    return 0;

  pi->pcap_file_name = a->pcap_file_name;
  pi->pcap_main.file_name = (char *) pi->pcap_file_name;
  pi->pcap_main.n_packets_to_capture = a->count;
  pi->pcap_main.packet_type = PCAP_PACKET_TYPE_ethernet;

  return 0;
}

static clib_error_t *
enable_disable_stream (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  pg_main_t *pg = &pg_main;
  int is_enable = cmd->function_arg != 0;
  u32 stream_index = ~0;

  if (unformat (input, "%U", unformat_eof))
    ;
  else if (unformat (input, "%U", unformat_hash_vec_string,
		     pg->stream_index_by_name, &stream_index))
    ;
  else
    return clib_error_create ("unknown input `%U'",
			      format_unformat_error, input);

  pg_enable_disable (stream_index, is_enable);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (enable_streams_cli, static) = {
  .path = "packet-generator enable-stream",
  .short_help = "Enable packet generator streams",
  .function = enable_disable_stream,
  .function_arg = 1,		/* is_enable */
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (disable_streams_cli, static) = {
  .path = "packet-generator disable-stream",
  .short_help = "Disable packet generator streams",
  .function = enable_disable_stream,
  .function_arg = 0,		/* is_enable */
};
/* *INDENT-ON* */

static u8 *
format_pg_stream (u8 * s, va_list * va)
{
  pg_stream_t *t = va_arg (*va, pg_stream_t *);
  u8 *v;

  if (!t)
    return format (s, "%=16s%=12s%=16s%s",
		   "Name", "Enabled", "Count", "Parameters");

  s = format (s, "%-16v%=12s%16Ld",
	      t->name,
	      pg_stream_is_enabled (t) ? "Yes" : "No",
	      t->n_packets_generated);

  v = 0;

  v = format (v, "limit %Ld, ", t->n_packets_limit);

  v = format (v, "rate %.2e pps, ", t->rate_packets_per_second);

  v = format (v, "size %d%c%d, ",
	      t->min_packet_bytes,
	      t->packet_size_edit_type == PG_EDIT_RANDOM ? '+' : '-',
	      t->max_packet_bytes);

  v = format (v, "buffer-size %d, ", t->buffer_bytes);

  v = format (v, "worker %d, ", t->worker_index);

  if (v)
    {
      s = format (s, "  %v", v);
      vec_free (v);
    }

  return s;
}

static clib_error_t *
show_streams (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  pg_main_t *pg = &pg_main;
  pg_stream_t *s;

  if (pool_elts (pg->streams) == 0)
    {
      vlib_cli_output (vm, "no streams currently defined");
      goto done;
    }

  vlib_cli_output (vm, "%U", format_pg_stream, 0);
  /* *INDENT-OFF* */
  pool_foreach (s, pg->streams, ({
      vlib_cli_output (vm, "%U", format_pg_stream, s);
    }));
  /* *INDENT-ON* */

done:
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_streams_cli, static) = {
  .path = "show packet-generator",
  .short_help = "Show packet generator streams",
  .function = show_streams,
};
/* *INDENT-ON* */

static clib_error_t *
pg_pcap_read (pg_stream_t * s, char *file_name)
{
#ifndef CLIB_UNIX
  return clib_error_return (0, "no pcap support");
#else
  pcap_main_t pm;
  clib_error_t *error;
  memset (&pm, 0, sizeof (pm));
  pm.file_name = file_name;
  error = pcap_read (&pm);
  s->replay_packet_templates = pm.packets_read;
  s->min_packet_bytes = pm.min_packet_bytes;
  s->max_packet_bytes = pm.max_packet_bytes;
  s->buffer_bytes = pm.max_packet_bytes;
  /* For PCAP buffers we never re-use buffers. */
  s->flags |= PG_STREAM_FLAGS_DISABLE_BUFFER_RECYCLE;

  if (s->n_packets_limit == 0)
    s->n_packets_limit = vec_len (pm.packets_read);

  return error;
#endif /* CLIB_UNIX */
}

static uword
unformat_pg_stream_parameter (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  f64 x;

  if (unformat (input, "limit %f", &x))
    s->n_packets_limit = x;

  else if (unformat (input, "rate %f", &x))
    s->rate_packets_per_second = x;

  else if (unformat (input, "size %d-%d", &s->min_packet_bytes,
		     &s->max_packet_bytes))
    s->packet_size_edit_type = PG_EDIT_INCREMENT;

  else if (unformat (input, "size %d+%d", &s->min_packet_bytes,
		     &s->max_packet_bytes))
    s->packet_size_edit_type = PG_EDIT_RANDOM;

  else if (unformat (input, "buffer-size %d", &s->buffer_bytes))
    ;

  else
    return 0;

  return 1;
}

static clib_error_t *
validate_stream (pg_stream_t * s)
{
  if (s->max_packet_bytes < s->min_packet_bytes)
    return clib_error_create ("max-size < min-size");

  if (s->buffer_bytes >= 4096 || s->buffer_bytes == 0)
    return
      clib_error_create ("buffer-size must be positive and < 4096, given %d",
			 s->buffer_bytes);

  if (s->rate_packets_per_second < 0)
    return clib_error_create ("negative rate");

  return 0;
}

static clib_error_t *
new_stream (vlib_main_t * vm,
	    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  u8 *tmp = 0;
  u32 hw_if_index;
  unformat_input_t sub_input = { 0 };
  int sub_input_given = 0;
  vnet_main_t *vnm = vnet_get_main ();
  pg_main_t *pg = &pg_main;
  pg_stream_t s = { 0 };
  char *pcap_file_name;

  s.sw_if_index[VLIB_RX] = s.sw_if_index[VLIB_TX] = ~0;
  s.node_index = ~0;
  s.max_packet_bytes = s.min_packet_bytes = 64;
  s.buffer_bytes = VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES;
  s.if_id = 0;
  pcap_file_name = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %v", &tmp))
	{
	  if (s.name)
	    vec_free (s.name);
	  s.name = tmp;
	}

      else if (unformat (input, "node %U",
			 unformat_vnet_hw_interface, vnm, &hw_if_index))
	{
	  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);

	  s.node_index = hi->output_node_index;
	  s.sw_if_index[VLIB_TX] = hi->sw_if_index;
	}

      else if (unformat (input, "source pg%u", &s.if_id))
	;

      else if (unformat (input, "node %U",
			 unformat_vlib_node, vm, &s.node_index))
	;

      else if (unformat (input, "worker %u", &s.worker_index))
	;

      else if (unformat (input, "interface %U",
			 unformat_vnet_sw_interface, vnm,
			 &s.sw_if_index[VLIB_RX]))
	;

      else if (unformat (input, "pcap %s", &pcap_file_name))
	;

      else if (!sub_input_given
	       && unformat (input, "data %U", unformat_input, &sub_input))
	sub_input_given++;

      else if (unformat_user (input, unformat_pg_stream_parameter, &s))
	;

      else if (unformat (input, "no-recycle"))
	s.flags |= PG_STREAM_FLAGS_DISABLE_BUFFER_RECYCLE;

      else
	{
	  error = clib_error_create ("unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  error = validate_stream (&s);
  if (error)
    return error;

  if (!sub_input_given && !pcap_file_name)
    {
      error = clib_error_create ("no packet data given");
      goto done;
    }

  if (s.node_index == ~0)
    {
      if (pcap_file_name != 0)
	{
	  vlib_node_t *n =
	    vlib_get_node_by_name (vm, (u8 *) "ethernet-input");
	  s.node_index = n->index;
	}
      else
	{
	  error = clib_error_create ("output interface or node not given");
	  goto done;
	}
    }

  {
    pg_node_t *n;

    if (s.node_index < vec_len (pg->nodes))
      n = pg->nodes + s.node_index;
    else
      n = 0;

    if (s.worker_index >= vlib_num_workers ())
      s.worker_index = 0;

    if (pcap_file_name != 0)
      {
	error = pg_pcap_read (&s, pcap_file_name);
	if (error)
	  goto done;
	vec_free (pcap_file_name);
      }

    else if (n && n->unformat_edit
	     && unformat_user (&sub_input, n->unformat_edit, &s))
      ;

    else if (!unformat_user (&sub_input, unformat_pg_payload, &s))
      {
	error = clib_error_create
	  ("failed to parse packet data from `%U'",
	   format_unformat_error, &sub_input);
	goto done;
      }
  }

  pg_stream_add (pg, &s);
  return 0;

done:
  pg_stream_free (&s);
  unformat_free (&sub_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (new_stream_cli, static) = {
  .path = "packet-generator new",
  .function = new_stream,
  .short_help = "Create packet generator stream",
  .long_help =
  "Create packet generator stream\n"
  "\n"
  "Arguments:\n"
  "\n"
  "name STRING          sets stream name\n"
  "interface STRING     interface for stream output \n"
  "node NODE-NAME       node for stream output\n"
  "data STRING          specifies packet data\n"
  "pcap FILENAME        read packet data from pcap file\n",
};
/* *INDENT-ON* */

static clib_error_t *
del_stream (vlib_main_t * vm,
	    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  pg_main_t *pg = &pg_main;
  u32 i;

  if (!unformat (input, "%U",
		 &unformat_hash_vec_string, pg->stream_index_by_name, &i))
    return clib_error_create ("expected stream name `%U'",
			      format_unformat_error, input);

  pg_stream_del (pg, i);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (del_stream_cli, static) = {
  .path = "packet-generator delete",
  .function = del_stream,
  .short_help = "Delete stream with given name",
};
/* *INDENT-ON* */

static clib_error_t *
change_stream_parameters (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  pg_main_t *pg = &pg_main;
  pg_stream_t *s, s_new;
  u32 stream_index = ~0;
  clib_error_t *error;

  if (unformat (input, "%U", unformat_hash_vec_string,
		pg->stream_index_by_name, &stream_index))
    ;
  else
    return clib_error_create ("expecting stream name; got `%U'",
			      format_unformat_error, input);

  s = pool_elt_at_index (pg->streams, stream_index);
  s_new = s[0];

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_user (input, unformat_pg_stream_parameter, &s_new))
	;

      else
	return clib_error_create ("unknown input `%U'",
				  format_unformat_error, input);
    }

  error = validate_stream (&s_new);
  if (!error)
    s[0] = s_new;

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (change_stream_parameters_cli, static) = {
  .path = "packet-generator configure",
  .short_help = "Change packet generator stream parameters",
  .function = change_stream_parameters,
};
/* *INDENT-ON* */

static clib_error_t *
pg_capture_cmd_fn (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_hw_interface_t *hi = 0;
  u8 *pcap_file_name = 0;
  u32 hw_if_index;
  u32 is_disable = 0;
  u32 count = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U",
		    unformat_vnet_hw_interface, vnm, &hw_if_index))
	{
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	}

      else if (unformat (line_input, "pcap %s", &pcap_file_name))
	;
      else if (unformat (line_input, "count %u", &count))
	;
      else if (unformat (line_input, "disable"))
	is_disable = 1;

      else
	{
	  error = clib_error_create ("unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!hi)
    {
      error = clib_error_return (0, "Please specify interface name");
      goto done;
    }

  if (hi->dev_class_index != pg_dev_class.index)
    {
      error =
	clib_error_return (0, "Please specify packet-generator interface");
      goto done;
    }

  if (!pcap_file_name && is_disable == 0)
    {
      error = clib_error_return (0, "Please specify pcap file name");
      goto done;
    }


  pg_capture_args_t _a, *a = &_a;

  a->hw_if_index = hw_if_index;
  a->dev_instance = hi->dev_instance;
  a->is_enabled = !is_disable;
  a->pcap_file_name = pcap_file_name;
  a->count = count;

  error = pg_capture (a);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pg_capture_cmd, static) = {
  .path = "packet-generator capture",
  .short_help = "packet-generator capture <interface name> pcap <filename> [count <n>]",
  .function = pg_capture_cmd_fn,
};
/* *INDENT-ON* */

static clib_error_t *
create_pg_if_cmd_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  pg_main_t *pg = &pg_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 if_id;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface pg%u", &if_id))
	;

      else
	{
	  error = clib_error_create ("unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  pg_interface_add_or_get (pg, if_id);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_pg_if_cmd, static) = {
  .path = "create packet-generator",
  .short_help = "create packet-generator interface <interface name>",
  .function = create_pg_if_cmd_fn,
};
/* *INDENT-ON* */

/* Dummy init function so that we can be linked in. */
static clib_error_t *
pg_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (pg_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
