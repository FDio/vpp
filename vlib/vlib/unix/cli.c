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
 * cli.c: Unix stdin/socket CLI.
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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <arpa/telnet.h>

typedef struct {
  u32 unix_file_index;

  /* Vector of output pending write to file descriptor. */
  u8 * output_vector;

  /* Vector of input saved by Unix input node to be processed by
     CLI process. */
  u8 * input_vector;

  u8 has_history;
  u8 ** command_history;
  u8 * current_command;
  i32 excursion;
  u32 history_limit;
  u8 * search_key;
  int search_mode;

  u32 process_node_index;
} unix_cli_file_t;

always_inline void
unix_cli_file_free (unix_cli_file_t * f)
{
  vec_free (f->output_vector);
  vec_free (f->input_vector);
}

typedef struct {
  /* Prompt string for CLI. */
  u8 * cli_prompt;

  unix_cli_file_t * cli_file_pool;

  u32 * unused_cli_process_node_indices;

  /* File pool index of current input. */
  u32 current_input_file_index;
} unix_cli_main_t;

static unix_cli_main_t unix_cli_main;

static void
unix_cli_add_pending_output (unix_file_t * uf,
			     unix_cli_file_t * cf,
			     u8 * buffer,
			     uword buffer_bytes)
{
  unix_main_t * um = &unix_main;

  vec_add (cf->output_vector, buffer, buffer_bytes);
  if (vec_len (cf->output_vector) > 0)
    {
      int skip_update = 0 != (uf->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE);
      uf->flags |= UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      if (! skip_update)
	um->file_update (uf, UNIX_FILE_UPDATE_MODIFY);
    }
}

static void
unix_cli_del_pending_output (unix_file_t * uf,
			     unix_cli_file_t * cf,
			     uword n_bytes)
{
  unix_main_t * um = &unix_main;

  vec_delete (cf->output_vector, n_bytes, 0);
  if (vec_len (cf->output_vector) <= 0)
    {
      int skip_update = 0 == (uf->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE);
      uf->flags &= ~UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      if (! skip_update)
	um->file_update (uf, UNIX_FILE_UPDATE_MODIFY);
    }
}

/* VLIB cli output function. */
static void unix_vlib_cli_output (uword cli_file_index,
				  u8 * buffer,
				  uword buffer_bytes)
{
  unix_main_t * um = &unix_main;
  unix_cli_main_t * cm = &unix_cli_main;
  unix_cli_file_t * cf;
  unix_file_t * uf;
  int n;
 
  cf = pool_elt_at_index (cm->cli_file_pool, cli_file_index);
  uf = pool_elt_at_index (um->file_pool, cf->unix_file_index);
  n = 0;
  if (vec_len (cf->output_vector) == 0)
    n = write (uf->file_descriptor, buffer, buffer_bytes);
  if (n < 0 && errno != EAGAIN)
    clib_unix_warning ("write");

  else if ((word) n < (word) buffer_bytes)
    {
      if (n < 0) n = 0;
      unix_cli_add_pending_output (uf, cf, buffer + n, buffer_bytes - n);
    }
}

static int unix_cli_line_edit (unix_main_t * um, unix_cli_file_t * cf)
{
  unix_file_t * uf = pool_elt_at_index (um->file_pool, cf->unix_file_index);
  u8 * prev;
  int i, j, delta;

  for (i = 0; i < vec_len (cf->input_vector); i++)
    {
      switch (cf->input_vector[i])
        {
        case 0:
          continue;
            
        case '?':
          /* Erase the current command (if any) plus ?*/
          for (j = 0; j < (vec_len (cf->current_command)+1); j++)
            unix_cli_add_pending_output (uf, cf, (u8 *) "\b \b", 3);
          
          unix_cli_add_pending_output (uf, cf, (u8 *) "\r\nHistory:\r\n", 12);

          for (j = 0; j < vec_len (cf->command_history); j++)
            {
              unix_cli_add_pending_output (uf, cf, cf->command_history[j],
                                           vec_len(cf->command_history[j]));
              unix_cli_add_pending_output (uf, cf, (u8 *) "\r\n", 2);
            }
          goto crlf;

          /* ^R - reverse search */
        case 'R' - '@':
        case 'S' - '@':
          if (cf->search_mode == 0)
            {
              /* Erase the current command (if any) plus ^R */
              for (j = 0; j < (vec_len (cf->current_command)+2); j++)
                  unix_cli_add_pending_output (uf, cf, (u8 *) "\b \b", 3);
              
              vec_reset_length (cf->search_key);
              vec_reset_length (cf->current_command);
              if (cf->input_vector[i] == 'R' - '@')
                  cf->search_mode = -1;
              else
                  cf->search_mode = 1;
            }
          else
            {
              if (cf->input_vector[i] == 'R' - '@')
                cf->search_mode = -1;
              else
                cf->search_mode = 1;

              cf->excursion += cf->search_mode;
              unix_cli_add_pending_output (uf, cf, (u8 *) "\b \b", 3);
              goto search_again;
            }
          break;

          /* ^U - line-kill */
        case 'U'-'@':
          /* Erase the command, plus ^U */
          for (j = 0; j < (vec_len (cf->current_command)+2); j++)
            unix_cli_add_pending_output (uf, cf, (u8 *) "\b \b", 3);
          vec_reset_length (cf->current_command);
          cf->search_mode = 0;
          continue;

          /* ^P - previous, ^N - next */
        case 'P' - '@':
        case 'N' - '@':
          cf->search_mode = 0;
          /* Erase the command, plus ^P */
          for (j = 0; j < (vec_len (cf->current_command)+2); j++)
            unix_cli_add_pending_output (uf, cf, (u8 *) "\b \b", 3);
          vec_reset_length (cf->current_command);
          if (vec_len (cf->command_history))
            {
              if (cf->input_vector[i] == 'P' - '@')
                delta = -1;
              else
                delta = 1;

              cf->excursion += delta;

              if (cf->excursion > (i32) vec_len (cf->command_history) -1)
                cf->excursion = 0;
              else if (cf->excursion < 0)
                cf->excursion = vec_len (cf->command_history) -1;

              prev = cf->command_history [cf->excursion];
              vec_validate (cf->current_command, vec_len(prev)-1);

              memcpy (cf->current_command, prev, vec_len(prev));
              _vec_len (cf->current_command) = vec_len(prev);
              unix_cli_add_pending_output (uf, cf, cf->current_command,
                                           vec_len (cf->current_command));
              break;
            }
          break;

        case 0x7f:
        case 'H' - '@':
          for (j = 0; j < 2; j++)
            unix_cli_add_pending_output (uf, cf, (u8 *) "\b \b", 3);
          if (vec_len (cf->current_command))
            {
              unix_cli_add_pending_output (uf, cf, (u8 *) "\b \b", 3);
              _vec_len (cf->current_command)--;
            }
          cf->search_mode = 0;
          cf->excursion = 0;
          cf->search_mode = 0;
          vec_reset_length (cf->search_key);
          break;

        case '\r':
        case '\n':
        crlf:
          vec_add1 (cf->current_command, '\r');
          vec_add1 (cf->current_command, '\n');
          unix_cli_add_pending_output (uf, cf, (u8 *) "\b\b  \b\b\r\n", 8);

          vec_validate (cf->input_vector, vec_len(cf->current_command)-1);
          memcpy (cf->input_vector, cf->current_command, 
                  vec_len(cf->current_command));
          _vec_len(cf->input_vector) = _vec_len (cf->current_command);

          if (vec_len(cf->command_history) >= cf->history_limit)
            {
              vec_free (cf->command_history[0]);
              vec_delete (cf->command_history, 1, 0);
            }
          /* Don't add blank lines to the cmd history */
          if (vec_len (cf->current_command) > 2)
            {
              _vec_len (cf->current_command) -= 2;
              vec_add1 (cf->command_history, cf->current_command);
              cf->current_command = 0;
            }
          else
            vec_reset_length (cf->current_command);
          cf->excursion = 0;
          cf->search_mode = 0;
          vec_reset_length (cf->search_key);
          return 0;

          /* telnet "mode character" blort, echo but don't process. */
        case 0xff:
            unix_cli_add_pending_output (uf, cf, cf->input_vector + i, 
                                         6);
            i += 6;
            continue;

        default:
          if (cf->search_mode)
            {
              int j, k, limit, offset;
              u8 * item;

              vec_add1 (cf->search_key, cf->input_vector[i]);

            search_again:
              for (j = 0; j < vec_len(cf->command_history); j++)
                {
                  if (cf->excursion > (i32) vec_len (cf->command_history) -1)
                    cf->excursion = 0;
                  else if (cf->excursion < 0)
                    cf->excursion = vec_len (cf->command_history) -1;

                  item = cf->command_history[cf->excursion];

                  limit = (vec_len(cf->search_key) > vec_len (item)) ?
                    vec_len(item) : vec_len (cf->search_key);

                  for (offset = 0; offset <= vec_len(item) - limit; offset++)
                    {
                      for (k = 0; k < limit; k++)
                        {
                          if (item[k+offset] != cf->search_key[k])
                            goto next_offset;
                        }
                      goto found_at_offset;

                    next_offset:
                      ;
                    }
                  goto next;

                found_at_offset:
                  for (j = 0; j < vec_len (cf->current_command)+1; j++)
                    unix_cli_add_pending_output (uf, cf, (u8 *) "\b \b", 3);

                  vec_validate (cf->current_command, vec_len(item)-1);

                  memcpy (cf->current_command, item, vec_len(item));
                  _vec_len (cf->current_command) = vec_len(item);
                  unix_cli_add_pending_output (uf, cf, cf->current_command,
                                               vec_len (cf->current_command));
                  goto found;

                next:
                  cf->excursion += cf->search_mode;
                }
              
              unix_cli_add_pending_output (uf, cf, (u8 *)"\r\nno match..", 12);
              vec_reset_length (cf->search_key);
              vec_reset_length (cf->current_command);
              cf->search_mode = 0;
              goto crlf;
            }
          else
            vec_add1 (cf->current_command, cf->input_vector[i]);

        found:

          break;
        }
    }
  vec_reset_length(cf->input_vector);
  return 1;
}

static void unix_cli_process_input (unix_cli_main_t * cm, uword cli_file_index)
{
  unix_main_t * um = &unix_main;
  unix_file_t * uf;
  unix_cli_file_t * cf = pool_elt_at_index (cm->cli_file_pool, cli_file_index);
  unformat_input_t input;
  int vlib_parse_eval (u8 *);

  /* Try vlibplex first.  Someday... */
  if (0 && vlib_parse_eval (cf->input_vector) == 0)
      goto done;

  /* Line edit, echo, etc. */
  if (cf->has_history && unix_cli_line_edit (um, cf))
    return;

  if (um->log_fd)
    {
      static u8 * lv;
      vec_reset_length (lv);
      lv = format (lv, "%U[%d]: %v", 
                   format_timeval,
                   0 /* current bat-time */,
                   0 /* current bat-format */,
                   cli_file_index,
                   cf->input_vector);
      {
	int rv __attribute__((unused)) = 
	  write (um->log_fd, lv, vec_len(lv));
      }
    }

  unformat_init_vector (&input, cf->input_vector);

  /* Remove leading white space from input. */
  (void) unformat (&input, "");

  cm->current_input_file_index = cli_file_index;

  if (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    vlib_cli_input (um->vlib_main, &input, unix_vlib_cli_output, cli_file_index);

  /* Re-fetch pointer since pool may have moved. */
  cf = pool_elt_at_index (cm->cli_file_pool, cli_file_index);

  /* Zero buffer since otherwise unformat_free will call vec_free on it. */
  input.buffer = 0;

  unformat_free (&input);

  /* Re-use input vector. */
done:
  _vec_len (cf->input_vector) = 0;

  /* Prompt. */
  uf = pool_elt_at_index (um->file_pool, cf->unix_file_index);
  unix_cli_add_pending_output (uf, cf,
			       cm->cli_prompt,
			       vec_len (cm->cli_prompt));
}

static void unix_cli_kill (unix_cli_main_t * cm, uword cli_file_index)
{
  unix_main_t * um = &unix_main;
  unix_cli_file_t * cf;
  unix_file_t * uf;
  int i;

  cf = pool_elt_at_index (cm->cli_file_pool, cli_file_index);
  uf = pool_elt_at_index (um->file_pool, cf->unix_file_index);

  /* Quit/EOF on stdin means quit program. */
  if (uf->file_descriptor == 0)
    clib_longjmp (&um->vlib_main->main_loop_exit, VLIB_MAIN_LOOP_EXIT_CLI);

  vec_free (cf->current_command);
  vec_free (cf->search_key);

  for (i = 0; i < vec_len (cf->command_history); i++)
      vec_free (cf->command_history[i]);

  vec_free (cf->command_history);

  unix_file_del (um, uf);

  unix_cli_file_free (cf);
  pool_put (cm->cli_file_pool, cf);
}

typedef enum {
  UNIX_CLI_PROCESS_EVENT_READ_READY,
  UNIX_CLI_PROCESS_EVENT_QUIT,
} unix_cli_process_event_type_t;

static uword
unix_cli_process (vlib_main_t * vm,
		  vlib_node_runtime_t * rt,
		  vlib_frame_t * f)
{
  unix_cli_main_t * cm = &unix_cli_main;
  uword i, * data = 0;

  while (1)
    {
      unix_cli_process_event_type_t event_type;
      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &data);

      switch (event_type)
	{
	case UNIX_CLI_PROCESS_EVENT_READ_READY:
	  for (i = 0; i < vec_len (data); i++)
	    unix_cli_process_input (cm, data[i]);
	  break;

	case UNIX_CLI_PROCESS_EVENT_QUIT:
	  /* Kill this process. */
	  for (i = 0; i < vec_len (data); i++)
	    unix_cli_kill (cm, data[i]);
	  goto done;
	}

      if (data)
	_vec_len (data) = 0;
    }

 done:
  vec_free (data);

  vlib_node_set_state (vm, rt->node_index, VLIB_NODE_STATE_DISABLED);

  /* Add node index so we can re-use this process later. */
  vec_add1 (cm->unused_cli_process_node_indices, rt->node_index);

  return 0;
}

static clib_error_t * unix_cli_write_ready (unix_file_t * uf)
{
  unix_cli_main_t * cm = &unix_cli_main;
  unix_cli_file_t * cf;
  int n;

  cf = pool_elt_at_index (cm->cli_file_pool, uf->private_data);

  /* Flush output vector. */
  n = write (uf->file_descriptor,
	     cf->output_vector, vec_len (cf->output_vector));

  if (n < 0 && errno != EAGAIN)
    return clib_error_return_unix (0, "write");

  else if (n > 0)
    unix_cli_del_pending_output (uf, cf, n);

  return /* no error */ 0;
}

static clib_error_t * unix_cli_read_ready (unix_file_t * uf)
{
  unix_main_t * um = &unix_main;
  unix_cli_main_t * cm = &unix_cli_main;
  unix_cli_file_t * cf;
  uword l;
  int n, n_read, n_try;

  cf = pool_elt_at_index (cm->cli_file_pool, uf->private_data);

  n = n_try = 4096;
  while (n == n_try) {
      l = vec_len (cf->input_vector);
      vec_resize (cf->input_vector, l + n_try);

      n = read (uf->file_descriptor, cf->input_vector + l, n_try);

      /* Error? */
      if (n < 0 && errno != EAGAIN)
          return clib_error_return_unix (0, "read");
  
      n_read = n < 0 ? 0 : n;
      _vec_len (cf->input_vector) = l + n_read;
  }

  if (! (n < 0))
    vlib_process_signal_event (um->vlib_main,
			       cf->process_node_index,
			       (n_read == 0
				? UNIX_CLI_PROCESS_EVENT_QUIT
				: UNIX_CLI_PROCESS_EVENT_READ_READY),
			       /* event data */ uf->private_data);

  return /* no error */ 0;
}

static u32 unix_cli_file_add (unix_cli_main_t * cm, char * name, int fd)
{
  unix_main_t * um = &unix_main;
  unix_cli_file_t * cf;
  unix_file_t * uf, template = {0};
  vlib_main_t * vm = um->vlib_main;
  vlib_node_t * n;

  name = (char *) format (0, "unix-cli-%s", name);

  if (vec_len (cm->unused_cli_process_node_indices) > 0)
    {
      uword l = vec_len (cm->unused_cli_process_node_indices);

      /* Find node and give it new name. */
      n = vlib_get_node (vm, cm->unused_cli_process_node_indices[l - 1]);
      vec_free (n->name);
      n->name = (u8 *) name;

      vlib_node_set_state (vm, n->index, VLIB_NODE_STATE_POLLING);

      _vec_len (cm->unused_cli_process_node_indices) = l - 1;
    }
  else
    {
      static vlib_node_registration_t r = {
	.function = unix_cli_process,
	.type = VLIB_NODE_TYPE_PROCESS,
	.process_log2_n_stack_bytes = 14,
      };

      r.name = name;
      vlib_register_node (vm, &r);
      vec_free (name);

      n = vlib_get_node (vm, r.index);
    }

  pool_get (cm->cli_file_pool, cf);
  memset (cf, 0, sizeof (*cf));

  template.read_function = unix_cli_read_ready;
  template.write_function = unix_cli_write_ready;
  template.file_descriptor = fd;
  template.private_data = cf - cm->cli_file_pool;

  cf->process_node_index = n->index;
  cf->unix_file_index = unix_file_add (um, &template);
  cf->output_vector = 0;
  cf->input_vector = 0;

  uf = pool_elt_at_index (um->file_pool, cf->unix_file_index);

  /* Prompt. */
  unix_cli_add_pending_output (uf, cf,
			       cm->cli_prompt, vec_len (cm->cli_prompt));

  vlib_start_process (vm, n->runtime_index);
  return cf - cm->cli_file_pool;
}

static clib_error_t * unix_cli_listen_read_ready (unix_file_t * uf)
{
  unix_main_t * um = &unix_main;
  unix_cli_main_t * cm = &unix_cli_main;
  clib_socket_t * s = &um->cli_listen_socket;
  clib_socket_t client;
  char * client_name;
  clib_error_t * error;
  unix_cli_file_t * cf;
  u32 cf_index;

  error = clib_socket_accept (s, &client);
  if (error)
    return error;

  client_name = (char *) format (0, "%U%c", format_sockaddr, &client.peer, 0);

  cf_index = unix_cli_file_add (cm, client_name, client.fd);
  cf = pool_elt_at_index (cm->cli_file_pool, cf_index);

  /* No longer need CLIB version of socket. */
  clib_socket_free (&client);

  vec_free (client_name);

  /* if we're supposed to run telnet session in character mode (default) */
  if (um->cli_line_mode == 0)
    {
      u8 charmode_option[6];

      cf->has_history = 1;
      cf->history_limit = um->cli_history_limit ? um->cli_history_limit : 50;

      /* 
       * Set telnet client character mode, echo on, suppress "go-ahead" 
       * Empirically, this sequence works. YMMV.
       */

      /* Tell the client no linemode, echo */
      charmode_option[0] = IAC;
      charmode_option[1] = DONT;
      charmode_option[2] = TELOPT_LINEMODE;
      charmode_option[3] = IAC;
      charmode_option[4] = DO;
      charmode_option[5] = TELOPT_SGA;
      
      uf = pool_elt_at_index (um->file_pool, cf->unix_file_index);
      
      unix_cli_add_pending_output (uf, cf, charmode_option, 
                                   ARRAY_LEN(charmode_option));
    }

  return error;
}

static clib_error_t *
unix_cli_config (vlib_main_t * vm, unformat_input_t * input)
{
  unix_main_t * um = &unix_main;
  unix_cli_main_t * cm = &unix_cli_main;
  int flags, standard_input_fd;
  clib_error_t * error = 0;

  /* We depend on unix flags being set. */
  if ((error = vlib_call_config_function (vm, unix_config)))
    return error;

  if (um->flags & UNIX_FLAG_INTERACTIVE)
    {
      standard_input_fd = 0;

      /* Set stdin to be non-blocking. */
      if ((flags = fcntl (standard_input_fd, F_GETFL, 0)) < 0)
	flags = 0;
      fcntl (standard_input_fd, F_SETFL, flags | O_NONBLOCK);

      unix_cli_file_add (cm, "stdin", standard_input_fd);
    }

  /* If we have socket config, LISTEN, otherwise, don't */
  clib_socket_t * s = &um->cli_listen_socket;
  if(s->config && s->config[0] != 0) {
    /* CLI listen. */
    unix_file_t template = {0};

    s->flags = SOCKET_IS_SERVER; /* listen, don't connect */
    error = clib_socket_init (s);

    if (error)
      return error;

    template.read_function = unix_cli_listen_read_ready;
    template.file_descriptor = s->fd;

    unix_file_add (um, &template);
  }

  /* Set CLI prompt. */
  if (! cm->cli_prompt)
    cm->cli_prompt = format (0, "VLIB: ");

  return 0;
}

VLIB_CONFIG_FUNCTION (unix_cli_config, "unix-cli");

void vlib_unix_cli_set_prompt (char * prompt)
{
  char * fmt = (prompt[strlen(prompt)-1] == ' ') ? "%s" : "%s ";
  unix_cli_main_t * cm = &unix_cli_main;
  if (cm->cli_prompt)
    vec_free (cm->cli_prompt);
  cm->cli_prompt = format (0, fmt, prompt);
}

static clib_error_t *
unix_cli_quit (vlib_main_t * vm,
	       unformat_input_t * input,
	       vlib_cli_command_t * cmd)
{
  unix_cli_main_t * cm = &unix_cli_main;

  vlib_process_signal_event (vm,
			     vlib_current_process (vm),
			     UNIX_CLI_PROCESS_EVENT_QUIT,
			     cm->current_input_file_index);
  return 0;
}

VLIB_CLI_COMMAND (unix_cli_quit_command, static) = {
  .path = "quit",
  .short_help = "Exit CLI",
  .function = unix_cli_quit,
};

static clib_error_t *
unix_cli_exec (vlib_main_t * vm,
	       unformat_input_t * input,
	       vlib_cli_command_t * cmd)
{
  char * file_name;
  int fd;
  unformat_input_t sub_input;
  clib_error_t * error;

  file_name = 0;
  fd = -1;
  error = 0;

  if (! unformat (input, "%s", &file_name))
    {
      error = clib_error_return (0, "expecting file name, got `%U'",
				 format_unformat_error, input);
      goto done;
    }

  fd = open (file_name, O_RDONLY);
  if (fd < 0)
    {
      error = clib_error_return_unix (0, "failed to open `%s'", file_name);
      goto done;
    }

  /* Make sure its a regular file. */
  {
    struct stat s;

    if (fstat (fd, &s) < 0)
      {
	error = clib_error_return_unix (0, "failed to stat `%s'", file_name);
	goto done;
      }
    
    if (! (S_ISREG (s.st_mode) || S_ISLNK (s.st_mode)))
      {
	error = clib_error_return (0, "not a regular file `%s'", file_name);
	goto done;
      }
  }

  unformat_init_unix_file (&sub_input, fd);

  vlib_cli_input (vm, &sub_input, 0, 0);
  unformat_free (&sub_input);

 done:
  if (fd > 0)
    close (fd);
  vec_free (file_name);

  return error;
}

VLIB_CLI_COMMAND (cli_exec, static) = {
  .path = "exec",
  .short_help = "Execute commands from file",
  .function = unix_cli_exec,
  .is_mp_safe = 1,
};

static clib_error_t *
unix_show_errors (vlib_main_t * vm,
		  unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  unix_main_t * um = &unix_main;
  clib_error_t * error = 0;
  int i, n_errors_to_show;
  unix_error_history_t * unix_errors = 0;

  n_errors_to_show = 1 << 30;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (! unformat (input, "%d", &n_errors_to_show))
	{
	  error = clib_error_return (0, "expecting integer number of errors to show, got `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  n_errors_to_show = clib_min (ARRAY_LEN (um->error_history), n_errors_to_show);

  i = um->error_history_index > 0 ? um->error_history_index - 1 : ARRAY_LEN (um->error_history) - 1;

  while (n_errors_to_show > 0)
    {
      unix_error_history_t * eh = um->error_history + i;

      if (! eh->error)
	break;

      vec_add1 (unix_errors, eh[0]);
      n_errors_to_show -= 1;
      if (i == 0)
	i = ARRAY_LEN (um->error_history) - 1;
      else
	i--;
    }

  if (vec_len (unix_errors) == 0)
    vlib_cli_output (vm, "no Unix errors so far");
  else
    {
      vlib_cli_output (vm, "%Ld total errors seen", um->n_total_errors);
      for (i = vec_len (unix_errors) - 1; i >= 0; i--)
	{
	  unix_error_history_t * eh = vec_elt_at_index (unix_errors, i);
	  vlib_cli_output (vm, "%U: %U",
			   format_time_interval, "h:m:s:u", eh->time,
			   format_clib_error, eh->error);
	}
      vlib_cli_output (vm, "%U: time now",
		       format_time_interval, "h:m:s:u", vlib_time_now (vm));
    }

 done:
  vec_free (unix_errors);
  return error;
}

VLIB_CLI_COMMAND (cli_unix_show_errors, static) = {
  .path = "show unix-errors",
  .short_help = "Show Unix system call error history",
  .function = unix_show_errors,
};

static clib_error_t *
unix_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (unix_cli_init);
