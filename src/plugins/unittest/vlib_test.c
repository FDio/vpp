/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>

u8 *vlib_validate_buffers (vlib_main_t * vm,
			   u32 * buffers,
			   uword next_buffer_stride,
			   uword n_buffers,
			   vlib_buffer_known_state_t known_state,
			   uword follow_buffer_next);

static clib_error_t *
test_vlib_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 bi;
  u8 *res;
  u32 allocated;
  vlib_buffer_t *b;
  vlib_buffer_t *last_b;
  u8 junk[4] = { 1, 2, 3, 4 };
  vlib_packet_template_t _t, *t = &_t;
  u8 *data_copy = 0;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;

  /* Cover vlib_packet_template_get_packet */
  t->packet_data = format (0, "silly packet data");
  t->min_n_buffers_each_alloc = 1;
  t->name = (u8 *) "test template";

  if (vlib_packet_template_get_packet (vm, t, &bi))
    vlib_buffer_free_one (vm, bi);

  vec_free (t->packet_data);

  /* Get a buffer */
  allocated = vlib_buffer_alloc (vm, &bi, 1);
  if (allocated != 1)
    return clib_error_return (0, "Buffer allocation failure!");

  b = vlib_get_buffer (vm, bi);

  /* Force buffer allocation */
  b->current_length = 2048;
  last_b = b;
  vlib_buffer_chain_append_data_with_alloc (vm, b, &last_b,
					    junk, ARRAY_LEN (junk));

  /* Cover vlib_buffer_length_in_chain_slow_path(...) */
  b->flags &= ~(VLIB_BUFFER_TOTAL_LENGTH_VALID);
  vlib_cli_output (vm, "buffer length %d",
		   vlib_buffer_length_in_chain (vm, b));
  b->flags &= ~(VLIB_BUFFER_TOTAL_LENGTH_VALID);
  vlib_cli_output (vm, "%u", vlib_buffer_index_length_in_chain (vm, bi));

  /* Add more data. Eat Mor Chikin. */
  vlib_buffer_add_data (vm, &bi, junk, ARRAY_LEN (junk));

  /* Dump the resulting two-chunk pkt */
  vlib_cli_output (vm, "%U", format_vlib_buffer_and_data, b);
  vlib_cli_output (vm, "%U", format_vlib_buffer_data, b->data, 17);

  vec_validate (data_copy, vlib_buffer_length_in_chain (vm, b) - 1);
  vlib_cli_output (vm, "%u", vlib_buffer_contents (vm, bi, data_copy));
  vec_free (data_copy);

  /* Cover simple functions in buffer.h / buffer_funcs.h */
  vlib_cli_output (vm, "%llx", vlib_buffer_get_va (b));
  vlib_cli_output (vm, "%llx", vlib_buffer_get_current_va (b));
  vlib_cli_output (vm, "%d", vlib_buffer_has_space (b, 100ll));
  vlib_buffer_reset (b);
  vlib_cli_output (vm, "%llx", vlib_buffer_get_tail (b));
  vlib_buffer_put_uninit (b, 0);
  vlib_buffer_push_uninit (b, 0);
  vlib_buffer_make_headroom (b, 0);
  (void) vlib_buffer_pull (b, 0);
  vlib_cli_output (vm, "%llx", vlib_buffer_get_pa (vm, b));
  vlib_cli_output (vm, "%llx", vlib_buffer_get_current_pa (vm, b));

  /* Validate it one way */
  res = vlib_validate_buffer (vm, bi, 1 /* follow_buffer_next */ );
  if (res)
    return clib_error_return (0, "%v", res);

  /* Validate it a different way */
  res = vlib_validate_buffers (vm, &bi, 0 /* stride */ ,
			       1, VLIB_BUFFER_KNOWN_ALLOCATED,
			       1 /* follow_buffer_next */ );
  if (res)
    return clib_error_return (0, "%v", res);

  /* Free it */
  vlib_buffer_free_one (vm, bi);
  /* It will be free */
  res = vlib_validate_buffers (vm, &bi, 0 /* stride */ ,
			       1, VLIB_BUFFER_KNOWN_FREE,
			       1 /* follow_buffer_next */ );
  if (res)
    return clib_error_return (0, "%v", res);

  /* Misc */
  vlib_cli_output
    (vm, "%u",
     vlib_combined_counter_n_counters (im->combined_sw_if_counters));

  /* buffer will not be allocated at this point, exercise error path */
  res = vlib_validate_buffers (vm, &bi, 0 /* stride */ ,
			       1, VLIB_BUFFER_KNOWN_ALLOCATED,
			       1 /* follow_buffer_next */ );
  if (res)
    return clib_error_return (0, "%v", res);

  /* NOTREACHED */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_vlib_command, static) =
{
  .path = "test vlib",
  .short_help = "vlib code coverage unit test",
  .function = test_vlib_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
test_format_vlib_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _i, *i = &_i;
  int enable = -1, disable = -1;
  int twenty_seven = -1;;
  int rxtx = -1;

  memset (i, 0, sizeof (*i));
  unformat_init_string (i, "enable disable rx tx 27", 23);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_vlib_enable_disable, &enable))
	;
      else if (unformat (i, "%U", unformat_vlib_enable_disable, &disable))
	;
      else if (unformat (i, "%U", unformat_vlib_number, &twenty_seven))
	;
      else if (unformat (i, "%U", unformat_vlib_rx_tx, &rxtx))
	;
      else
	break;
    }

  rxtx = VLIB_TX;
  vlib_cli_output (vm, "%U", format_vlib_read_write, rxtx);
  vlib_cli_output (vm, "%U", format_vlib_rx_tx, rxtx);

  rxtx = VLIB_RX;
  vlib_cli_output (vm, "%U", format_vlib_read_write, rxtx);
  vlib_cli_output (vm, "%U", format_vlib_rx_tx, rxtx);
  rxtx = 12345;
  vlib_cli_output (vm, "%U", format_vlib_read_write, rxtx);
  vlib_cli_output (vm, "%U", format_vlib_rx_tx, rxtx);

  unformat_free (i);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_format_vlib_command, static) =
{
  .path = "test format-vlib",
  .short_help = "vlib format code coverate unit test",
  .function = test_format_vlib_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
test_vlib2_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *s;
  u8 **result;

  s = format (0, "show       ");
  result = vlib_cli_get_possible_completions (s);
  vec_free (result);
  vec_free (s);

  s = 0;
  vec_add1 (s, 0);
  result = vlib_cli_get_possible_completions (s);
  vec_free (result);
  vec_free (s);

  s = format (0, "show            ?");
  result = vlib_cli_get_possible_completions (s);
  vec_free (result);
  vec_free (s);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_vlib2_command, static) =
{
  .path = "test vlib2",
  .short_help = "vlib code coverage unit test #2",
  .function = test_vlib2_command_fn,
};
/* *INDENT-ON* */





/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
