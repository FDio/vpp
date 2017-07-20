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
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <math.h>

int
main (int argc, char *argv[])
{
  return vlib_unix_main (argc, argv);
}

static clib_error_t *
main_stub_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = unix_physmem_init (vm)))
    return error;

  if ((error = vlib_call_init_function (vm, unix_cli_init)))
    return error;

  return error;
}

VLIB_INIT_FUNCTION (main_stub_init);

#if 0
/* Node test code. */
typedef struct
{
  int scalar;
  int vector[0];
} my_frame_t;

static u8 *
format_my_node_frame (u8 * s, va_list * va)
{
  vlib_frame_t *f = va_arg (*va, vlib_frame_t *);
  my_frame_t *g = vlib_frame_args (f);
  int i;

  s = format (s, "scalar %d, vector { ", g->scalar);
  for (i = 0; i < f->n_vectors; i++)
    s = format (s, "%d, ", g->vector[i]);
  s = format (s, " }");

  return s;
}

static uword
my_func (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vlib_node_t *node;
  my_frame_t *y;
  u32 i, n_left = 0;
  static int serial;
  int verbose;

  node = vlib_get_node (vm, rt->node_index);

  verbose = 0;

  if (verbose && f)
    vlib_cli_output (vm, "%v: call frame %p %U", node->name,
		     f, format_my_node_frame, f);

  if (rt->n_next_nodes > 0)
    {
      vlib_frame_t *next = vlib_get_next_frame (vm, rt, /* next index */ 0);
      n_left = VLIB_FRAME_SIZE - next->n_vectors;
      y = vlib_frame_args (next);
      y->scalar = serial++;
    }
  else
    y = 0;

  for (i = 0; i < 5; i++)
    {
      if (y)
	{
	  ASSERT (n_left > 0);
	  n_left--;
	  y->vector[i] = y->scalar + i;
	}
    }
  if (y)
    vlib_put_next_frame (vm, rt, /* next index */ 0, n_left);

  if (verbose)
    vlib_cli_output (vm, "%v: return frame %p", node->name, f);

  return i;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (my_node1,static) = {
  .function = my_func,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "my-node1",
  .scalar_size = sizeof (my_frame_t),
  .vector_size = STRUCT_SIZE_OF (my_frame_t, vector[0]),
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "my-node2",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (my_node2,static) = {
  .function = my_func,
  .name = "my-node2",
  .scalar_size = sizeof (my_frame_t),
  .vector_size = STRUCT_SIZE_OF (my_frame_t, vector[0]),
};
/* *INDENT-ON* */

#endif

#if 0

typedef enum
{
  MY_EVENT_TYPE1,
  MY_EVENT_TYPE2,
} my_process_completion_type_t;

typedef struct
{
  int a;
  f64 b;
} my_process_event_data_t;

static u8 *
format_my_process_event_data (u8 * s, va_list * va)
{
  my_process_event_data_t *d = va_arg (*va, my_process_event_data_t *);
  return format (s, "{ a %d b %.6f}", d->a, d->b);
}

static uword
my_proc (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vlib_node_t *node;
  u32 i;

  node = vlib_get_node (vm, rt->node_index);

  vlib_cli_output (vm, "%v: call frame %p", node->name, f);

  for (i = 0; i < 5; i++)
    {
      vlib_cli_output (vm, "%v: %d", node->name, i);
      vlib_process_suspend (vm, 1e0 /* secs */ );
    }

  vlib_cli_output (vm, "%v: return frame %p", node->name, f);

  if (0)
    {
      uword n_events_seen, type, *data = 0;

      for (n_events_seen = 0; n_events_seen < 2;)
	{
	  vlib_process_wait_for_event (vm);
	  type = vlib_process_get_events (vm, &data);
	  n_events_seen += vec_len (data);
	  vlib_cli_output (vm, "%U %v: completion #%d type %d data 0x%wx",
			   format_time_interval, "h:m:s:u",
			   vlib_time_now (vm), node->name, i, type, data[0]);
	  _vec_len (data) = 0;
	}

      vec_free (data);
    }
  else
    {
      uword n_events_seen, i, type;
      my_process_event_data_t *data;
      for (n_events_seen = 0; n_events_seen < 2;)
	{
	  vlib_process_wait_for_event (vm);
	  data = vlib_process_get_event_data (vm, &type);
	  vec_foreach_index (i, data)
	  {
	    vlib_cli_output (vm, "%U event type %d data %U",
			     format_time_interval, "h:m:s:u",
			     vlib_time_now (vm), type,
			     format_my_process_event_data, data);
	  }
	  n_events_seen += vec_len (data);
	  vlib_process_put_event_data (vm, data);
	}
    }

  return i;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (my_proc_node,static) = {
  .function = my_proc,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "my-proc",
};
/* *INDENT-ON* */

static uword
my_proc_input (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  static int i;

  if (i++ < 2)
    {
      if (0)
	vlib_process_signal_event (vm, my_proc_node.index,
				   i == 1 ? MY_EVENT_TYPE1 : MY_EVENT_TYPE2,
				   0x12340000 + i);
      else
	{
	  my_process_event_data_t *d;
	  f64 dt = 5;
	  d = vlib_process_signal_event_at_time (vm,
						 i * dt,
						 my_proc_node.index,
						 i ==
						 1 ? MY_EVENT_TYPE1 :
						 MY_EVENT_TYPE2,
						 1 /* elts */ ,
						 sizeof (d[0]));
	  d->a = i;
	  d->b = vlib_time_now (vm);
	}
    }
  else
    vlib_node_set_state (vm, rt->node_index, VLIB_NODE_STATE_DISABLED);

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (my_proc_input_node,static) = {
  .function = my_proc_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "my-proc-input",
};
/* *INDENT-ON* */

static uword
_unformat_farith (unformat_input_t * i, va_list * args)
{
  u32 prec = va_arg (*args, u32);
  f64 *result = va_arg (*args, f64 *);
  f64 tmp[2];

  /* Binary operations in from lowest to highest precedence. */
  char *binops[] = {
    "+%U", "-%U", "/%U", "*%U", "^%U",
  };

  if (prec <= ARRAY_LEN (binops) - 1
      && unformat_user (i, _unformat_farith, prec + 1, &tmp[0]))
    {
      int p;
      for (p = prec; p < ARRAY_LEN (binops); p++)
	{
	  if (unformat (i, binops[p], _unformat_farith, prec + 0, &tmp[1]))
	    {
	      switch (binops[p][0])
		{
		case '+':
		  result[0] = tmp[0] + tmp[1];
		  break;
		case '-':
		  result[0] = tmp[0] - tmp[1];
		  break;
		case '/':
		  result[0] = tmp[0] / tmp[1];
		  break;
		case '*':
		  result[0] = tmp[0] * tmp[1];
		  break;
		case '^':
		  result[0] = pow (tmp[0], tmp[1]);
		  break;
		default:
		  abort ();
		}
	      return 1;
	    }
	}
      result[0] = tmp[0];
      return 1;
    }

  else if (unformat (i, "-%U", _unformat_farith, prec + 0, &tmp[0]))
    {
      result[0] = -tmp[0];
      return 1;
    }

  else if (unformat (i, "(%U)", _unformat_farith, 0, &tmp[0]))
    {
      result[0] = tmp[0];
      return 1;
    }

  else if (unformat (i, "%f", result))
    return 1;

  else
    return 0;
}

static uword
unformat_farith (unformat_input_t * i, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  f64 *result = va_arg (*args, f64 *);
  return unformat_user (i, _unformat_farith, 0, result);
}

static uword
unformat_integer (unformat_input_t * i, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  u32 *data = va_arg (*args, u32 *);
  return unformat (i, "%d", data);
}

static VLIB_CLI_PARSE_RULE (my_parse_rule1) =
{
.name = "decimal_integer",.short_help =
    "a decimal integer",.unformat_function = unformat_integer,.data_size =
    sizeof (u32),};

static VLIB_CLI_PARSE_RULE (my_parse_rule2) =
{
.name = "float_expression",.short_help =
    "floating point expression",.unformat_function =
    unformat_farith,.data_size = sizeof (f64),};

static clib_error_t *
bar_command (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  switch (cmd->function_arg)
    {
    case 2:
      {
	u32 *d, *e;
	d = vlib_cli_get_parse_rule_result (vm, 0);
	e = vlib_cli_get_parse_rule_result (vm, 1);
	vlib_cli_output (vm, "bar2 %d %d", d[0], e[0]);
	break;
      }

    case 1:
      {
	u32 *d = vlib_cli_get_parse_rule_result (vm, 0);
	vlib_cli_output (vm, "bar1 %d", d[0]);
	break;
      }

    case 3:
      {
	f64 *d = vlib_cli_get_parse_rule_result (vm, 0);
	vlib_cli_output (vm, "expr %.6f", d[0]);
      }
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bar_command2, static) = {
  .path = "bar %decimal_integer",
  .short_help = "bar1 command",
  .function = bar_command,
  .function_arg = 1,
};
VLIB_CLI_COMMAND (bar_command1, static) = {
  .path = "bar %decimal_integer %decimal_integer",
  .short_help = "bar2 command",
  .function = bar_command,
  .function_arg = 2,
};
VLIB_CLI_COMMAND (bar_command3, static) = {
  .path = "zap %float_expression",
  .short_help = "bar3 command",
  .function = bar_command,
  .function_arg = 3,
};
/* *INDENT-ON* */

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
