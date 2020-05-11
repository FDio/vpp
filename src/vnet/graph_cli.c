/* Hey Emacs use -*- mode: C -*- */
/*
 * Copyright 2020 Rubicon Communications, LLC.
 *
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

#include <sys/socket.h>
#include <linux/if.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/format_fns.h>

#include <vnet/graph.h>
#include <vnet/graph.api_enum.h>
#include <vnet/graph.api_types.h>

static void graph_node_print (vlib_main_t *vm, vlib_node_t *n)
{
  vlib_cli_output (vm, "Node (%4d): %v\n", n->index, n->name);
}


static int
node_cmp (void *a1, void *a2)
{
  vlib_node_t **n1 = a1;
  vlib_node_t **n2 = a2;

  return vec_cmp (n1[0]->name, n2[0]->name);
}

static clib_error_t *
graph_node_show_cmd (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *n;
  u32 index;
  u8 *name = 0;

  index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "node %d", &index))
	{
	  n = vlib_get_node (vm, index);
	  graph_node_print (vm, n);
	  return 0;
	}
      else if (unformat (input, "node %v", &name))
	{
	  n = vlib_get_node_by_name (vm, name);
	  vlib_cli_output(vm, "vec len is %d\n", vec_len(name));
	  graph_node_print (vm, n);
	  return 0;
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  vlib_node_t **nodes = vec_dup (nm->nodes);
  uword i;

  vec_sort_with_function (nodes, node_cmp);

  for (i = 0; i < vec_len (nodes); ++i)
    {
      graph_node_print (vm, nodes[i]);
    }

  vec_free (nodes);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (graph_node_show_command, static) = {
  .path = "show graph",
  .short_help = "show graph [node <index>|<name>]",
  .function = graph_node_show_cmd,
};
/* *INDENT-ON* */


/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
