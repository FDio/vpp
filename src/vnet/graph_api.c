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
#include <vlibmemory/api.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#include <vnet/graph.h>


#define MIN(x,y)	(((x) < (y)) ? (x) : (y))


static void
send_graph_node_details (vlib_node_main_t * nm,
			 vl_api_registration_t * reg,
			 u32 context, vlib_node_t * n, bool want_arcs)
{
  vl_api_graph_node_details_t *mp;
  u32 msg_size;

  msg_size = sizeof (*mp);
  if (want_arcs)
    msg_size += vec_len (n->next_nodes) * sizeof (*n->next_nodes);

  mp = vl_msg_api_alloc (msg_size);
  if (!mp)
    return;

  clib_memset (mp, 0, msg_size);

  mp->_vl_msg_id = ntohs (VL_API_GRAPH_NODE_DETAILS);
  mp->context = context;
  mp->index = htonl (n->index);
  mp->flags = htonl (n->flags);

  clib_strncpy ((char *) mp->name, (char *) n->name,
		MIN (sizeof (mp->name) - 1, vec_len (n->name)));

  if (want_arcs)
    {
      int i;

      mp->n_arcs = htonl (vec_len (n->next_nodes));
      for (i = 0; i < vec_len (n->next_nodes); ++i)
	{
	  mp->arcs_out[i] = htonl (n->next_nodes[i]);
	}
    }

  vl_api_send_msg (reg, (u8 *) mp);
}


static int
node_cmp (void *a1, void *a2)
{
  vlib_node_t **n1 = a1;
  vlib_node_t **n2 = a2;

  return vec_cmp (n1[0]->name, n2[0]->name);
}


/*
 * if index == ~0 and name[0] == 0 and flag == 0, dump all nodes
 * if index != ~0, dump node with given index
 * if index == ~0 and name given, dump node with given name
 * if index == ~0 and name[0] == 0, dump nodes matching 'flag'
 */
static void
vl_api_graph_node_dump_t_handler (vl_api_graph_node_dump_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_main_t *nm = &vm->node_main;
  vl_api_registration_t *reg;
  vlib_node_t *n;
  u32 node_index;
  bool want_arcs;
  u32 i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  want_arcs = ! !mp->want_arcs;

  node_index = ntohl (mp->index);
  if (node_index != ~0)
    {
      if (node_index >= vec_len (nm->nodes))
	return;

      n = vlib_get_node (vm, node_index);
      if (n)
	send_graph_node_details (nm, reg, mp->context, n, want_arcs);
      return;
    }

  if (mp->name[0] != 0)
    {
      n = vlib_get_node_by_name (vm, (u8 *) mp->name);
      if (n)
	send_graph_node_details (nm, reg, mp->context, n, want_arcs);
      return;
    }

  u32 flags = ntohl (mp->flags);

  vlib_node_t **nodes = vec_dup (nm->nodes);
  vec_sort_with_function (nodes, node_cmp);

  for (i = 0; i < vec_len (nodes); ++i)
    {
      n = nodes[i];
      if (flags == 0 || (n->flags & flags))
	send_graph_node_details (nm, reg, mp->context, n, want_arcs);
    }

  vec_free (nodes);
}


#define vl_msg_name_crc_list
#include <vnet/graph.api.h>
#undef vl_msg_name_crc_list


static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_graph;
#undef _
}


#define foreach_vpe_api_msg		  \
  _(GRAPH_NODE_DUMP, graph_node_dump)	  \

static clib_error_t *
graph_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

#define _(N,n)						      \
  vl_msg_api_set_handlers(VL_API_##N, #n,                     \
			  vl_api_##n##_t_handler,	      \
			  vl_noop_handler,		      \
			  vl_api_##n##_t_endian,	      \
			  vl_api_##n##_t_print,		      \
			  sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  setup_message_id_table (am);

  return 0;
}

VLIB_INIT_FUNCTION (graph_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
