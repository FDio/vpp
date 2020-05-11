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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <tracedump/graph.api_enum.h>
#include <tracedump/graph.api_types.h>

#define REPLY_MSG_ID_BASE	gmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

#include <tracedump/graph.h>


graph_main_t graph_main;


#define MIN(x,y)	(((x) < (y)) ? (x) : (y))


/*
 * If ever the graph or set of nodes changes, this cache of
 * nodes in sorted order should be invalidated.
 */
void
graph_node_invalid_cache (void)
{
  graph_main_t *gmp = &graph_main;

  vec_free (gmp->sorted_node_vec);
}


static clib_error_t *
graph_node_cache_reaper (u32 client_index)
{
  graph_node_invalid_cache ();
  return 0;
}

VL_MSG_API_REAPER_FUNCTION (graph_node_cache_reaper);


static void
send_graph_node_reply (vl_api_registration_t * rp,
		       u32 context, u32 retval, u32 cursor)
{
  graph_main_t *gmp = &graph_main;
  vl_api_graph_node_get_reply_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_GRAPH_NODE_GET_REPLY + gmp->msg_id_base);
  rmp->context = context;
  rmp->retval = clib_host_to_net_u32 (retval);
  rmp->cursor = htonl (cursor);

  vl_api_send_msg (rp, (u8 *) rmp);
}


static void
send_graph_node_details (vlib_node_main_t * nm,
			 vl_api_registration_t * reg,
			 u32 context, vlib_node_t * n, bool want_arcs)
{
  graph_main_t *gmp = &graph_main;
  vl_api_graph_node_details_t *mp;
  u32 msg_size;

  msg_size = sizeof (*mp);
  if (want_arcs)
    msg_size += vec_len (n->next_nodes) * sizeof (*n->next_nodes);

  mp = vl_msg_api_alloc (msg_size);
  if (!mp)
    return;

  clib_memset (mp, 0, msg_size);

  mp->_vl_msg_id = htons (VL_API_GRAPH_NODE_DETAILS + gmp->msg_id_base);
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
 * When cursor == ~0, it begins a request:
 *    if index != ~0, dump node with given index
 *    if index == ~0 and name[0] != 0, dump node with given name
 *    if index == ~0 and name[0] == 0, and flag != 0, dump flagged nodes
 *    else
 *        index == ~0 and name[0] == 0 and flag == 0, so dump all nodes.
 *
 * When cursor != ~0, it is the middle of a request:
 *    The same (index, name, and flag) parameters are assumed,
 *    The next results resume from cursor.
 */
static void
vl_api_graph_node_get_t_handler (vl_api_graph_node_get_t * mp)
{
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (!rp)
    return;

  vlib_main_t *vm = vlib_get_main ();
  vlib_node_main_t *nm = &vm->node_main;
  graph_main_t *gmp = &graph_main;
  vlib_node_t *n;
  u32 cursor;
  u32 node_index;
  bool want_arcs;

  want_arcs = ! !mp->want_arcs;
  cursor = ntohl (mp->cursor);
  n = 0;

  /*
   * Return details on a specific node by index?
   */
  node_index = ntohl (mp->index);
  if (cursor == ~0 && node_index != ~0)
    {
      if (node_index < vec_len (nm->nodes))
	n = vlib_get_node (vm, node_index);
      if (!n)
	{
	  send_graph_node_reply (rp, mp->context,
				 VNET_API_ERROR_NO_SUCH_ENTRY, ~0);
	  return;
	}
      send_graph_node_details (nm, rp, mp->context, n, want_arcs);
      send_graph_node_reply (rp, mp->context, 0, ~0);
      return;
    }

  /*
   * Return details on a specific node by name?
   */
  if (cursor == ~0 && mp->name[0] != 0)
    {
      n = vlib_get_node_by_name (vm, (u8 *) mp->name);
      if (!n)
	{
	  send_graph_node_reply (rp, mp->context,
				 VNET_API_ERROR_NO_SUCH_ENTRY, ~0);
	  return;
	}

      send_graph_node_details (nm, rp, mp->context, n, want_arcs);
      send_graph_node_reply (rp, mp->context, 0, ~0);
      return;
    }

  /*
   * Inspect all nodes, but potentially limit them by flag selection.
   * As iteration my need to occur over multiple streaming API calls,
   * determine the API client index and cache a sorted list of nodes.
   *
   * First time through, make a sorted node list and cache it.
   */
  vlib_node_t **nodes = gmp->sorted_node_vec;
  if (!nodes)
    {
      nodes = vec_dup (nm->nodes);
      vec_sort_with_function (nodes, node_cmp);
      gmp->sorted_node_vec = nodes;
    }

  u32 flags = ntohl (mp->flags);
  u32 first_index = (cursor == ~0) ? 0 : cursor;

  /* Don't overflow the existing queue space. */
  svm_queue_t *q = rp->vl_input_queue;
  u32 queue_slots_available = q->maxsize - q->cursize;
  int chunk = (queue_slots_available > 0) ? queue_slots_available - 1 : 0;
  u32 i;

  for (i = first_index; i < vec_len (nodes); ++i)
    {
      if (chunk-- == 0)
	{
	  /*
	   * Pick up again at cursor = i.
	   */
	  send_graph_node_reply (rp, mp->context, VNET_API_ERROR_EAGAIN, i);
	  return;
	}

      n = nodes[i];
      if (flags == 0 || (n->flags & flags))
	{
	  send_graph_node_details (nm, rp, mp->context, n, want_arcs);
	}
    }

  send_graph_node_reply (rp, mp->context, 0, ~0);
}


#include <vnet/format_fns.h>
#include <tracedump/graph.api.c>

static clib_error_t *
graph_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();
  graph_main_t *gmp = &graph_main;

  gmp->msg_id_base = setup_message_id_table ();

  am->is_mp_safe[gmp->msg_id_base + VL_API_GRAPH_NODE_GET] = 1;

  am->is_autoendian[gmp->msg_id_base + VL_API_GRAPH_NODE_DETAILS] = 1;

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
