/*
 * Copyright (c) 2020 cisco
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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vppinfra/time_range.h>
#include <vnet/ethernet/ethernet.h>
#include <vpp-api/client/stat_client.h>

#define __plugin_msg_base graph_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#include <vnet/format_fns.h>
#include <tracedump/graph.api_enum.h>
#include <tracedump/graph.api_types.h>
#include <vpp/api/vpe.api_types.h>

typedef struct
{
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} graph_test_main_t;

graph_test_main_t graph_test_main;


uword
api_unformat_node_index (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);

  return unformat (input, "%u", result);
}


static void
vl_api_graph_node_get_reply_t_handler (vl_api_graph_node_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;

  clib_warning ("Next node index: %u\n", mp->cursor);
  vam->result_ready = 1;
}

int
api_graph_node_get (vat_main_t * vam)
{
  graph_test_main_t *gtm = &graph_test_main;
  unformat_input_t *i = vam->input;
  vl_api_graph_node_get_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 node_index;
  char *node_name;
  u32 flags;
  bool want_arcs;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for graph_node_get");
      return -99;
    }

  node_index = ~0;
  node_name = 0;
  flags = 0;
  want_arcs = false;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "node_index %u", &node_index))
	;
      else if (unformat (i, "node_name %s", &node_name))
	;
      else if (unformat (i, "want_arcs"))
	want_arcs = true;
      else if (unformat (i, "trace_supported"))
	flags |= NODE_FLAG_TRACE_SUPPORTED;
      else if (unformat (i, "input"))
	flags |= NODE_FLAG_TRACE_SUPPORTED;
      else if (unformat (i, "drop"))
	flags |= NODE_FLAG_IS_DROP;
      else if (unformat (i, "ouptput"))
	flags |= NODE_FLAG_IS_OUTPUT;
      else if (unformat (i, "punt"))
	flags |= NODE_FLAG_IS_PUNT;
      else if (unformat (i, "handoff"))
	flags |= NODE_FLAG_IS_HANDOFF;
      else if (unformat (i, "no_free"))
	flags |= NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH;
      else if (unformat (i, "polling"))
	flags |= NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE;
      else if (unformat (i, "interrupt"))
	flags |= NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE;
      else
	{
	  clib_warning ("Unknown input: %U\n", format_unformat_error, i);
	  return -99;
	}
    }

  M (GRAPH_NODE_GET, mp);
  mp->index = htonl (node_index);
  mp->flags = htonl (flags);
  mp->want_arcs = want_arcs;

  if (node_name && node_name[0])
    clib_strncpy ((char *) mp->name, node_name, sizeof (mp->name) - 1);

  int ret = 0;
  S (mp);

  if (!gtm->ping_id)
    gtm->ping_id =
      vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));

  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (gtm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  S (mp_ping);
  W (ret);

  return ret;
}

void
vl_api_graph_node_details_t_handler (vl_api_graph_node_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 n_arcs;
  int i;

  fformat (vam->ofp,
	   "Node: %s  Index:%d  Flags:0x%x\n",
	   mp->name, ntohl (mp->index), ntohl (mp->flags));

  n_arcs = ntohl (mp->n_arcs);
  for (i = 0; i < n_arcs; ++i)
    {
      u32 node_index = ntohl (mp->arcs_out[i]);
      fformat (vam->ofp, "    next: %d\n", node_index);
    }
}

void
vl_api_graph_node_details_t_handler_json (vl_api_graph_node_details_t * mp)
{
  clib_error ("graph_node_details JSON not supported");
}

/* Override generated plugin register symbol */
#define vat_plugin_register graph_test_vat_plugin_register
#include <tracedump/graph.api_test.c>

static clib_error_t *
graph_api_hookup_shim (vlib_main_t * vm)
{
  graph_test_vat_plugin_register (&vat_main);
  return 0;
}

VLIB_API_INIT_FUNCTION (graph_api_hookup_shim);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
