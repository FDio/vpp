/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <vpp/api/types.h>
#include <vnet/mpls/packet.h>
#include <vnet/ip/ip_types_api.h>

typedef struct
{
  u16 msg_id_base;
  vat_main_t *vat_main;
} vlib_test_main_t;
vlib_test_main_t vlib_test_main;

#define __plugin_msg_base vlib_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <vlibmemory/vlib.api_enum.h>
#include <vlibmemory/vlib.api_types.h>

static void
vl_api_cli_reply_t_handler (vl_api_cli_reply_t *mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  vam->retval = retval;
  vam->shmem_result = uword_to_pointer (mp->reply_in_shmem, u8 *);
  vam->result_ready = 1;
}

static void
vl_api_cli_inband_reply_t_handler (vl_api_cli_inband_reply_t *mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  vec_reset_length (vam->cmd_reply);

  vam->retval = retval;
  if (retval == 0)
    vam->cmd_reply = vl_api_from_api_to_new_vec (mp, &mp->reply);
  vam->result_ready = 1;
}

static void
vl_api_get_node_index_reply_t_handler (vl_api_get_node_index_reply_t *mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      if (retval == 0)
	errmsg ("node index %d", ntohl (mp->node_index));
      vam->result_ready = 1;
    }
}

static void
vl_api_get_next_index_reply_t_handler (vl_api_get_next_index_reply_t *mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      if (retval == 0)
	errmsg ("next node index %d", ntohl (mp->next_index));
      vam->result_ready = 1;
    }
}

static void
vl_api_add_node_next_reply_t_handler (vl_api_add_node_next_reply_t *mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      if (retval == 0)
	errmsg ("next index %d", ntohl (mp->next_index));
      vam->result_ready = 1;
    }
}

static void
vl_api_get_f64_endian_value_reply_t_handler (
  vl_api_get_f64_endian_value_reply_t *mp)
{
  // not yet implemented
}

static void
vl_api_get_f64_increment_by_one_reply_t_handler (
  vl_api_get_f64_increment_by_one_reply_t *mp)
{
  // not yet implemented
}

static int
api_get_f64_endian_value (vat_main_t *vam)
{
  // not yet implemented
  return -1;
}

static int
api_get_f64_increment_by_one (vat_main_t *vam)
{
  // not yet implemented
  return -1;
}

/*
 * Pass CLI buffers directly in the CLI_INBAND API message,
 * instead of an additional shared memory area.
 */
static int
exec_inband (vat_main_t *vam)
{
  vl_api_cli_inband_t *mp;
  unformat_input_t *i = vam->input;
  int ret;

  if (vec_len (i->buffer) == 0)
    return -1;

  if (vam->exec_mode == 0 && unformat (i, "mode"))
    {
      vam->exec_mode = 1;
      return 0;
    }
  if (vam->exec_mode == 1 && (unformat (i, "exit") || unformat (i, "quit")))
    {
      vam->exec_mode = 0;
      return 0;
    }

  /*
   * In order for the CLI command to work, it
   * must be a vector ending in \n, not a C-string ending
   * in \n\0.
   */
  M2 (CLI_INBAND, mp, vec_len (vam->input->buffer));
  vl_api_vec_to_api_string (vam->input->buffer, &mp->cmd);

  S (mp);
  W (ret);
  /* json responses may or may not include a useful reply... */
  if (vec_len (vam->cmd_reply))
    print (vam->ofp, "%v", (char *) (vam->cmd_reply));
  return ret;
}
static int
api_cli_inband (vat_main_t *vam)
{
  return exec_inband (vam);
}

int
exec (vat_main_t *vam)
{
  return exec_inband (vam);
}

static int
api_cli (vat_main_t *vam)
{
  return exec_inband (vam);
}

static int
api_get_node_index (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_get_node_index_t *mp;
  u8 *name = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "node %s", &name))
	;
      else
	break;
    }
  if (name == 0)
    {
      errmsg ("node name required");
      return -99;
    }
  if (vec_len (name) >= ARRAY_LEN (mp->node_name))
    {
      errmsg ("node name too long, max %d", ARRAY_LEN (mp->node_name));
      return -99;
    }

  M (GET_NODE_INDEX, mp);
  clib_memcpy (mp->node_name, name, vec_len (name));
  vec_free (name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_get_next_index (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_get_next_index_t *mp;
  u8 *node_name = 0, *next_node_name = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "node-name %s", &node_name))
	;
      else if (unformat (i, "next-node-name %s", &next_node_name))
	break;
    }

  if (node_name == 0)
    {
      errmsg ("node name required");
      return -99;
    }
  if (vec_len (node_name) >= ARRAY_LEN (mp->node_name))
    {
      errmsg ("node name too long, max %d", ARRAY_LEN (mp->node_name));
      return -99;
    }

  if (next_node_name == 0)
    {
      errmsg ("next node name required");
      return -99;
    }
  if (vec_len (next_node_name) >= ARRAY_LEN (mp->next_name))
    {
      errmsg ("next node name too long, max %d", ARRAY_LEN (mp->next_name));
      return -99;
    }

  M (GET_NEXT_INDEX, mp);
  clib_memcpy (mp->node_name, node_name, vec_len (node_name));
  clib_memcpy (mp->next_name, next_node_name, vec_len (next_node_name));
  vec_free (node_name);
  vec_free (next_node_name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_add_node_next (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_add_node_next_t *mp;
  u8 *name = 0;
  u8 *next = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "node %s", &name))
	;
      else if (unformat (i, "next %s", &next))
	;
      else
	break;
    }
  if (name == 0)
    {
      errmsg ("node name required");
      return -99;
    }
  if (vec_len (name) >= ARRAY_LEN (mp->node_name))
    {
      errmsg ("node name too long, max %d", ARRAY_LEN (mp->node_name));
      return -99;
    }
  if (next == 0)
    {
      errmsg ("next node required");
      return -99;
    }
  if (vec_len (next) >= ARRAY_LEN (mp->next_name))
    {
      errmsg ("next name too long, max %d", ARRAY_LEN (mp->next_name));
      return -99;
    }

  M (ADD_NODE_NEXT, mp);
  clib_memcpy (mp->node_name, name, vec_len (name));
  clib_memcpy (mp->next_name, next, vec_len (next));
  vec_free (name);
  vec_free (next);

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_show_threads_reply_t_handler (vl_api_show_threads_reply_t *mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  int i, count = 0;

  if (retval >= 0)
    count = ntohl (mp->count);

  for (i = 0; i < count; i++)
    print (vam->ofp, "\n%-2d %-11s %-11s %-5d %-6d %-4d %-6d",
	   ntohl (mp->thread_data[i].id), mp->thread_data[i].name,
	   mp->thread_data[i].type, ntohl (mp->thread_data[i].pid),
	   ntohl (mp->thread_data[i].cpu_id), ntohl (mp->thread_data[i].core),
	   ntohl (mp->thread_data[i].cpu_socket));

  vam->retval = retval;
  vam->result_ready = 1;
}

static int
api_show_threads (vat_main_t *vam)
{
  vl_api_show_threads_t *mp;
  int ret;

  print (vam->ofp, "\n%-2s %-11s %-11s %-5s %-6s %-4s %-6s", "ID", "Name",
	 "Type", "LWP", "cpu_id", "Core", "Socket");

  M (SHOW_THREADS, mp);

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_get_node_graph_reply_t_handler (vl_api_get_node_graph_reply_t *mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  u8 *pvt_copy, *reply;
  void *oldheap;
  vlib_node_t *node;
  int i;

  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }

  /* "Should never happen..." */
  if (retval != 0)
    return;

  reply = uword_to_pointer (mp->reply_in_shmem, u8 *);
  pvt_copy = vec_dup (reply);

  /* Toss the shared-memory original... */
  oldheap = vl_msg_push_heap ();

  vec_free (reply);

  vl_msg_pop_heap (oldheap);

  if (vam->graph_nodes)
    {
      hash_free (vam->graph_node_index_by_name);

      for (i = 0; i < vec_len (vam->graph_nodes[0]); i++)
	{
	  node = vam->graph_nodes[0][i];
	  vec_free (node->name);
	  vec_free (node->next_nodes);
	  vec_free (node);
	}
      vec_free (vam->graph_nodes[0]);
      vec_free (vam->graph_nodes);
    }

  vam->graph_node_index_by_name = hash_create_string (0, sizeof (uword));
  vam->graph_nodes = vlib_node_unserialize (pvt_copy);
  vec_free (pvt_copy);

  for (i = 0; i < vec_len (vam->graph_nodes[0]); i++)
    {
      node = vam->graph_nodes[0][i];
      hash_set_mem (vam->graph_node_index_by_name, node->name, i);
    }
}

static int
api_get_node_graph (vat_main_t *vam)
{
  vl_api_get_node_graph_t *mp;
  int ret;

  M (GET_NODE_GRAPH, mp);

  /* send it... */
  S (mp);
  /* Wait for the reply */
  W (ret);
  return ret;
}

#define VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE local_setup_message_id_table
static void
local_setup_message_id_table (vat_main_t *vam)
{
  /* Add exec as an alias for cli_inband */
  hash_set_mem (vam->function_by_name, "exec", api_cli_inband);
  hash_set_mem (vam->help_by_name, "exec",
		"usage: exec <vpe-debug-CLI-command>");
}

#include <vlibmemory/vlib.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
