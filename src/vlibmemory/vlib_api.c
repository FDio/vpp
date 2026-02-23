/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

/* vlib_api.c VLIB API implementation */

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/api_errno.h>

#include <vlibmemory/vlib.api_enum.h>
#include <vlibmemory/vlib.api_types.h>

static u16 msg_id_base;
#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
shmem_cli_output (uword arg, u8 *buffer, uword buffer_bytes)
{
  u8 **shmem_vecp = (u8 **) arg;
  u8 *shmem_vec;
  void *oldheap;
  u32 offset;

  shmem_vec = *shmem_vecp;

  offset = vec_len (shmem_vec);

  oldheap = vl_msg_push_heap ();

  vec_validate (shmem_vec, offset + buffer_bytes - 1);

  clib_memcpy (shmem_vec + offset, buffer, buffer_bytes);

  vl_msg_pop_heap (oldheap);

  *shmem_vecp = shmem_vec;
}

static void
vl_api_cli_t_handler (vl_api_cli_t *mp)
{
  vl_api_cli_reply_t *rp;
  vl_api_registration_t *reg;
  vlib_main_t *vm = vlib_get_main ();
  unformat_input_t input;
  u8 *shmem_vec = 0;
  void *oldheap;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  ;

  rp = vl_msg_api_alloc (sizeof (*rp));
  rp->_vl_msg_id = ntohs (VL_API_CLI_REPLY + REPLY_MSG_ID_BASE);
  rp->context = mp->context;

  unformat_init_vector (&input, (u8 *) (uword) mp->cmd_in_shmem);

  vlib_cli_input (vm, &input, shmem_cli_output, (uword) &shmem_vec);

  oldheap = vl_msg_push_heap ();
  vec_add1 (shmem_vec, 0);
  vl_msg_pop_heap (oldheap);

  rp->reply_in_shmem = (uword) shmem_vec;

  vl_api_send_msg (reg, (u8 *) rp);
}

static void
inband_cli_output (uword arg, u8 *buffer, uword buffer_bytes)
{
  u8 **mem_vecp = (u8 **) arg;
  u8 *mem_vec = *mem_vecp;
  u32 offset = vec_len (mem_vec);

  vec_validate (mem_vec, offset + buffer_bytes - 1);
  clib_memcpy (mem_vec + offset, buffer, buffer_bytes);
  *mem_vecp = mem_vec;
}

static void
vl_api_cli_inband_t_handler (vl_api_cli_inband_t *mp)
{
  vl_api_cli_inband_reply_t *rmp;
  int rv = 0;
  vlib_main_t *vm = vlib_get_main ();
  unformat_input_t input;
  u8 *out_vec = 0;
  u8 *cmd_vec = 0;

  if (vl_msg_api_get_msg_length (mp) <
      vl_api_string_len (&mp->cmd) + sizeof (*mp))
    {
      rv = -1;
      goto error;
    }

  cmd_vec = vl_api_from_api_to_new_vec (mp, &mp->cmd);

  unformat_init_string (&input, (char *) cmd_vec,
			vl_api_string_len (&mp->cmd));
  rv = vlib_cli_input (vm, &input, inband_cli_output, (uword) &out_vec);
  unformat_free (&input);

error:
  REPLY_MACRO3 (VL_API_CLI_INBAND_REPLY, vec_len (out_vec),
		({ vl_api_vec_to_api_string (out_vec, &rmp->reply); }));
  vec_free (out_vec);
  vec_free (cmd_vec);
}

static void
vl_api_get_node_index_t_handler (vl_api_get_node_index_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_get_node_index_reply_t *rmp;
  vlib_node_t *n;
  int rv = 0;
  u32 node_index = ~0;

  n = vlib_get_node_by_name (vm, mp->node_name);

  if (n == 0)
    rv = VNET_API_ERROR_NO_SUCH_NODE;
  else
    node_index = n->index;

  REPLY_MACRO2 (VL_API_GET_NODE_INDEX_REPLY,
		({ rmp->node_index = htonl (node_index); }));
}

static void
vl_api_add_node_next_t_handler (vl_api_add_node_next_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_add_node_next_reply_t *rmp;
  vlib_node_t *n, *next;
  int rv = 0;
  u32 next_index = ~0;

  n = vlib_get_node_by_name (vm, mp->node_name);

  if (n == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto out;
    }

  next = vlib_get_node_by_name (vm, mp->next_name);

  if (next == 0)
    rv = VNET_API_ERROR_NO_SUCH_NODE2;
  else
    next_index = vlib_node_add_next (vm, n->index, next->index);

out:
  REPLY_MACRO2 (VL_API_ADD_NODE_NEXT_REPLY,
		({ rmp->next_index = htonl (next_index); }));
}

static void
get_thread_data (vl_api_thread_data_t *td, int index)
{
  vlib_worker_thread_t *w = vlib_worker_threads + index;
  td->id = htonl (index);
  if (w->name)
    strncpy ((char *) td->name, (char *) w->name, ARRAY_LEN (td->name) - 1);
  if (w->registration)
    strncpy ((char *) td->type, (char *) w->registration->name,
	     ARRAY_LEN (td->type) - 1);
  td->pid = htonl (w->lwp);
  td->cpu_id = htonl (w->cpu_id);
  td->core = htonl (w->core_id);
  td->cpu_socket = htonl (w->numa_id);
}

static void
vl_api_show_threads_t_handler (vl_api_show_threads_t *mp)
{
  int count = 0;

#if !defined(__powerpc64__)
  vl_api_registration_t *reg;
  vl_api_show_threads_reply_t *rmp;
  vl_api_thread_data_t *td;
  int i, msg_size = 0;
  count = vec_len (vlib_worker_threads);
  if (!count)
    return;

  msg_size = sizeof (*rmp) + sizeof (rmp->thread_data[0]) * count;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id = htons (VL_API_SHOW_THREADS_REPLY + REPLY_MSG_ID_BASE);
  rmp->context = mp->context;
  rmp->count = htonl (count);
  td = rmp->thread_data;

  for (i = 0; i < count; i++)
    {
      get_thread_data (&td[i], i);
    }

  vl_api_send_msg (reg, (u8 *) rmp);
#else

  /* unimplemented support */
  rv = -9;
  clib_warning ("power pc does not support show threads api");
  REPLY_MACRO2 (VL_API_SHOW_THREADS_REPLY, ({ rmp->count = htonl (count); }));
#endif
}

static void
vl_api_get_node_graph_t_handler (vl_api_get_node_graph_t *mp)
{
  int rv = 0;
  u8 *vector = 0;
  vlib_main_t *vm = vlib_get_main ();
  void *oldheap;
  vl_api_get_node_graph_reply_t *rmp;
  static vlib_node_t ***node_dups;
  static vlib_main_t **stat_vms;

  oldheap = vl_msg_push_heap ();

  /*
   * Keep the number of memcpy ops to a minimum (e.g. 1).
   */
  vec_validate (vector, 16384);
  vec_reset_length (vector);

  vlib_node_get_nodes (vm, 0 /* main threads */, 0 /* include stats */,
		       1 /* barrier sync */, &node_dups, &stat_vms);
  vector = vlib_node_serialize (vm, node_dups, vector, 1 /* include nexts */,
				1 /* include stats */);

  vl_msg_pop_heap (oldheap);

  REPLY_MACRO2 (VL_API_GET_NODE_GRAPH_REPLY,
		({ rmp->reply_in_shmem = (uword) vector; }));
}

static void
vl_api_get_next_index_t_handler (vl_api_get_next_index_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_get_next_index_reply_t *rmp;
  vlib_node_t *node, *next_node;
  int rv = 0;
  u32 next_node_index = ~0, next_index = ~0;
  uword *p;

  node = vlib_get_node_by_name (vm, mp->node_name);

  if (node == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto out;
    }

  next_node = vlib_get_node_by_name (vm, mp->next_name);

  if (next_node == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE2;
      goto out;
    }
  else
    next_node_index = next_node->index;

  p = hash_get (node->next_slot_by_node, next_node_index);

  if (p == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto out;
    }
  else
    next_index = p[0];

out:
  REPLY_MACRO2 (VL_API_GET_NEXT_INDEX_REPLY,
		({ rmp->next_index = htonl (next_index); }));
}

static void
vl_api_get_f64_endian_value_t_handler (vl_api_get_f64_endian_value_t *mp)
{
  int rv = 0;
  f64 one = 1.0;
  vl_api_get_f64_endian_value_reply_t *rmp;
  if (1.0 != clib_net_to_host_f64 (mp->f64_one))
    rv = VNET_API_ERROR_API_ENDIAN_FAILED;

  REPLY_MACRO2 (VL_API_GET_F64_ENDIAN_VALUE_REPLY,
		({ rmp->f64_one_result = clib_host_to_net_f64 (one); }));
}

static void
vl_api_get_f64_increment_by_one_t_handler (
  vl_api_get_f64_increment_by_one_t *mp)
{
  int rv = 0;
  vl_api_get_f64_increment_by_one_reply_t *rmp;

  REPLY_MACRO2 (VL_API_GET_F64_INCREMENT_BY_ONE_REPLY, ({
		  rmp->f64_value = clib_host_to_net_f64 (
		    clib_net_to_host_f64 (mp->f64_value) + 1.0);
		}));
}

#include <vlibmemory/vlib.api.c>
static clib_error_t *
vlib_apis_hookup (vlib_main_t *vm)
{
  api_main_t *am = vlibapi_get_main ();

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  msg_id_base = setup_message_id_table ();

  /* Mark messages as mp safe */
  vl_api_set_msg_thread_safe (am, msg_id_base + VL_API_CLI_INBAND, 1);
  vl_api_set_msg_thread_safe (am, msg_id_base + VL_API_GET_NODE_GRAPH, 1);
  vl_api_set_msg_thread_safe (am, msg_id_base + VL_API_SHOW_THREADS, 1);

  return 0;
}

VLIB_API_INIT_FUNCTION (vlib_apis_hookup);
