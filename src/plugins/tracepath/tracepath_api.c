/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <tracepath/tracepath.h>
#include <vlib/node_funcs.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#include <tracepath/tracepath.api_enum.h>
#include <tracepath/tracepath.api_types.h>

static u32 tracepath_base_msg_id;

#define REPLY_MSG_ID_BASE (tracepath_base_msg_id)
#include <vlibapi/api_helper_macros.h>

static void
vl_api_tracepath_dump_t_handler (vl_api_tracepath_dump_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (!rp)
    return;

  trace_path_t *merged_paths = trace_paths_collect_all ();
  trace_path_t *p;

  vec_foreach (p, merged_paths)
    {
      u32 n_nodes = vec_len (p->path_indices);
      size_t msg_size =
	sizeof (vl_api_tracepath_details_t) + n_nodes * sizeof (vl_api_trace_path_node_t);

      vl_api_tracepath_details_t *rmp = vl_msg_api_alloc (msg_size);
      clib_memset (rmp, 0, msg_size);

      /* TODO: Sending back the thread bitmap over API currently only support first 64 threads */
      rmp->_vl_msg_id = ntohs (VL_API_TRACEPATH_DETAILS + tracepath_base_msg_id);
      rmp->context = mp->context;
      rmp->path_id = clib_host_to_net_u64 (p->path_id);
      rmp->n_pkts = htonl (p->n_pkts);
      rmp->thread_bitmap = clib_host_to_net_u64 ((p->thread_bitmap ? p->thread_bitmap[0] : 0));
      rmp->n_nodes = htonl (n_nodes);

      for (u32 i = 0; i < n_nodes; i++)
	{
	  vlib_node_t *node = vlib_get_node (vm, p->path_indices[i]);
	  u32 name_len = clib_min (vec_len (node->name), sizeof (rmp->nodes[i].name) - 1);
	  clib_memcpy (rmp->nodes[i].name, node->name, name_len);
	}

      vl_api_send_msg (rp, (u8 *) rmp);

      vec_free (p->path_indices);
      clib_bitmap_free (p->thread_bitmap);
    }

  vec_free (merged_paths);
}

#include <tracepath/tracepath.api.c>

static clib_error_t *
tracepath_api_init (vlib_main_t *vm)
{
  tracepath_base_msg_id = setup_message_id_table ();
  return 0;
}

VLIB_INIT_FUNCTION (tracepath_api_init);
