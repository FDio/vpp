/*
 *------------------------------------------------------------------
 * pg_api.c - vnet pg api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/pg/pg.h>

#include <vnet/format_fns.h>
#include <vnet/pg/pg.api_enum.h>
#include <vnet/pg/pg.api_types.h>

#define REPLY_MSG_ID_BASE pg->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_pg_create_interface_t_handler (vl_api_pg_create_interface_t * mp)
{
  vl_api_pg_create_interface_reply_t *rmp;
  int rv = 0;

  pg_main_t *pg = &pg_main;
  u32 pg_if_id =
    pg_interface_add_or_get (pg, ntohl (mp->interface_id), mp->gso_enabled,
			     ntohl (mp->gso_size), 0, PG_MODE_ETHERNET);
  pg_interface_t *pi = pool_elt_at_index (pg->interfaces, pg_if_id);

  REPLY_MACRO2(VL_API_PG_CREATE_INTERFACE_REPLY,
  ({
    rmp->sw_if_index = ntohl(pi->sw_if_index);
  }));
}

static void
vl_api_pg_create_interface_v2_t_handler (vl_api_pg_create_interface_v2_t *mp)
{
  vl_api_pg_create_interface_v2_reply_t *rmp;
  int rv = 0;

  pg_main_t *pg = &pg_main;
  u32 pg_if_id =
    pg_interface_add_or_get (pg, ntohl (mp->interface_id), mp->gso_enabled,
			     ntohl (mp->gso_size), 0, (u8) mp->mode);
  pg_interface_t *pi = pool_elt_at_index (pg->interfaces, pg_if_id);

  REPLY_MACRO2 (VL_API_PG_CREATE_INTERFACE_V2_REPLY,
		({ rmp->sw_if_index = ntohl (pi->sw_if_index); }));
}

static void
vl_api_pg_delete_interface_t_handler (vl_api_pg_delete_interface_t *mp)
{
  vl_api_pg_delete_interface_reply_t *rmp;
  pg_main_t *pg = &pg_main;
  u32 sw_if_index = ~0;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  rv = pg_interface_delete (sw_if_index);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_PG_DELETE_INTERFACE_REPLY);
}

static void
  vl_api_pg_interface_enable_disable_coalesce_t_handler
  (vl_api_pg_interface_enable_disable_coalesce_t * mp)
{
  vl_api_pg_interface_enable_disable_coalesce_reply_t *rmp;
  pg_main_t *pg = &pg_main;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = ntohl (mp->sw_if_index);

  vnet_hw_interface_t *hw =
    vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);

  if (hw)
    {
      pg_interface_t *pi =
	pool_elt_at_index (pg->interfaces, hw->dev_instance);
      if (pi->gso_enabled)
	pg_interface_enable_disable_coalesce (pi, mp->coalesce_enabled,
					      hw->tx_node_index);
      else
	rv = VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE;
    }
  else
    {
      rv = VNET_API_ERROR_NO_MATCHING_INTERFACE;
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE_REPLY);
}

static void
vl_api_pg_zmq_capture_t_handler (vl_api_pg_zmq_capture_t *mp)
{
  pg_main_t *pg = &pg_main;
  vl_api_pg_zmq_capture_reply_t *rmp;
  int rv = 0;
  u16 socket_port = 0;

  u32 pg_if_id = pg_interface_add_or_get (
    pg, ntohl (mp->interface_id), 0 /* gso_enabled */, 0 /* gso_size */,
    0 /* coalesce_enabled */, PG_MODE_ETHERNET);
  pg_interface_t *pi = pool_elt_at_index (pg->interfaces, pg_if_id);
  clib_error_t *error = pg_add_zmq_socket (pi);

  if (error)
    {
      clib_error_report (error);
      rv = VNET_API_ERROR_CANNOT_CREATE_PCAP_FILE;
    }

  socket_port = pi->zmq_socket_port;
  REPLY_MACRO2 (VL_API_PG_ZMQ_CAPTURE_REPLY,
		({ rmp->port = ntohs (socket_port); }));
  // vnet_main_t *vnm = vnet_get_main ();
  // vnet_hw_interface_t *hi = vnet_get_hw_interface(vnm,
  // ntohl(mp->interface_id)); pg_capture_args_t _a, *a = &_a;

  // a->hw_if_index = ntohl (mp->interface_id);
  // a->dev_instance = hi->dev_instance;
  // a->is_enabled = mp->is_enabled;
  // a->count = ntohl (mp->count);

  // clib_error_t *error = pg_zmq_capture (a);

  // if (error)
  // {
  //   clib_error_report (error);
  //   rv = VNET_API_ERROR_CANNOT_CREATE_PCAP_FILE;
  // }

  /* Find an interface to use. */
  // u32 pg_if_id = pg_interface_add_or_get (
  //   pg, ntohl (mp->interface_id), 0 /* gso_enabled */, 0 /* gso_size */,
  //   0 /* coalesce_enabled */, PG_MODE_ETHERNET);
  // pg_interface_t *pi = pool_elt_at_index (pg->interfaces, pg_if_id);
  // socket_port = pi->zmq_socket_port;

  // REPLY_MACRO2 (VL_API_PG_ZMQ_CAPTURE_REPLY, ({
  //   rmp->port = ntohs(socket_port);
  // }));

  // vnet_interface_main_t *im = &vnm->interface_main;

  // u8 *intf_name = format (0, "pg%d", ntohl (mp->interface_id), 0);
  // vec_terminate_c_string (intf_name);
  // u32 hw_if_index = ~0;
  // uword *p = hash_get_mem (im->hw_interface_by_name, intf_name);
  // if (p) {
  //   hw_if_index = *p;
  // }
  // else {
  //   socket_port = ntohl (mp->interface_id);
  // }

  // vec_free (intf_name);

  // if (hw_if_index != ~0)
  //   {
  //     pg_capture_args_t _a, *a = &_a;

  //     hi = vnet_get_sup_hw_interface (vnm, hw_if_index);
  //     a->hw_if_index = hw_if_index;
  //     a->dev_instance = hi->dev_instance;
  //     a->is_enabled = mp->is_enabled;
  //     a->count = ntohl (mp->count);

  //     clib_error_t *e = pg_zmq_capture (a);
  //     if (e)
  // {
  //   clib_error_report (e);
  //   rv = VNET_API_ERROR_CANNOT_CREATE_PCAP_FILE;
  // }
  //     // pg_interface_t *pi = pool_elt_at_index (pg->interfaces,
  //     a->dev_instance);
  //     // socket_port = pi->zmq_socket_port;
  //     socket_port = 2;

  //   }
  // REPLY_MACRO2 (VL_API_PG_ZMQ_CAPTURE_REPLY, ({
  //   rmp->port = ntohs(socket_port);
  // }));
}

static void
vl_api_pg_capture_t_handler (vl_api_pg_capture_t * mp)
{
  pg_main_t *pg = &pg_main;
  vl_api_pg_capture_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi = 0;

  u8 *intf_name = format (0, "pg%d", ntohl (mp->interface_id), 0);
  vec_terminate_c_string (intf_name);
  u32 hw_if_index = ~0;
  uword *p = hash_get_mem (im->hw_interface_by_name, intf_name);
  if (p)
    hw_if_index = *p;
  vec_free (intf_name);

  if (hw_if_index != ~0)
    {
      pg_capture_args_t _a, *a = &_a;
      char *pcap_file_name =
	vl_api_from_api_to_new_c_string (&mp->pcap_file_name);

      hi = vnet_get_sup_hw_interface (vnm, hw_if_index);
      a->hw_if_index = hw_if_index;
      a->dev_instance = hi->dev_instance;
      a->is_enabled = mp->is_enabled;
      a->pcap_file_name = pcap_file_name;
      a->count = ntohl (mp->count);

      clib_error_t *e = pg_capture (a);
      if (e)
	{
	  clib_error_report (e);
	  rv = VNET_API_ERROR_CANNOT_CREATE_PCAP_FILE;
	}

      vec_free (pcap_file_name);
    }
  REPLY_MACRO (VL_API_PG_CAPTURE_REPLY);
}

static void
vl_api_pg_enable_disable_t_handler (vl_api_pg_enable_disable_t * mp)
{
  vl_api_pg_enable_disable_reply_t *rmp;
  int rv = 0;

  pg_main_t *pg = &pg_main;
  u32 stream_index = ~0;

  int is_enable = mp->is_enabled != 0;

  if (vl_api_string_len (&mp->stream_name) > 0)
    {
      u8 *stream_name = vl_api_from_api_to_new_vec (mp, &mp->stream_name);
      uword *p = hash_get_mem (pg->stream_index_by_name, stream_name);
      if (p)
	stream_index = *p;
      vec_free (stream_name);
    }

  pg_enable_disable (stream_index, is_enable);

  REPLY_MACRO (VL_API_PG_ENABLE_DISABLE_REPLY);
}

#include <vnet/pg/pg.api.c>
static clib_error_t *
pg_api_hookup (vlib_main_t * vm)
{
  pg_main_t *pg = &pg_main;
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  pg->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (pg_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
