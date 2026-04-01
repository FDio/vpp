/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */
#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <snort/snort.h>
#include <vlibapi/api_types.h>

#include <snort/snort.api_enum.h>
#include <snort/snort.api_types.h>

#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>
#include <vnet/api_errno.h>

/**
 * Base message ID fot the plugin
 */
static u32 snort_base_msg_id;
#define REPLY_MSG_ID_BASE snort_base_msg_id

#include <vlibapi/api_helper_macros.h>

#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <sys/eventfd.h>

static void
vl_api_snort_instance_create_v2_t_handler (vl_api_snort_instance_create_v2_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_instance_create_v2_reply_t *rmp;
  char *name = vl_api_from_api_to_new_c_string (&mp->name);
  u32 queue_sz = clib_net_to_host_u32 (mp->queue_size);
  u32 qpairs_per_thread = clib_net_to_host_u32 (mp->qpairs_per_thread);
  u8 drop_on_disconnect = mp->drop_on_disconnect;
  u8 drop_bitmap = mp->drop_bitmap;
  int rv = 0;
  u32 instance_index = ~0;
  snort_instance_t *si;

  rv = snort_instance_create (vm,
			      &(snort_instance_create_args_t){
				.drop_on_disconnect = drop_on_disconnect,
				.drop_bitmap = drop_bitmap,
				.qpairs_per_thread = qpairs_per_thread,
				.log2_queue_sz = min_log2 (queue_sz),
			      },
			      "%s", name);

  if ((si = snort_get_instance_by_name (name)))
    {
      instance_index = si->index;
    }

  REPLY_MACRO2 (VL_API_SNORT_INSTANCE_CREATE_V2_REPLY,
		({ rmp->instance_index = clib_host_to_net_u32 (instance_index); }));
}

static void
vl_api_snort_instance_delete_t_handler (vl_api_snort_instance_delete_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_instance_delete_reply_t *rmp;
  u32 instance_index = clib_net_to_host_u32 (mp->instance_index);
  int rv;

  rv = snort_instance_delete (vm, instance_index);

  REPLY_MACRO (VL_API_SNORT_INSTANCE_DELETE_REPLY);
}

static void
vl_api_snort_set_drop_bitmap_t_handler (vl_api_snort_set_drop_bitmap_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_set_drop_bitmap_reply_t *rmp;
  u32 instance_index = clib_net_to_host_u32 (mp->instance_index);
  u8 drop_bitmap = mp->drop_bitmap;
  int rv;

  rv = snort_set_drop_bitmap (vm, instance_index, drop_bitmap);

  REPLY_MACRO (VL_API_SNORT_SET_DROP_BITMAP_REPLY);
}

static void
vl_api_snort_interface_attach_t_handler (vl_api_snort_interface_attach_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_interface_attach_reply_t *rmp;
  u32 instance_index = clib_net_to_host_u32 (mp->instance_index);
  snort_instance_t *instance = 0;
  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  u8 snort_dir = mp->snort_dir;
  int rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  int in = 0, out = 0;

  VALIDATE_SW_IF_INDEX (mp);
  switch (snort_dir)
    {
    case SNORT_API_DIRECTION_INPUT:
      in = 1;
      break;
    case SNORT_API_DIRECTION_OUTPUT:
      out = 1;
      break;
    case SNORT_API_DIRECTION_INOUT:
      in = out = 1;
      break;
    default:
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto bad_sw_if_index;
    }
  instance = snort_get_instance_by_index (instance_index);
  if (instance)
    {
      rv = snort_interface_enable_disable (
	vm, (char *) instance->name, sw_if_index, 1 /* is_enable */, in, out);
    }
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SNORT_INTERFACE_ATTACH_REPLY);
}

static void
send_snort_instance_v2_details (const snort_instance_t *instance, vl_api_registration_t *rp,
				u32 context)
{
  vl_api_snort_instance_v2_details_t *rmp;
  u32 name_len = vec_len (instance->name);
  u32 client_index = instance->qpairs[0]->client_index;

  REPLY_MACRO_DETAILS5 (VL_API_SNORT_INSTANCE_V2_DETAILS, name_len, rp, context, ({
			  rmp->instance_index = clib_host_to_net_u32 (instance->index);
			  rmp->snort_client_index = clib_host_to_net_u32 (client_index);
			  vl_api_vec_to_api_string (instance->name, &rmp->name);
			  rmp->shm_size = clib_host_to_net_u32 (instance->shm_size);
			  rmp->shm_fd = clib_host_to_net_u32 (instance->shm_fd);
			  rmp->drop_bitmap = instance->drop_bitmap;
			  rmp->drop_on_disconnect = instance->drop_on_disconnect;
			  rmp->qpairs_per_thread =
			    clib_host_to_net_u32 (instance->qpairs_per_thread);
			}));
}

static void
vl_api_snort_instance_v2_get_t_handler (vl_api_snort_instance_v2_get_t *mp)
{
  snort_main_t *sm = &snort_main;
  snort_instance_t *instance = 0;
  vl_api_snort_instance_v2_get_reply_t *rmp;
  u32 instance_index;
  int rv = 0;

  instance_index = clib_net_to_host_u32 (mp->instance_index);

  if (instance_index == INDEX_INVALID)
    {
      /* clang-format off */
      REPLY_AND_DETAILS_MACRO (
        VL_API_SNORT_INSTANCE_V2_GET_REPLY, sm->instances, ({
	  instance = pool_elt_at_index (sm->instances, cursor);
          send_snort_instance_v2_details (instance, rp, mp->context);
        }));
      /* clang-format on */
    }
  else
    {
      instance = snort_get_instance_by_index (instance_index);

      if (instance)
	{
	  vl_api_registration_t *rp = vl_api_client_index_to_registration (mp->client_index);

	  if (rp == NULL)
	    {
	      return;
	    }

	  send_snort_instance_v2_details (instance, rp, mp->context);
	}
      else
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      /* clang-format off */
      REPLY_MACRO2 (VL_API_SNORT_INSTANCE_V2_GET_REPLY, ({
        rmp->cursor = INDEX_INVALID;
      }));
      /* clang-format on */
    }
}

static void
send_snort_interface_v2_details (u32 sw_if_index, u16 in_instance_index, u16 out_instance_index,
				 vl_api_registration_t *rp, u32 context)
{
  vl_api_snort_interface_v2_details_t *rmp;

  if (in_instance_index != 0xffff || out_instance_index != 0xffff)
    {
      REPLY_MACRO_DETAILS4 (VL_API_SNORT_INTERFACE_V2_DETAILS, rp, context, ({
			      rmp->in_instance_index = clib_host_to_net_u16 (in_instance_index);
			      rmp->out_instance_index = clib_host_to_net_u16 (out_instance_index);
			      rmp->sw_if_index = clib_host_to_net_u32 (sw_if_index);
			    }));
    }
}

static void
vl_api_snort_interface_v2_get_t_handler (vl_api_snort_interface_v2_get_t *mp)
{
  snort_main_t *sm = &snort_main;
  vl_api_snort_interface_v2_get_reply_t *rmp;
  u32 sw_if_index;
  u16 *index;
  u16 *outdex;
  int rv = 0;

  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);

  if (sw_if_index == INDEX_INVALID)
    {
      /* clang-format off */
      if (vec_len (sm->input_instance_by_interface) == 0)
        {
	  REPLY_MACRO2 (VL_API_SNORT_INTERFACE_V2_GET_REPLY, ({ rmp->cursor = ~0; }));
	  return;
        }

      REPLY_AND_DETAILS_VEC_MACRO(VL_API_SNORT_INTERFACE_V2_GET_REPLY,
				  sm->input_instance_by_interface,
				  mp, rmp, rv, ({
	  index = vec_elt_at_index (sm->input_instance_by_interface, cursor);
	  outdex = vec_elt_at_index (sm->output_instance_by_interface, cursor);

	  send_snort_interface_v2_details (cursor, *index, *outdex, rp, mp->context);
      }))
      /* clang-format on */
    }
  else
    {
      index = vec_elt_at_index (sm->input_instance_by_interface, sw_if_index);
      outdex = vec_elt_at_index (sm->output_instance_by_interface, sw_if_index);
      if (snort_get_instance_by_index (*index) || snort_get_instance_by_index (*outdex))
	{
	  vl_api_registration_t *rp = vl_api_client_index_to_registration (mp->client_index);

	  if (rp == NULL)
	    {
	      return;
	    }

	  send_snort_interface_v2_details (sw_if_index, *index, *outdex, rp, mp->context);
	}
      else
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      /* clang-format off */
      REPLY_MACRO2 (VL_API_SNORT_INTERFACE_V2_GET_REPLY, ({
        rmp->cursor = INDEX_INVALID;
      }));
      /* clang-format on */
    }
}

static void
send_snort_client_v2_details (const snort_client_t *client, vl_api_registration_t *rp, u32 context)
{
  snort_main_t *sm = &snort_main;
  vl_api_snort_client_v2_details_t *rmp;
  u32 n_threads = client->n_instances ? client->n_instances : 1;

  REPLY_MACRO_DETAILS4 (VL_API_SNORT_CLIENT_V2_DETAILS, rp, context, ({
			  rmp->mode = client->mode;
			  rmp->n_instances = clib_host_to_net_u16 (n_threads);
			  rmp->snort_client_index = clib_host_to_net_u32 (client - sm->clients);
			}));
}

static void
vl_api_snort_client_v2_get_t_handler (vl_api_snort_client_v2_get_t *mp)
{
  snort_main_t *sm = &snort_main;
  snort_client_t *client;
  vl_api_snort_client_v2_get_reply_t *rmp;
  u32 client_index;
  int rv = 0;

  client_index = clib_net_to_host_u32 (mp->snort_client_index);

  if (client_index == INDEX_INVALID)
    {
      /* clang-format off */
      REPLY_AND_DETAILS_MACRO (
        VL_API_SNORT_CLIENT_GET_REPLY, sm->clients, ({
          client = pool_elt_at_index (sm->clients, cursor);
          send_snort_client_v2_details (client, rp, mp->context);
        }));
      /* clang-format on */
    }
  else
    {
      client = pool_elt_at_index (sm->clients, client_index);

      if (client)
	{
	  vl_api_registration_t *rp = vl_api_client_index_to_registration (mp->client_index);

	  if (rp == NULL)
	    {
	      return;
	    }

	  send_snort_client_v2_details (client, rp, mp->context);
	}
      else
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      /* clang-format off */
      REPLY_MACRO2 (VL_API_SNORT_CLIENT_V2_GET_REPLY, ({
        rmp->cursor = INDEX_INVALID;
      }));
      /* clang-format on */
    }
}

static void
vl_api_snort_client_disconnect_t_handler (vl_api_snort_client_disconnect_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_client_disconnect_reply_t *rmp;
  u32 client_index = clib_net_to_host_u32 (mp->snort_client_index);
  int rv = 0;

  rv = snort_client_disconnect (vm, client_index);

  REPLY_MACRO (VL_API_SNORT_CLIENT_DISCONNECT_REPLY);
}

static void
vl_api_snort_instance_disconnect_t_handler (vl_api_snort_instance_disconnect_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_instance_disconnect_reply_t *rmp;
  u32 instance_index = clib_net_to_host_u32 (mp->instance_index);
  int rv;

  rv = snort_instance_disconnect_all (vm, instance_index);

  REPLY_MACRO (VL_API_SNORT_INSTANCE_DISCONNECT_REPLY);
}

static void
vl_api_snort_interface_detach_v2_t_handler (vl_api_snort_interface_detach_v2_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_interface_detach_v2_reply_t *rmp;
  u32 instance_index = clib_net_to_host_u32 (mp->instance_index);
  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  u8 in, out, snort_dir = mp->snort_dir;
  snort_instance_t *instance;
  int rv = VNET_API_ERROR_NO_SUCH_ENTRY;

  VALIDATE_SW_IF_INDEX (mp);

  in = snort_dir & SNORT_API_DIRECTION_INPUT;
  out = snort_dir & SNORT_API_DIRECTION_OUTPUT;
  instance = snort_get_instance_by_index (instance_index);

  if (!in && !out)
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
    }
  else if (instance)
    {
      rv = snort_interface_enable_disable (vm, (char *) instance->name, sw_if_index,
					   0 /* is_enable */, in, out);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SNORT_INTERFACE_DETACH_V2_REPLY);
}

/* Deprecated functions */

static void
vl_api_snort_instance_create_t_handler (vl_api_snort_instance_create_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_instance_create_reply_t *rmp;
  char *name = vl_api_from_api_to_new_c_string (&mp->name);
  u32 queue_sz = clib_net_to_host_u32 (mp->queue_size);
  u8 drop_on_disconnect = mp->drop_on_disconnect;
  int rv = 0;
  u32 instance_index = ~0;
  snort_instance_t *si;

  rv = snort_instance_create (vm,
			      &(snort_instance_create_args_t){
				.drop_on_disconnect = drop_on_disconnect,
				.log2_queue_sz = min_log2 (queue_sz),
			      },
			      "%s", name);

  if ((si = snort_get_instance_by_name (name)))
    {
      instance_index = si->index;
    }

  REPLY_MACRO2 (VL_API_SNORT_INSTANCE_CREATE_REPLY,
		({ rmp->instance_index = clib_host_to_net_u32 (instance_index); }));
}

static void
send_snort_instance_details (const snort_instance_t *instance,
			     vl_api_registration_t *rp, u32 context)
{
  vl_api_snort_instance_details_t *rmp;
  u32 name_len = vec_len (instance->name);

  REPLY_MACRO_DETAILS5 (
    VL_API_SNORT_INSTANCE_DETAILS, name_len, rp, context, ({
      rmp->instance_index = clib_host_to_net_u32 (instance->index);
      vl_api_vec_to_api_string (instance->name, &rmp->name);
      rmp->snort_client_index = clib_host_to_net_u32 (0);
      rmp->shm_size = clib_host_to_net_u32 (instance->shm_size);
      rmp->shm_fd = clib_host_to_net_u32 (instance->shm_fd);
      rmp->drop_on_disconnect = instance->drop_on_disconnect;
    }));
}

static void
vl_api_snort_instance_get_t_handler (vl_api_snort_instance_get_t *mp)
{
  snort_main_t *sm = &snort_main;
  snort_instance_t *instance = 0;
  vl_api_snort_instance_get_reply_t *rmp;
  u32 instance_index;
  int rv = 0;

  instance_index = clib_net_to_host_u32 (mp->instance_index);

  if (instance_index == INDEX_INVALID)
    {
      /* clang-format off */
      REPLY_AND_DETAILS_MACRO (
        VL_API_SNORT_INSTANCE_GET_REPLY, sm->instances, ({
	  instance = pool_elt_at_index (sm->instances, cursor);
          send_snort_instance_details (instance, rp, mp->context);
        }));
      /* clang-format on */
    }
  else
    {
      instance = snort_get_instance_by_index (instance_index);

      if (instance)
	{
	  vl_api_registration_t *rp =
	    vl_api_client_index_to_registration (mp->client_index);

	  if (rp == NULL)
	    {
	      return;
	    }

	  send_snort_instance_details (instance, rp, mp->context);
	}
      else
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      /* clang-format off */
      REPLY_MACRO2 (VL_API_SNORT_INSTANCE_GET_REPLY, ({
        rmp->cursor = INDEX_INVALID;
      }));
      /* clang-format on */
    }
}

static void
vl_api_snort_interface_get_t_handler (vl_api_snort_interface_get_t *mp)
{
  vl_api_snort_interface_get_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_SNORT_INTERFACE_GET_REPLY, ({ rmp->cursor = ~0; }));
}

static void
send_snort_client_details (const snort_client_t *client,
			   vl_api_registration_t *rp, u32 context)
{
  snort_main_t *sm = &snort_main;
  vl_api_snort_client_details_t *rmp;

  REPLY_MACRO_DETAILS4 (VL_API_SNORT_CLIENT_DETAILS, rp, context, ({
			  rmp->instance_index = 0;
			  rmp->client_index =
			    clib_host_to_net_u32 (client - sm->clients);
			}));
}

static void
vl_api_snort_client_get_t_handler (vl_api_snort_client_get_t *mp)
{
  snort_main_t *sm = &snort_main;
  snort_client_t *client;
  vl_api_snort_client_get_reply_t *rmp;
  u32 client_index;
  int rv = 0;

  client_index = clib_net_to_host_u32 (mp->snort_client_index);

  if (client_index == INDEX_INVALID)
    {
      /* clang-format off */
      REPLY_AND_DETAILS_MACRO (
        VL_API_SNORT_CLIENT_GET_REPLY, sm->clients, ({
          client = pool_elt_at_index (sm->clients, cursor);
          send_snort_client_details (client, rp, mp->context);
        }));
      /* clang-format on */
    }
  else
    {
      client = pool_elt_at_index (sm->clients, client_index);

      if (client)
	{
	  vl_api_registration_t *rp =
	    vl_api_client_index_to_registration (mp->client_index);

	  if (rp == NULL)
	    {
	      return;
	    }

	  send_snort_client_details (client, rp, mp->context);
	}
      else
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      /* clang-format off */
      REPLY_MACRO2 (VL_API_SNORT_CLIENT_GET_REPLY, ({
        rmp->cursor = INDEX_INVALID;
      }));
      /* clang-format on */
    }
}

static void
vl_api_snort_interface_detach_t_handler (vl_api_snort_interface_detach_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_interface_detach_reply_t *rmp;
  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  int rv;

  VALIDATE_SW_IF_INDEX (mp);
  rv = snort_interface_disable_all (vm, sw_if_index);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SNORT_INTERFACE_DETACH_REPLY);
}

static void
vl_api_snort_input_mode_get_t_handler (vl_api_snort_input_mode_get_t *mp)
{
  vl_api_snort_input_mode_get_reply_t *rmp;
  int rv = VNET_API_ERROR_UNSUPPORTED;

  REPLY_MACRO (VL_API_SNORT_INPUT_MODE_GET_REPLY);
}

static void
vl_api_snort_input_mode_set_t_handler (vl_api_snort_input_mode_set_t *mp)
{
  vl_api_snort_input_mode_set_reply_t *rmp;
  int rv = VNET_API_ERROR_UNSUPPORTED;

  REPLY_MACRO (VL_API_SNORT_INPUT_MODE_SET_REPLY);
}

/* API definitions */
#include <snort/snort.api.c>

clib_error_t *
snort_init_api (vlib_main_t *vm)
{
  /* Add our API messages to the global name_crc hash table */
  snort_base_msg_id = setup_message_id_table ();

  return NULL;
}

VLIB_INIT_FUNCTION (snort_init_api);
