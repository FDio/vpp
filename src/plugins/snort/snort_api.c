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

VLIB_REGISTER_LOG_CLASS (snort_log, static) = {
  .class_name = "snort",
};

#define log_debug(fmt, ...) vlib_log_debug (snort_log._class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)   vlib_log_err (snort_log._class, fmt, __VA_ARGS__)

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

  rv =
    snort_instance_create (vm, name, min_log2 (queue_sz), drop_on_disconnect);

  if ((si = snort_get_instance_by_name (name)))
    {
      instance_index = si->index;
    }

  REPLY_MACRO2 (VL_API_SNORT_INSTANCE_CREATE_REPLY, ({
		  rmp->instance_index = clib_host_to_net_u32 (instance_index);
		}));
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
vl_api_snort_interface_attach_t_handler (vl_api_snort_interface_attach_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_interface_attach_reply_t *rmp;
  u32 instance_index = clib_net_to_host_u32 (mp->instance_index);
  snort_instance_t *instance = 0;
  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  u8 snort_dir = mp->snort_dir;
  int rv = VNET_API_ERROR_NO_SUCH_ENTRY;

  VALIDATE_SW_IF_INDEX (mp);
  switch (snort_dir)
    {
    case SNORT_INPUT:
    case SNORT_OUTPUT:
    case SNORT_INOUT:
      break;
    default:
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto bad_sw_if_index;
    }
  instance = snort_get_instance_by_index (instance_index);
  if (instance)
    {
      rv = snort_interface_enable_disable (vm, (char *) instance->name,
					   sw_if_index, 1 /* is_enable */,
					   snort_dir);
    }
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SNORT_INTERFACE_ATTACH_REPLY);
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
      rmp->snort_client_index = clib_host_to_net_u32 (instance->client_index);
      rmp->shm_size = clib_host_to_net_u32 (instance->shm_size);
      rmp->shm_fd = clib_host_to_net_u32 (instance->shm_fd);
      rmp->drop_on_disconnect = instance->drop_on_disconnect;
    }));
}

static void
vl_api_snort_instance_get_t_handler (vl_api_snort_instance_get_t *mp)
{
  snort_main_t *sm = snort_get_main ();
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
send_snort_interface_details (u32 sw_if_index, u32 instance_index,
			      vl_api_registration_t *rp, u32 context)
{
  vl_api_snort_interface_details_t *rmp;

  if (instance_index != ~0)
    {
      REPLY_MACRO_DETAILS4 (VL_API_SNORT_INTERFACE_DETAILS, rp, context, ({
			      rmp->instance_index =
				clib_host_to_net_u32 (instance_index);
			      rmp->sw_if_index =
				clib_host_to_net_u32 (sw_if_index);
			    }));
    }
}

static void
vl_api_snort_interface_get_t_handler (vl_api_snort_interface_get_t *mp)
{
  snort_main_t *sm = snort_get_main ();
  vl_api_snort_interface_get_reply_t *rmp;
  u32 sw_if_index;
  u32 *instances;
  u32 index;
  int rv = 0;

  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);

  if (sw_if_index == INDEX_INVALID)
    {
      /* clang-format off */
      if (vec_len (sm->interfaces) == 0)
	{
	  REPLY_MACRO2 (VL_API_SNORT_INTERFACE_GET_REPLY, ({ rmp->cursor = ~0; }));
	  return;
	}

      REPLY_AND_DETAILS_VEC_MACRO(
	VL_API_SNORT_INTERFACE_GET_REPLY,
	sm->interfaces,
	mp, rmp, rv, ({
          instances = vec_len(sm->interfaces[cursor].input_instance_indices) ?
           sm->interfaces[cursor].input_instance_indices : sm->interfaces[cursor].output_instance_indices;
          if (vec_len(instances) == 0)
          {
            index = ~0;
          }
          else {
            index = instances[0];
          }
          send_snort_interface_details (cursor, index, rp, mp->context);
	}))
      /* clang-format on */
    }
  else
    {
      instances =
	vec_len (sm->interfaces[sw_if_index].input_instance_indices) ?
	  sm->interfaces[sw_if_index].input_instance_indices :
	  sm->interfaces[sw_if_index].output_instance_indices;
      if (vec_len (instances) == 0)
	{
	  index = ~0;
	}
      else
	{
	  index = instances[0];
	}
      if (snort_get_instance_by_index (index))
	{
	  vl_api_registration_t *rp =
	    vl_api_client_index_to_registration (mp->client_index);

	  if (rp == NULL)
	    {
	      return;
	    }

	  send_snort_interface_details (sw_if_index, *instances, rp,
					mp->context);
	}
      else
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      /* clang-format off */
      REPLY_MACRO2 (VL_API_SNORT_INTERFACE_GET_REPLY, ({
        rmp->cursor = INDEX_INVALID;
      }));
      /* clang-format on */
    }
}

static void
send_snort_client_details (const snort_client_t *client,
			   vl_api_registration_t *rp, u32 context)
{
  snort_main_t *sm = snort_get_main ();
  vl_api_snort_client_details_t *rmp;
  snort_instance_t *instance;

  if (client->instance_index == ~0)
    {
      return;
    }

  instance = pool_elt_at_index (sm->instances, client->instance_index);
  if (instance)
    {
      REPLY_MACRO_DETAILS4 (VL_API_SNORT_CLIENT_DETAILS, rp, context, ({
			      rmp->instance_index =
				clib_host_to_net_u32 (client->instance_index);
			      rmp->client_index =
				clib_host_to_net_u32 (client - sm->clients);
			    }));
    }
}

static void
vl_api_snort_client_get_t_handler (vl_api_snort_client_get_t *mp)
{
  snort_main_t *sm = snort_get_main ();
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
vl_api_snort_client_disconnect_t_handler (vl_api_snort_client_disconnect_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  snort_main_t *sm = snort_get_main ();
  snort_client_t *client;
  vl_api_snort_client_disconnect_reply_t *rmp;
  u32 client_index = clib_net_to_host_u32 (mp->snort_client_index);
  int rv = 0;

  if (pool_is_free_index (sm->clients, client_index))
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
    }
  else
    {
      client = pool_elt_at_index (sm->clients, client_index);
      rv = snort_instance_disconnect (vm, client->instance_index);
    }

  REPLY_MACRO (VL_API_SNORT_CLIENT_DISCONNECT_REPLY);
}

static void
vl_api_snort_instance_disconnect_t_handler (
  vl_api_snort_instance_disconnect_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_instance_disconnect_reply_t *rmp;
  u32 instance_index = clib_net_to_host_u32 (mp->instance_index);
  int rv = snort_instance_disconnect (vm, instance_index);

  REPLY_MACRO (VL_API_SNORT_INSTANCE_DISCONNECT_REPLY);
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
  snort_main_t *sm = &snort_main;
  vl_api_snort_input_mode_get_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_SNORT_INPUT_MODE_GET_REPLY, ({
		  rmp->snort_mode = clib_host_to_net_u32 (sm->input_mode);
		}));
}

static void
vl_api_snort_input_mode_set_t_handler (vl_api_snort_input_mode_set_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_snort_input_mode_set_reply_t *rmp;
  u8 mode = mp->input_mode;
  int rv = 0;

  if (mode != VLIB_NODE_STATE_INTERRUPT && mode != VLIB_NODE_STATE_POLLING)
    {
      clib_error_return (0, "invalid input mode %u", mode);
    }
  snort_set_node_mode (vm, mode);

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
