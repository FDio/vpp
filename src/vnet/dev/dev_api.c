/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/api.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <dev/dev.api_enum.h>
#include <dev/dev.api_types.h>

static u16 vnet_dev_api_msg_id_base;

#define REPLY_MSG_ID_BASE (vnet_dev_api_msg_id_base)
#include <vlibapi/api_helper_macros.h>

#define _(b, n, d)                                                            \
  STATIC_ASSERT ((int) VL_API_DEV_FLAG_##n == (int) VNET_DEV_F_##n, "");
foreach_vnet_dev_flag;
#undef _

#ifndef VL_API_DEV_PORT_FLAG_QUEUE_PER_THREAD
#define VL_API_DEV_PORT_FLAG_QUEUE_PER_THREAD VNET_DEV_PORT_F_QUEUE_PER_THREAD
#endif

#define _(b, n, d)                                                            \
  STATIC_ASSERT ((int) VL_API_DEV_PORT_FLAG_##n == (int) VNET_DEV_PORT_F_##n, \
		 "");
foreach_vnet_dev_port_flag;
#undef _

static void
vl_api_dev_attach_t_handler (vl_api_dev_attach_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_dev_attach_reply_t *rmp;
  vnet_dev_api_attach_args_t a = {};
  vnet_dev_rv_t rv;
  u8 *error_string = 0;

  STATIC_ASSERT (sizeof (mp->device_id) == sizeof (a.device_id), "");
  STATIC_ASSERT (sizeof (mp->driver_name) == sizeof (a.driver_name), "");
  STATIC_ASSERT (sizeof (mp->flags) == sizeof (a.flags), "");

  a.flags.n = mp->flags;
  snprintf (a.device_id, sizeof (a.device_id), "%s", (char *) mp->device_id);
  snprintf (a.driver_name, sizeof (a.driver_name), "%s", (char *) mp->driver_name);
  vec_add (a.args, mp->args.buf, mp->args.length);

  rv = vnet_dev_api_attach (vm, &a);

  if (rv != VNET_DEV_OK)
    error_string = format (0, "%U", format_vnet_dev_rv, rv);

  vec_free (a.args);

  REPLY_MACRO3_END (VL_API_DEV_ATTACH_REPLY, vec_len (error_string), ({
		      rmp->retval = rv;
		      if (error_string)
			{
			  rmp->dev_index = ~0;
			  vl_api_vec_to_api_string (error_string,
						    &rmp->error_string);
			}
		      else
			rmp->dev_index = a.dev_index;
		    }));

  vec_free (a.args);
  vec_free (error_string);
}

static void
vl_api_dev_detach_t_handler (vl_api_dev_detach_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_dev_detach_reply_t *rmp;
  vnet_dev_api_detach_args_t a = {};
  vnet_dev_rv_t rv;
  u8 *error_string = 0;

  a.dev_index = mp->dev_index;

  rv = vnet_dev_api_detach (vm, &a);

  if (rv != VNET_DEV_OK)
    error_string = format (0, "%U", format_vnet_dev_rv, rv);

  REPLY_MACRO3_END (VL_API_DEV_DETACH_REPLY, vec_len (error_string), ({
		      rmp->retval = rv;
		      if (error_string)
			vl_api_vec_to_api_string (error_string,
						  &rmp->error_string);
		    }));

  vec_free (error_string);
}

static void
vl_api_dev_create_port_if_t_handler (vl_api_dev_create_port_if_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_dev_create_port_if_reply_t *rmp;
  vnet_dev_api_create_port_if_args_t a = {};
  vnet_dev_rv_t rv;
  u8 *error_string = 0;

  STATIC_ASSERT (sizeof (mp->intf_name) == sizeof (a.intf_name), "");
  STATIC_ASSERT (sizeof (mp->flags) == sizeof (a.flags), "");

  a.flags.n = mp->flags;
#define _(n) a.n = mp->n;
  _ (dev_index)
  _ (port_id)
  _ (num_rx_queues)
  _ (num_tx_queues)
  _ (rx_queue_size)
  _ (tx_queue_size)
#undef _

  strncpy (a.intf_name, (char *) mp->intf_name, sizeof (a.intf_name));
  vec_add (a.args, mp->args.buf, mp->args.length);

  rv = vnet_dev_api_create_port_if (vm, &a);

  if (rv != VNET_DEV_OK)
    error_string = format (0, "%U", format_vnet_dev_rv, rv);

  vec_free (a.args);

  REPLY_MACRO3_END (VL_API_DEV_CREATE_PORT_IF_REPLY, vec_len (error_string), ({
		      rmp->retval = rv;
		      if (error_string)
			{
			  rmp->sw_if_index = ~0;
			  vl_api_vec_to_api_string (error_string,
						    &rmp->error_string);
			}
		      else
			rmp->sw_if_index = a.sw_if_index;
		    }));

  vec_free (a.args);
  vec_free (error_string);
}

static void
vl_api_dev_remove_port_if_t_handler (vl_api_dev_remove_port_if_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_dev_remove_port_if_reply_t *rmp;
  vnet_dev_api_remove_port_if_args_t a = {};
  vnet_dev_rv_t rv;
  u8 *error_string = 0;

  a.sw_if_index = mp->sw_if_index;

  rv = vnet_dev_api_remove_port_if (vm, &a);

  if (rv != VNET_DEV_OK)
    error_string = format (0, "%U", format_vnet_dev_rv, rv);

  REPLY_MACRO3_END (VL_API_DEV_REMOVE_PORT_IF_REPLY, vec_len (error_string), ({
		      rmp->retval = rv;
		      if (error_string)
			vl_api_vec_to_api_string (error_string,
						  &rmp->error_string);
		    }));

  vec_free (error_string);
}

/* set tup the API message handling tables */

#include <dev/dev.api.c>

static clib_error_t *
vnet_dev_api_hookup (vlib_main_t *vm)
{
  api_main_t *am = vlibapi_get_main ();

  /* ask for a correctly-sized block of API message decode slots */
  vnet_dev_api_msg_id_base = setup_message_id_table ();

  foreach_int (i, VL_API_DEV_ATTACH, VL_API_DEV_DETACH,
	       VL_API_DEV_CREATE_PORT_IF, VL_API_DEV_REMOVE_PORT_IF)
    vl_api_set_msg_thread_safe (am, vnet_dev_api_msg_id_base + i, 1);

  return 0;
}

VLIB_API_INIT_FUNCTION (vnet_dev_api_hookup);
