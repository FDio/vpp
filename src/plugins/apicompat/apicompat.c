/*
 * apicompat.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vnet/plugin/plugin.h>
#include <apicompat/apicompat.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>


/* define message IDs */
#include <apicompat/apicompat_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe.api.h>
#include <apicompat/apicompat_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <apicompat/apicompat_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <apicompat/apicompat_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <apicompat/apicompat_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE amp->msg_id_base
#include <vlibapi/api_helper_macros.h>

apicompat_main_t apicompat_main;

/* List of message types that this plugin understands */

#define foreach_apicompat_plugin_api_msg                           \
_(APICOMPAT_ENABLE_DISABLE, apicompat_enable_disable)

/* Action function shared between message handler and debug CLI */

int
apicompat_enable_disable (apicompat_main_t * amp, u32 sw_if_index,
			  int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (amp->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (amp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  apicompat_create_periodic_process (amp);

  /* Send an event to enable/disable the periodic scanner process */
  vlib_process_signal_event (amp->vlib_main,
			     amp->periodic_node_index,
			     APICOMPAT_EVENT_PERIODIC_ENABLE_DISABLE,
			     (uword) enable_disable);
  return rv;
}

static clib_error_t *
apicompat_enable_disable_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  apicompat_main_t *amp = &apicompat_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 amp->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = apicompat_enable_disable (amp, sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "apicompat_enable_disable returned %d",
				rv);
    }
  return 0;
}


void
apicompat_send_and_handle (apicompat_main_t * amp, void *msg)
{
  vl_api_registration_t *rp;
  rp = vl_api_client_index_to_registration (amp->api_index);
  vl_api_send_msg (rp, msg);

  void *the_msg;
  svm_queue_sub (amp->q, (u8 *) & the_msg, SVM_Q_NOWAIT, 0);
  vl_msg_api_handler (the_msg);
}

int
apicompat_get_message (apicompat_main_t * amp, void **msg)
{
  return (!svm_queue_sub (amp->q, (u8 *) msg, SVM_Q_NOWAIT, 0));
}

void
apicompat_msg (apicompat_main_t * amp, u16 msg_id)
{
  vl_api_control_ping_t *mp_ping;

  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  clib_memset (mp_ping, 0, sizeof (*mp_ping));
  mp_ping->_vl_msg_id = ntohs (msg_id);	// VL_API_CONTROL_PING);
  mp_ping->client_index = amp->api_index;

  apicompat_send_and_handle (amp, mp_ping);

  void *msg;
  while (apicompat_get_message (amp, &msg))
    {
      u16 id = clib_net_to_host_u16 (*((u16 *) msg));
      clib_warning ("got message: %d", id);
      vl_msg_api_free ((void *) msg);
    }

}


static clib_error_t *
apicompat_test_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  // apicompat_main_t *amp = &apicompat_main;
  u32 message_id = ~0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &message_id))
	;
      else
	break;
    }

  clib_warning ("Testing message id %d", message_id);
  apicompat_msg (&apicompat_main, message_id);

  rv = 0;

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "apicompat_enable_disable returned %d",
				rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (apicompat_enable_disable_command, static) =
{
  .path = "apicompat enable-disable",
  .short_help =
  "apicompat enable-disable <interface-name> [disable]",
  .function = apicompat_enable_disable_command_fn,
};
VLIB_CLI_COMMAND (apicompat_test_command, static) =
{
  .path = "apicompat test",
  .short_help =
  "apicompat enable-disable <message-id>",
  .function = apicompat_test_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_apicompat_enable_disable_t_handler
  (vl_api_apicompat_enable_disable_t * mp)
{
  vl_api_apicompat_enable_disable_reply_t *rmp;
  apicompat_main_t *amp = &apicompat_main;
  int rv;

  rv = apicompat_enable_disable (amp, ntohl (mp->sw_if_index),
				 (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_APICOMPAT_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
apicompat_plugin_api_hookup (vlib_main_t * vm)
{
  apicompat_main_t *amp = &apicompat_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + amp->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_apicompat_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <apicompat/apicompat_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (apicompat_main_t * amp, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + amp->msg_id_base);
  foreach_vl_msg_name_crc_apicompat;
#undef _
}




void
register_legacy_message_and_crc (char *name_and_crc, void *action_handler,
				 void *print_handler)
{
  clib_warning ("Registering message %s", name_and_crc);
  u32 msg_index = vl_msg_api_get_msg_index ((u8 *) name_and_crc);
  clib_warning ("Result: %x", msg_index);
  if (msg_index == ~0)
    {
      api_main_t *am = &api_main;

      msg_index = vl_msg_api_get_msg_ids (name_and_crc, 1);
      vl_msg_api_add_msg_name_crc (am, name_and_crc, msg_index);
      vl_msg_api_set_handlers (msg_index, name_and_crc, action_handler,
			       vl_noop_handler, vl_noop_handler,
			       print_handler, 0, 1);
      clib_warning ("Registered with ID: %d", msg_index);

    }
  else
    {
      clib_warning ("message already is registered!");
    }
}



/* this is obtained via dlsym */
extern void foobar_register (void);


static clib_error_t *
apicompat_init (vlib_main_t * vm)
{
  apicompat_main_t *amp = &apicompat_main;
  clib_error_t *error = 0;
  u8 *name;
  clib_warning ("late init");

  amp->vlib_main = vm;
  amp->vnet_main = vnet_get_main ();

  name = format (0, "apicompat_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  amp->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = apicompat_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (amp, &api_main);

  vec_free (name);

  /* now register the dependent functions */
  foobar_register ();

  amp->q = svm_queue_alloc_and_init (64, sizeof (uword), getpid ());

  amp->api_index = vl_api_memclnt_create_internal ("api-compat", amp->q);

  apicompat_msg (amp, 848);

  return error;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (apicompat_init) =
{
  .runs_after = VLIB_INITS ("*"),
};

VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "API backwards-compatibility layer",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
