
/*
 * macswap.c - skeleton vpp engine plug-in 
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
#include <macswap/macswap.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <macswap/macswap_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <macswap/macswap_all_api_h.h> 
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <macswap/macswap_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <macswap/macswap_all_api_h.h> 
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <macswap/macswap_all_api_h.h>
#undef vl_api_version

/* 
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

#define REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+sm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);


/* List of message types that this plugin understands */

#define foreach_macswap_plugin_api_msg                           \
_(MACSWAP_ENABLE_DISABLE, macswap_enable_disable)		 \
_(MACSWAP_SHOW_STATUS, macswap_show_status)

/* 
 * This routine exists to convince the vlib plugin framework that
 * we haven't accidentally copied a random .dll into the plugin directory.
 *
 * Also collects global variable pointers passed from the vpp engine
 */

clib_error_t * 
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
                      int from_early_init)
{
  macswap_main_t * sm = &macswap_main;
  clib_error_t * error = 0;

  sm->vlib_main = vm;
  sm->vnet_main = h->vnet_main;
  sm->ethernet_main = h->ethernet_main;
  sm->interface = ~0;

  return error;
}

/* Action function shared between message handler and debug CLI */

int macswap_enable_disable (macswap_main_t * sm, u32 sw_if_index,
                                   int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv;
  u32 node_index = enable_disable ? macswap_node.index : ~0;

  /* Utterly wrong? */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces, 
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  /* Not a physical port? */
  sw = vnet_get_sw_interface (sm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  
  /* 
   * Redirect pkts from the driver to the macswap node.
   * Returns VNET_API_ERROR_UNIMPLEMENTED if the h/w driver
   * doesn't implement the API. 
   *
   * Node_index = ~0 => shut off redirection
   */
  rv = vnet_hw_interface_rx_redirect_to_node (sm->vnet_main, sw_if_index,
                                              node_index);

  /*
   * If we successfully redirected, save this interface.
   * NB: it would probably be easier as a bitmap but I'm lazy
   *     and am still learning VPP.
   */
  if (rv == 0) {
    if (enable_disable) {
      sm->interface = sw_if_index;
    } else {
      sm->interface = ~0;
    }
  }

  return rv;
}

static clib_error_t *
macswap_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  macswap_main_t * sm = &macswap_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;
    
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "disable"))
      enable_disable = 0;
    else if (unformat (input, "%U", unformat_vnet_sw_interface,
                       sm->vnet_main, &sw_if_index))
      ;
    else
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");
    
  rv = macswap_enable_disable (sm, sw_if_index, enable_disable);

  switch(rv) {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return 
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "macswap_enable_disable returned %d",
                              rv);
  }
  return 0;
}

VLIB_CLI_COMMAND (macswap_enable_disable_command, static) = {
    .path = "macswap enable-disable",
    .short_help = 
    "macswap enable-disable <interface-name> [disable]",
    .function = macswap_enable_disable_command_fn,
};

static clib_error_t *
show_macswap_status (vlib_main_t *vm,
		     unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  vnet_sw_interface_t *si = NULL;
  macswap_main_t *sm = &macswap_main;

  if (sm->interface != ~0) {
    si = vnet_get_sw_interface (sm->vnet_main, sm->interface);
    vlib_cli_output(vm, "macswap is enabled on %U\n",
		    format_vnet_sw_interface, sm->vnet_main, si);

  } else {
    vlib_cli_output(vm, "macswap is disabled\n");
  }

  return 0;
}

VLIB_CLI_COMMAND (show_macswap_status_command, static) = {
  .path = "show macswap",
  .short_help = "Show current status of macswap",
  .function = show_macswap_status,
};

/* API message handler */
static void vl_api_macswap_enable_disable_t_handler
(vl_api_macswap_enable_disable_t * mp)
{
  vl_api_macswap_enable_disable_reply_t * rmp;
  macswap_main_t * sm = &macswap_main;
  int rv;

  rv = macswap_enable_disable (sm, ntohl(mp->sw_if_index), 
                                      (int) (mp->enable_disable));
  
  REPLY_MACRO(VL_API_MACSWAP_ENABLE_DISABLE_REPLY);
}

/* API message handler */
static void vl_api_macswap_show_status_t_handler
(vl_api_macswap_show_status_t *mp)
{
  unix_shared_memory_queue_t *q =
    vl_api_client_index_to_input_queue (mp->client_index);
  vl_api_macswap_show_status_reply_t *rmp;
  macswap_main_t *sm = &macswap_main;
  u8 *if_name = NULL;
  vnet_sw_interface_t *si = NULL;

  /* Setup our reply message */
  rmp = vl_msg_api_alloc(sizeof (*rmp));
  memset(rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs(VL_API_MACSWAP_SHOW_STATUS_REPLY+sm->msg_id_base);
  rmp->context = mp->context;

  if (sm->interface != ~0) {
    rmp->enabled_disabled = 1;
    si = vnet_get_sw_interface (sm->vnet_main, sm->interface);
    if_name = format (if_name, "%U", 
		      format_vnet_sw_interface_name, sm->vnet_main, si);
    strncpy((char *)rmp->if_name, (char *)if_name, ARRAY_LEN(rmp->if_name)-1);
  }

  /* Send the message */
  vl_msg_api_send_shmem (q, (u8 *)&rmp);
}

/* Set up the API message handling tables */
static clib_error_t *
macswap_plugin_api_hookup (vlib_main_t *vm)
{
  macswap_main_t * sm = &macswap_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_macswap_plugin_api_msg;
#undef _

    return 0;
}

static clib_error_t * macswap_init (vlib_main_t * vm)
{
  macswap_main_t * sm = &macswap_main;
  clib_error_t * error = 0;
  u8 * name;

  name = format (0, "macswap_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = macswap_plugin_api_hookup (vm);

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (macswap_init);
