/*
 * cdp.c - cdp protocol plug-in
 *
 * Copyright (c) 2011-2018 by Cisco and/or its affiliates.
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
#include <cdp/cdp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <cdp/cdp_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <cdp/cdp_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <cdp/cdp_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <cdp/cdp_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <cdp/cdp_all_api_h.h>
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
    rmp->_vl_msg_id = ntohs((t)+cm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);


/* List of message types that this plugin understands */

#define foreach_cdp_plugin_api_msg                           \
_(CDP_ENABLE_DISABLE, cdp_enable_disable)

/* Action function shared between message handler and debug CLI */

int
cdp_enable_disable (cdp_main_t * cm, int enable_disable)
{
  int rv = 0;

  if (enable_disable)
    vlib_process_signal_event (cm->vlib_main, cdp_process_node.index,
			       CDP_EVENT_ENABLE, 0);
  else
    vlib_process_signal_event (cm->vlib_main, cdp_process_node.index,
			       CDP_EVENT_DISABLE, 0);
  cm->enabled = enable_disable;

  return rv;
}

static clib_error_t *
cdp_command_fn (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  cdp_main_t *cm = &cdp_main;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "enable"))
	enable_disable = 1;
      else
	break;
    }

  rv = cdp_enable_disable (cm, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "cdp_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cdp_command, static) =
{
  .path = "cdp",
  .short_help = "cdp enable | disable",
  .function = cdp_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_cdp_enable_disable_t_handler
  (vl_api_cdp_enable_disable_t * mp)
{
  vl_api_cdp_enable_disable_reply_t *rmp;
  cdp_main_t *cm = &cdp_main;
  int rv;

  rv = cdp_enable_disable (cm, (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_CDP_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
cdp_plugin_api_hookup (vlib_main_t * vm)
{
  cdp_main_t *cm = &cdp_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + cm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_cdp_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <cdp/cdp_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (cdp_main_t * cm, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + cm->msg_id_base);
  foreach_vl_msg_name_crc_cdp;
#undef _
}

static clib_error_t *
cdp_init (vlib_main_t * vm)
{
  cdp_main_t *cm = &cdp_main;
  clib_error_t *error = 0;
  u8 *name;

  cm->vlib_main = vm;

  name = format (0, "cdp_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  cm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = cdp_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (cm, &api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (cdp_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
