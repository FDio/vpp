/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
/*
 *------------------------------------------------------------------
 * sr_ioam_export.c - ioam export API / debug CLI handling
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ioam/export-common/ioam_export.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

#include <ioam/srv6/sr_ioam.h>

/* define message IDs */
#include <ioam/export-srv6/sr_ioam_export_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ioam/export-srv6/sr_ioam_export_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ioam/export-srv6/sr_ioam_export_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ioam/export-srv6/sr_ioam_export_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ioam/export-srv6/sr_ioam_export_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */
#define foreach_sr_ioam_export_plugin_api_msg                        \
_(SR_IOAM_EXPORT_ENABLE_DISABLE, sr_ioam_export_enable_disable)

ioam_export_main_t sr_ioam_export_main;
extern vlib_node_registration_t sr_export_node;

extern void sr_set_next_override (uword next);
/* Action function shared between message handler and debug CLI */
int
sr_ioam_export_enable_disable (ioam_export_main_t * em,
			       u8 is_disable,
			       ip4_address_t * collector_address,
			       ip4_address_t * src_address)
{
  vlib_main_t *vm = em->vlib_main;
  u32 node_index = sr_export_node.index;
  vlib_node_t *sr_decap_ioam_node = NULL;

  if (is_disable == 0)
    {
      if (em->my_hbh_slot == ~0)
	{
	  /* Hook this export node to sr-decap-ioam-v6 */
	  sr_decap_ioam_node =
	    vlib_get_node_by_name (vm, (u8 *) "sr-localsid-ioam");
	  if (!sr_decap_ioam_node)
	    {
	      /* node does not exist give up */
	      return (-1);
	    }
	  em->my_hbh_slot =
	    vlib_node_add_next (vm, sr_decap_ioam_node->index, node_index);
	}
      if (1 == ioam_export_header_create (em, collector_address, src_address))
	{
	  ioam_export_thread_buffer_init (em, vm);
	  sr_set_next_override (em->my_hbh_slot);
	  /* Turn on the export buffer check process */
	  vlib_process_signal_event (vm, em->export_process_node_index, 1, 0);

	}
      else
	{
	  return (-2);
	}
    }
  else
    {
      //sr_set_next_override (SR_DECAP_IOAM_NEXT_POP);
      ioam_export_header_cleanup (em, collector_address, src_address);
      ioam_export_thread_buffer_free (em);
      /* Turn off the export buffer check process */
      vlib_process_signal_event (vm, em->export_process_node_index, 2, 0);

    }

  return 0;
}

/* API message handler */
static void vl_api_sr_ioam_export_enable_disable_t_handler
  (vl_api_sr_ioam_export_enable_disable_t * mp)
{
  vl_api_sr_ioam_export_enable_disable_reply_t *rmp;
  ioam_export_main_t *sm = &sr_ioam_export_main;
  int rv;

  rv = sr_ioam_export_enable_disable (sm, (int) (mp->is_disable),
				      (ip4_address_t *)
				      mp->collector_address,
				      (ip4_address_t *) mp->src_address);

  REPLY_MACRO (VL_API_SR_IOAM_EXPORT_ENABLE_DISABLE_REPLY);
}				/* API message handler */



/* Set up the API message handling tables */
static clib_error_t *
sr_ioam_export_plugin_api_hookup (vlib_main_t * vm)
{
  ioam_export_main_t *sm = &sr_ioam_export_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_sr_ioam_export_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <ioam/export-srv6/sr_ioam_export_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (ioam_export_main_t * sm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_sr_ioam_export;
#undef _
}


static clib_error_t *
set_sr_ioam_export_ipfix_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  ioam_export_main_t *em = &sr_ioam_export_main;
  ip4_address_t collector, src;
  u8 is_disable = 0;

  collector.as_u32 = 0;
  src.as_u32 = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "collector %U", unformat_ip4_address, &collector))
	;
      else if (unformat (input, "src %U", unformat_ip4_address, &src))
	;
      else if (unformat (input, "disable"))
	is_disable = 1;
      else
	break;
    }

  if (collector.as_u32 == 0)
    return clib_error_return (0, "collector address required");

  if (src.as_u32 == 0)
    return clib_error_return (0, "src address required");

  em->ipfix_collector.as_u32 = collector.as_u32;
  em->src_address.as_u32 = src.as_u32;

  vlib_cli_output (vm, "Collector %U, src address %U",
		   format_ip4_address, &em->ipfix_collector,
		   format_ip4_address, &em->src_address);

  /* Turn on the export timer process */
  // vlib_process_signal_event (vm, flow_report_process_node.index,
  //1, 0);
  if (0 != sr_ioam_export_enable_disable (em, is_disable, &collector, &src))
    {
      return clib_error_return (0, "Unable to set ioam sr export");
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_sr_ioam_ipfix_command, static) =
{
.path = "set sr-ioam export ipfix",
.short_help = "set sr-ioam export ipfix collector <ip4-address> src <ip4-address>",
.function = set_sr_ioam_export_ipfix_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
sr_ioam_export_init (vlib_main_t * vm)
{
  ioam_export_main_t *em = &sr_ioam_export_main;
  clib_error_t *error = 0;
  u8 *name;

  em->set_id = IPFIX_SR_IOAM_EXPORT_ID;

  name = format (0, "sr_ioam_export_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  em->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);
  em->unix_time_0 = (u32) time (0);	/* Store starting time */
  em->vlib_time_0 = vlib_time_now (vm);

  error = sr_ioam_export_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (em, &api_main);

  em->my_hbh_slot = ~0;
  em->vlib_main = vm;
  em->vnet_main = vnet_get_main ();
  ioam_export_reset_next_node (em);
  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (sr_ioam_export_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
