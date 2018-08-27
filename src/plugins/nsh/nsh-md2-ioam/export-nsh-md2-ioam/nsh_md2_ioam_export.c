/*
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
 */
/*
 *------------------------------------------------------------------
 * nsh_md2_ioam_export.c - ioam export API / debug CLI handling
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ioam/export-common/ioam_export.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <nsh/nsh.h>
#include <nsh/nsh-md2-ioam/nsh_md2_ioam.h>


ioam_export_main_t nsh_md2_ioam_export_main;


extern vlib_node_registration_t nsh_md2_ioam_export_node;
extern void nsh_md2_set_next_ioam_export_override (uword next);
/* Action function shared between message handler and debug CLI */
int
nsh_md2_ioam_export_enable_disable (ioam_export_main_t * em,
				    u8 is_disable,
				    ip4_address_t * collector_address,
				    ip4_address_t * src_address)
{
  vlib_main_t *vm = em->vlib_main;
  u32 node_index = nsh_md2_ioam_export_node.index;
  vlib_node_t *nsh_input_node = NULL;

  if (is_disable == 0)
    {
      if (em->my_hbh_slot == ~0)
	{
	  /* Hook this export node to nsh-input */
	  nsh_input_node = vlib_get_node_by_name (vm, (u8 *) "nsh-input");
	  if (!nsh_input_node)
	    {
	      /* node does not exist give up */
	      return (-1);
	    }
	  em->my_hbh_slot =
	    vlib_node_add_next (vm, nsh_input_node->index, node_index);
	}
      if (1 == ioam_export_header_create (em, collector_address, src_address))
	{
	  ioam_export_thread_buffer_init (em, vm);
	  nsh_md2_set_next_ioam_export_override (em->my_hbh_slot);
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
      nsh_md2_set_next_ioam_export_override (0);	// VXLAN_GPE_DECAP_IOAM_V4_NEXT_POP
      ioam_export_header_cleanup (em, collector_address, src_address);
      ioam_export_thread_buffer_free (em);
      /* Turn off the export buffer check process */
      vlib_process_signal_event (vm, em->export_process_node_index, 2, 0);

    }

  return 0;
}



static clib_error_t *
set_nsh_md2_ioam_export_ipfix_command_fn (vlib_main_t * vm,
					  unformat_input_t * input,
					  vlib_cli_command_t * cmd)
{
  ioam_export_main_t *em = &nsh_md2_ioam_export_main;
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
  if (0 !=
      nsh_md2_ioam_export_enable_disable (em, is_disable, &collector, &src))
    {
      return clib_error_return (0, "Unable to set ioam nsh-md2 export");
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_nsh_md2_ioam_ipfix_command, static) =
{
.path = "set nsh-md2-ioam export ipfix",
.short_help = "set nsh-md2-ioam export ipfix collector <ip4-address> src <ip4-address>",
.function = set_nsh_md2_ioam_export_ipfix_command_fn,
};
/* *INDENT-ON* */


#define IPFIX_NSH_MD2_IOAM_EXPORT_ID 274	// TODO: Move this to ioam/ioam_export.h
static clib_error_t *
nsh_md2_ioam_export_init (vlib_main_t * vm)
{
  ioam_export_main_t *em = &nsh_md2_ioam_export_main;
  clib_error_t *error = 0;

  em->set_id = IPFIX_NSH_MD2_IOAM_EXPORT_ID;
  em->unix_time_0 = (u32) time (0);	/* Store starting time */
  em->vlib_time_0 = vlib_time_now (vm);

  em->my_hbh_slot = ~0;
  em->vlib_main = vm;
  em->vnet_main = vnet_get_main ();
  ioam_export_reset_next_node (em);

  return error;
}

VLIB_INIT_FUNCTION (nsh_md2_ioam_export_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
