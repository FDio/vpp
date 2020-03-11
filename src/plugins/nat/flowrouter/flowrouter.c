/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 *
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

#include <stdbool.h>
#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vlib/vlib.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.c>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_table.h>
#include "flowrouter.h"
#include <vnet/feature/feature.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <arpa/inet.h>
#include <vnet/fib/ip4_fib.h>

#ifdef UNITTEST
#define vnet_feature_next_with_data stub_vnet_feature_next_with_data
#define vlib_get_buffer stub_vlib_get_buffer
#endif

typedef struct {
  bool enabled; /* Timer process state */
   
  /* Interface pool */
  flowrouter_interface_t *interfaces;
  u32 *interface_by_sw_if_index;

  flowrouter_state_change_t *state_change;

  /* Handover nodes */
  u32 slow_path_node_index;
  u32 fast_path_node_index;
} flowrouter_main_t;

flowrouter_main_t flowrouter_main;

void flowrouter_init (void)
{
  flowrouter_main_t *fwm = &flowrouter_main;
  if (fwm->enabled) return;
  fwm->fast_path_node_index = vlib_frame_queue_main_init (flowrouter_node.index, 0);
  fwm->enabled = true;
}

void
flowrouter_register_interface (u32 sw_if_index, u32 node_index, flowrouter_session_find_t *f,
			       flowrouter_state_change_t *sf,
			       u32 process_node_index)
{
  flowrouter_main_t *fwm = &flowrouter_main;
  flowrouter_interface_t *interface;

  pool_get (fwm->interfaces, interface);
  interface->sw_if_index = sw_if_index;
  vec_validate_init_empty(fwm->interface_by_sw_if_index, sw_if_index, ~0);
  fwm->interface_by_sw_if_index[sw_if_index] = interface - fwm->interfaces;
  interface->session_find = f;
  fwm->state_change = sf ? sf : fwm->state_change;

  interface->process_node = process_node_index;
  interface->punt_node = node_index != ~0 ? vlib_frame_queue_main_init (node_index, 0) : ~0;


  ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
}

u8 *
format_flowrouter_state (u8 *s, va_list * args)
{
  enum flowrouter_session_state state = va_arg (*args, enum flowrouter_session_state);

  switch (state) {
  case FLOWROUTER_STATE_TCP_SYN_SEEN:
    s = format (s, "syn seen");
    break;
  case FLOWROUTER_STATE_TCP_ESTABLISHED:
    s = format (s, "tcp established");
    break;
  case FLOWROUTER_STATE_TCP_FIN_WAIT:
    s = format (s, "tcp fin wait");
    break;
  case FLOWROUTER_STATE_TCP_CLOSE_WAIT:
    s = format (s, "tcp close wait");
    break;
  case FLOWROUTER_STATE_TCP_CLOSED:
    s = format (s, "tcp closed");
    break;
  case FLOWROUTER_STATE_TCP_LAST_ACK:
    s = format (s, "tcp last ack");
    break;
  case FLOWROUTER_STATE_UNKNOWN:
  default:
    s = format (s, "unknown");
  }
  return s;
}

u8 *
format_flowrouter_session (u8 * s, va_list * args)
{
  flowrouter_session_t *ses = va_arg (*args, flowrouter_session_t *);
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);

  if (ses->instructions & (FLOW_INSTR_DESTINATION_ADDRESS|FLOW_INSTR_DESTINATION_PORT)) {
    s = format (s,
		"%U%%%u:%u -> %U:%u (%U:%u) state: %U last heard: %.2f",
		format_ip4_address, &ses->k.sa,	ses->fib_index, ntohs(ses->k.sp),
		format_ip4_address, &ses->k.da, ntohs(ses->k.dp),
		format_ip4_address, &ses->post_da, ntohs(ses->post_dp),
		format_flowrouter_state, ses->state, now - ses->last_heard);
  } else if (ses->instructions & (FLOW_INSTR_SOURCE_ADDRESS|FLOW_INSTR_SOURCE_PORT)) {
    s = format (s,
		"%U%%%u:%u (%U:%u) -> %U:%u state: %U last heard: %.2f",
		format_ip4_address, &ses->k.sa, ses->fib_index, ntohs(ses->k.sp),
		format_ip4_address, &ses->post_sa, ntohs(ses->post_sp),
		format_ip4_address, &ses->k.da, ntohs(ses->k.dp),
		format_flowrouter_state, ses->state, now - ses->last_heard);
  } else
    s = format (s, "UNKNOWN INSTRUCTIONS %u", ses->instructions);
  s = format (s, "\n");
  return s;
}

static clib_error_t *
show_flowrouter_summary_command_fn (vlib_main_t * vm, unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  flowrouter_main_t *fwm = &flowrouter_main;
  flowrouter_interface_t *interface;
  //  flowrouter_db_t *db;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      vlib_cli_output(vm, "Enabled interfaces %u", pool_elts(fwm->interfaces)); 
      /* *INDENT-OFF* */
      pool_foreach(interface, fwm->interfaces,
		   ({
		     vlib_cli_output(vm, "NAT enabled on: %u", interface->sw_if_index);
		   }));
      /* *INDENT-ON* */
      return 0;
    }
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND(show_flowrouter_summary_command, static) = {
  .path = "show flowrouter summary",
  .short_help = "show flowrouter summary",
  .function = show_flowrouter_summary_command_fn,
};
