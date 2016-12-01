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

#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <vnet/feature/feature.h>

#include <vnet/span/span.h>

int
span_add_delete_entry (vlib_main_t * vm,
		       u32 src_sw_if_index, u32 dst_sw_if_index, u8 state)
{
  span_main_t *sm = &span_main;
  span_instance_t *si;

  if (state > 3)
    return VNET_API_ERROR_UNIMPLEMENTED;

  if ((src_sw_if_index == ~0) || (dst_sw_if_index == ~0 && state > 0)
      || (src_sw_if_index == dst_sw_if_index))
    return VNET_API_ERROR_INVALID_INTERFACE;

  vec_validate_aligned (sm->interfaces, src_sw_if_index,
			CLIB_CACHE_LINE_BYTES);
  si = vec_elt_at_index (sm->interfaces, src_sw_if_index);
  si->state = state;
  si->mirror_sw_if_index = dst_sw_if_index;
  vnet_feature_enable_disable ("device-input", "span-input",
			       src_sw_if_index, ((state & 1) != 0), 0, 0);
  vnet_feature_enable_disable ("interface-output", "span-output",
			       src_sw_if_index, ((state & 2) != 0), 0, 0);
  return 0;
}

static clib_error_t *
set_interface_span_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  span_main_t *sm = &span_main;
  u32 src_sw_if_index = ~0;
  u32 dst_sw_if_index = ~0;
  u8 state = 3;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    sm->vnet_main, &src_sw_if_index))
	;
      else if (unformat (input, "destination %U", unformat_vnet_sw_interface,
			 sm->vnet_main, &dst_sw_if_index))
	;
      else if (unformat (input, "disable"))
	state = 0;
      else if (unformat (input, "rx"))
	state = 1;
      else if (unformat (input, "tx"))
	state = 2;
      else if (unformat (input, "both"))
	state = 3;
      else
	break;
    }

  int rv =
    span_add_delete_entry (vm, src_sw_if_index, dst_sw_if_index, state);
  if (rv == VNET_API_ERROR_INVALID_INTERFACE)
    return clib_error_return (0, "Invalid interface");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_span_command, static) = {
  .path = "set interface span",
  .short_help = "set interface span <if-name> [disable | destination <if-name>]",
  .function = set_interface_span_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_interfaces_span_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{

  span_main_t *sm = &span_main;
  span_instance_t *si;
  vnet_main_t *vnm = &vnet_main;
  u8 header = 1;

  vec_foreach (si, sm->interfaces)
  {
    if (si->state > 0)
      {
	if (header)
	  {
	    vlib_cli_output (vm,
			     "SPAN source interface to destination interface table");
	    header = 0;
	  }
	// FIXME add direction
	vlib_cli_output (vm, "%32U => %-32U",
			 format_vnet_sw_if_index_name, vnm, si - sm->interfaces,
			 format_vnet_sw_if_index_name, vnm, si->mirror_sw_if_index);
      }
  }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_interfaces_span_command, static) = {
  .path = "show interfaces span",
  .short_help = "Shows SPAN mirror table",
  .function = show_interfaces_span_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
span_init (vlib_main_t * vm)
{
  span_main_t *sm = &span_main;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (span_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
