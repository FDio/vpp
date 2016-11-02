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

/* TODO return VNET_API_ERROR_* here
   strings should be in CLI handler function*/
clib_error_t *
set_span_add_delete_entry (vlib_main_t * vm,
			   u32 src_sw_if_index,
			   u32 dst_sw_if_index, u8 is_add)
{
  span_main_t *sm = &span_main;

  if (src_sw_if_index == ~0)
    return clib_error_return (0, "Source interface must be set...");
  if (dst_sw_if_index == ~0 && is_add)
    return clib_error_return (0, "Destination interface must be set...");
  if (src_sw_if_index == dst_sw_if_index)
    return clib_error_return (0,
			      "Source interface must be different to Destination interface");

#if 0
  uword *p = hash_get (sm->dst_sw_if_index_by_src, src_sw_if_index);
  if (p != 0 && is_add)
    return clib_error_return (0,
			      "Source interface is already mirrored to interface index %d",
			      p[0]);
  if (p == 0 && !is_add)
    return clib_error_return (0, "Source interface is not mirrored");
  if (is_add)
    hash_set (sm->dst_sw_if_index_by_src, src_sw_if_index, dst_sw_if_index);
  else
    hash_unset (sm->dst_sw_if_index_by_src, src_sw_if_index);
#endif

  vec_validate_aligned (sm->dst_by_src_sw_if_index, src_sw_if_index,
			CLIB_CACHE_LINE_BYTES);
  sm->dst_by_src_sw_if_index[src_sw_if_index] = is_add ? dst_sw_if_index : ~0;
  vnet_feature_enable_disable ("device-input", "span-input",
			       src_sw_if_index, is_add, 0, 0);

  vnet_feature_enable_disable ("device-input", "span2-input",
			       src_sw_if_index, is_add, 0, 0);
  return 0;
}

static clib_error_t *
set_span_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  span_main_t *sm = &span_main;
  u32 src_sw_if_index = ~0;
  u32 dst_sw_if_index = ~0;
  u8 is_add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src %U", unformat_vnet_sw_interface,
		    sm->vnet_main, &src_sw_if_index))
	;
      else if (unformat (input, "dst %U", unformat_vnet_sw_interface,
			 sm->vnet_main, &dst_sw_if_index))
	;
      else if (unformat (input, "disable"))
	is_add = 0;
      else
	break;
    }

  return set_span_add_delete_entry (vm, src_sw_if_index, dst_sw_if_index,
				    is_add);
}

/* *INDENT-OFF* */
/* TODO cli should be "set inteface span <if-name> [disable | destination <if-name>] */
VLIB_CLI_COMMAND (set_span_command, static) = {
  .path = "set span",
  .short_help =
      "set span src <interface-name> [dst <interface-name>|disable]",
  .function = set_span_command_fn,
};
/* *INDENT-ON* */

/* TODO "show interface span" */
#if 0
static clib_error_t *
show_span_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  span_main_t *sm = &span_main;
  vnet_main_t *vnm = &vnet_main;
  u32 src_sw_if_index = ~0, dst_sw_if_index = ~0;

  /* *INDENT-OFF* */
  vlib_cli_output (vm, "SPAN source interface to destination interface table");
  hash_foreach (src_sw_if_index, dst_sw_if_index, sm->dst_sw_if_index_by_src, ({
      vlib_cli_output (vm, "%32U => %-32U",
          format_vnet_sw_if_index_name, vnm, src_sw_if_index,
          format_vnet_sw_if_index_name, vnm, dst_sw_if_index);
  }));
  /* *INDENT-ON* */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_span_command, static) = {
  .path = "show span",
  .short_help = "Shows SPAN mirror table",
  .function = show_span_command_fn,
};
/* *INDENT-ON* */
#endif

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
