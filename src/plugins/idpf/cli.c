/*
 *------------------------------------------------------------------
 * Copyright (c) 2023 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */
#include <idpf/idpf.h>

static clib_error_t *
idpf_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  idpf_create_if_args_t args;
  u32 tmp;

  clib_memset (&args, 0, sizeof (idpf_create_if_args_t));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_pci_addr, &args.addr))
	;
      else if (unformat (line_input, "rx-single %u", &tmp))
	args.rxq_single = 1;
      else if (unformat (line_input, "tx-single %u", &tmp))
	args.txq_single = 1;
      else if (unformat (line_input, "rxq-num %u", &tmp))
	args.rxq_num = tmp;
      else if (unformat (line_input, "txq-num %u", &tmp))
	args.txq_num = tmp;
      else if (unformat (line_input, "rxq-size %u", &tmp))
	args.rxq_size = tmp;
      else if (unformat (line_input, "txq-size %u", &tmp))
	args.txq_size = tmp;
      else if (unformat (line_input, "vport-num %u", &tmp))
	args.req_vport_nb = tmp;
      else if (unformat (line_input, "name %s", &args.name))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  idpf_create_if (vm, &args);

  vec_free (args.name);

  return args.error;
}

VLIB_CLI_COMMAND (idpf_create_command, static) = {
  .path = "create interface idpf",
  .short_help = "create interface idpf <pci-address> "
		"[vport <size>] [rx-single <size>] [tx-single <size>]",
  .function = idpf_create_command_fn,
};

static clib_error_t *
idpf_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  if (hw == NULL || idpf_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not an IDPF interface");

  vlib_process_signal_event (vm, idpf_process_node.index,
			     IDPF_PROCESS_EVENT_DELETE_IF, hw->dev_instance);

  return 0;
}

VLIB_CLI_COMMAND (idpf_delete_command, static) = {
  .path = "delete interface idpf",
  .short_help = "delete interface idpf "
		"{<interface> | sw_if_index <sw_idx>}",
  .function = idpf_delete_command_fn,
  .is_mp_safe = 1,
};

clib_error_t *
idpf_cli_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (idpf_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
