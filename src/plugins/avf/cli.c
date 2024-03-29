/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <avf/avf.h>

static clib_error_t *
avf_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  avf_create_if_args_t args;
  u32 tmp;

  clib_memset (&args, 0, sizeof (avf_create_if_args_t));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vlib_pci_addr, &args.addr))
	;
      else if (unformat (input, "elog"))
	args.enable_elog = 1;
      else if (unformat (input, "rx-queue-size %u", &tmp))
	args.rxq_size = tmp;
      else if (unformat (input, "tx-queue-size %u", &tmp))
	args.txq_size = tmp;
      else if (unformat (input, "num-rx-queues %u", &tmp))
	args.rxq_num = tmp;
      else if (unformat (input, "num-tx-queues %u", &tmp))
	args.txq_num = tmp;
      else if (unformat (input, "name %s", &args.name))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  avf_create_if (vm, &args);

  vec_free (args.name);

  return args.error;
}

VLIB_CLI_COMMAND (avf_create_command, static) = {
  .path = "create interface avf",
  .short_help = "create interface avf <pci-address> "
		"[rx-queue-size <size>] [tx-queue-size <size>] "
		"[num-rx-queues <size>]",
  .function = avf_create_command_fn,
};

static clib_error_t *
avf_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  if (hw == NULL || avf_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not an AVF interface");

  vlib_process_signal_event (vm, avf_process_node.index,
			     AVF_PROCESS_EVENT_DELETE_IF, hw->dev_instance);

  return 0;
}

VLIB_CLI_COMMAND (avf_delete_command, static) = {
  .path = "delete interface avf",
  .short_help = "delete interface avf "
    "{<interface> | sw_if_index <sw_idx>}",
  .function = avf_delete_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
avf_test_command_fn (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  avf_device_t *ad;
  vnet_main_t *vnm = vnet_get_main ();
  int test_irq = 0, enable_elog = 0, disable_elog = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (input, "irq"))
	test_irq = 1;
      else if (unformat (input, "elog-on"))
	enable_elog = 1;
      else if (unformat (input, "elog-off"))
	disable_elog = 1;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  if (hw == NULL || avf_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a AVF interface");

  ad = avf_get_device (hw->dev_instance);

  if (enable_elog)
    ad->flags |= AVF_DEVICE_F_ELOG;

  if (disable_elog)
    ad->flags &= ~AVF_DEVICE_F_ELOG;

  if (test_irq)
    avf_reg_write (ad, AVFINT_DYN_CTL0, (1 << 0) | (3 << 3) | (1 << 2));

  return 0;
}

VLIB_CLI_COMMAND (avf_test_command, static) = {
  .path = "test avf",
  .short_help = "test avf [<interface> | sw_if_index <sw_idx>] [irq] "
    "[elog-on] [elog-off]",
  .function = avf_test_command_fn,
};

clib_error_t *
avf_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (avf_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
