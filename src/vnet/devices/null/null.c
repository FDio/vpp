/*
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
 */

#include <vnet/vnet.h>
#include <vnet/devices/null/null.h>

/**
 * Various 'module' level variables
 */
typedef struct null_main_t_
{
  /**
   * Allocated null instances
   */
  uword *instances;
} null_main_t;

static null_main_t null_main;

/*
 * The null rewrite is 0 length vector
 */
static u8 *
null_build_rewrite (vnet_main_t * vnm,
		    u32 sw_if_index,
		    vnet_link_t link_type, const void *dst_address)
{
  u8 *rewrite = NULL;

  vec_validate (rewrite, 0);
  vec_reset_length (rewrite);

  return (rewrite);
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (null_hw_interface_class) = {
  .name = "null",
  .build_rewrite = null_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

static u8 *
format_null_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "null%d", dev_instance);
}

static clib_error_t *
null_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi;
  u32 id, sw_if_index;

  u32 hw_flags = ((flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
		  VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  /* *INDENT-OFF* */
  hi = vnet_get_hw_interface (vnm, hw_if_index);
  hash_foreach (id, sw_if_index, hi->sub_interface_sw_if_index_by_id,
  ({
    vnet_sw_interface_set_flags (vnm, sw_if_index, flags);
  }));
  /* *INDENT-ON* */

  return (NULL);
}

static uword
null_tx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u16 nexts[VLIB_FRAME_SIZE];
  u32 *from;

  from = vlib_frame_vector_args (frame);
  clib_memset_u16 (nexts, 0, VLIB_FRAME_SIZE);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (null_device_class) = {
  .name = "null",
  .format_device_name = format_null_name,
  .admin_up_down_function = null_admin_up_down,
  .tx_function = null_tx,
};
/* *INDENT-ON* */

/*
 * Maintain a bitmap of allocated null instance numbers.
 */
#define NULL_MAX_INSTANCE		(16 * 1024)

static u32
null_instance_alloc (u8 is_specified, u32 want)
{
  /*
   * Check for dynamically allocaetd instance number.
   */
  if (!is_specified)
    {
      u32 bit;

      bit = clib_bitmap_first_clear (null_main.instances);
      if (bit >= NULL_MAX_INSTANCE)
	{
	  return ~0;
	}
      null_main.instances = clib_bitmap_set (null_main.instances, bit, 1);
      return bit;
    }

  /*
   * In range?
   */
  if (want >= NULL_MAX_INSTANCE)
    {
      return ~0;
    }

  /*
   * Already in use?
   */
  if (clib_bitmap_get (null_main.instances, want))
    {
      return ~0;
    }

  /*
   * Grant allocation request.
   */
  null_main.instances = clib_bitmap_set (null_main.instances, want, 1);

  return want;
}

static int
null_instance_free (u32 instance)
{
  if (instance >= NULL_MAX_INSTANCE)
    {
      return -1;
    }

  if (clib_bitmap_get (null_main.instances, instance) == 0)
    {
      return -1;
    }

  null_main.instances = clib_bitmap_set (null_main.instances, instance, 0);
  return 0;
}

int
null_interface_add (u32 instance, u32 * sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hi;
  u32 hw_if_index;

  ASSERT (sw_if_index);

  /*
   * Allocate a null instance.  Either select one dynamically
   * or try to use the desired user_instance number.
   */

  instance = null_instance_alloc ((~0 != instance), instance);

  if (~0 == instance)
    return VNET_API_ERROR_INVALID_REGISTRATION;

  hw_if_index = vnet_register_interface (vnm,
					 null_device_class.index,
					 instance,
					 null_hw_interface_class.index,
					 instance);

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  *sw_if_index = hi->sw_if_index;

  vlib_node_add_named_next (vm, hi->tx_node_index, "error-drop");

  return 0;
}

static clib_error_t *
null_interface_add_cmd (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 user_instance = ~0;
  u32 sw_if_index;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "instance %d", &user_instance))
	;
      else
	break;
    }

  rv = null_interface_add (user_instance, &sw_if_index);

  if (rv)
    return clib_error_return (0, "null_interface_add failed");

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		   vnet_get_main (), sw_if_index);
  return 0;
}

/*?
 * Create a null interface.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{null create-interface [mac <mac-addr>] [instance <instance>]}
 * Example of how to create a null interface:
 * @cliexcmd{null create}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (null_create_interface_command, static) = {
  .path = "null create",
  .short_help = "null create [instance <instance>]",
  .function = null_interface_add_cmd,
};
/* *INDENT-ON* */

int
null_interface_delete (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;
  vnet_hw_interface_t *hi;

  si = vnet_get_sw_interface (vnm, sw_if_index);
  hi = vnet_get_hw_interface (vnm, si->hw_if_index);

  null_instance_free (hi->dev_instance);
  vnet_delete_hw_interface (vnm, si->hw_if_index);

  return 0;
}

static clib_error_t *
null_interface_del_cmd (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface not specified");

  rv = null_interface_delete (sw_if_index);

  if (rv)
    return clib_error_return (0, "null_interface_Del failed");

  return 0;
}

/*?
 * Delete a null interface.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{null delete intfc <interface>}
 * Example of how to delete a null interface:
 * @cliexcmd{null delete-interface intfc loop0}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (null_delete_interface_command, static) = {
  .path = "null delete",
  .short_help = "null delete <interface>",
  .function = null_interface_del_cmd,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
