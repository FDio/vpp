/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <snort/snort.h>
#include <vnet/vnet.h>

VLIB_REGISTER_LOG_CLASS (snort_log, static) = {
  .class_name = "snort",
  .subclass_name = "interface",
};

VNET_FEATURE_INIT (snort_ip4_input, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "snort-ip4-input",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (snort_ip4_output, static) = {
  .arc_name = "ip4-output",
  .node_name = "snort-ip4-output",
  .runs_before = VNET_FEATURES ("interface-output"),
};

static void
snort_feature_enable_disable (u32 sw_if_index, int is_enable, int input,
			      int output)
{
  u32 fa_data = input ? 1 : 0 | output ? 1 : 0;

  if (input)
    vnet_feature_enable_disable ("ip4-unicast", "snort-ip4-input", sw_if_index,
				 is_enable, &fa_data, sizeof (fa_data));

  if (output)
    vnet_feature_enable_disable ("ip4-output", "snort-ip4-output", sw_if_index,
				 is_enable, &fa_data, sizeof (fa_data));
}

int
snort_interface_enable_disable (vlib_main_t *vm, char *instance_name,
				u32 sw_if_index, int is_enable, int input,
				int output)
{
  snort_main_t *sm = &snort_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *software_interface =
    vnet_get_sw_interface (vnm, sw_if_index);
  snort_instance_t *instance;
  u16 *input_instance, *output_instance, instance_index;
  int rv = 0;

  /* If interface is up, do not allow modifying attached instances */
  if (software_interface->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    {
      rv = VNET_API_ERROR_INSTANCE_IN_USE;
      log_err ("interface '%U' is currently up", format_vnet_sw_if_index_name,
	       vnm, sw_if_index);
      goto done;
    }

  /* Check if provided instance name exists */
  instance = snort_get_instance_by_name (instance_name);
  if (instance == NULL)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      log_err ("unknown instance '%s'", instance_name);
      goto done;
    }

  /* Check if interface is attached before unnecessarily increasing size of
   * vector */
  if (!is_enable && vec_len (sm->input_instance_by_interface) <= sw_if_index)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      log_err ("interface %U is not assigned to snort instance %s!",
	       format_vnet_sw_if_index_name, vnm, sw_if_index, instance->name);
      goto done;
    }

  /* vec_validate initialises empty space to 0s, which corresponds to null
   * pointers (i.e. empty vectors) in the snort_interface_data_t structs which
   * is precisely what we need */
  vec_validate_init_empty (sm->input_instance_by_interface, sw_if_index, ~0);
  vec_validate_init_empty (sm->output_instance_by_interface, sw_if_index, ~0);
  input_instance = sm->input_instance_by_interface + sw_if_index;
  output_instance = sm->output_instance_by_interface + sw_if_index;

  instance_index = instance->index;

  /* When detaching with direction SNORT_INOUT choose currently attached
   * directions */
  if (!is_enable)
    {
      if (input && *input_instance != instance_index)
	{
	  rv = VNET_API_ERROR_INVALID_INTERFACE;
	  log_err ("interface %U is not assigned to snort instance %s!",
		   format_vnet_sw_if_index_name, vnm, sw_if_index,
		   instance->name);
	  goto done;
	}

      if (output && *output_instance != instance_index)
	{
	  rv = VNET_API_ERROR_INVALID_INTERFACE;
	  log_err ("interface %U is not assigned to snort instance %s!",
		   format_vnet_sw_if_index_name, vnm, sw_if_index,
		   instance->name);
	  goto done;
	}

      if (input)
	*input_instance = ~0;
      if (output)
	*output_instance = ~0;
    }
  else
    {
      if (input && *input_instance == instance_index)
	{
	  rv = VNET_API_ERROR_FEATURE_ALREADY_ENABLED;
	  log_err ("interface %U already assgined to instance '%s' on "
		   "input direction",
		   format_vnet_sw_if_index_name, vnm, sw_if_index,
		   instance->name);
	  goto done;
	}
      if (output && *output_instance == instance_index)
	{
	  rv = VNET_API_ERROR_FEATURE_ALREADY_ENABLED;
	  log_err ("interface %U already assgined to instance '%s' on "
		   "output direction",
		   format_vnet_sw_if_index_name, vnm, sw_if_index,
		   instance->name);
	  goto done;
	}

      if (input)
	*input_instance = instance_index;
      if (output)
	*output_instance = instance_index;
    }

  snort_feature_enable_disable (sw_if_index, is_enable, input, output);

done:
  return rv;
}

int
snort_interface_disable_all (vlib_main_t *vm, u32 sw_if_index)
{
  snort_main_t *sm = &snort_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *software_interface =
    vnet_get_sw_interface (vnm, sw_if_index);
  int rv = 0, in, out;

  if (software_interface->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    {
      rv = VNET_API_ERROR_INSTANCE_IN_USE;
      log_err ("interface '%U' is currently up", format_vnet_sw_if_index_name,
	       vnm, sw_if_index);
      goto done;
    }

  if (vec_len (sm->input_instance_by_interface) <= sw_if_index)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      log_err ("no instances attached to interface %U",
	       format_vnet_sw_if_index_name, vnm, sw_if_index);
      goto done;
    }

  in = sm->input_instance_by_interface[sw_if_index] != (u16) ~0;
  out = sm->output_instance_by_interface[sw_if_index] != (u16) ~0;

  if (!in && !out)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      log_err ("no instances attached to interface %U",
	       format_vnet_sw_if_index_name, vnm, sw_if_index);
      goto done;
    }

  snort_feature_enable_disable (sw_if_index, 0 /* is_enable */, in, out);
done:
  return rv;
}

int
snort_strip_instance_interfaces (vlib_main_t *vm, snort_instance_t *instance)
{
  snort_main_t *sm = &snort_main;

  int i;
  int rv = 0;

  vec_foreach_index (i, sm->input_instance_by_interface)
    if (sm->input_instance_by_interface[i] == instance->index)
      rv = snort_interface_enable_disable (vm, (char *) instance->name, i,
					   0 /* is_enable */, 1, 0);

  vec_foreach_index (i, sm->output_instance_by_interface)
    if (sm->output_instance_by_interface[i] == instance->index)
      rv = snort_interface_enable_disable (vm, (char *) instance->name, i,
					   0 /* is_enable */, 0, 1);

  return rv;
}
