/*
 * Copyright (c) 2016,2020 Cisco and/or its affiliates.
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <plugins/adl/adl.h>

adl_main_t adl_main;

static clib_error_t *
adl_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  adl_main_t *am = &adl_main;
  adl_config_data_t _data, *data = &_data;
  vlib_main_t *vm = am->vlib_main;
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);;
  adl_config_main_t *acm;
  int address_family;
  u32 ci, default_next;

  clib_memset (data, 0, sizeof (*data));

  /*
   * Ignore local interface, pg interfaces. $$$ need a #define for the
   * first "real" interface. The answer is 5 at the moment.
   */
  if (hi->dev_class_index == vnet_local_interface_device_class.index)
    return 0;

  for (address_family = VNET_ADL_IP4; address_family < VNET_N_ADLS;
       address_family++)
    {
      acm = &am->adl_config_mains[address_family];

      /*
       * Once-only code to initialize the per-address-family
       * adl feature subgraphs.
       * Since the (single) start-node, adl-input, must be able
       * to push pkts into three separate subgraphs, we
       * use a unified adl_feature_type_t enumeration.
       */

      if (!(acm->config_main.node_index_by_feature_index))
	{
	  switch (address_family)
	    {
	    case VNET_ADL_IP4:
	      {
		static char *start_nodes[] = { "adl-input" };
		static char *feature_nodes[] = {
		  [IP4_RX_ADL_ALLOWLIST] = "ip4-adl-allowlist",
		  [IP4_RX_ADL_INPUT] = "ip4-input",
		};

		vnet_config_init (vm, &acm->config_main,
				  start_nodes, ARRAY_LEN (start_nodes),
				  feature_nodes, ARRAY_LEN (feature_nodes));
	      }
	      break;
	    case VNET_ADL_IP6:
	      {
		static char *start_nodes[] = { "adl-input" };
		static char *feature_nodes[] = {
		  [IP6_RX_ADL_ALLOWLIST] = "ip6-adl-allowlist",
		  [IP6_RX_ADL_INPUT] = "ip6-input",
		};
		vnet_config_init (vm, &acm->config_main,
				  start_nodes, ARRAY_LEN (start_nodes),
				  feature_nodes, ARRAY_LEN (feature_nodes));
	      }
	      break;

	    case VNET_ADL_DEFAULT:
	      {
		static char *start_nodes[] = { "adl-input" };
		static char *feature_nodes[] = {
		  [DEFAULT_RX_ADL_ALLOWLIST] = "default-adl-allowlist",
		  [DEFAULT_RX_ADL_INPUT] = "ethernet-input",
		};
		vnet_config_init (vm, &acm->config_main,
				  start_nodes, ARRAY_LEN (start_nodes),
				  feature_nodes, ARRAY_LEN (feature_nodes));
	      }
	      break;

	    default:
	      clib_warning ("bug");
	      break;
	    }
	}
      vec_validate_init_empty (acm->config_index_by_sw_if_index, sw_if_index,
			       ~0);

      ci = acm->config_index_by_sw_if_index[sw_if_index];

      /* Create a sensible initial config: send pkts to xxx-input */
      if (address_family == VNET_ADL_IP4)
	default_next = IP4_RX_ADL_INPUT;
      else if (address_family == VNET_ADL_IP6)
	default_next = IP6_RX_ADL_INPUT;
      else
	default_next = DEFAULT_RX_ADL_INPUT;

      if (is_add)
	ci = vnet_config_add_feature (vm, &acm->config_main,
				      ci, default_next, data, sizeof (*data));
      else
	ci = vnet_config_del_feature (vm, &acm->config_main,
				      ci, default_next, data, sizeof (*data));

      acm->config_index_by_sw_if_index[sw_if_index] = ci;
    }
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (adl_sw_interface_add_del);

static clib_error_t *
adl_init (vlib_main_t * vm)
{
  adl_main_t *cm = &adl_main;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();

  /*
   * Setup the packet generator so we can inject ethernet
   * frames into this node
   */
  ethernet_setup_node (vm, adl_input_node.index);
  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (adl_init) =
{
  .runs_after = VLIB_INITS ("ip4_allowlist_init", "ip6_allowlist_init"),
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT (adl, static) =
{
  .arc_name = "device-input",
  .node_name = "adl-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

int adl_interface_enable_disable (u32 sw_if_index, int enable_disable)
{
  /*
   * Redirect pkts from the driver to the adl node.
   */
  vnet_feature_enable_disable ("device-input", "adl-input",
			       sw_if_index, enable_disable, 0, 0);
  return 0;
}

static clib_error_t *
adl_enable_disable_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  adl_main_t * cm = &adl_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "disable"))
      enable_disable = 0;
    else if (unformat (input, "%U", unformat_vnet_sw_interface,
                       cm->vnet_main, &sw_if_index))
      ;
    else
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = adl_interface_enable_disable (sw_if_index, enable_disable);

  switch(rv) {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "adl_interface_enable_disable returned %d",
                              rv);
  }
  return 0;
}

VLIB_CLI_COMMAND (adl_interface_command, static) = {
    .path = "adl interface",
    .short_help =
    "adl interface <interface-name> [disable]",
    .function = adl_enable_disable_command_fn,
};


int adl_allowlist_enable_disable (adl_allowlist_enable_disable_args_t *a)
{
  adl_main_t * cm = &adl_main;
  vlib_main_t * vm = cm->vlib_main;
  ip4_main_t * im4 = &ip4_main;
  ip6_main_t * im6 = &ip6_main;
  int address_family;
  int is_add;
  adl_config_main_t * acm;
  u32 next_to_add_del = 0;
  uword * p;
  u32 fib_index = 0;
  u32 ci;
  adl_config_data_t _data, *data=&_data;

  /*
   * Enable / disable allowlist processing on the specified interface
   */

  for (address_family = VNET_ADL_IP4; address_family < VNET_N_ADLS;
       address_family++)
    {
      acm = &cm->adl_config_mains[address_family];

      switch(address_family)
        {
        case VNET_ADL_IP4:
          is_add = (a->ip4 != 0);
          next_to_add_del = IP4_RX_ADL_ALLOWLIST;
          /* configured opaque data must match, or no supper */
          p = hash_get (im4->fib_index_by_table_id, a->fib_id);
          if (p)
            fib_index = p[0];
          else
            {
              if (is_add)
                return VNET_API_ERROR_NO_SUCH_FIB;
              else
                continue;
            }
          break;

        case VNET_ADL_IP6:
          is_add = (a->ip6 != 0);
          next_to_add_del = IP6_RX_ADL_ALLOWLIST;
          p = hash_get (im6->fib_index_by_table_id, a->fib_id);
          if (p)
            fib_index = p[0];
          else
            {
              if (is_add)
                return VNET_API_ERROR_NO_SUCH_FIB;
              else
                continue;
            }
          break;

        case VNET_ADL_DEFAULT:
          is_add = (a->default_adl != 0);
          next_to_add_del = DEFAULT_RX_ADL_ALLOWLIST;
          break;

        default:
          clib_warning ("BUG");
        }

      ci = acm->config_index_by_sw_if_index[a->sw_if_index];
      data->fib_index = fib_index;

      if (is_add)
	ci = vnet_config_add_feature (vm, &acm->config_main,
				      ci,
                                      next_to_add_del,
                                      data, sizeof (*data));
      else
	ci = vnet_config_del_feature (vm, &acm->config_main,
				      ci,
                                      next_to_add_del,
                                      data, sizeof (*data));

      acm->config_index_by_sw_if_index[a->sw_if_index] = ci;
    }
  return 0;
}

static clib_error_t *
adl_allowlist_enable_disable_command_fn (vlib_main_t * vm,
                                         unformat_input_t * input,
                                         vlib_cli_command_t * cmd)
{
  adl_main_t * cm = &adl_main;
  u32 sw_if_index = ~0;
  u8 ip4 = 0;
  u8 ip6 = 0;
  u8 default_adl = 0;
  u32 fib_id = 0;
  int rv;
  adl_allowlist_enable_disable_args_t _a, * a = &_a;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "ip4"))
      ip4 = 1;
    else if (unformat (input, "ip6"))
      ip6 = 1;
    else if (unformat (input, "default"))
      default_adl = 1;
    else if (unformat (input, "%U", unformat_vnet_sw_interface,
                       cm->vnet_main, &sw_if_index))
      ;
    else if (unformat (input, "fib-id %d", &fib_id))
      ;
    else
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  a->sw_if_index = sw_if_index;
  a->ip4 = ip4;
  a->ip6 = ip6;
  a->default_adl = default_adl;
  a->fib_id = fib_id;

  rv = adl_allowlist_enable_disable (a);

  switch(rv) {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_NO_SUCH_FIB:
    return clib_error_return
      (0, "Invalid fib");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "adl_allowlist_enable_disable returned %d",
                              rv);
  }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (adl_allowlist_command, static) =
{
   .path = "adl allowlist",
   .short_help =
   "adl allowlist <interface-name> [ip4][ip6][default][fib-id <NN>][disable]",
   .function = adl_allowlist_enable_disable_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Allow/deny list plugin",
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
