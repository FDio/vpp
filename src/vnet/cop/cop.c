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
#include <vnet/cop/cop.h>

cop_main_t cop_main;

static clib_error_t *
cop_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  cop_main_t * cm = &cop_main;
  cop_config_data_t _data, *data = &_data;
  vlib_main_t * vm = cm->vlib_main;
  vnet_hw_interface_t * hi = vnet_get_sup_hw_interface (vnm, sw_if_index);;
  cop_config_main_t * ccm;
  int address_family;
  u32 ci, default_next;

  memset (data, 0, sizeof(*data));

  /* 
   * Ignore local interface, pg interfaces. $$$ need a #define for the
   * first "real" interface. The answer is 5 at the moment.
   */
  if (hi->dev_class_index == vnet_local_interface_device_class.index)
    return 0;

   for (address_family = VNET_COP_IP4; address_family < VNET_N_COPS;
       address_family++)
    {
      ccm = &cm->cop_config_mains[address_family];

      /* 
       * Once-only code to initialize the per-address-family
       * cop feature subgraphs.
       * Since the (single) start-node, cop-input, must be able
       * to push pkts into three separate subgraphs, we
       * use a unified cop_feature_type_t enumeration.
       */

      if (!(ccm->config_main.node_index_by_feature_index))
        {
          switch (address_family)
            {
            case VNET_COP_IP4:
              {
                static char * start_nodes[] = { "cop-input" };
                static char * feature_nodes[] = {
                  [IP4_RX_COP_WHITELIST] = "ip4-cop-whitelist",
                  [IP4_RX_COP_INPUT] = "ip4-input",
                };
                
                vnet_config_init (vm, &ccm->config_main, 
                                  start_nodes, ARRAY_LEN(start_nodes),
                                  feature_nodes, ARRAY_LEN(feature_nodes));
              }
              break;
            case VNET_COP_IP6:
              {
                static char * start_nodes[] = { "cop-input" };
                static char * feature_nodes[] = {
                  [IP6_RX_COP_WHITELIST] = "ip6-cop-whitelist",
                  [IP6_RX_COP_INPUT] = "ip6-input",
                };
                vnet_config_init (vm, &ccm->config_main, 
                                  start_nodes, ARRAY_LEN(start_nodes),
                                  feature_nodes, ARRAY_LEN(feature_nodes));
              }
              break;

            case VNET_COP_DEFAULT:
              {
                static char * start_nodes[] = { "cop-input" };
                static char * feature_nodes[] = {
                  [DEFAULT_RX_COP_WHITELIST] = "default-cop-whitelist",
                  [DEFAULT_RX_COP_INPUT] = "ethernet-input",
                };
                vnet_config_init (vm, &ccm->config_main, 
                                  start_nodes, ARRAY_LEN(start_nodes),
                                  feature_nodes, ARRAY_LEN(feature_nodes));
              }
              break;

            default:
              clib_warning ("bug");
              break;
            }
        }
      vec_validate_init_empty (ccm->config_index_by_sw_if_index, sw_if_index,
                               ~0);

      ci = ccm->config_index_by_sw_if_index[sw_if_index];

      /* Create a sensible initial config: send pkts to xxx-input */
      if (address_family == VNET_COP_IP4)
        default_next = IP4_RX_COP_INPUT;
      else if (address_family == VNET_COP_IP6)
        default_next = IP6_RX_COP_INPUT;
      else
        default_next = DEFAULT_RX_COP_INPUT;
        
      if (is_add)
        ci = vnet_config_add_feature (vm, &ccm->config_main,
                                      ci, 
                                      default_next,
                                      data, sizeof(*data));
      else
        ci = vnet_config_del_feature (vm, &ccm->config_main,
                                      ci, 
                                      default_next,
                                      data, sizeof(*data));

      ccm->config_index_by_sw_if_index[sw_if_index] = ci;
    }
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (cop_sw_interface_add_del);

static clib_error_t *
cop_init (vlib_main_t *vm)
{
  cop_main_t * cm = &cop_main;
  clib_error_t * error;

  if ((error = vlib_call_init_function (vm, ip4_whitelist_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip6_whitelist_init)))
    return error;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (cop_init);

int cop_interface_enable_disable (u32 sw_if_index, int enable_disable)
{
  cop_main_t * cm = &cop_main;
  vnet_sw_interface_t * sw;
  int rv;
  u32 node_index = enable_disable ? cop_input_node.index : ~0;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (cm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  
  /* 
   * Redirect pkts from the driver to the cop node.
   * Returns VNET_API_ERROR_UNIMPLEMENTED if the h/w driver
   * doesn't implement the API. 
   *
   * Node_index = ~0 => shut off redirection
   */
  rv = vnet_hw_interface_rx_redirect_to_node (cm->vnet_main, sw_if_index,
                                              node_index);
  return rv;
}

static clib_error_t *
cop_enable_disable_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  cop_main_t * cm = &cop_main;
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
    
  rv = cop_interface_enable_disable (sw_if_index, enable_disable);

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
    return clib_error_return (0, "cop_interface_enable_disable returned %d",
                              rv);
  }
  return 0;
}

VLIB_CLI_COMMAND (cop_interface_command, static) = {
    .path = "cop interface",
    .short_help = 
    "cop interface <interface-name> [disable]",
    .function = cop_enable_disable_command_fn,
};


int cop_whitelist_enable_disable (cop_whitelist_enable_disable_args_t *a)
{
  cop_main_t * cm = &cop_main;
  vlib_main_t * vm = cm->vlib_main;
  ip4_main_t * im4 = &ip4_main;
  ip6_main_t * im6 = &ip6_main;
  int address_family;
  int is_add;
  cop_config_main_t * ccm;
  u32 next_to_add_del = 0;
  uword * p;
  u32 fib_index = 0;
  u32 ci;
  cop_config_data_t _data, *data=&_data;

  /*
   * Enable / disable whitelist processing on the specified interface
   */

  for (address_family = VNET_COP_IP4; address_family < VNET_N_COPS;
       address_family++) 
    {
      ccm = &cm->cop_config_mains[address_family];
    
      switch(address_family)
        {
        case VNET_COP_IP4:
          is_add = (a->ip4 != 0);
          next_to_add_del = IP4_RX_COP_WHITELIST;
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
              
        case VNET_COP_IP6:
          is_add = (a->ip6 != 0);
          next_to_add_del = IP6_RX_COP_WHITELIST;
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

        case VNET_COP_DEFAULT:
          is_add = (a->default_cop != 0);
          next_to_add_del = DEFAULT_RX_COP_WHITELIST;
          break;
        
        default:
          clib_warning ("BUG");
        }

      ci = ccm->config_index_by_sw_if_index[a->sw_if_index];
      data->fib_index = fib_index;

      if (is_add)
	ci = vnet_config_add_feature (vm, &ccm->config_main,
				      ci,
                                      next_to_add_del,
                                      data, sizeof (*data));
      else
	ci = vnet_config_del_feature (vm, &ccm->config_main,
				      ci,
                                      next_to_add_del,
                                      data, sizeof (*data));

      ccm->config_index_by_sw_if_index[a->sw_if_index] = ci;
    }
  return 0;
}

static clib_error_t *
cop_whitelist_enable_disable_command_fn (vlib_main_t * vm,
                                         unformat_input_t * input,
                                         vlib_cli_command_t * cmd)
{
  cop_main_t * cm = &cop_main;
  u32 sw_if_index = ~0;
  u8 ip4 = 0;
  u8 ip6 = 0;
  u8 default_cop = 0;
  u32 fib_id = 0;
  int rv;
  cop_whitelist_enable_disable_args_t _a, * a = &_a;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "ip4"))
      ip4 = 1;
    else if (unformat (input, "ip6"))
      ip6 = 1;
    else if (unformat (input, "default"))
      default_cop = 1;
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
  a->default_cop = default_cop;
  a->fib_id = fib_id;

  rv = cop_whitelist_enable_disable (a);

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
    return clib_error_return (0, "cop_whitelist_enable_disable returned %d",
                              rv);
  }

  return 0;
}

VLIB_CLI_COMMAND (cop_whitelist_command, static) = {
    .path = "cop whitelist",
    .short_help = 
    "cop whitelist <interface-name> [ip4][ip6][default][fib-id <NN>][disable]",
    .function = cop_whitelist_enable_disable_command_fn,
};

