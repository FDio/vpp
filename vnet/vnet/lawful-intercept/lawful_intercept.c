/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/lawful-intercept/lawful_intercept.h>

static clib_error_t *
set_li_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  li_main_t * lm = &li_main;
  ip4_address_t collector;
  u8 collector_set = 0;
  ip4_address_t src;
  u8 src_set = 0;
  u32 tmp;
  u16 udp_port = 0;
  u8 is_add = 1;
  int i;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "collector %U", unformat_ip4_address, &collector))
      collector_set = 1;
    if (unformat (input, "src %U", unformat_ip4_address, &src))
      src_set = 1;
    else if (unformat (input, "udp-port %d", &tmp))
      udp_port = tmp;
    else if (unformat (input, "del"))
      is_add = 0;
    else
      break;
  }

  if (collector_set == 0)
    return clib_error_return (0, "collector must be set...");
  if (src_set == 0)
    return clib_error_return (0, "src must be set...");
  if (udp_port == 0)
    return clib_error_return (0, "udp-port must be set...");

  if (is_add == 1)
    {
      for (i = 0; i < vec_len (lm->collectors); i++)
        {
          if (lm->collectors[i].as_u32 == collector.as_u32)
            {
              if (lm->ports[i] == udp_port)
                return clib_error_return 
                  (0, "collector %U:%d already configured", 
                   &collector, udp_port);
              else
                return clib_error_return
                  (0, "collector %U already configured with port %d", 
                   &collector, (int)(lm->ports[i]));
            }
        }
      vec_add1 (lm->collectors, collector);
      vec_add1 (lm->ports, udp_port);
      vec_add1 (lm->src_addrs, src);
      return 0;
    }
  else
    {
      for (i = 0; i < vec_len (lm->collectors); i++)
        {
          if ((lm->collectors[i].as_u32 == collector.as_u32)
              && lm->ports[i] == udp_port)
            {
              vec_delete (lm->collectors, 1, i);
              vec_delete (lm->ports, 1, i);
              vec_delete (lm->src_addrs, 1, i);
              return 0;
            }
        }
      return clib_error_return (0, "collector %U:%d not configured",
                                &collector, udp_port);
    }
  return 0;
}

VLIB_CLI_COMMAND (set_li_command, static) = {
    .path = "set li",
    .short_help = 
    "set li src <ip4-address> collector <ip4-address> udp-port <nnnn>",
    .function = set_li_command_fn,
};

static clib_error_t *
li_init (vlib_main_t * vm)
{
  li_main_t * lm = &li_main;

  lm->vlib_main = vm;
  lm->vnet_main = vnet_get_main();
  lm->hit_node_index = li_hit_node.index;
  return 0;
}

VLIB_INIT_FUNCTION(li_init);

