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

#if DPDK==1
#include <vnet/lawful-intercept/lawful_intercept.h>

clib_error_t *
set_li_add_delete_entry (vlib_main_t * vm,
			 ip4_address_t src_ip4_addr,
			 ip4_address_t collector, u16 udp_port, u8 delete)
{
  li_main_t *lm = &li_main;
  int i;

  clib_warning ("src %U collector %U port %u %s",
		format_ip4_address, &src_ip4_addr,
		format_ip4_address, &collector, udp_port,
		delete ? "del" : "");

  if (collector.data_u32 == 0)
    return clib_error_return (0, "collector must be set...");
  if (udp_port == 0)
    return clib_error_return (0, "udp-port must be set...");

  if (delete == 0)
    {
      if (src_ip4_addr.data_u32 == 0)
	return clib_error_return (0, "src must be set...");

      for (i = 0; i < vec_len (lm->collectors); i++)
	{
	  if (lm->collectors[i].as_u32 == collector.as_u32)
	    {
	      if (lm->ports[i] == udp_port)
		return clib_error_return
		  (0, "collector %U:%d already configured ",
		   format_ip4_address, &collector, udp_port);
	      else
		return clib_error_return
		  (0, "collector %U already configured with port %d ",
		   format_ip4_address, &collector, (int) (lm->ports[i]));
	    }
	}
      vec_add1 (lm->collectors, collector);
      vec_add1 (lm->ports, udp_port);
      vec_add1 (lm->src_addrs, src_ip4_addr);
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
				format_ip4_address, &collector, udp_port);
    }

  return 0;
}

static clib_error_t *
set_li_command_fn (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip4_address_t collector;
  ip4_address_t src;
  u32 tmp;
  u16 udp_port = 0;
  u8 delete = 0;

  collector.data_u32 = 0;
  src.data_u32 = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "collector %U", unformat_ip4_address, &collector))
	;
      if (unformat (input, "src %U", unformat_ip4_address, &src))
	;
      else if (unformat (input, "udp-port %d", &tmp))
	udp_port = tmp;
      else if (unformat (input, "del"))
	delete = 1;
      else
	break;
    }

  return set_li_add_delete_entry (vm, src, collector, udp_port, delete);
}

static clib_error_t *
show_li_command_fn (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  li_main_t *lm = &li_main;
  int i;

  vlib_cli_output (vm, "LI source interface to destination interface table");
  vlib_cli_output (vm, "\nIndex    Src addr           Collector(ip:port)");
  for (i = 0; i < vec_len (lm->collectors); i++)
    {
      vlib_cli_output (vm, "%3u      %-15U -> %U:%d", i,
		       format_ip4_address, &lm->src_addrs[i],
		       format_ip4_address, &lm->collectors[i],
		       (int) (lm->ports[i]));
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_li_command, static) = {
    .path = "set li",
    .short_help =
    "set li src <ip4-address> collector <ip4-address> udp-port <nnnn> [del]",
    .function = set_li_command_fn,
};

VLIB_CLI_COMMAND (show_li_command, static) = {
  .path = "show li",
  .short_help = "Shows Lawful Intercept mirror table",
  .function = show_li_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
li_init (vlib_main_t * vm)
{
  li_main_t *lm = &li_main;

  lm->vlib_main = vm;
  lm->vnet_main = vnet_get_main ();
  lm->hit_node_index = li_hit_node.index;
  return 0;
}

VLIB_INIT_FUNCTION (li_init);
#else
#endif /* DPDK */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
