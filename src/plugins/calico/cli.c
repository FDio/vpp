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

#include <calico/calico.h>
#include <calico/util.h>

static clib_error_t *
calico_vip_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  calico_vip_add_args_t args;
  u8 del = 0;
  int ret;
  u32 port = 0;
  u32 encap = 0;
  u32 target_port = 0;
  clib_error_t *error = 0;

  args.new_length = 1024;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat(line_input, "%U", unformat_ip46_prefix, &(args.prefix),
                &(args.plen), IP46_TYPE_ANY, &(args.plen))) {
    error = clib_error_return (0, "invalid vip prefix: '%U'",
                               format_unformat_error, line_input);
    goto done;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "new_len %d", &(args.new_length)))
      ;
    else if (unformat(line_input, "del"))
      del = 1;
    else if (unformat(line_input, "protocol tcp"))
      {
        args.protocol = (u8)IP_PROTOCOL_TCP;
      }
    else if (unformat(line_input, "protocol udp"))
      {
        args.protocol = (u8)IP_PROTOCOL_UDP;
      }
    else if (unformat(line_input, "port %d", &port))
      ;
    else if (unformat(line_input, "encap nat4"))
      encap = CALICO_ENCAP_TYPE_NAT4;
    else if (unformat(line_input, "encap nat6"))
      encap = CALICO_ENCAP_TYPE_NAT6;
    else if (unformat(line_input, "target_port %d", &target_port))
      ;
    else {
      error = clib_error_return (0, "parse error: '%U'",
                                format_unformat_error, line_input);
      goto done;
    }
  }

  /* if port == 0, it means all-port VIP */
  if (port == 0)
    {
      args.protocol = ~0;
      args.port = 0;
    }
  else
    {
      args.port = clib_host_to_net_u16(port);
    }

  if (ip46_prefix_is_ip4(&(args.prefix), (args.plen)))
    {
      if (encap == CALICO_ENCAP_TYPE_NAT4)
        args.type = CALICO_VIP_TYPE_IP4_NAT4;
      else if (encap == CALICO_ENCAP_TYPE_NAT6)
        {
          error = clib_error_return(0, "currently does not support NAT46");
          goto done;
        }
    }
  else
    {
      if (encap == CALICO_ENCAP_TYPE_NAT6)
        args.type = CALICO_VIP_TYPE_IP6_NAT6;
      else if (encap == CALICO_ENCAP_TYPE_NAT4)
        {
          error = clib_error_return(0, "currently does not support NAT64");
          goto done;
        }
    }

  calico_garbage_collection();

  u32 index;
  if (!del) {
    args.target_port = clib_host_to_net_u16(target_port);

    if ((ret = calico_vip_add(args, &index))) {
      error = clib_error_return (0, "calico_vip_add error %d", ret);
      goto done;
    } else {
      vlib_cli_output(vm, "calico_vip_add ok %d", index);
    }
  } else {
    if ((ret = calico_vip_find_index(&(args.prefix), args.plen,
                                 args.protocol, args.port, &index))) {
      error = clib_error_return (0, "calico_vip_find_index error %d", ret);
      goto done;
    } else if ((ret = calico_vip_del(index))) {
      error = clib_error_return (0, "calico_vip_del error %d", ret);
      goto done;
    }
  }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (calico_vip_command, static) =
{
  .path = "calico vip",
  .short_help = "calico vip <prefix> "
      "[protocol (tcp|udp) port <n>] "
      "[encap (nat4|nat6)] "
      "[target_port <n>] "
      "[new_len <n>] [del]",
  .function = calico_vip_command_fn,
};

static clib_error_t *
calico_as_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t vip_prefix, as_addr;
  u8 vip_plen;
  ip46_address_t *as_array = 0;
  u32 vip_index;
  u32 port = 0;
  u8 protocol = 0;
  u8 del = 0;
  u8 flush = 0;
  int ret;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat(line_input, "%U", unformat_ip46_prefix,
                &vip_prefix, &vip_plen, IP46_TYPE_ANY))
  {
    error = clib_error_return (0, "invalid as address: '%U'",
                               format_unformat_error, line_input);
    goto done;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "%U", unformat_ip46_address,
                 &as_addr, IP46_TYPE_ANY))
      {
        vec_add1(as_array, as_addr);
      }
    else if (unformat(line_input, "del"))
      {
        del = 1;
      }
    else if (unformat(line_input, "flush"))
      {
        flush = 1;
      }
    else if (unformat(line_input, "protocol tcp"))
      {
          protocol = (u8)IP_PROTOCOL_TCP;
      }
    else if (unformat(line_input, "protocol udp"))
      {
          protocol = (u8)IP_PROTOCOL_UDP;
      }
    else if (unformat(line_input, "port %d", &port))
      ;
    else {
      error = clib_error_return (0, "parse error: '%U'",
                                 format_unformat_error, line_input);
      goto done;
    }
  }

  /* If port == 0, it means all-port VIP */
  if (port == 0)
    {
      protocol = ~0;
    }

  if ((ret = calico_vip_find_index(&vip_prefix, vip_plen, protocol,
                               clib_host_to_net_u16 (port), &vip_index))){
    error = clib_error_return (0, "calico_vip_find_index error %d", ret);
    goto done;
  }

  if (!vec_len(as_array)) {
    error = clib_error_return (0, "No AS address provided");
    goto done;
  }

  calico_garbage_collection();
  clib_warning("vip index is %d", vip_index);

  if (del) {
    if ((ret = calico_vip_del_ass(vip_index, as_array, vec_len(as_array), flush)))
    {
      error = clib_error_return (0, "calico_vip_del_ass error %d", ret);
      goto done;
    }
  } else {
    if ((ret = calico_vip_add_ass(vip_index, as_array, vec_len(as_array))))
    {
      error = clib_error_return (0, "calico_vip_add_ass error %d", ret);
      goto done;
    }
  }

done:
  unformat_free (line_input);
  vec_free(as_array);

  return error;
}

VLIB_CLI_COMMAND (calico_as_command, static) =
{
  .path = "calico as",
  .short_help = "calico as <vip-prefix> [protocol (tcp|udp) port <n>]"
      " [<address> [<address> [...]]] [del] [flush]",
  .function = calico_as_command_fn,
};


// FIXME : remove
static clib_error_t *
calico_conf_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  calico_main_t *cam = &calico_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 per_cpu_sticky_buckets = cam->per_cpu_sticky_buckets;
  u32 per_cpu_sticky_buckets_log2 = 0;
  u32 flow_timeout = cam->flow_timeout;
  int ret;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "buckets %d", &per_cpu_sticky_buckets))
      ;
    else if (unformat(line_input, "buckets-log2 %d", &per_cpu_sticky_buckets_log2)) {
      if (per_cpu_sticky_buckets_log2 >= 32)
        return clib_error_return (0, "buckets-log2 value is too high");
      per_cpu_sticky_buckets = 1 << per_cpu_sticky_buckets_log2;
    } else if (unformat(line_input, "timeout %d", &flow_timeout))
      ;
    else {
      error = clib_error_return (0, "parse error: '%U'",
                                 format_unformat_error, line_input);
      goto done;
    }
  }

  calico_garbage_collection();

  if ((ret = calico_conf(per_cpu_sticky_buckets, flow_timeout))) {
    error = clib_error_return (0, "calico_conf error %d", ret);
    goto done;
  }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (calico_conf_command, static) =
{
  .path = "calico conf",
  .short_help = "calico conf [buckets <n>] [timeout <s>]",
  .function = calico_conf_command_fn,
};

static clib_error_t *
calico_snat_command_fn (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  calico_add_del_snat_args_t args;
  clib_error_t *error = 0;
  int ret;
  int is_add = 1;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "%U", unformat_ip46_prefix, &args.prefix, &args.len, IP46_TYPE_ANY))
      ;
    else if (unformat(line_input, "with %U", unformat_ip46_address, &args.target_addr))
      ;
    else if (unformat(line_input, "table %d", &args.fib_index))
      ;
    else if (unformat(line_input, "del"))
      is_add = 0;
    else {
      error = clib_error_return (0, "parse error: '%U'",
                                 format_unformat_error, line_input);
      goto done;
    }
  }
   if ((ret = calico_add_del_snat_entry(&args, is_add)))
    {
      error = clib_error_return (0, "calico add/del snat error %d", ret);
    }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (calico_snat_command, static) =
{
  .path = "calico snat",
  .short_help = "calico snat <prefix> with <addr>",
  .function = calico_snat_command_fn,
};

static clib_error_t *
calico_show_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cli_output(vm, "%U", format_calico_main);
  return NULL;
}


VLIB_CLI_COMMAND (calico_show_command, static) =
{
  .path = "show calico",
  .short_help = "show calico",
  .function = calico_show_command_fn,
};

static clib_error_t *
calico_show_vips_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t line_input;
  calico_main_t *cam = &calico_main;
  calico_vip_t *vip;
  u8 verbose = 0;

  if (!unformat_user (input, unformat_line_input, &line_input))
      return 0;

  if (unformat(&line_input, "verbose"))
    verbose = 1;

  /* Hide dummy VIP */
  pool_foreach(vip, cam->vips, {
    if (vip != cam->vips) {
      vlib_cli_output(vm, "%U\n", verbose?format_calico_vip_detailed:format_calico_vip, vip);
    }
  });

  unformat_free (&line_input);
  return NULL;
}

VLIB_CLI_COMMAND (calico_show_vips_command, static) =
{
  .path = "show calico vips",
  .short_help = "show calico vips [verbose]",
  .function = calico_show_vips_command_fn,
};

static clib_error_t *
calico_set_interface_nat_command_fn (vlib_main_t * vm,
                                 unformat_input_t * input,
                                 vlib_cli_command_t * cmd,
                                 u8 is_nat6)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 _sw_if_index, *sw_if_index = &_sw_if_index;
  u32 * inside_sw_if_indices = 0;
  int is_del = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %U", unformat_vnet_sw_interface,
                    vnm, sw_if_index))
        vec_add1 (inside_sw_if_indices, *sw_if_index);
      else if (unformat (line_input, "del"))
        is_del = 1;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
            format_unformat_error, line_input);
          goto done;
        }
    }

    vec_foreach (sw_if_index, inside_sw_if_indices)
    {
      if (!is_nat6)
        {
          if (calico_nat4_interface_add_del (*sw_if_index, is_del))
            {
              error = clib_error_return(
                  0, "%s %U failed", is_del ? "del" : "add",
                  format_vnet_sw_interface_name, vnm,
                  vnet_get_sw_interface (vnm, *sw_if_index));
              goto done;
            }
        }
      else
        {
          if (calico_nat6_interface_add_del (*sw_if_index, is_del))
            {
              error = clib_error_return(
                  0, "%s %U failed", is_del ? "del" : "add",
                  format_vnet_sw_interface_name, vnm,
                  vnet_get_sw_interface (vnm, *sw_if_index));
              goto done;
            }
        }
    }

done:
  unformat_free (line_input);
  vec_free (inside_sw_if_indices);

  return error;
}

static clib_error_t *
calico_set_interface_nat4_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  return calico_set_interface_nat_command_fn(vm, input, cmd, 0);
}

VLIB_CLI_COMMAND (calico_set_interface_nat4_command, static) = {
  .path = "calico set interface nat4",
  .function = calico_set_interface_nat4_command_fn,
  .short_help = "calico set interface nat4 in <intfc> [del]",
};

static clib_error_t *
calico_set_interface_nat6_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  return calico_set_interface_nat_command_fn(vm, input, cmd, 1);
}

VLIB_CLI_COMMAND (calico_set_interface_nat6_command, static) = {
  .path = "calico set interface nat6",
  .function = calico_set_interface_nat6_command_fn,
  .short_help = "calico set interface nat6 in <intfc> [del]",
};

static clib_error_t *
calico_flowtable_flush_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  calico_flush_vip_as(~0, 0);

  return NULL;
}

static clib_error_t *
calico_flush_vip_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  int ret;
  ip46_address_t vip_prefix;
  u8 vip_plen;
  u32 vip_index;
  u8 protocol = 0;
  u32 port = 0;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat(line_input, "%U", unformat_ip46_prefix, &vip_prefix,
                &vip_plen, IP46_TYPE_ANY, &vip_plen)) {
    error = clib_error_return (0, "invalid vip prefix: '%U'",
                               format_unformat_error, line_input);
    goto done;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "protocol tcp"))
      {
        protocol = (u8)IP_PROTOCOL_TCP;
      }
    else if (unformat(line_input, "protocol udp"))
      {
        protocol = (u8)IP_PROTOCOL_UDP;
      }
    else if (unformat(line_input, "port %d", &port))
      ;
  }

  if (port == 0)
    {
      protocol = ~0;
    }

  if ((ret = calico_vip_find_index(&vip_prefix, vip_plen, protocol,
                               (u16)port, &vip_index))){
    error = clib_error_return (0, "calico_vip_find_index error %d", ret);
    goto done;
  }

  if ((ret = calico_flush_vip_as(vip_index, ~0)))
    {
      error = clib_error_return (0, "calico_flush_vip error %d", ret);
    }
  else
    {
        vlib_cli_output(vm, "calico_flush_vip ok %d", vip_index);
    }

done:
  unformat_free (line_input);

  return error;
}

/*
 * flush calico flowtable as per vip
 */
VLIB_CLI_COMMAND (calico_flush_vip_command, static) =
{
  .path = "calico flush vip",
  .short_help = "calico flush vip <prefix> "
      "[protocol (tcp|udp) port <n>]",
  .function = calico_flush_vip_command_fn,
};

/*
 * flush all calico flowtables
 * This is indented for debug and unit-tests purposes only
 */
VLIB_CLI_COMMAND (calico_flowtable_flush_command, static) =
{
  .path = "test calico flowtable flush",
  .short_help = "test calico flowtable flush",
  .function = calico_flowtable_flush_command_fn,
};
