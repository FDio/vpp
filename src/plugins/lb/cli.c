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

#include <lb/lb.h>
#include <lb/util.h>

static clib_error_t *
lb_vip_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  lb_vip_add_args_t args;
  u8 del = 0;
  int ret;
  u32 port = 0;
  u32 encap = 0;
  u32 dscp = ~0;
  u32 srv_type = LB_SRV_TYPE_CLUSTERIP;
  u32 target_port = 0;
  clib_error_t *error = 0;

  args.new_length = 1024;
  args.src_ip_sticky = 0;

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
    else if (unformat (line_input, "src_ip_sticky"))
      args.src_ip_sticky = 1;
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
    else if (unformat(line_input, "encap gre4"))
      encap = LB_ENCAP_TYPE_GRE4;
    else if (unformat(line_input, "encap gre6"))
      encap = LB_ENCAP_TYPE_GRE6;
    else if (unformat(line_input, "encap l3dsr"))
      encap = LB_ENCAP_TYPE_L3DSR;
    else if (unformat(line_input, "encap nat4"))
      encap = LB_ENCAP_TYPE_NAT4;
    else if (unformat(line_input, "encap nat6"))
      encap = LB_ENCAP_TYPE_NAT6;
    else if (unformat(line_input, "dscp %d", &dscp))
      ;
    else if (unformat(line_input, "type clusterip"))
      srv_type = LB_SRV_TYPE_CLUSTERIP;
    else if (unformat(line_input, "type nodeport"))
      srv_type = LB_SRV_TYPE_NODEPORT;
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
      args.port = (u16)port;
    }

  if ((encap != LB_ENCAP_TYPE_L3DSR) && (dscp != ~0))
    {
      error = clib_error_return(0, "lb_vip_add error: "
                                "should not configure dscp for none L3DSR.");
      goto done;
    }

  if ((encap == LB_ENCAP_TYPE_L3DSR) && (dscp >= 64))
    {
      error = clib_error_return(0, "lb_vip_add error: "
                                "dscp for L3DSR should be less than 64.");
      goto done;
    }

  if (ip46_prefix_is_ip4(&(args.prefix), (args.plen)))
    {
      if (encap == LB_ENCAP_TYPE_GRE4)
        args.type = LB_VIP_TYPE_IP4_GRE4;
      else if (encap == LB_ENCAP_TYPE_GRE6)
        args.type = LB_VIP_TYPE_IP4_GRE6;
      else if (encap == LB_ENCAP_TYPE_L3DSR)
        args.type = LB_VIP_TYPE_IP4_L3DSR;
      else if (encap == LB_ENCAP_TYPE_NAT4)
        args.type = LB_VIP_TYPE_IP4_NAT4;
      else if (encap == LB_ENCAP_TYPE_NAT6)
        {
          error = clib_error_return(0, "currently does not support NAT46");
          goto done;
        }
    }
  else
    {
      if (encap == LB_ENCAP_TYPE_GRE4)
        args.type = LB_VIP_TYPE_IP6_GRE4;
      else if (encap == LB_ENCAP_TYPE_GRE6)
        args.type = LB_VIP_TYPE_IP6_GRE6;
      else if (encap == LB_ENCAP_TYPE_NAT6)
        args.type = LB_VIP_TYPE_IP6_NAT6;
      else if (encap == LB_ENCAP_TYPE_NAT4)
        {
          error = clib_error_return(0, "currently does not support NAT64");
          goto done;
        }
    }

  lb_garbage_collection();

  u32 index;
  if (!del) {
    if (encap == LB_ENCAP_TYPE_L3DSR) {
        args.encap_args.dscp = (u8)(dscp & 0x3F);
      }
      else if ((encap == LB_ENCAP_TYPE_NAT4)
               || (encap == LB_ENCAP_TYPE_NAT6))
        {
          args.encap_args.srv_type = (u8) srv_type;
          args.encap_args.target_port = (u16) target_port;
        }

    if ((ret = lb_vip_add(args, &index))) {
      error = clib_error_return (0, "lb_vip_add error %d", ret);
      goto done;
    } else {
      vlib_cli_output(vm, "lb_vip_add ok %d", index);
    }
  } else {
    if ((ret = lb_vip_find_index(&(args.prefix), args.plen,
                                 args.protocol, args.port, &index))) {
      error = clib_error_return (0, "lb_vip_find_index error %d", ret);
      goto done;
    } else if ((ret = lb_vip_del(index))) {
      error = clib_error_return (0, "lb_vip_del error %d", ret);
      goto done;
    }
  }

done:
  unformat_free (line_input);

  return error;
}

/* clang-format off */
VLIB_CLI_COMMAND (lb_vip_command, static) =
{
  .path = "lb vip",
  .short_help = "lb vip <prefix> "
      "[protocol (tcp|udp) port <n>] "
      "[encap (gre6|gre4|l3dsr|nat4|nat6)] "
      "[dscp <n>] "
      "[type (nodeport|clusterip) target_port <n>] "
      "[new_len <n>] [src_ip_sticky] [del]",
  .function = lb_vip_command_fn,
};
/* clang-format on */

static clib_error_t *
lb_as_command_fn (vlib_main_t * vm,
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

  if ((ret = lb_vip_find_index(&vip_prefix, vip_plen, protocol,
                               (u16)port, &vip_index))){
    error = clib_error_return (0, "lb_vip_find_index error %d", ret);
    goto done;
  }

  if (!vec_len(as_array)) {
    error = clib_error_return (0, "No AS address provided");
    goto done;
  }

  lb_garbage_collection();
  clib_warning("vip index is %d", vip_index);

  if (del) {
    if ((ret = lb_vip_del_ass(vip_index, as_array, vec_len(as_array), flush)))
    {
      error = clib_error_return (0, "lb_vip_del_ass error %d", ret);
      goto done;
    }
  } else {
    if ((ret = lb_vip_add_ass(vip_index, as_array, vec_len(as_array))))
    {
      error = clib_error_return (0, "lb_vip_add_ass error %d", ret);
      goto done;
    }
  }

done:
  unformat_free (line_input);
  vec_free(as_array);

  return error;
}

VLIB_CLI_COMMAND (lb_as_command, static) =
{
  .path = "lb as",
  .short_help = "lb as <vip-prefix> [protocol (tcp|udp) port <n>]"
      " [<address> [<address> [...]]] [del] [flush]",
  .function = lb_as_command_fn,
};

static clib_error_t *
lb_conf_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lb_main_t *lbm = &lb_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t ip4 = lbm->ip4_src_address;
  ip6_address_t ip6 = lbm->ip6_src_address;
  u32 per_cpu_sticky_buckets = lbm->per_cpu_sticky_buckets;
  u32 per_cpu_sticky_buckets_log2 = 0;
  u32 flow_timeout = lbm->flow_timeout;
  int ret;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "ip4-src-address %U", unformat_ip4_address, &ip4))
      ;
    else if (unformat(line_input, "ip6-src-address %U", unformat_ip6_address, &ip6))
      ;
    else if (unformat(line_input, "buckets %d", &per_cpu_sticky_buckets))
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

  lb_garbage_collection();

  if ((ret = lb_conf(&ip4, &ip6, per_cpu_sticky_buckets, flow_timeout))) {
    error = clib_error_return (0, "lb_conf error %d", ret);
    goto done;
  }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (lb_conf_command, static) =
{
  .path = "lb conf",
  .short_help = "lb conf [ip4-src-address <addr>] [ip6-src-address <addr>] [buckets <n>] [timeout <s>]",
  .function = lb_conf_command_fn,
};

static clib_error_t *
lb_show_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cli_output(vm, "%U", format_lb_main);
  return NULL;
}


VLIB_CLI_COMMAND (lb_show_command, static) =
{
  .path = "show lb",
  .short_help = "show lb",
  .function = lb_show_command_fn,
};

static clib_error_t *
lb_show_vips_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t line_input;
  lb_main_t *lbm = &lb_main;
  lb_vip_t *vip;
  u8 verbose = 0;

  if (!unformat_user (input, unformat_line_input, &line_input))
      return 0;

  if (unformat(&line_input, "verbose"))
    verbose = 1;

  /* Hide placeholder VIP */
  pool_foreach (vip, lbm->vips) {
    if (vip != lbm->vips) {
      vlib_cli_output(vm, "%U\n", verbose?format_lb_vip_detailed:format_lb_vip, vip);
    }
  }

  unformat_free (&line_input);
  return NULL;
}

VLIB_CLI_COMMAND (lb_show_vips_command, static) =
{
  .path = "show lb vips",
  .short_help = "show lb vips [verbose]",
  .function = lb_show_vips_command_fn,
};

static clib_error_t *
lb_set_interface_nat_command_fn (vlib_main_t * vm,
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
          if (lb_nat4_interface_add_del (*sw_if_index, is_del))
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
          if (lb_nat6_interface_add_del (*sw_if_index, is_del))
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
lb_set_interface_nat4_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  return lb_set_interface_nat_command_fn(vm, input, cmd, 0);
}

VLIB_CLI_COMMAND (lb_set_interface_nat4_command, static) = {
  .path = "lb set interface nat4",
  .function = lb_set_interface_nat4_command_fn,
  .short_help = "lb set interface nat4 in <intfc> [del]",
};

static clib_error_t *
lb_set_interface_nat6_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  return lb_set_interface_nat_command_fn(vm, input, cmd, 1);
}

VLIB_CLI_COMMAND (lb_set_interface_nat6_command, static) = {
  .path = "lb set interface nat6",
  .function = lb_set_interface_nat6_command_fn,
  .short_help = "lb set interface nat6 in <intfc> [del]",
};

static clib_error_t *
lb_flowtable_flush_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lb_flush_vip_as(~0, 0);

  return NULL;
}

static clib_error_t *
lb_flush_vip_command_fn (vlib_main_t * vm,
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

  if ((ret = lb_vip_find_index(&vip_prefix, vip_plen, protocol,
                               (u16)port, &vip_index))){
    error = clib_error_return (0, "lb_vip_find_index error %d", ret);
    goto done;
  }

  if ((ret = lb_flush_vip_as(vip_index, ~0)))
    {
      error = clib_error_return (0, "lb_flush_vip error %d", ret);
    }
  else
    {
        vlib_cli_output(vm, "lb_flush_vip ok %d", vip_index);
    }

done:
  unformat_free (line_input);

  return error;
}

/*
 * flush lb flowtable as per vip
 */
VLIB_CLI_COMMAND (lb_flush_vip_command, static) =
{
  .path = "lb flush vip",
  .short_help = "lb flush vip <prefix> "
      "[protocol (tcp|udp) port <n>]",
  .function = lb_flush_vip_command_fn,
};

/*
 * flush all lb flowtables
 * This is indented for debug and unit-tests purposes only
 */
VLIB_CLI_COMMAND (lb_flowtable_flush_command, static) =
{
  .path = "test lb flowtable flush",
  .short_help = "test lb flowtable flush",
  .function = lb_flowtable_flush_command_fn,
};
