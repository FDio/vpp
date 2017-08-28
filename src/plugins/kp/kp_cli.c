/*
 * Copyright (c) 2016 Intel and/or its affiliates.
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

#include <kp/kp.h>
#include <kp/kp_util.h>

static clib_error_t *
kp_vip_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t prefix;
  u8 plen;
  u32 new_len = 1024;
  u16 port = 0;
  u16 target_port = 0;
  u16 node_port = 0;
  u8 del = 0;
  int ret;
  u32 nat4 = 0;
  kp_vip_type_t type;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat(line_input, "%U", unformat_ip46_prefix, &prefix, &plen, IP46_TYPE_ANY, &plen)) {
    error = clib_error_return (0, "invalid vip prefix: '%U'",
                               format_unformat_error, line_input);
    goto done;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "new_len %d", &new_len))
      ;
    else if (unformat(line_input, "port %d", &port))
      ;
    else if (unformat(line_input, "target_port %d", &target_port))
      ;
    else if (unformat(line_input, "node_port %d", &node_port))
      ;
    else if (unformat(line_input, "del"))
      del = 1;
    else if (unformat(line_input, "nat4"))
      nat4 = 1;
    else if (unformat(line_input, "nat6"))
      nat4 = 0;
    else {
      error = clib_error_return (0, "parse error: '%U'",
                                format_unformat_error, line_input);
      goto done;
    }
  }


  if (ip46_prefix_is_ip4(&prefix, plen)) {
    type = (nat4)?KP_VIP_TYPE_IP4_NAT44:KP_VIP_TYPE_IP4_NAT46;
  } else {
    type = (nat4)?KP_VIP_TYPE_IP6_NAT64:KP_VIP_TYPE_IP6_NAT66;
  }

  kp_garbage_collection();

  u32 index;
  if (!del) {
    if ((ret = kp_vip_add(&prefix, plen, type, new_len, &index,
			  port, target_port, node_port))) {
      error = clib_error_return (0, "kp_vip_add error %d", ret);
      goto done;
    } else {
      vlib_cli_output(vm, "kp_vip_add ok %d", index);
    }
  } else {
    if ((ret = kp_vip_find_index(&prefix, plen, &index))) {
      error = clib_error_return (0, "kp_vip_find_index error %d", ret);
      goto done;
    } else if ((ret = kp_vip_del(index))) {
      error = clib_error_return (0, "kp_vip_del error %d", ret);
      goto done;
    }
  }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (kp_vip_command, static) =
{
  .path = "kp vip",
  .short_help = "kp vip <prefix> port <n> target_port <n> node_port <n>"
                " [nat4|nat6)] [new_len <n>] [del]",
  .function = kp_vip_command_fn,
};

static clib_error_t *
kp_as_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t vip_prefix, as_addr;
  u8 vip_plen;
  ip46_address_t *as_array = 0;
  u32 vip_index;
  u8 del = 0;
  int ret;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat(line_input, "%U", unformat_ip46_prefix, &vip_prefix, &vip_plen, IP46_TYPE_ANY)) {
    error = clib_error_return (0, "invalid as address: '%U'",
                               format_unformat_error, line_input);
    goto done;
  }

  if ((ret = kp_vip_find_index(&vip_prefix, vip_plen, &vip_index))) {
    error = clib_error_return (0, "kp_vip_find_index error %d", ret);
    goto done;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "%U", unformat_ip46_address, &as_addr, IP46_TYPE_ANY)) {
      vec_add1(as_array, as_addr);
    } else if (unformat(line_input, "del")) {
      del = 1;
    } else {
      error = clib_error_return (0, "parse error: '%U'",
                                 format_unformat_error, line_input);
      goto done;
    }
  }

  if (!vec_len(as_array)) {
    error = clib_error_return (0, "No AS address provided");
    goto done;
  }

  kp_garbage_collection();
  clib_warning("vip index is %d", vip_index);

  if (del) {
    if ((ret = kp_vip_del_ass(vip_index, as_array, vec_len(as_array)))) {
      error = clib_error_return (0, "kp_vip_del_ass error %d", ret);
      goto done;
    }
  } else {
    if ((ret = kp_vip_add_ass(vip_index, as_array, vec_len(as_array)))) {
      error = clib_error_return (0, "kp_vip_add_ass error %d", ret);
      goto done;
    }
  }

done:
  unformat_free (line_input);
  vec_free(as_array);

  return error;
}

VLIB_CLI_COMMAND (kp_as_command, static) =
{
  .path = "kp as",
  .short_help = "kp as <vip-prefix> [<address> [<address> [...]]] [del]",
  .function = kp_as_command_fn,
};

static clib_error_t *
kp_conf_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  kp_main_t *kpm = &kp_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 per_cpu_sticky_buckets = kpm->per_cpu_sticky_buckets;
  u32 per_cpu_sticky_buckets_log2 = 0;
  u32 flow_timeout = kpm->flow_timeout;
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

  kp_garbage_collection();

  if ((ret = kp_conf(per_cpu_sticky_buckets, flow_timeout))) {
    error = clib_error_return (0, "kp_conf error %d", ret);
    goto done;
  }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (kp_conf_command, static) =
{
  .path = "kp conf",
  .short_help = "kp conf [buckets <n>] [timeout <s>]",
  .function = kp_conf_command_fn,
};

static clib_error_t *
kp_show_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cli_output(vm, "%U", format_kp_main);
  return NULL;
}


VLIB_CLI_COMMAND (kp_show_command, static) =
{
  .path = "show kp",
  .short_help = "show kp",
  .function = kp_show_command_fn,
};

static clib_error_t *
kp_show_vips_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t line_input;
  kp_main_t *kpm = &kp_main;
  kp_vip_t *vip;
  u8 verbose = 0;

  if (!unformat_user (input, unformat_line_input, &line_input))
      return 0;

  if (unformat(&line_input, "verbose"))
    verbose = 1;

  pool_foreach(vip, kpm->vips, {
      vlib_cli_output(vm, "%U\n", verbose?format_kp_vip_detailed:format_kp_vip, vip);
  });

  unformat_free (&line_input);
  return NULL;
}

VLIB_CLI_COMMAND (kp_show_vips_command, static) =
{
  .path = "show kp vips",
  .short_help = "show kp vips [verbose]",
  .function = kp_show_vips_command_fn,
};
