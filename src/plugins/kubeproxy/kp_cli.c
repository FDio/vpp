/*
 * Copyright (c) 2016 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "POD IS" BPODIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <kubeproxy/kp.h>


static clib_error_t *
kp_vip_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t prefix;
  u8 plen;
  u32 new_len = 1024;
  u32 port = 0;
  u32 target_port = 0;
  u32 node_port = 0;
  u32 del = 0;
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
			  (u16)port, (u16)target_port, (u16)node_port))) {
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
  .path = "kube-proxy vip",
  .short_help = "kube-proxy vip <prefix> port <n> target_port <n>"
                " node_port <n> [nat4|nat6)] [new_len <n>] [del]",
  .function = kp_vip_command_fn,
};

static clib_error_t *
kp_pod_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t vip_prefix, pod_addr;
  u8 vip_plen;
  ip46_address_t *pod_array = 0;
  u32 vip_index;
  u8 del = 0;
  int ret;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat(line_input, "%U", unformat_ip46_prefix, &vip_prefix, &vip_plen, IP46_TYPE_ANY)) {
    error = clib_error_return (0, "invalid pod address: '%U'",
                               format_unformat_error, line_input);
    goto done;
  }

  if ((ret = kp_vip_find_index(&vip_prefix, vip_plen, &vip_index))) {
    error = clib_error_return (0, "kp_vip_find_index error %d", ret);
    goto done;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "%U", unformat_ip46_address, &pod_addr, IP46_TYPE_ANY)) {
      vec_add1(pod_array, pod_addr);
    } else if (unformat(line_input, "del")) {
      del = 1;
    } else {
      error = clib_error_return (0, "parse error: '%U'",
                                 format_unformat_error, line_input);
      goto done;
    }
  }

  if (!vec_len(pod_array)) {
    error = clib_error_return (0, "No POD address provided");
    goto done;
  }

  kp_garbage_collection();
  clib_warning("vip index is %d", vip_index);

  if (del) {
    if ((ret = kp_vip_del_pods(vip_index, pod_array, vec_len(pod_array)))) {
      error = clib_error_return (0, "kp_vip_del_pods error %d", ret);
      goto done;
    }
  } else {
    if ((ret = kp_vip_add_pods(vip_index, pod_array, vec_len(pod_array)))) {
      error = clib_error_return (0, "kp_vip_add_pods error %d", ret);
      goto done;
    }
  }

done:
  unformat_free (line_input);
  vec_free(pod_array);

  return error;
}

VLIB_CLI_COMMAND (kp_pod_command, static) =
{
  .path = "kube-proxy pod",
  .short_help =
      "kube-proxy pod <vip-prefix> [<address> [<address> [...]]] [del]",
  .function = kp_pod_command_fn,
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
  .path = "kube-proxy conf",
  .short_help = "kube-proxy conf [buckets <n>] [timeout <s>]",
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
  .path = "show kube-proxy",
  .short_help = "show kube-proxy",
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
  .path = "show kube-proxy vips",
  .short_help = "show kube-proxy vips [verbose]",
  .function = kp_show_vips_command_fn,
};

static clib_error_t *
kp_set_interface_nat4_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 sw_if_index;
  u32 * inside_sw_if_indices = 0;
  int is_del = 0;
  int i;

  sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %U", unformat_vnet_sw_interface,
                    vnm, &sw_if_index))
        vec_add1 (inside_sw_if_indices, sw_if_index);
      else if (unformat (line_input, "del"))
        is_del = 1;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
            format_unformat_error, line_input);
          goto done;
        }
    }

  if (vec_len (inside_sw_if_indices))
    {
      for (i = 0; i < vec_len(inside_sw_if_indices); i++)
        {
          sw_if_index = inside_sw_if_indices[i];

	  if (kp_nat4_interface_add_del (sw_if_index, is_del))
	    {
	      error = clib_error_return (0, "%s %U failed",
					 is_del ? "del" : "add",
					 format_vnet_sw_interface_name, vnm,
					 vnet_get_sw_interface (vnm,
								sw_if_index));
	      goto done;
	    }
        }
    }

done:
  unformat_free (line_input);
  vec_free (inside_sw_if_indices);

  return error;
}

VLIB_CLI_COMMAND (kp_set_interface_nat4_command, static) = {
  .path = "kube-proxy set interface nat4",
  .function = kp_set_interface_nat4_command_fn,
  .short_help = "kube-proxy set interface nat4 in <intfc> [del]",
};

static clib_error_t *
kp_flowtable_flush_command_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 thread_index;
  vlib_thread_main_t *tm = vlib_get_thread_main();
  kp_main_t *kpm = &kp_main;

  for(thread_index = 0; thread_index < tm->n_vlib_mains; thread_index++ ) {
    kp_hash_t *h = kpm->per_cpu[thread_index].sticky_ht;
    if (h != NULL) {
        kp_hash_bucket_t *b;
        u32 i;
        kp_hash_foreach_entry(h, b, i) {
          vlib_refcount_add(&kpm->pod_refcount, thread_index, b->value[i], -1);
          vlib_refcount_add(&kpm->pod_refcount, thread_index, 0, 1);
        }

        kp_hash_free(h);
        kpm->per_cpu[thread_index].sticky_ht = NULL;
    }
  }

  return NULL;
}

/*
 * flush all kube-proxy flowtables
 * This is indented for debug and unit-tests purposes only
 */
VLIB_CLI_COMMAND (kp_flowtable_flush_command, static) = {
  .path = "test kube-proxy flowtable flush",
  .short_help = "test kube-proxy flowtable flush",
  .function = kp_flowtable_flush_command_fn,
};
