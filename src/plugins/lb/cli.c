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
  ip46_address_t prefix;
  u8 plen;
  u32 new_len = 1024;
  u8 del = 0;
  int ret;
  u32 gre4 = 0;
  lb_vip_type_t type;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat(line_input, "%U", unformat_ip46_prefix, &prefix, &plen, IP46_TYPE_ANY)) {
    error = clib_error_return (0, "invalid vip prefix: '%U'",
                               format_unformat_error, line_input);
    goto done;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "new_len %d", &new_len))
      ;
    else if (unformat(line_input, "del"))
      del = 1;
    else if (unformat(line_input, "encap gre4"))
      gre4 = 1;
    else if (unformat(line_input, "encap gre6"))
      gre4 = 0;
    else {
      error = clib_error_return (0, "parse error: '%U'",
                                format_unformat_error, line_input);
      goto done;
    }
  }


  if (ip46_prefix_is_ip4(&prefix, plen)) {
    type = (gre4)?LB_VIP_TYPE_IP4_GRE4:LB_VIP_TYPE_IP4_GRE6;
  } else {
    type = (gre4)?LB_VIP_TYPE_IP6_GRE4:LB_VIP_TYPE_IP6_GRE6;
  }

  lb_garbage_collection();

  u32 index;
  if (!del) {
    if ((ret = lb_vip_add(&prefix, plen, type, new_len, &index))) {
      error = clib_error_return (0, "lb_vip_add error %d", ret);
      goto done;
    } else {
      vlib_cli_output(vm, "lb_vip_add ok %d", index);
    }
  } else {
    if ((ret = lb_vip_find_index(&prefix, plen, &index))) {
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

VLIB_CLI_COMMAND (lb_vip_command, static) =
{
  .path = "lb vip",
  .short_help = "lb vip <prefix> [encap (gre6|gre4)] [new_len <n>] [del]",
  .function = lb_vip_command_fn,
};

static clib_error_t *
lb_as_command_fn (vlib_main_t * vm,
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

  if ((ret = lb_vip_find_index(&vip_prefix, vip_plen, &vip_index))) {
    error = clib_error_return (0, "lb_vip_find_index error %d", ret);
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

  lb_garbage_collection();
  clib_warning("vip index is %d", vip_index);

  if (del) {
    if ((ret = lb_vip_del_ass(vip_index, as_array, vec_len(as_array)))) {
      error = clib_error_return (0, "lb_vip_del_ass error %d", ret);
      goto done;
    }
  } else {
    if ((ret = lb_vip_add_ass(vip_index, as_array, vec_len(as_array)))) {
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
  .short_help = "lb as <vip-prefix> [<address> [<address> [...]]] [del]",
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

  pool_foreach(vip, lbm->vips, {
      vlib_cli_output(vm, "%U\n", verbose?format_lb_vip_detailed:format_lb_vip, vip);
  });

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
lb_flowtable_flush_command_fn (vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 thread_index;
  vlib_thread_main_t *tm = vlib_get_thread_main();
  lb_main_t *lbm = &lb_main;

  for(thread_index = 0; thread_index < tm->n_vlib_mains; thread_index++ ) {
    lb_hash_t *h = lbm->per_cpu[thread_index].sticky_ht;
    if (h != NULL) {
        u32 i;
        lb_hash_bucket_t *b;

        lb_hash_foreach_entry(h, b, i) {
            vlib_refcount_add(&lbm->as_refcount, thread_index, b->value[i], -1);
            vlib_refcount_add(&lbm->as_refcount, thread_index, 0, 1);
        }

        lb_hash_free(h);
        lbm->per_cpu[thread_index].sticky_ht = 0;
    }
  }

  return NULL;
}

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
